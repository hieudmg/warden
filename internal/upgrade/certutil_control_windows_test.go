package upgrade

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Called synchronously after the owned import Start and BEFORE Wait can release
// its process handle. Creation FILETIME plus a live handle prevents PID reuse
// from converting the later child observations into observations of a stranger.
func certutilFixtureOwnedControlCommand(ctx context.Context, pid int, ca certutilFixtureCAIdentity, env []string) (*exec.Cmd, error) {
	if err := ca.validateCertificate(); err != nil {
		return nil, err
	}
	if pid <= 0 || uint64(pid) > 1<<32-1 || pid == os.Getpid() {
		return nil, errors.New("invalid/self owned target")
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, uint32(pid))
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(h)
	creation, err := certutilFixtureProcessCreation(h)
	if err != nil {
		return nil, err
	}
	return certutilFixtureControlCommand(ctx, certutilFixtureControlTarget{PID: pid, Creation: creation, CA: ca}, env)
}

func certutilFixtureProcessCreation(h windows.Handle) (uint64, error) {
	state, err := windows.WaitForSingleObject(h, 0)
	if err != nil {
		return 0, err
	}
	if state != uint32(windows.WAIT_TIMEOUT) && state != uint32(windows.WAIT_OBJECT_0) {
		return 0, errors.New("owned process state unavailable")
	}
	var creation, exit, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(h, &creation, &exit, &kernel, &user); err != nil {
		return 0, err
	}
	identity := uint64(creation.HighDateTime)<<32 | uint64(creation.LowDateTime)
	if state == uint32(windows.WAIT_OBJECT_0) {
		return identity, errCertutilFixtureImportCompleted
	}
	return identity, nil
}

// Private infrastructure, not a seventeenth native acceptance test. No target
// means no action. Helper0 means guarded dispatch only, never import acceptance.
func TestCertutilFixtureOwnedControlsProcess(t *testing.T) {
	value := os.Getenv(certutilFixtureControlEnv)
	if value == "" {
		return
	}
	err := func() error {
		if os.Getenv("WARDEN_NATIVE_HTTPS_FIXTURE") != "1" || os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_OS") != "Windows" {
			return errors.New("disposable hosted fixture required")
		}
		if len(value) > 4096 {
			return errors.New("oversized observer identity")
		}
		var target certutilFixtureControlTarget
		decoder := json.NewDecoder(strings.NewReader(value))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&target); err != nil {
			return err
		}
		if decoder.Decode(new(any)) != io.EOF {
			return errors.New("trailing observer identity")
		}
		if err := target.validate(); err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return certutilFixtureOwnedControls(ctx, target)
	}()
	fmt.Printf("owned certificate consent: guardedDispatch=%t error=%v; exact DER import postcondition still required\n", err == nil, err)
	if err == nil {
		os.Exit(0)
	}
	if errors.Is(err, errCertutilFixtureImportCompleted) {
		os.Exit(certutilFixtureImportCompletedExit)
	}
	os.Exit(3) // identity/layout/ownership/action error; no retry
}

func certutilFixtureOwnedControls(ctx context.Context, target certutilFixtureControlTarget) error {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, uint32(target.PID))
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	processError := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		creation, err := certutilFixtureProcessCreation(h)
		if creation != target.Creation {
			return errors.New("owned process creation mismatch")
		}
		return err
	}
	live := func() bool { return processError() == nil }
	if err := processError(); err != nil {
		return err
	}
	user32 := windows.NewLazySystemDLL("user32.dll")
	enumThread := user32.NewProc("EnumThreadWindows")
	enumChild := user32.NewProc("EnumChildWindows")
	getCaption := user32.NewProc("GetWindowTextW")
	getParent := user32.NewProc("GetParent")
	getID := user32.NewProc("GetDlgCtrlID")
	isChild := user32.NewProc("IsChild")
	sendMessageTimeout := user32.NewProc("SendMessageTimeoutW")
	for _, proc := range []*windows.LazyProc{enumThread, enumChild, getCaption, getParent, getID, isChild, sendMessageTimeout, user32.NewProc("GetWindowThreadProcessId"), user32.NewProc("GetClassNameW")} {
		if err := proc.Find(); err != nil {
			return fmt.Errorf("API %s unavailable: %w", proc.Name, err)
		}
	}
	owns := func(hwnd uintptr, tid uint32) bool {
		if hwnd == 0 || !live() {
			return false
		}
		var pid uint32
		thread, err := windows.GetWindowThreadProcessId(windows.HWND(hwnd), &pid)
		return err == nil && pid == uint32(target.PID) && thread == tid
	}
	classOf := func(hwnd uintptr) (string, bool) {
		var class [64]uint16
		n, err := windows.GetClassName(windows.HWND(hwnd), &class[0], int32(len(class)))
		return windows.UTF16ToString(class[:]), err == nil && n > 0 && n < int32(len(class)-1)
	}
	// Only a numeric THREAD snapshot is system-wide. Filter owner BEFORE any
	// window enumeration, class/caption query or logging. Polling is capped, not
	// an import retry; missing/raced data is UNKNOWN, never evidence of no UI.
	readSnapshot := func() ([]certutilFixtureDialog, error) {
		if err := processError(); err != nil {
			return nil, err
		}
		dialogs, err := func() ([]certutilFixtureDialog, error) {
			snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
			if err != nil {
				return nil, err
			}
			defer windows.CloseHandle(snapshot)
			var dialogs []certutilFixtureDialog
			var readErr error
			var tid uint32
			threads, callbacks, entries := 0, 0, 0
			callback := syscall.NewCallback(func(hwnd, _ uintptr) uintptr {
				callbacks++
				if callbacks > 16 {
					readErr = errors.New("owned window cap reached")
					return 0
				}
				if !owns(hwnd, tid) {
					readErr = errors.New("lost window ownership")
					return 0
				}
				class, complete := classOf(hwnd)
				if !owns(hwnd, tid) || !complete {
					readErr = errors.New("class/ownership unavailable")
					return 0
				}
				if class != "#32770" {
					// Observed non-dialog certutil/Windows input infrastructure only.
					switch class {
					case "CertUtil", "MSCTFIME UI", "IME":
						return 1
					}
					readErr = errors.New("unknown owned top-level window class")
					return 0
				}
				var caption [128]uint16
				n, _, _ := getCaption.Call(hwnd, uintptr(unsafe.Pointer(&caption[0])), uintptr(len(caption)))
				if !owns(hwnd, tid) {
					readErr = errors.New("lost dialog ownership")
					return 0
				}
				title := windows.UTF16ToString(caption[:])
				dialogs = append(dialogs, certutilFixtureDialog{HWND: uint64(hwnd), PID: uint32(target.PID), TID: tid, Creation: target.Creation, Class: class, Caption: title, Complete: n > 0 && n < uintptr(len(caption)-1) && title == "Security Warning"})
				return 1
			})
			entry := windows.ThreadEntry32{Size: uint32(unsafe.Sizeof(windows.ThreadEntry32{}))}
			err = windows.Thread32First(snapshot, &entry)
			for err == nil && readErr == nil && live() {
				entries++
				if entries > 4096 || entry.Size != uint32(unsafe.Sizeof(entry)) {
					return nil, errors.New("thread traversal cap/incomplete entry")
				}
				if entry.OwnerProcessID == uint32(target.PID) {
					threads++
					if threads > 32 {
						return nil, errors.New("owned thread cap reached")
					}
					tid = entry.ThreadID
					enumThread.Call(uintptr(tid), callback, 0)
				}
				entry.Size = uint32(unsafe.Sizeof(entry))
				err = windows.Thread32Next(snapshot, &entry)
			}
			if readErr != nil {
				return nil, readErr
			}
			if err != nil && !errors.Is(err, windows.ERROR_NO_MORE_FILES) {
				return nil, err
			}
			if err := processError(); err != nil {
				return nil, err
			}
			return dialogs, nil
		}()
		if err != nil {
			return nil, err
		}
		if len(dialogs) == 0 {
			return dialogs, nil
		}
		if len(dialogs) != 1 || !dialogs[0].Complete {
			return nil, errors.New("missing/duplicate/unexpected owned warning; no child read")
		}
		d := &dialogs[0]
		root := uintptr(d.HWND)
		// Recheck the exact known parent on every control read. EnumChildWindows
		// with a null parent would be global enumeration and is never allowed here.
		dialogOK := func() bool {
			if root == 0 || !owns(root, d.TID) {
				return false
			}
			class, complete := classOf(root)
			if !complete || class != d.Class {
				return false
			}
			var caption [128]uint16
			n, _, _ := getCaption.Call(root, uintptr(unsafe.Pointer(&caption[0])), uintptr(len(caption)))
			return n > 0 && n < uintptr(len(caption)-1) && windows.UTF16ToString(caption[:]) == d.Caption && owns(root, d.TID)
		}
		var readErr error
		callback := syscall.NewCallback(func(hwnd, _ uintptr) uintptr {
			if len(d.Controls) == 32 {
				readErr = errors.New("owned control cap reached")
				return 0
			}
			member := func() bool {
				if !dialogOK() || !owns(hwnd, d.TID) {
					return false
				}
				result, _, _ := isChild.Call(root, hwnd)
				return result != 0
			}
			if !member() {
				readErr = errors.New("lost dialog/control ownership")
				return 0
			}
			class, complete := classOf(hwnd)
			parent, _, _ := getParent.Call(hwnd)
			id, _, _ := getID.Call(hwnd)
			c := certutilFixtureControl{HWND: uint64(hwnd), Parent: uint64(parent), PID: d.PID, TID: d.TID, ID: int32(id), Class: class}
			if !member() {
				readErr = errors.New("lost control metadata ownership")
				return 0
			}
			// Only standard public certificate text/buttons are queried. Other classes
			// retain metadata but are incomplete/UNKNOWN; no guessed control IDs/labels.
			if complete && (class == "Static" || class == "Button") {
				var text [1024]uint16
				var chars uintptr
				if !member() {
					readErr = errors.New("lost ownership before text read")
					return 0
				}
				// WM_GETTEXT=0x000D is system-marshalled across processes. BLOCK(1),
				// ABORTIFHUNG(2), ERRORONEXIT(0x20); never NOTIMEOUTIFNOTHUNG/broadcast.
				result, _, _ := sendMessageTimeout.Call(hwnd, 0x000D, uintptr(len(text)), uintptr(unsafe.Pointer(&text[0])), 0x23, 100, uintptr(unsafe.Pointer(&chars)))
				if !member() {
					readErr = errors.New("lost ownership after text read")
					return 0
				}
				currentClass, classOK := classOf(hwnd)
				currentParent, _, _ := getParent.Call(hwnd)
				currentID, _, _ := getID.Call(hwnd)
				if !classOK || currentClass != class || currentParent != parent || currentID != id || !member() {
					readErr = errors.New("control identity changed during text read")
					return 0
				}
				if result != 0 && chars < uintptr(len(text)-1) && text[chars] == 0 {
					c.Text = windows.UTF16ToString(text[:chars])
					c.Complete = id != 0 && parent != 0
				}
			}
			d.Controls = append(d.Controls, c)
			return 1
		})
		if !dialogOK() {
			return nil, errors.New("lost parent dialog before scoped enumeration")
		}
		enumChild.Call(root, callback, 0)
		if readErr != nil {
			return nil, readErr
		}
		if !dialogOK() {
			return nil, errors.New("lost parent dialog after scoped enumeration")
		}
		return dialogs, nil
	}
	var state certutilFixtureConsentState
	for attempt := 0; attempt < 32; attempt++ {
		dialogs, err := readSnapshot()
		if err != nil {
			return err
		}
		if len(dialogs) == 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(100 * time.Millisecond):
				continue
			}
		}
		// Only log the known public fixture warning, never foreign/unknown text.
		if err := certutilFixtureControlIdentityEvidence(target, dialogs); err != nil {
			return err
		}
		d := &dialogs[0]
		fmt.Printf("owned dialog pid=%d tid=%d creation=%d hwnd=%d class=%q caption=%q complete=%t\n", d.PID, d.TID, d.Creation, d.HWND, d.Class, d.Caption, d.Complete)
		for i, c := range d.Controls {
			fmt.Printf("owned control index=%d hwnd=%d parent=%d pid=%d tid=%d id=%d class=%q complete=%t textRunes=%d\n", i, c.HWND, c.Parent, c.PID, c.TID, c.ID, c.Class, c.Complete, len([]rune(c.Text)))
			// Quoted public text in fixed chunks stays below the streaming 1024-byte
			// line cap even if every rune needs a six-byte escape; no silent identity loss.
			runes := []rune(c.Text)
			for part := 0; len(runes) > 0; part++ {
				n := min(120, len(runes))
				fmt.Printf("owned control text index=%d part=%d value=%q\n", i, part, string(runes[:n]))
				runes = runes[n:]
			}
		}
		return state.dispatch(ctx, target, dialogs, readSnapshot, func(d certutilFixtureDialog) error {
			// One last full live-process/layout/text/DER read at the native seam;
			// every previous handle must still identify the same owned controls.
			current, err := readSnapshot()
			if err != nil {
				return err
			}
			if err := certutilFixtureControlIdentityEvidence(target, current); err != nil {
				return err
			}
			if !reflect.DeepEqual(current, []certutilFixtureDialog{d}) {
				return errors.New("native target changed before dispatch")
			}
			var yes certutilFixtureControl
			for _, c := range d.Controls {
				if c.ID == 6 {
					yes = c
				}
			}
			if !owns(uintptr(d.HWND), d.TID) || !owns(uintptr(yes.HWND), d.TID) {
				return errors.New("lost final Yes ownership")
			}
			parent, _, _ := getParent.Call(uintptr(yes.HWND))
			id, _, _ := getID.Call(uintptr(yes.HWND))
			class, complete := classOf(uintptr(yes.HWND))
			if !complete || class != "Button" || uint64(parent) != d.HWND || id != 6 || !owns(uintptr(yes.HWND), d.TID) {
				return errors.New("changed final Yes metadata")
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			// BM_CLICK has no message return value. Check FUNCTION success, not
			// the output LRESULT (normally zero). No focus/activation operation:
			// an inactive dialog might not act; only exit + exact DER prove import.
			// BLOCK|ABORTIFHUNG,100ms; omit ERRORONEXIT because a normal click can
			// destroy the button while processing. Never retry any ambiguous result.
			var ignored uintptr
			result, _, _ := sendMessageTimeout.Call(uintptr(yes.HWND), 0x00F5, 0, 0, 0x3, 100, uintptr(unsafe.Pointer(&ignored)))
			if result == 0 {
				return errors.New("Yes dispatch failed or timed out; attempt consumed")
			}
			fmt.Println("owned Yes dispatch completed once; not proof of import acceptance")
			return nil
		})
	}
	return errors.New("owned warning missing/unavailable within fixed observation bound")
}
