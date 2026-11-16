package upgrade

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Capture creation synchronously after owned PowerShell Start, BEFORE Wait can
// release its process handle. The later observer opens/pins and revalidates it.
func certutilFixtureBindCleanupObserver(pid int, ca certutilFixtureCAIdentity, phase string, env []string) (certutilFixtureCleanupObserver, error) {
	if err := ca.validateCertificate(); err != nil {
		return nil, err
	}
	if pid <= 0 || uint64(pid) > 1<<32-1 || pid == os.Getpid() {
		return nil, errors.New("invalid/self cleanup target")
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
	target := certutilFixtureCleanupTarget{Process: certutilFixtureControlTarget{PID: pid, Creation: creation, CA: ca}, Phase: phase}
	if err := target.validate(); err != nil {
		return nil, err
	}
	return func(ctx context.Context) (*exec.Cmd, error) {
		return certutilFixtureCleanupSnapshotCommand(ctx, target, env)
	}, nil
}

// Private read-only entry, NOT an extra acceptance name and NEVER an import
// consent handler. No target means no observation; unknown UI cannot be acted on.
func TestCertutilFixtureOwnedCleanupSnapshotProcess(t *testing.T) {
	value := os.Getenv(certutilFixtureCleanupSnapshotEnv)
	if value == "" {
		return
	}
	err := func() error {
		if os.Getenv("WARDEN_NATIVE_HTTPS_FIXTURE") != "1" || os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_OS") != "Windows" {
			return errors.New("disposable hosted fixture required")
		}
		if len(value) > 4096 {
			return errors.New("oversized cleanup target")
		}
		var target certutilFixtureCleanupTarget
		decoder := json.NewDecoder(strings.NewReader(value))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&target); err != nil {
			return err
		}
		if decoder.Decode(new(any)) != io.EOF {
			return errors.New("trailing cleanup identity")
		}
		if err := target.validate(); err != nil {
			return err
		}
		h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, uint32(target.Process.PID))
		if err != nil {
			return err
		}
		defer windows.CloseHandle(h)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		ownsProcess := func() bool {
			creation, err := certutilFixtureProcessCreation(h)
			return ctx.Err() == nil && target.matchesProcess(creation, err)
		}
		if !ownsProcess() {
			return errors.New("cleanup process/creation/public DER guard unavailable")
		}
		fmt.Printf("owned cleanup phase=%s pid=%d creation=%d expectedCN=%q expectedSHA1=%s DER-SHA256=%x; READ ONLY NO ACTION\n", target.Phase, target.Process.PID, target.Process.Creation, target.Process.CA.CN, target.Process.CA.Thumbprint, target.Process.CA.DERSHA256)
		certutilFixtureOwnedSnapshotGuarded(uint32(target.Process.PID), ownsProcess, func(root uintptr, tid uint32, caption string) {
			certutilFixtureCleanupOwnedControls(target, root, tid, caption, ownsProcess)
		})
		if !ownsProcess() {
			return errors.New("cleanup snapshot ended with unavailable process/DER/context; UNKNOWN")
		}
		return nil
	}()
	fmt.Printf("owned cleanup observation finished: error=%v; UI cause/identity/layout UNKNOWN; NO ACTION\n", err)
	if err != nil {
		os.Exit(3)
	}
}

// Read only standard Static/Button controls of this explicit owned dialog.
// Unknown strings never reach output: only numeric metadata and expected public
// identity occurrence counts are emitted. Counts cannot authorize a UI action.
func certutilFixtureCleanupOwnedControls(target certutilFixtureCleanupTarget, root uintptr, tid uint32, caption string, ownsProcess func() bool) {
	user32 := windows.NewLazySystemDLL("user32.dll")
	enumChild := user32.NewProc("EnumChildWindows")
	getParent := user32.NewProc("GetParent")
	getID := user32.NewProc("GetDlgCtrlID")
	isChild := user32.NewProc("IsChild")
	getCaption := user32.NewProc("GetWindowTextW")
	getText := user32.NewProc("SendMessageTimeoutW")
	for _, proc := range []*windows.LazyProc{enumChild, getParent, getID, isChild, getCaption, getText} {
		if err := proc.Find(); err != nil {
			fmt.Println("cleanup controls UNKNOWN: API unavailable")
			return
		}
	}
	owns := func(hwnd uintptr) bool {
		if hwnd == 0 || !ownsProcess() {
			return false
		}
		var owner uint32
		thread, err := windows.GetWindowThreadProcessId(windows.HWND(hwnd), &owner)
		return err == nil && owner == uint32(target.Process.PID) && thread == tid
	}
	classOf := func(hwnd uintptr) (string, bool) {
		var class [64]uint16
		n, err := windows.GetClassName(windows.HWND(hwnd), &class[0], int32(len(class)))
		return windows.UTF16ToString(class[:]), err == nil && n > 0 && n < int32(len(class)-1)
	}
	parentOK := func() bool {
		if root == 0 || !owns(root) {
			return false
		}
		class, complete := classOf(root)
		if !complete || class != "#32770" || !owns(root) {
			return false
		}
		var text [128]uint16
		n, _, _ := getCaption.Call(root, uintptr(unsafe.Pointer(&text[0])), uintptr(len(text)))
		return n > 0 && n < uintptr(len(text)-1) && windows.UTF16ToString(text[:]) == caption && owns(root)
	}
	count := 0
	complete := true
	callback := syscall.NewCallback(func(hwnd, _ uintptr) uintptr {
		count++
		if count > 32 {
			complete = false
			return 0
		}
		member := func() bool {
			if !parentOK() || !owns(hwnd) {
				return false
			}
			child, _, _ := isChild.Call(root, hwnd)
			return child != 0
		}
		if !member() {
			complete = false
			return 0
		}
		class, classOK := classOf(hwnd)
		parent, _, _ := getParent.Call(hwnd)
		id, _, _ := getID.Call(hwnd)
		if !member() {
			complete = false
			return 0
		}
		if !classOK || uint64(parent) != uint64(root) || (class != "Static" && class != "Button") {
			fmt.Printf("cleanup owned control id=%d; unsupported/incomplete metadata; text not queried; UNKNOWN\n", int32(id))
			complete = false
			return 1
		}
		var text [1024]uint16
		var chars uintptr
		if !member() {
			complete = false
			return 0
		}
		// WM_GETTEXT only; BLOCK|ABORTIFHUNG|ERRORONEXIT,100ms. No action message.
		result, _, _ := getText.Call(hwnd, 0x000D, uintptr(len(text)), uintptr(unsafe.Pointer(&text[0])), 0x23, 100, uintptr(unsafe.Pointer(&chars)))
		if !member() {
			complete = false
			return 0
		}
		currentClass, classOK := classOf(hwnd)
		currentParent, _, _ := getParent.Call(hwnd)
		currentID, _, _ := getID.Call(hwnd)
		if !classOK || currentClass != class || currentParent != parent || currentID != id || !member() {
			complete = false
			return 0
		}
		if result == 0 || chars >= uintptr(len(text)-1) || text[chars] != 0 {
			fmt.Println("cleanup owned control text incomplete/timeout; UNKNOWN")
			complete = false
			return 1
		}
		fmt.Println(certutilFixtureCleanupPublicControlEvidence(target, root, tid, certutilFixtureControl{
			HWND: uint64(hwnd), Parent: uint64(parent), PID: uint32(target.Process.PID), TID: tid, ID: int32(id), Class: class, Text: windows.UTF16ToString(text[:chars]), Complete: true,
		}))
		return 1
	})
	if !parentOK() {
		fmt.Println("cleanup controls UNKNOWN: lost explicit owned parent")
		return
	}
	enumChild.Call(root, callback, 0)
	fmt.Printf("cleanup scoped controls:end count=%d complete=%t; missing/partial/unknown data cannot exclude UI; NO ACTION\n", count, count > 0 && complete && parentOK())
}
