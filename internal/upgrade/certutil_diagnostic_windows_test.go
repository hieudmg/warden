package upgrade

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"syscall"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Private subprocess entry, not one of the 16 native acceptance names. Running
// this test without the parent's explicit target does not observe any process.
func TestCertutilFixtureOwnedSnapshotProcess(t *testing.T) {
	value := os.Getenv(certutilFixtureSnapshotPID)
	if value == "" {
		return
	}
	pid, err := strconv.ParseUint(value, 10, 32)
	if err != nil || pid == 0 || pid == uint64(os.Getpid()) {
		fmt.Println("owned snapshot UNKNOWN: invalid/self target; no window query")
		return
	}
	certutilFixtureOwnedSnapshot(uint32(pid))
}

func certutilFixtureOwnedSnapshot(pid uint32) {
	certutilFixtureOwnedSnapshotGuarded(pid, func() bool { return true }, nil)
}

// Cleanup adds a pinned process/DER guard and a read-only owned-dialog visitor;
// the original snapshot entry retains its metadata-only behavior.
func certutilFixtureOwnedSnapshotGuarded(pid uint32, ownsProcess func() bool, ownedDialog func(uintptr, uint32, string)) {
	if !ownsProcess() {
		fmt.Println("owned snapshot UNKNOWN: process/CA guard unavailable")
		return
	}
	var session uint32
	if err := windows.ProcessIdToSessionId(pid, &session); err != nil {
		fmt.Printf("owned snapshot pid=%d session=UNKNOWN error=%v\n", pid, err)
	} else {
		fmt.Printf("owned snapshot pid=%d session=%d; categorical thread wait reason=UNKNOWN/not queried\n", pid, session)
	}
	user32 := windows.NewLazySystemDLL("user32.dll")
	enumThreadWindows := user32.NewProc("EnumThreadWindows")
	getWindowText := user32.NewProc("GetWindowTextW")
	getDlgItem := user32.NewProc("GetDlgItem")
	for _, proc := range []*windows.LazyProc{enumThreadWindows, getWindowText, getDlgItem, user32.NewProc("GetWindowThreadProcessId"), user32.NewProc("GetClassNameW")} {
		if err := proc.Find(); err != nil {
			fmt.Printf("owned snapshot UNKNOWN: API=%s error=%v\n", proc.Name, err)
			return
		}
	}
	// Toolhelp exposes a read-only numeric system thread table. Never log or
	// query windows for an entry until its OwnerProcessID equals the owned PID.
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		fmt.Printf("owned snapshot UNKNOWN: thread snapshot error=%v\n", err)
		return
	}
	defer func() {
		if err := windows.CloseHandle(snapshot); err != nil {
			fmt.Printf("owned snapshot handle close error=%v\n", err)
		}
	}()
	var tid uint32
	threads, callbacks, ownedWindows := 0, 0, 0
	ownerUnavailable, ownerRejected := 0, 0
	ownsWindow := func(hwnd uintptr) bool {
		if !ownsProcess() {
			ownerUnavailable++
			return false
		}
		var owner uint32
		windowThread, err := windows.GetWindowThreadProcessId(windows.HWND(hwnd), &owner)
		if err != nil || windowThread == 0 {
			ownerUnavailable++
		} else if owner != pid || windowThread != tid {
			ownerRejected++
		}
		return err == nil && owner == pid && windowThread == tid
	}
	callback := syscall.NewCallback(func(hwnd, _ uintptr) uintptr {
		callbacks++
		if callbacks > 16 {
			return 0
		}
		if !ownsWindow(hwnd) {
			return 1
		}
		var class [64]uint16
		classChars, classErr := windows.GetClassName(windows.HWND(hwnd), &class[0], int32(len(class)))
		if !ownsWindow(hwnd) {
			return 1
		}
		// EnumThreadWindows supplies nonchild windows in ANOTHER process;
		// GetWindowTextW reads only its bounded caption, not control text and
		// not WM_GETTEXT/SendMessage into a possibly blocked target.
		var caption [128]uint16
		captionChars, _, _ := getWindowText.Call(hwnd, uintptr(unsafe.Pointer(&caption[0])), uintptr(len(caption)))
		if !ownsWindow(hwnd) {
			return 1
		}
		yes, _, _ := getDlgItem.Call(hwnd, 6) // IDYES: presence only, NEVER a message/action
		no, _, _ := getDlgItem.Call(hwnd, 7)  // IDNO
		if !ownsWindow(hwnd) {
			return 1
		}
		ownedWindows++
		fmt.Printf("owned window pid=%d tid=%d class=%q classChars=%d classError=%v IDYES=%t IDNO=%t\n", pid, tid, windows.UTF16ToString(class[:]), classChars, classErr, yes != 0, no != 0)
		fmt.Printf("owned caption pid=%d tid=%d chars=%d title=%q; empty/truncated/raced caption is inconclusive\n", pid, tid, captionChars, windows.UTF16ToString(caption[:]))
		if ownedDialog != nil && classErr == nil && classChars > 0 && classChars < int32(len(class)-1) && windows.UTF16ToString(class[:]) == "#32770" && captionChars > 0 && captionChars < uintptr(len(caption)-1) {
			ownedDialog(hwnd, tid, windows.UTF16ToString(caption[:]))
		}
		return 1
	})
	entry := windows.ThreadEntry32{Size: uint32(unsafe.Sizeof(windows.ThreadEntry32{}))}
	err = windows.Thread32First(snapshot, &entry)
	entries := 0
	for err == nil && ownsProcess() {
		entries++
		if entries > 4096 {
			fmt.Println("owned snapshot UNKNOWN: thread traversal cap reached")
			return
		}
		if entry.Size != uint32(unsafe.Sizeof(entry)) {
			fmt.Println("owned snapshot UNKNOWN: incomplete thread entry")
			return
		}
		if entry.OwnerProcessID == pid {
			if threads == 32 || callbacks >= 16 {
				fmt.Println("owned snapshot UNKNOWN: fixed thread/window cap reached")
				break
			}
			tid = entry.ThreadID
			threads++
			fmt.Printf("owned thread pid=%d tid=%d\n", pid, tid)
			result, _, _ := enumThreadWindows.Call(uintptr(tid), callback, 0)
			// FALSE means no windows OR stopped callback, not a capability proof.
			fmt.Printf("owned thread enumeration pid=%d tid=%d result=%t; false/empty does NOT exclude UI\n", pid, tid, result != 0)
		}
		entry.Size = uint32(unsafe.Sizeof(entry))
		err = windows.Thread32Next(snapshot, &entry)
	}
	if err != nil && !errors.Is(err, windows.ERROR_NO_MORE_FILES) {
		fmt.Printf("owned snapshot UNKNOWN: thread traversal error=%v\n", err)
	}
	fmt.Printf("owned snapshot:end pid=%d threads=%d windows=%d ownerUnavailable=%d ownerRejected=%d; observation ONLY; absent/unavailable/partial metadata=UNKNOWN, not no-UI; no causal or consent decision\n", pid, threads, ownedWindows, ownerUnavailable, ownerRejected)
}
