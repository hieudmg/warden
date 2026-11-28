//go:build windows

package upgrade

import (
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func prepareReplacement(path string) (replacementPlan, error) {
	return prepareWindowsReplacement(path, nil)
}

func prepareWindowsReplacement(path string, beforeLock func()) (replacementPlan, error) {
	canonical, original, err := probeWindowsTarget(path)
	if err != nil {
		return replacementPlan{}, fmt.Errorf("inspect executable %s: %w", path, err)
	}
	// Only upgrade ordinary local-volume paths. Use the extended literal
	// spelling for rename, but omit its prefix in user-facing paths.
	if !strings.HasPrefix(canonical, `\\?\`) || len(canonical) < 7 || canonical[5:7] != `:\` {
		return replacementPlan{}, fmt.Errorf("upgrade requires a local drive path, got %s", canonical)
	}
	displayPath := strings.TrimPrefix(canonical, `\\?\`)

	// Acquire the shared installer lock before denying writes or deletes on
	// the target. Windows removes the inherited lock on last close or exit.
	if beforeLock != nil {
		beforeLock()
	}
	lock, err := openUpgradeFile(canonical+".upgrade.lock", windows.DELETE, windows.CREATE_NEW, windows.FILE_FLAG_DELETE_ON_CLOSE)
	if err != nil {
		return replacementPlan{}, fmt.Errorf("acquire upgrade lock for %s: %w", displayPath, err)
	}
	var guard windows.Handle
	closeHandles := func() {
		if guard != 0 {
			_ = windows.CloseHandle(guard)
		}
		_ = windows.CloseHandle(lock)
	}
	ok := false
	defer func() {
		if !ok {
			closeHandles()
		}
	}()

	guard, err = openUpgradeFile(canonical, windows.GENERIC_READ, windows.OPEN_EXISTING, 0)
	if err != nil {
		return replacementPlan{}, fmt.Errorf("guard executable %s: %w", path, err)
	}
	current, err := inspectUpgradeTarget(guard)
	if err != nil {
		return replacementPlan{}, fmt.Errorf("inspect guarded executable %s: %w", path, err)
	}
	if current != original {
		return replacementPlan{}, fmt.Errorf("executable identity changed while acquiring upgrade lock for %s; retry the upgrade", path)
	}
	guardPath, err := finalUpgradePath(guard, 0) // VOLUME_NAME_DOS
	if err != nil {
		return replacementPlan{}, fmt.Errorf("resolve guarded executable %s: %w", path, err)
	}
	if guardPath != canonical {
		return replacementPlan{}, fmt.Errorf("executable path changed while acquiring upgrade lock for %s; retry the upgrade", path)
	}
	image, err := finalUpgradePath(guard, 2) // VOLUME_NAME_NT, as returned by QueryFullProcessImageName
	if err != nil {
		return replacementPlan{}, fmt.Errorf("resolve executable image %s: %w", path, err)
	}
	ok = true
	return replacementPlan{
		path:        displayPath,
		close:       closeHandles,
		keepStaging: true,
		apply: func(stagedPath, digest string, _ fs.FileMode) (string, error) {
			status, err := scheduleWindowsReplacement(stagedPath, digest, canonical, image, guard, lock)
			if err != nil {
				return "", fmt.Errorf("%w; staging retained at %s", err, stagedPath)
			}
			return status, nil
		},
	}, nil
}

type windowsUpgradeFileID struct {
	volume uint64
	id     [16]byte
}

func probeWindowsTarget(path string) (string, windowsUpgradeFileID, error) {
	// Discover the sidecar name without interfering with another publisher.
	const shareAll = windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE | windows.FILE_SHARE_DELETE
	handle, err := openUpgradeFileWithSharing(path, windows.FILE_READ_ATTRIBUTES, shareAll, windows.OPEN_EXISTING, 0)
	if err != nil {
		return "", windowsUpgradeFileID{}, err
	}
	defer windows.CloseHandle(handle)
	id, err := inspectUpgradeTarget(handle)
	if err != nil {
		return "", windowsUpgradeFileID{}, err
	}
	canonical, err := finalUpgradePath(handle, 0) // VOLUME_NAME_DOS
	return canonical, id, err
}

func inspectUpgradeTarget(handle windows.Handle) (windowsUpgradeFileID, error) {
	var id windowsUpgradeFileID
	info, err := inspectUpgradeFile(handle)
	if err != nil {
		return id, err
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_READONLY != 0 {
		return id, fmt.Errorf("executable is read-only")
	}
	err = windows.GetFileInformationByHandleEx(handle, windows.FileIdInfo, (*byte)(unsafe.Pointer(&id)), uint32(unsafe.Sizeof(id)))
	return id, err
}

func openUpgradeFile(path string, access, disposition, flags uint32) (windows.Handle, error) {
	return openUpgradeFileWithSharing(path, access, windows.FILE_SHARE_READ, disposition, flags)
}

func openUpgradeFileWithSharing(path string, access, share, disposition, flags uint32) (windows.Handle, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	handle, err := windows.CreateFile(name, access, share, nil, disposition, flags|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return 0, err
	}
	return handle, nil
}

func inspectUpgradeFile(handle windows.Handle) (windows.ByHandleFileInformation, error) {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return info, err
	}
	if info.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT) != 0 || info.NumberOfLinks != 1 {
		return info, fmt.Errorf("expected a regular file with no reparse point or additional hard links")
	}
	return info, nil
}

func finalUpgradePath(handle windows.Handle, flags uint32) (string, error) {
	buf := make([]uint16, 32768)
	n, err := windows.GetFinalPathNameByHandle(handle, &buf[0], uint32(len(buf)), flags)
	if err != nil {
		return "", err
	}
	if n >= uint32(len(buf)) {
		return "", fmt.Errorf("path is too long")
	}
	return windows.UTF16ToString(buf[:n]), nil
}

func scheduleWindowsReplacement(stagedPath, digest, target, image string, guard, lock windows.Handle) (string, error) {
	// Pin the exact staged file object and recheck the release digest using
	// that handle. Share neither write nor delete access through publication.
	stage, err := openUpgradeFile(`\\?\`+stagedPath, windows.GENERIC_READ|windows.DELETE, windows.OPEN_EXISTING, 0)
	if err != nil {
		return "", fmt.Errorf("open verified staging: %w", err)
	}
	stagedFile := os.NewFile(uintptr(stage), stagedPath)
	defer stagedFile.Close()
	if _, err := inspectUpgradeFile(stage); err != nil {
		return "", fmt.Errorf("inspect verified staging: %w", err)
	}
	stagePath, err := finalUpgradePath(stage, 0)
	if err != nil {
		return "", fmt.Errorf("resolve verified staging: %w", err)
	}
	if stagePath != `\\?\`+stagedPath || filepath.Dir(stagePath) != filepath.Dir(target) {
		return "", fmt.Errorf("verified staging is no longer beside the executable")
	}
	got, err := openFileSHA256(stagedFile)
	if err != nil {
		return "", err
	}
	if got != digest {
		return "", fmt.Errorf("staging checksum changed: got %s, want %s", got, digest)
	}

	systemDir, err := windows.GetSystemDirectory()
	if err != nil {
		return "", fmt.Errorf("locate system PowerShell: %w", err)
	}
	// Explicitly inherit only these handles and the redirected output. In
	// particular the parent handle refers to this process even if its PID
	// would otherwise be recycled before the helper gets to run.
	ready, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return "", fmt.Errorf("create replacement helper readiness event: %w", err)
	}
	defer windows.CloseHandle(ready)
	authorized, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return "", fmt.Errorf("create replacement helper authorization event: %w", err)
	}
	defer windows.CloseHandle(authorized)

	self := windows.CurrentProcess()
	sources := []struct {
		handle windows.Handle
		access uint32
	}{
		{self, windows.SYNCHRONIZE}, {guard, 0}, {stage, 0}, {lock, 0},
		{ready, windows.EVENT_MODIFY_STATE}, {authorized, windows.SYNCHRONIZE},
	}
	var handles []syscall.Handle
	for _, source := range sources {
		options := uint32(0)
		if source.access == 0 {
			options = windows.DUPLICATE_SAME_ACCESS
		}
		var inherited windows.Handle
		if err := windows.DuplicateHandle(self, source.handle, self, &inherited, source.access, true, options); err != nil {
			return "", fmt.Errorf("prepare replacement helper handles: %w", err)
		}
		defer windows.CloseHandle(inherited)
		handles = append(handles, syscall.Handle(inherited))
	}

	statusPath := stagedPath + ".log"
	log, err := os.OpenFile(statusPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return "", fmt.Errorf("create replacement log %s: %w", statusPath, err)
	}
	defer log.Close()
	if _, err := fmt.Fprintf(log, "Verified staging: %s\nStarting replacement helper.\n", stagedPath); err != nil {
		return "", fmt.Errorf("write replacement log %s: %w", statusPath, err)
	}

	cmd := exec.Command(filepath.Join(systemDir, "WindowsPowerShell", "v1.0", "powershell.exe"),
		"-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", encodePowerShellCommand(windowsHelperProgram))
	cmd.Dir = systemDir
	cmd.Env = append(os.Environ(), windowsHelperEnv(target, image, uintptr(handles[0]), uintptr(handles[1]),
		uintptr(handles[2]), uintptr(handles[3]), uintptr(handles[4]), uintptr(handles[5]))...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		// Start without a console, with NUL stdin and file-backed stdout/stderr.
		// A nested exec waiting on its own pipes must not wait for this helper.
		CreationFlags:              windows.CREATE_NO_WINDOW,
		AdditionalInheritedHandles: handles,
	}
	if err := startWindowsHelper(cmd, ready, authorized, log); err != nil {
		_, _ = fmt.Fprintf(log, "Replacement failed: could not start helper: %v\n", err)
		return "", fmt.Errorf("start replacement helper (log: %s): %w", statusPath, err)
	}
	return statusPath, nil
}

func startWindowsHelper(cmd *exec.Cmd, ready, authorized windows.Handle, log *os.File) error {
	// Log host failures too, including errors before PowerShell enters the script.
	cmd.Stdout, cmd.Stderr = log, log
	if err := cmd.Start(); err != nil {
		return err
	}
	var result uint32
	var waitErr error
	if err := cmd.Process.WithHandle(func(handle uintptr) {
		const startupTimeout = 10 * time.Second
		result, waitErr = windows.WaitForMultipleObjects([]windows.Handle{windows.Handle(handle), ready}, false, uint32(startupTimeout.Milliseconds()))
	}); err != nil {
		waitErr = err
	}
	if waitErr == nil {
		switch result {
		case windows.WAIT_OBJECT_0:
			if err := cmd.Wait(); err != nil {
				return fmt.Errorf("PowerShell exited before readiness: %w", err)
			}
			return fmt.Errorf("PowerShell exited without signaling readiness")
		case windows.WAIT_OBJECT_0 + 1:
			if err := windows.SetEvent(authorized); err == nil {
				_ = cmd.Process.Release()
				return nil
			} else {
				waitErr = fmt.Errorf("authorize replacement helper: %w", err)
			}
		case uint32(windows.WAIT_TIMEOUT):
			waitErr = fmt.Errorf("timed out waiting for PowerShell readiness")
		default:
			waitErr = fmt.Errorf("unexpected replacement helper wait result %#x", result)
		}
	}
	// Without authorization the child cannot stop processes or rename files,
	// even if killing this timed-out helper unexpectedly fails.
	if cmd.Process.Kill() == nil {
		_ = cmd.Wait()
	} else {
		_ = cmd.Process.Release()
	}
	return waitErr
}
