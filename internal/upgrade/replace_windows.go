//go:build windows

package upgrade

import (
	"fmt"
	"io/fs"
	"os/exec"
	"syscall"
)

// replaceExecutable schedules replacement of executablePath after this process
// exits. Windows locks a running executable, so a detached cmd.exe helper waits
// briefly, moves the verified download over the target with move /y, and
// deletes the download if the move fails. Replacement is asynchronous, so the
// returned scheduled flag is always true.
func replaceExecutable(tempPath, executablePath string, mode fs.FileMode) (bool, error) {
	script := "ping -n 3 127.0.0.1 >nul & move /y \"" + tempPath + "\" \"" + executablePath + "\" >nul 2>&1 || del /f /q \"" + tempPath + "\" >nul 2>&1"
	cmd := exec.Command("cmd.exe", "/d", "/s", "/c", script)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP,
	}
	if err := cmd.Start(); err != nil {
		return false, fmt.Errorf("start replacement helper: %w", err)
	}
	// Replacement is scheduled once the helper starts; a release failure must
	// not report failure, because Upgrade would then delete the verified
	// download that the helper is about to move.
	_ = cmd.Process.Release()
	return true, nil
}
