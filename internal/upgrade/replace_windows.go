//go:build windows

package upgrade

import (
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"syscall"
)

// replaceExecutable schedules replacement of executablePath after this process
// exits. Windows locks a running executable, so a detached PowerShell helper
// waits for the lock to clear and then moves the verified download over the
// target. The paths travel through the environment and the helper program is
// passed as an encoded command, so `%`, `&`, `"`, and `'` in a path are never
// interpreted as shell syntax. Replacement is asynchronous, so the returned
// scheduled flag is always true.
func replaceExecutable(tempPath, executablePath string, mode fs.FileMode) (bool, error) {
	cmd := exec.Command("powershell.exe",
		"-NoLogo",
		"-NoProfile",
		"-NonInteractive",
		"-ExecutionPolicy", "Bypass",
		"-EncodedCommand", encodePowerShellCommand(windowsHelperProgram),
	)
	cmd.Env = append(os.Environ(), windowsHelperEnv(tempPath, executablePath, os.Getpid())...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP,
	}
	if err := cmd.Start(); err != nil {
		return false, fmt.Errorf("start replacement helper: %w", err)
	}
	// Replacement is scheduled once the helper starts; a later move failure
	// must not report failure, because Upgrade would then delete the verified
	// download that the helper is still retrying to move.
	_ = cmd.Process.Release()
	return true, nil
}
