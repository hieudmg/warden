//go:build !windows

package upgrade

import (
	"fmt"
	"io/fs"
	"os"
)

// replaceExecutable atomically replaces executablePath with the verified
// download at tempPath. Unix can rename over a running executable, so the
// replacement is complete before Upgrade returns.
func replaceExecutable(tempPath, executablePath string, mode fs.FileMode) (bool, error) {
	if mode.Perm() == 0 {
		mode = 0o755
	}
	if err := os.Chmod(tempPath, mode); err != nil {
		return false, fmt.Errorf("set mode %v on %s: %w", mode.Perm(), tempPath, err)
	}
	if err := os.Rename(tempPath, executablePath); err != nil {
		return false, fmt.Errorf("rename %s to %s: %w", tempPath, executablePath, err)
	}
	return false, nil
}
