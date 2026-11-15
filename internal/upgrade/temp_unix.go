//go:build !windows

package upgrade

import "os"

func createUpgradeTemp(dir, prefix string) (*os.File, error) {
	return os.CreateTemp(dir, prefix)
}
