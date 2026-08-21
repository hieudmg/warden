//go:build linux

package crypto

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestValidateMasterKeyPermissionsRejectsSpecialBits(t *testing.T) {
	for _, tc := range []struct {
		name string
		mode os.FileMode
	}{
		{name: "setuid", mode: 0o600 | os.ModeSetuid},
		{name: "setgid", mode: 0o600 | os.ModeSetgid},
		{name: "sticky", mode: 0o600 | os.ModeSticky},
		{name: "all-special-bits", mode: 0o600 | os.ModeSetuid | os.ModeSetgid | os.ModeSticky},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateMasterKeyPermissions("master.key", tc.mode)
			if err == nil {
				t.Fatal("validateMasterKeyPermissions() error = nil, want error")
			}
			if !strings.Contains(strings.ToLower(err.Error()), "permission") {
				t.Fatalf("validateMasterKeyPermissions() error = %v, want permission error", err)
			}
		})
	}
}

func TestLoadMasterKeyRejectsMismatchedOwner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "master.key")
	writeKeyFile(t, path, bytes.Repeat([]byte{0x33}, 32), 0o600)

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("os.Stat() error = %v", err)
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatalf("FileInfo.Sys() = %T, want *syscall.Stat_t", info.Sys())
	}

	_, err = loadMasterKeyLinux(path, func() int {
		return int(stat.Uid) + 1
	})
	if err == nil {
		t.Fatal("loadMasterKeyLinux() error = nil, want error")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "owner") {
		t.Fatalf("loadMasterKeyLinux() error = %v, want ownership error", err)
	}
}
