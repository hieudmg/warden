package crypto

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestLoadMasterKeyValid(t *testing.T) {
	requireUnixKeyfileValidation(t)

	path := filepath.Join(t.TempDir(), "master.key")
	want := bytes.Repeat([]byte{0x7a}, 32)
	writeKeyFile(t, path, want, 0o600)

	got, err := LoadMasterKey(path)
	if err != nil {
		t.Fatalf("LoadMasterKey() error = %v", err)
	}
	if !bytes.Equal(got[:], want) {
		t.Fatalf("LoadMasterKey() = %x, want %x", got, want)
	}
}

func TestLoadMasterKeyMissing(t *testing.T) {
	requireUnixKeyfileValidation(t)

	_, err := LoadMasterKey(filepath.Join(t.TempDir(), "missing.key"))
	if err == nil {
		t.Fatal("LoadMasterKey() error = nil, want error")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("LoadMasterKey() error = %v, want os.ErrNotExist", err)
	}
}

func TestLoadMasterKeyRejectsWrongLength(t *testing.T) {
	requireUnixKeyfileValidation(t)

	for _, tc := range []struct {
		name string
		size int
	}{
		{name: "short", size: 31},
		{name: "long", size: 33},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "master.key")
			writeKeyFile(t, path, bytes.Repeat([]byte{0x42}, tc.size), 0o600)

			_, err := LoadMasterKey(path)
			if err == nil {
				t.Fatal("LoadMasterKey() error = nil, want error")
			}
			if !strings.Contains(err.Error(), "exactly 32 bytes") {
				t.Fatalf("LoadMasterKey() error = %v, want exact-length error", err)
			}
		})
	}
}

func TestLoadMasterKeyRejectsUnsafePermissions(t *testing.T) {
	requireUnixKeyfileValidation(t)

	path := filepath.Join(t.TempDir(), "master.key")
	writeKeyFile(t, path, bytes.Repeat([]byte{0x24}, 32), 0o640)

	_, err := LoadMasterKey(path)
	if err == nil {
		t.Fatal("LoadMasterKey() error = nil, want error")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "permission") {
		t.Fatalf("LoadMasterKey() error = %v, want permission error", err)
	}
}

func requireUnixKeyfileValidation(t *testing.T) {
	t.Helper()

	if runtime.GOOS == "windows" {
		t.Skip("LoadMasterKey is only supported for Unix-like server platforms")
	}
}

func writeKeyFile(t *testing.T, path string, content []byte, mode os.FileMode) {
	t.Helper()

	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("os.Chmod() error = %v", err)
	}
}
