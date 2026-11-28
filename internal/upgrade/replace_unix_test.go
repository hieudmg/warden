//go:build !windows

package upgrade

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestReplaceExecutable(t *testing.T) {
	dir := t.TempDir()
	current := filepath.Join(dir, "current")
	download := filepath.Join(dir, "download")
	// A non-default mode catches an implementation that always chmods 0755.
	if err := os.WriteFile(current, []byte("old binary"), 0o711); err != nil {
		t.Fatalf("write current: %v", err)
	}
	if err := os.Chmod(current, 0o711); err != nil {
		t.Fatalf("chmod current: %v", err)
	}
	if err := os.WriteFile(download, []byte("new binary"), 0o600); err != nil {
		t.Fatalf("write download: %v", err)
	}

	scheduled, err := replaceExecutable(download, current, 0o711)
	if err != nil {
		t.Fatalf("replaceExecutable() error = %v", err)
	}
	if scheduled {
		t.Fatalf("replaceExecutable() scheduled = true, want false on %s", runtime.GOOS)
	}
	assertFileContent(t, current, "new binary")
	if got := fileMode(t, current); got != 0o711 {
		t.Errorf("current mode = %v, want preserved 0711", got)
	}
	if _, err := os.Stat(download); !os.IsNotExist(err) {
		t.Errorf("temporary source still present after replacement: err = %v", err)
	}
}

func TestReplaceExecutableFailureLeavesTargetUnchanged(t *testing.T) {

	t.Run("missing parent directory", func(t *testing.T) {
		dir := t.TempDir()
		download := filepath.Join(dir, "download")
		if err := os.WriteFile(download, []byte("new binary"), 0o600); err != nil {
			t.Fatalf("write download: %v", err)
		}
		target := filepath.Join(dir, "missing", "current")

		if _, err := replaceExecutable(download, target, 0o755); err == nil {
			t.Fatal("replaceExecutable() error = nil, want rename failure")
		}
		if _, err := os.Stat(target); !os.IsNotExist(err) {
			t.Errorf("target exists after failed replacement: err = %v", err)
		}
		// A failed replacement must not destroy the verified download; Upgrade
		// removes it through its deferred cleanup.
		assertFileContent(t, download, "new binary")
	})

	t.Run("destination is an existing directory", func(t *testing.T) {
		dir := t.TempDir()
		download := filepath.Join(dir, "download")
		if err := os.WriteFile(download, []byte("new binary"), 0o600); err != nil {
			t.Fatalf("write download: %v", err)
		}
		target := filepath.Join(dir, "current")
		if err := os.Mkdir(target, 0o755); err != nil {
			t.Fatalf("mkdir target: %v", err)
		}
		old := filepath.Join(target, "old")
		if err := os.WriteFile(old, []byte("old binary"), 0o755); err != nil {
			t.Fatalf("write old: %v", err)
		}

		if _, err := replaceExecutable(download, target, 0o755); err == nil {
			t.Fatal("replaceExecutable() error = nil, want rename failure")
		}
		assertFileContent(t, old, "old binary")
	})
}
