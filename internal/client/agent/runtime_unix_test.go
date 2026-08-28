//go:build !windows

package agent

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestRuntimeUnixRemovesOnlyStaleSocket(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "warden", "agent")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	endpoint := filepath.Join(dir, runtimeEndpoint)
	fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("create stale socket: %v", err)
	}
	if err := syscall.Bind(fd, &syscall.SockaddrUnix{Name: endpoint}); err != nil {
		_ = syscall.Close(fd)
		t.Fatalf("bind stale socket: %v", err)
	}
	if err := syscall.Close(fd); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(endpoint); err != nil {
		t.Fatalf("stale socket disappeared before test: %v", err)
	}

	runtime, err := NewRuntimeAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.Listen(); err != nil {
		t.Fatalf("Listen over stale socket: %v", err)
	}
	if err := runtime.Cleanup(); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}

	if err := os.WriteFile(endpoint, []byte("do not remove"), 0600); err != nil {
		t.Fatal(err)
	}
	runtime, err = NewRuntimeAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.Listen(); err == nil {
		t.Fatal("Listen over regular file succeeded")
	}
	if got, err := os.ReadFile(endpoint); err != nil || string(got) != "do not remove" {
		t.Fatalf("regular endpoint changed: %q, %v", got, err)
	}
	if err := os.Remove(endpoint); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Cleanup(); err != nil {
		t.Fatalf("Cleanup after regular endpoint: %v", err)
	}
}

func TestRuntimeUnixPermissions(t *testing.T) {
	runtime, err := NewRuntimeAt(filepath.Join(t.TempDir(), "warden", "agent"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}

	endpointInfo, err := os.Stat(runtime.endpointPath())
	if err != nil {
		t.Fatalf("socket stat: %v", err)
	}
	if got, want := endpointInfo.Mode().Perm(), os.FileMode(0600); got != want {
		t.Fatalf("socket mode = %o, want %o", got, want)
	}
	dirInfo, err := os.Stat(runtime.dirPath())
	if err != nil {
		t.Fatalf("runtime directory stat: %v", err)
	}
	if got, want := dirInfo.Mode().Perm(), os.FileMode(0700); got != want {
		t.Fatalf("runtime directory mode = %o, want %o", got, want)
	}
	tokenInfo, err := os.Stat(runtime.tokenPath())
	if err != nil {
		t.Fatalf("token stat: %v", err)
	}
	if got, want := tokenInfo.Mode().Perm(), os.FileMode(0600); got != want {
		t.Fatalf("token mode = %o, want %o", got, want)
	}
	endpoint := runtime.endpointPath()
	if err := runtime.Cleanup(); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	if _, err := os.Stat(endpoint); !os.IsNotExist(err) {
		t.Fatalf("socket after Cleanup: %v", err)
	}
}
