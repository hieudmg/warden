//go:build !windows

package agent

import (
	"bytes"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestRuntimeUnixRejectsUnsafeDiscoveryPaths(t *testing.T) {
	for _, kind := range []string{"directory symlink", "ancestor symlink", "public directory", "credential symlink", "public credentials", "credential hardlink", "lock symlink"} {
		t.Run(kind, func(t *testing.T) {
			base := t.TempDir()
			if err := os.Chmod(base, 0700); err != nil {
				t.Fatal(err)
			}
			runtime, _ := NewRuntimeAt(filepath.Join(base, "agent"))
			if _, err := runtime.Listen(); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(runtime.tokenPath())
			if err != nil {
				t.Fatal(err)
			}
			if err := runtime.Cleanup(); err != nil {
				t.Fatal(err)
			}
			// Prepare private valid stale credentials without a running endpoint.
			if err := os.WriteFile(runtime.tokenPath(), before, 0600); err != nil {
				t.Fatal(err)
			}
			outside := filepath.Join(base, "outside")
			if err := os.WriteFile(outside, []byte("unchanged"), 0600); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "directory symlink":
				if err := os.Rename(runtime.dir, runtime.dir+"-real"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(runtime.dir+"-real", runtime.dir); err != nil {
					t.Fatal(err)
				}
			case "ancestor symlink":
				if err := os.Mkdir(filepath.Join(base, "real"), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Join(base, "real"), filepath.Join(base, "link")); err != nil {
					t.Fatal(err)
				}
				runtime, _ = NewRuntimeAt(filepath.Join(base, "link", "agent"))
			case "public directory":
				if err := os.Chmod(runtime.dir, 0755); err != nil {
					t.Fatal(err)
				}
			case "credential symlink":
				if err := os.Remove(runtime.tokenPath()); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, runtime.tokenPath()); err != nil {
					t.Fatal(err)
				}
			case "public credentials":
				if err := os.Chmod(runtime.tokenPath(), 0644); err != nil {
					t.Fatal(err)
				}
			case "credential hardlink":
				if err := os.Link(runtime.tokenPath(), filepath.Join(base, "alias")); err != nil {
					t.Fatal(err)
				}
			case "lock symlink":
				if err := os.Remove(filepath.Join(runtime.dir, runtimeLock)); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, filepath.Join(runtime.dir, runtimeLock)); err != nil {
					t.Fatal(err)
				}
			}
			if kind != "lock symlink" {
				if _, err := runtime.ReadToken(); err == nil {
					t.Fatal("unsafe discovery read accepted")
				}
			}
			if _, err := runtime.Listen(); err == nil {
				runtime.Cleanup()
				t.Fatal("unsafe discovery replaced during startup")
			}
			after, err := os.ReadFile(outside)
			if err != nil || !bytes.Equal(after, []byte("unchanged")) {
				t.Fatal("startup followed or changed external target")
			}
		})
	}
}

func TestRuntimeUnixProbeCannotRemoveReplacedEndpoint(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "agent")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	runtime, _ := NewRuntimeAt(dir)
	path := runtime.EndpointPath()
	createStaleUnixSocket(t, path)
	original := dialUnixEndpoint
	defer func() { dialUnixEndpoint = original }()
	dialUnixEndpoint = func(string, time.Duration) (net.Conn, error) {
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("replacement"), 0600); err != nil {
			t.Fatal(err)
		}
		return nil, syscall.ECONNREFUSED
	}
	if _, err := runtime.Listen(); err == nil {
		t.Fatal("replaced endpoint was removed")
	}
	after, err := os.ReadFile(path)
	if err != nil || string(after) != "replacement" {
		t.Fatal("probe deleted replacement", err)
	}
}

func TestRuntimeUnixOpenedDescriptorOwner(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root runner uses the chown fixture below")
	}
	file, err := os.Open("/")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if info.Sys().(*syscall.Stat_t).Uid != 0 {
		t.Skip("OS root directory is not root-owned")
	}
	if err := validateUnixOwnerMode(info, 0700); err == nil || !strings.Contains(err.Error(), "wrong owner") {
		t.Fatalf("opened other-owner descriptor accepted: %v", err)
	}
}

func TestRuntimeUnixRejectsWrongOwner(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "agent")
	runtime, _ := NewRuntimeAt(dir)
	if _, err := runtime.Listen(); err != nil {
		t.Fatal(err)
	}
	defer runtime.Cleanup()
	uid := os.Geteuid() + 1
	if err := os.Chown(runtime.tokenPath(), uid, -1); err != nil {
		if errors.Is(err, os.ErrPermission) {
			t.Skip("requires chown privilege; native wrong-owner fixture pending")
		}
		t.Fatal(err)
	}
	defer os.Chown(runtime.tokenPath(), os.Geteuid(), -1)
	if _, err := runtime.ReadToken(); err == nil {
		t.Fatal("accepted other-owner trust")
	}
}
