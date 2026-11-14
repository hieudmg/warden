package agent

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestRuntimeCrashStartup(t *testing.T) {
	if path := os.Getenv("WARDEN_T10_TEST_CRASH_DIR"); path != "" {
		runtime, _ := NewRuntimeAt(path)
		if _, err := runtime.Listen(); err != nil {
			os.Exit(24)
		}
		os.Exit(23) // No cleanup: OS lock release, stale endpoint and valid discovery.
	}
	path := filepath.Join(t.TempDir(), "agent")
	command := exec.Command(os.Args[0], "-test.run=^TestRuntimeCrashStartup$")
	command.Env = append(os.Environ(), "WARDEN_T10_TEST_CRASH_DIR="+path)
	err := command.Run()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 23 {
		t.Fatalf("crash fixture did not listen: %v", err)
	}
	runtime, _ := NewRuntimeAt(path)
	old, err := os.ReadFile(runtime.tokenPath())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.Listen(); err != nil {
		t.Fatal("validated crash leftovers did not recover", err)
	}
	defer runtime.Cleanup()
	fresh, err := os.ReadFile(runtime.tokenPath())
	if err != nil || bytes.Equal(old, fresh) {
		t.Fatal("crash reused old identity")
	}
}

func TestRuntimeBindBeforeDiscovery(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent")
	owner, _ := NewRuntimeAt(path)
	listener, err := owner.Listen()
	if err != nil {
		t.Fatal(err)
	}
	old, err := os.ReadFile(owner.tokenPath())
	if err != nil {
		t.Fatal(err)
	}
	_ = listener.Close()
	if err := owner.Cleanup(); err != nil {
		t.Fatal(err)
	}
	// Windows mode bits do not create a private descriptor. Copy via the native
	// creator (the source record is synthetic IPC material).
	if err := rewritePrivateDiscovery(owner, old); err != nil {
		t.Fatal(err)
	}
	squatter, err := listenRuntime(owner, owner.EndpointPath())
	if err != nil {
		t.Fatal(err)
	}
	defer squatter.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		for {
			conn, err := squatter.Accept()
			if err != nil {
				return
			}
			conn.Close()
			if ctx.Err() != nil {
				return
			}
		}
	}()
	contender, _ := NewRuntimeAt(path)
	if _, err := contender.Listen(); err == nil {
		t.Fatal("startup joined live endpoint")
	}
	after, err := os.ReadFile(owner.tokenPath())
	if err != nil || !bytes.Equal(after, old) {
		t.Fatal("published trust before owning endpoint")
	}
	_ = contender.Cleanup()
}

func rewritePrivateDiscovery(runtime *Runtime, data []byte) error {
	directory, err := openPrivateDirectory(runtime.dir, false)
	if err != nil {
		return err
	}
	defer directory.Close()
	if err := directory.root.Remove(runtimeToken); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	file, err := openPrivateChild(directory.file, runtimeToken, os.O_WRONLY|os.O_CREATE|os.O_EXCL)
	if err != nil {
		return err
	}
	defer file.Close()
	return writeAll(file, data)
}

func TestRuntimeConcurrentStartup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a")
	const count = 8
	results := make(chan *Runtime, count)
	for i := 0; i < count; i++ {
		go func() {
			runtime, _ := NewRuntimeAt(path)
			if _, err := runtime.Listen(); err != nil {
				_ = runtime.Cleanup()
				results <- nil
			} else {
				results <- runtime
			}
		}()
	}
	var winner *Runtime
	wins := 0
	for i := 0; i < count; i++ {
		select {
		case runtime := <-results:
			if runtime != nil {
				winner = runtime
				wins++
			}
		case <-time.After(3 * time.Second):
			t.Fatal("startup race hung")
		}
	}
	if wins != 1 {
		t.Fatalf("startup winners %d, want1", wins)
	}
	defer winner.Cleanup()
	if _, err := winner.ReadToken(); err != nil {
		t.Fatal(err)
	}
}
