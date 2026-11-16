//go:build !windows

package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"

	clientagent "warden/internal/client/agent"
)

func TestAgentProcessExternalStop(t *testing.T) {
	if os.Getenv("WARDEN_T10_TEST_AGENT_CHILD") == "1" {
		os.Exit(run([]string{"agent", "serve"}, os.Stdout, os.Stderr, os.LookupEnv))
	}
	cache := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", cache)
	t.Setenv("HOME", cache)
	runtime, err := clientagent.NewRuntime()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(os.Args[0], "-test.run=^TestAgentProcessExternalStop$")
	command.Env = append(os.Environ(), "WARDEN_T10_TEST_AGENT_CHILD=1")
	var output bytes.Buffer
	command.Stdout = &output
	command.Stderr = &output
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	waited := false
	defer func() {
		if !waited {
			command.Process.Kill()
			command.Wait()
		}
	}()
	deadline := time.Now().Add(3 * time.Second)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		conn, err := runtime.Dial(ctx)
		cancel()
		if err == nil {
			conn.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("private child not ready: %v", err)
		}
		time.Sleep(5 * time.Millisecond)
	}
	if err := command.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	select {
	case err := <-done:
		waited = true
		if err != nil {
			t.Fatalf("external stop was not clean: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("daemon did not exit after external stop")
	}
	if output.Len() != 0 {
		t.Fatalf("stop emitted output: %q", output.String())
	}
	if _, err := runtime.ReadToken(); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("external stop retained discovery", err)
	}
}
