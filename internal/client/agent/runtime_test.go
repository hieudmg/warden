package agent

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRuntimeToken(t *testing.T) {
	runtime, err := NewRuntimeAt(filepath.Join(t.TempDir(), "warden", "agent"))
	if err != nil {
		t.Fatal(err)
	}

	got, err := runtime.CreateToken()
	if err != nil {
		t.Fatalf("CreateToken: %v", err)
	}
	if len(got) != tokenBytes {
		t.Fatalf("token length = %d, want %d", len(got), tokenBytes)
	}
	read, err := runtime.ReadToken()
	if err != nil {
		t.Fatalf("ReadToken: %v", err)
	}
	if !bytes.Equal(read, got) {
		t.Fatalf("ReadToken() = %x, want %x", read, got)
	}
	if _, err := runtime.CreateToken(); !errors.Is(err, os.ErrExist) {
		t.Fatalf("second CreateToken() error = %v, want os.ErrExist", err)
	}
}

func TestRuntimeListenDialAndCleanup(t *testing.T) {
	runtime, err := NewRuntimeAt(filepath.Join(t.TempDir(), "warden", "agent"))
	if err != nil {
		t.Fatal(err)
	}
	listener, err := runtime.Listen()
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}

	accepted := make(chan net.Conn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- conn
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := runtime.Dial(ctx)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	conn.Close()
	select {
	case acceptedConn := <-accepted:
		acceptedConn.Close()
	case err := <-acceptErr:
		t.Fatalf("Accept: %v", err)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for accepted connection")
	}

	token := runtime.tokenPath()
	if _, err := os.Stat(token); err != nil {
		t.Fatalf("token stat: %v", err)
	}
	if err := runtime.Cleanup(); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	if _, err := os.Stat(token); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("token after Cleanup: %v", err)
	}
}
