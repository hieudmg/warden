package agent

import (
	"bytes"
	"context"
	"crypto/tls"
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

	if _, err := runtime.Listen(); err != nil {
		t.Fatal(err)
	}
	defer runtime.Cleanup()
	got, err := runtime.ReadToken()
	if err != nil {
		t.Fatalf("ReadToken: %v", err)
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
	if _, err := runtime.Listen(); err != nil {
		t.Fatalf("idempotent Listen: %v", err)
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
		if err := conn.(*tls.Conn).Handshake(); err != nil {
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
