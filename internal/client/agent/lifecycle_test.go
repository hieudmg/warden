package agent

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	clientssh "warden/internal/client/ssh"
	"warden/internal/model"
)

func TestAuthAgentLivesUntilExternalCancellation(t *testing.T) {
	clock := &poolClock{now: time.Unix(500, 0)}
	pool := NewPool(func(context.Context, model.SSHBundle) (*clientssh.Graph, error) { return &clientssh.Graph{}, nil }, clock.Now, 10*time.Minute)
	runtime, _ := NewRuntimeAt(filepath.Join(t.TempDir(), "agent"))
	server, err := NewRuntimeServer(runtime, pool)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	initial, err := os.ReadFile(runtime.tokenPath())
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		// Zero API credentials is the current implementation, not a fake future
		// logout/revocation API. Outage/lock handling belongs to T4, not this test.
		clock.Advance(365 * 24 * time.Hour)
		pool.Expire()
		requestCtx, stop := context.WithTimeout(context.Background(), time.Second)
		conn, token, err := tryRuntime(requestCtx, runtime)
		if err != nil {
			stop()
			t.Fatal(err)
		}
		err = relayRequest(requestCtx, conn, token, Request{Operation: "liveness"}, clientssh.Streams{}, false)
		stop()
		if err == nil || err.Error() != "unknown agent operation" {
			t.Fatalf("agent stopped accepting: %v", err)
		}
	}
	after, err := os.ReadFile(runtime.tokenPath())
	if err != nil || !bytes.Equal(initial, after) {
		t.Fatal("idle changed runtime identity")
	}
	// Keep a verified connection waiting for its token frame when cancel arrives.
	conn, err := runtime.Dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("external cancel did not drain active IPC connection")
	}
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("active connection survived cancel")
	}
	if _, err := os.Stat(runtime.tokenPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("cancel retained runtime credentials", err)
	}
	if _, err := pool.Acquire(context.Background(), testBundle("secret")); !errors.Is(err, ErrPoolClosed) {
		t.Fatal("cancel left pool open", err)
	}
}

type firstWriteConn struct {
	net.Conn
	started chan struct{}
	once    sync.Once
}

func (c *firstWriteConn) Write(data []byte) (int, error) {
	c.once.Do(func() { close(c.started) })
	return c.Conn.Write(data)
}

func TestRelayRequestCancellationInterruptsInitialWrite(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	started := make(chan struct{})
	observed := &firstWriteConn{Conn: client, started: started}
	go func() {
		done <- relayRequest(ctx, observed, bytes.Repeat([]byte{1}, TokenBytes), Request{Operation: operationSSH}, clientssh.Streams{}, false)
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("first write did not start")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation error: %v", err)
		}
	case <-time.After(200 * time.Millisecond):
		client.Close()
		<-done
		t.Fatal("canceled client hung in first frame write")
	}
}
