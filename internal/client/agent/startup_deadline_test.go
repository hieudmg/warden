package agent

import (
	"context"
	"io"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestConnectOrStartOverallDeadline(t *testing.T) {
	runtime, _ := NewRuntimeAt(filepath.Join(t.TempDir(), "a"))
	listener, err := runtime.Listen()
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Cleanup()
	listener.Close()
	stalled, err := listenRuntime(runtime, runtime.EndpointPath())
	if err != nil {
		t.Fatal(err)
	}
	defer stalled.Close()
	var peers sync.WaitGroup
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		for {
			conn, err := stalled.Accept()
			if err != nil {
				return
			}
			peers.Add(1)
			go func() { defer peers.Done(); defer conn.Close(); _, _ = io.Copy(io.Discard, conn) }()
		}
	}()
	defer func() { stalled.Close(); <-acceptDone; peers.Wait() }()
	original := startAgentServer
	defer func() { startAgentServer = original }()
	starts := 0
	startAgentServer = func() error { starts++; return nil }
	start := time.Now()
	conn, _, err := connectOrStart(context.Background(), runtime)
	elapsed := time.Since(start)
	if err == nil {
		conn.Close()
		t.Fatal("stalled impostor connected")
	}
	if elapsed > agentStartupTimeout+500*time.Millisecond {
		t.Fatalf("startup exceeded total5s bound: %v", elapsed)
	}
	if starts != 1 {
		t.Fatalf("starts=%d, want1", starts)
	}
}
