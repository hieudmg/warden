package agent

import (
	"context"
	"io"
	"net"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestGraphOwnsAgentConnectionThroughPoolReuseAndIdleEviction(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix SSH_AUTH_SOCK fixture; native Windows pending")
	}
	socket := filepath.Join(t.TempDir(), "auth.sock")
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	t.Setenv("SSH_AUTH_SOCK", socket)
	connected, agentDone := make(chan struct{}), make(chan struct{})
	var auth net.Conn
	go func() {
		defer close(agentDone)
		auth, _ = ln.Accept()
		if auth == nil {
			return
		}
		defer auth.Close()
		close(connected)
		io.Copy(io.Discard, auth)
	}()
	peer := newPoolLifecyclePeer(t, "dial")
	bundle := peer.bundle
	bundle.Target.Password = nil
	clock := &poolClock{now: time.Unix(1, 0)}
	pool := NewPool(lifecyclePoolDial, clock.Now, time.Minute)
	defer pool.shutdown()
	first, err := pool.Acquire(context.Background(), bundle)
	if err != nil {
		t.Fatal(err)
	}
	waitPoolPhase(t, connected)
	second, err := pool.Acquire(context.Background(), bundle)
	if err != nil {
		t.Fatal(err)
	}
	if first.Graph() != second.Graph() {
		t.Error("pool did not reuse graph")
	}
	first.Release()
	clock.Advance(2 * time.Minute)
	pool.Expire()
	select {
	case <-agentDone:
		t.Error("idle eviction closed an actively borrowed agent connection")
	default:
	}
	second.Release()
	clock.Advance(time.Minute)
	pool.Expire()
	select {
	case <-agentDone:
	case <-time.After(time.Second):
		auth.Close()
		<-agentDone
		t.Error("idle eviction did not close graph-owned agent connection")
	}
	if !pool.Empty() {
		t.Error("evicted graph retained")
	}
}
