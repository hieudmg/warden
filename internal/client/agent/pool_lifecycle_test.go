package agent

import (
	"context"
	"errors"
	"testing"
	"time"

	clientssh "warden/internal/client/ssh"
	"warden/internal/model"
)

func TestPoolShutdownCancelsDialOwnerWithoutGraph(t *testing.T) {
	entered := make(chan struct{})
	escaped := make(chan struct{})
	pool := NewPool(func(ctx context.Context, _ model.SSHBundle) (*clientssh.Graph, error) {
		close(entered)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-escaped:
			return nil, errors.New("fixture abort")
		}
	}, time.Now, time.Minute)
	done := make(chan error, 1)
	go func() { _, err := pool.Acquire(context.Background(), testBundle("secret")); done <- err }()
	<-entered
	pool.shutdown()
	select {
	case <-done:
	case <-time.After(200 * time.Millisecond):
		close(escaped)
		<-done
		t.Error("shutdown left an unpublished dial owner running")
	}
	if !pool.Empty() {
		t.Error("shutdown leaked a dialing reservation")
	}
}

func TestPoolCanceledOwnerCannotPublishLateGraph(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	pool := NewPool(func(context.Context, model.SSHBundle) (*clientssh.Graph, error) {
		close(entered)
		<-release
		return &clientssh.Graph{}, nil
	}, time.Now, time.Minute)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		l, err := pool.Acquire(ctx, testBundle("secret"))
		if l != nil {
			l.Release()
		}
		done <- err
	}()
	<-entered
	cancel()
	close(release)
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Errorf("late graph publication error=%v; want context.Canceled", err)
	}
	if !pool.Empty() {
		t.Error("canceled acquisition retained a graph/reservation")
	}
	pool.Close()
}

func TestPoolShutdownReclaimsGraphCompletedBeforePublication(t *testing.T) {
	peer := newPoolLifecyclePeer(t, "dial")
	completed, publish := make(chan struct{}), make(chan struct{})
	var graph *clientssh.Graph
	pool := NewPool(func(ctx context.Context, bundle model.SSHBundle) (*clientssh.Graph, error) {
		g, err := lifecyclePoolDial(ctx, bundle)
		if err != nil {
			return nil, err
		}
		graph = g
		close(completed)
		<-publish
		return g, nil
	}, time.Now, time.Minute)
	result := make(chan error, 1)
	go func() {
		l, err := pool.Acquire(context.Background(), peer.bundle)
		if l != nil {
			l.Release()
		}
		result <- err
	}()
	waitPoolPhase(t, completed)
	pool.shutdown()
	close(publish)
	select {
	case err := <-result:
		if err == nil {
			t.Error("published graph after shutdown")
		}
	case <-time.After(time.Second):
		t.Fatal("late publication did not finish")
	}
	closed := make(chan struct{})
	go func() { graph.Target().Wait(); close(closed) }()
	waitPoolPhase(t, closed)
	if !pool.Empty() {
		t.Error("late publication retained lease/reservation")
	}
}

func TestPoolCanceledFollowerDoesNotLoseLease(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	pool := NewPool(func(context.Context, model.SSHBundle) (*clientssh.Graph, error) {
		close(entered)
		<-release
		return &clientssh.Graph{}, nil
	}, time.Now, time.Minute)
	defer pool.Close()
	done := make(chan *Lease, 1)
	go func() { l, _ := pool.Acquire(context.Background(), testBundle("secret")); done <- l }()
	<-entered
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if l, err := pool.Acquire(ctx, testBundle("secret")); l != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled follower=%v %v", l, err)
	}
	close(release)
	l := <-done
	l.Release()
	pool.mu.Lock()
	defer pool.mu.Unlock()
	for _, e := range pool.entries {
		if e.active != 0 {
			t.Errorf("active leases=%d", e.active)
		}
	}
}
