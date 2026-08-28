package agent

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	clientssh "warden/internal/client/ssh"
	"warden/internal/model"
)

type poolClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *poolClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *poolClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

func testBundle(password string) model.SSHBundle {
	return model.SSHBundle{Target: model.SSHNode{
		ID:       7,
		Host:     "target.example",
		Port:     22,
		Username: "user",
		Password: []byte(password),
	}}
}

func TestPoolReusesBundleAndExpiresAfterFinalRelease(t *testing.T) {
	clock := &poolClock{now: time.Unix(100, 0)}
	var calls atomic.Int64
	graph := &clientssh.Graph{}
	pool := NewPool(func(context.Context, model.SSHBundle) (*clientssh.Graph, error) {
		calls.Add(1)
		return graph, nil
	}, clock.Now, 10*time.Minute)
	bundle := testBundle("secret")

	first, err := pool.Acquire(context.Background(), bundle)
	if err != nil {
		t.Fatalf("first Acquire: %v", err)
	}
	second, err := pool.Acquire(context.Background(), bundle)
	if err != nil {
		t.Fatalf("second Acquire: %v", err)
	}
	if first.Graph() != second.Graph() {
		t.Fatal("same bundle did not reuse graph")
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("dial calls = %d, want 1", got)
	}

	first.Release()
	clock.Advance(10 * time.Minute)
	pool.Expire()
	if pool.Empty() {
		t.Fatal("pool expired graph while a lease remained")
	}
	second.Release()
	clock.Advance(10*time.Minute - time.Nanosecond)
	pool.Expire()
	if pool.Empty() {
		t.Fatal("pool expired before the final-release TTL")
	}
	clock.Advance(time.Nanosecond)
	pool.Expire()
	if !pool.Empty() {
		t.Fatal("pool retained graph at the final-release TTL")
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("dial calls after expiry = %d, want 1", got)
	}
}

func TestPoolFingerprintIncludesChangedPassword(t *testing.T) {
	clock := &poolClock{now: time.Unix(200, 0)}
	var calls atomic.Int64
	pool := NewPool(func(context.Context, model.SSHBundle) (*clientssh.Graph, error) {
		calls.Add(1)
		return &clientssh.Graph{}, nil
	}, clock.Now, time.Minute)
	first, err := pool.Acquire(context.Background(), testBundle("one"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := pool.Acquire(context.Background(), testBundle("two"))
	if err != nil {
		t.Fatal(err)
	}
	if first.Graph() == second.Graph() {
		t.Fatal("changed password reused graph")
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("dial calls = %d, want 2", got)
	}
	first.Release()
	second.Release()
}

func TestPoolRetireUsesReplacementWithoutReplayingLease(t *testing.T) {
	clock := &poolClock{now: time.Unix(300, 0)}
	var calls atomic.Int64
	pool := NewPool(func(context.Context, model.SSHBundle) (*clientssh.Graph, error) {
		if calls.Add(1) == 1 {
			return &clientssh.Graph{}, nil
		}
		return &clientssh.Graph{}, nil
	}, clock.Now, time.Minute)
	bundle := testBundle("secret")
	old, err := pool.Acquire(context.Background(), bundle)
	if err != nil {
		t.Fatal(err)
	}
	old.Retire()
	if pool.Empty() {
		// The retired lease is still active, so the pool is not actually
		// empty even though the entry is removed from future lookup.
		t.Fatal("retired active lease was treated as empty")
	}
	newLease, err := pool.Acquire(context.Background(), bundle)
	if err != nil {
		t.Fatal(err)
	}
	if old.Graph() == newLease.Graph() {
		t.Fatal("replacement acquisition reused retired graph")
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("dial calls = %d, want 2", got)
	}
	old.Release()
	newLease.Release()
	clock.Advance(time.Minute)
	pool.Expire()
	if !pool.Empty() {
		t.Fatal("pool retained graph after final release and expiry")
	}
}

func TestPoolConcurrentAcquireSingleFlight(t *testing.T) {
	started := make(chan struct{})
	allow := make(chan struct{})
	var calls atomic.Int64
	graph := &clientssh.Graph{}
	pool := NewPool(func(ctx context.Context, _ model.SSHBundle) (*clientssh.Graph, error) {
		calls.Add(1)
		close(started)
		select {
		case <-allow:
			return graph, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}, time.Now, time.Minute)

	bundle := testBundle("secret")
	firstResult := make(chan *Lease, 1)
	firstErr := make(chan error, 1)
	go func() {
		lease, err := pool.Acquire(context.Background(), bundle)
		firstResult <- lease
		firstErr <- err
	}()
	<-started

	secondResult := make(chan *Lease, 1)
	secondErr := make(chan error, 1)
	go func() {
		lease, err := pool.Acquire(context.Background(), bundle)
		secondResult <- lease
		secondErr <- err
	}()
	select {
	case <-secondResult:
		t.Fatal("follower acquired before the in-progress dial completed")
	case <-time.After(20 * time.Millisecond):
	}
	close(allow)
	first := <-firstResult
	if err := <-firstErr; err != nil {
		t.Fatal(err)
	}
	second := <-secondResult
	if err := <-secondErr; err != nil {
		t.Fatal(err)
	}
	if first.Graph() != second.Graph() {
		t.Fatal("single-flight followers received different graphs")
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("dial calls = %d, want 1", got)
	}
	first.Release()
	second.Release()
}

func TestPoolPublishesDialErrorToFollowers(t *testing.T) {
	want := errors.New("dial failed")
	started := make(chan struct{})
	allow := make(chan struct{})
	pool := NewPool(func(context.Context, model.SSHBundle) (*clientssh.Graph, error) {
		close(started)
		<-allow
		return nil, want
	}, time.Now, time.Minute)
	bundle := testBundle("secret")

	results := make(chan error, 2)
	go func() {
		_, err := pool.Acquire(context.Background(), bundle)
		results <- err
	}()
	<-started
	go func() {
		_, err := pool.Acquire(context.Background(), bundle)
		results <- err
	}()
	time.Sleep(20 * time.Millisecond)
	close(allow)
	for i := 0; i < 2; i++ {
		if err := <-results; !errors.Is(err, want) {
			t.Fatalf("Acquire error = %v, want %v", err, want)
		}
	}
}
