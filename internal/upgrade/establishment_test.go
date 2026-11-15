package upgrade

import (
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type establishmentCloseFixture struct {
	net.Conn
	calls            atomic.Int32
	entered, release chan struct{}
}

func (c *establishmentCloseFixture) Close() error {
	c.calls.Add(1)
	err := c.Conn.Close()
	if c.entered != nil {
		close(c.entered)
		<-c.release
	}
	return err
}

func TestEstablishmentStopJoinsRunningAbort(t *testing.T) {
	left, right := net.Pipe()
	defer right.Close()
	raw := &establishmentCloseFixture{Conn: left, entered: make(chan struct{}), release: make(chan struct{})}
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(raw.release) }) }
	conn := newEstablishmentConn(raw, time.Now().Add(time.Millisecond))
	defer func() { release(); _ = conn.Close() }()
	requireProxyEvent(t, raw.entered, "running raw-close callback")
	stopped := make(chan struct{})
	started := make(chan struct{})
	go func() { close(started); conn.stopEstablishment(); close(stopped) }()
	<-started
	select {
	case <-stopped:
		t.Error("readiness returned while abort callback still running")
	case <-time.After(50 * time.Millisecond):
	}
	release()
	requireProxyEvent(t, stopped, "readiness callback join")
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if raw.calls.Load() != 1 {
		t.Fatalf("raw closes=%d", raw.calls.Load())
	}
}

func TestEstablishmentLateReadyAndReuse(t *testing.T) {
	for _, alreadyReady := range []bool{false, true} {
		t.Run(map[bool]string{false: "late first readiness", true: "healthy reuse after original deadline"}[alreadyReady], func(t *testing.T) {
			left, right := net.Pipe()
			defer right.Close()
			raw := &establishmentCloseFixture{Conn: left}
			conn := newEstablishmentConn(raw, time.Now().Add(time.Hour))
			defer conn.Close()
			if alreadyReady {
				conn.stopEstablishment()
			}
			// Keep the actual callback held in the future while modeling a deadline
			// elapsed before its timer goroutine was scheduled. No global clock changes.
			conn.deadline = time.Now().Add(-time.Hour)
			conn.stopEstablishment()
			want := int32(1)
			if alreadyReady {
				want = 0
			}
			if raw.calls.Load() != want {
				t.Fatalf("raw closes=%d want=%d", raw.calls.Load(), want)
			}
			if conn.expired.Load() == alreadyReady {
				t.Fatalf("expired=%t, already ready=%t", conn.expired.Load(), alreadyReady)
			}
		})
	}
}
