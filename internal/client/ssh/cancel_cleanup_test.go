package ssh

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	golangssh "golang.org/x/crypto/ssh"
	"warden/internal/model"
)

// heldDeadlineContext models an elapsed deadline whose timer delivery has not
// run yet. Deadline is immutable; the explicit cancel releases timer ownership.
// This is a clock/dispatcher seam, not a sleep racing a real timer.
type heldDeadlineContext struct{ context.Context }

func (heldDeadlineContext) Deadline() (time.Time, bool) { return time.Unix(1, 0), true }

type cleanupOwner struct {
	golangssh.Conn
	once       sync.Once
	aborted    chan struct{}
	calls      atomic.Int32
	rootCloses atomic.Int32
	channel    *blockingCleanupChannel
}

func (o *cleanupOwner) Close() error {
	o.rootCloses.Add(1)
	o.once.Do(func() { close(o.aborted) })
	return nil
}
func (o *cleanupOwner) OpenChannel(string, []byte) (golangssh.Channel, <-chan *golangssh.Request, error) {
	rs := make(chan *golangssh.Request)
	close(rs)
	return o.channel, rs, nil
}

type blockingCleanupChannel struct {
	golangssh.Channel
	aborted <-chan struct{}
	closes  atomic.Int32
}

func (c *blockingCleanupChannel) Close() error          { c.closes.Add(1); <-c.aborted; return nil }
func (c *blockingCleanupChannel) Stderr() io.ReadWriter { return &bytes.Buffer{} }

func TestDialTCPContextStoppedCallbackStillAbortsExpiredLateChannel(t *testing.T) {
	base, cancel := context.WithCancel(context.Background())
	defer cancel()
	owner := &cleanupOwner{aborted: make(chan struct{})}
	owner.channel = &blockingCleanupChannel{aborted: owner.aborted}
	client := &golangssh.Client{Conn: owner}
	done := make(chan error, 1)
	go func() {
		_, err := DialTCPContext(heldDeadlineContext{base}, client, "127.0.0.1:3306", func(reason string) {
			owner.calls.Add(1)
			if reason != ChannelOpenCanceled {
				t.Errorf("reason=%q", reason)
			}
			owner.Close()
		})
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("error=%v", err)
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("stopped callback left expired late-channel Close without owner abort")
		owner.Close()
		<-done // RED cleanup must join, not abandon the blocked close.
	}
	if owner.calls.Load() != 1 {
		t.Errorf("owner abort calls=%d, want 1", owner.calls.Load())
	}
	if owner.channel.closes.Load() != 1 {
		t.Errorf("channel closes=%d, want 1", owner.channel.closes.Load())
	}
}

// cancelOnStoppedError is a real cancelable context with a deterministic
// cancellation at the first Err observation AFTER AfterFunc successfully stops.
// Value deliberately hides the native cancelCtx so AfterFunc uses our stop seam.
type cancelOnStoppedError struct {
	context.Context
	cancel  context.CancelFunc
	stopped atomic.Bool
}

func (c *cancelOnStoppedError) Value(any) any { return nil }
func (c *cancelOnStoppedError) AfterFunc(f func()) func() bool {
	stop := context.AfterFunc(c.Context, f)
	return func() bool {
		won := stop()
		if won {
			c.stopped.Store(true)
		}
		return won
	}
}
func (c *cancelOnStoppedError) Err() error {
	if c.stopped.Load() {
		c.cancel()
	}
	return c.Context.Err()
}
func TestCancellationStopWinThenCancelStillAbortsExactlyOnce(t *testing.T) {
	base, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx := &cancelOnStoppedError{Context: base, cancel: cancel}
	var aborts atomic.Int32
	finish := stopCancellation(ctx, func() { aborts.Add(1) })
	if err := finish(); !errors.Is(err, context.Canceled) {
		t.Errorf("finish=%v", err)
	}
	finish()
	if !ctx.stopped.Load() {
		t.Fatal("test did not make stopping win")
	}
	if aborts.Load() != 1 {
		t.Errorf("aborts=%d want 1", aborts.Load())
	}
}

type cleanupCONNECTConn struct {
	net.Conn
	response      *bytes.Reader
	aborted       <-chan struct{}
	cancelOnReset context.CancelFunc
	closes        atomic.Int32
}

func (c *cleanupCONNECTConn) Read(p []byte) (int, error)  { return c.response.Read(p) }
func (c *cleanupCONNECTConn) Write(p []byte) (int, error) { return len(p), nil }
func (c *cleanupCONNECTConn) SetDeadline(d time.Time) error {
	if c.cancelOnReset == nil {
		return errors.New("SSH channels have no deadlines")
	}
	if d.IsZero() {
		c.cancelOnReset()
	}
	return nil
}
func (c *cleanupCONNECTConn) Close() error { c.closes.Add(1); <-c.aborted; return nil }
func TestProxyCONNECTStoppedCallbackRetainsOwnerThroughCleanup(t *testing.T) {
	for _, phase := range []string{"elapsed-before-timer", "cancel-during-reset"} {
		t.Run(phase, func(t *testing.T) {
			base, cancel := context.WithCancel(context.Background())
			defer cancel()
			var ctx context.Context = heldDeadlineContext{base}
			owner := &cleanupOwner{aborted: make(chan struct{})}
			conn := &cleanupCONNECTConn{response: bytes.NewReader([]byte("HTTP/1.1 200 Connection established\r\n\r\n")), aborted: owner.aborted}
			if phase == "cancel-during-reset" {
				var stop context.CancelFunc
				ctx, stop = context.WithTimeout(base, time.Hour)
				defer stop()
				conn.cancelOnReset = cancel
			}
			done := make(chan error, 1)
			go func() {
				_, err := negotiateProxy(ctx, conn, &golangssh.Client{Conn: owner}, model.SSHNode{}, "fixture:22")
				done <- err
			}()
			select {
			case err := <-done:
				want := context.DeadlineExceeded
				if phase == "cancel-during-reset" {
					want = context.Canceled
				}
				if !errors.Is(err, want) {
					t.Errorf("error=%v want %v", err, want)
				}
			case <-time.After(100 * time.Millisecond):
				t.Error("CONNECT cleanup blocked after stopping root-abort callback")
				owner.Close()
				<-done
			}
			select {
			case <-owner.aborted:
			default:
				t.Error("failed through-hop CONNECT did not abort root")
			}
			if owner.rootCloses.Load() != 1 {
				t.Errorf("root closes=%d want 1", owner.rootCloses.Load())
			}
			if conn.closes.Load() != 1 {
				t.Errorf("CONNECT closes=%d want 1", conn.closes.Load())
			}
		})
	}
}
