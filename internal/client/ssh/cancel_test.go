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

type deadlineErrorConn struct {
	net.Conn
	closes    atomic.Int32
	deadlines atomic.Int32
}

func (c *deadlineErrorConn) SetDeadline(time.Time) error {
	c.deadlines.Add(1)
	return errors.New("injected deadline failure")
}
func (c *deadlineErrorConn) Close() error { c.closes.Add(1); return c.Conn.Close() }

func TestNetworkNegotiationDeadlineErrorsStillCancelAndTimeout(t *testing.T) {
	for _, protocol := range []string{"ssh", "CONNECT"} {
		for _, mode := range []string{"cancel", "timeout"} {
			t.Run(protocol+"/"+mode, func(t *testing.T) {
				a, b := net.Pipe()
				defer a.Close()
				defer b.Close()
				raw := &deadlineErrorConn{Conn: a}
				entered, peerDone := make(chan struct{}), make(chan struct{})
				go func() {
					defer close(peerDone)
					var data [2048]byte
					b.Read(data[:])
					close(entered)
					io.Copy(io.Discard, b)
				}()
				var ctx context.Context
				var cancel context.CancelFunc
				if mode == "timeout" {
					ctx, cancel = context.WithTimeout(context.Background(), 30*time.Millisecond)
				} else {
					ctx, cancel = context.WithCancel(context.Background())
				}
				defer cancel()
				done := make(chan error, 1)
				go func() {
					var err error
					if protocol == "ssh" {
						_, err = handshakeNode(ctx, model.SSHNode{Host: "fixture", Port: 22, Password: []byte("unused")}, raw, nil, testOptions().HostKeyCallback)
					} else {
						_, err = negotiateProxy(ctx, raw, nil, model.SSHNode{}, "fixture:22")
					}
					done <- err
				}()
				waitLifecycle(t, entered, "negotiation write")
				if mode == "cancel" {
					cancel()
				}
				want := context.Canceled
				if mode == "timeout" {
					want = context.DeadlineExceeded
				}
				select {
				case err := <-done:
					if !errors.Is(err, want) {
						t.Errorf("error=%v want %v", err, want)
					}
				case <-time.After(time.Second):
					a.Close()
					<-done
					t.Fatal("deadline-error transport did not terminate")
				}
				waitLifecycle(t, peerDone, "peer handler")
				if raw.closes.Load() != 1 {
					t.Errorf("raw Close calls=%d; want exactly 1", raw.closes.Load())
				}
				if raw.deadlines.Load() == 0 {
					t.Error("test did not exercise SetDeadline error")
				}
			})
		}
	}
}

type observedDeadlineConn struct {
	net.Conn
	mu        sync.Mutex
	deadlines []time.Time
	failReset bool
}

func (c *observedDeadlineConn) SetDeadline(d time.Time) error {
	c.mu.Lock()
	c.deadlines = append(c.deadlines, d)
	c.mu.Unlock()
	if d.IsZero() && c.failReset {
		return errors.New("deadline reset failed")
	}
	return c.Conn.SetDeadline(d)
}
func TestReusableHandshakeStopsCancellationAndResetsDeadline(t *testing.T) {
	for _, resetError := range []bool{false, true} {
		name := "success"
		if resetError {
			name = "reset-error"
		}
		t.Run(name, func(t *testing.T) {
			peer := newLifecyclePeer(t, &golangssh.ServerConfig{NoClientAuth: true}, func(ctx context.Context, ch golangssh.NewChannel) {
				cc, rs, err := ch.Accept()
				if err != nil {
					return
				}
				defer cc.Close()
				for r := range rs {
					r.Reply(true, nil)
					if r.Type == "exec" {
						cc.SendRequest("exit-status", false, golangssh.Marshal(struct{ Status uint32 }{0}))
						return
					}
				}
			})
			c, err := net.Dial("tcp", peer.ln.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			raw := &observedDeadlineConn{Conn: c, failReset: resetError}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			node, err := handshakeNode(ctx, peer.node(), raw, nil, testOptions().HostKeyCallback)
			raw.mu.Lock()
			ds := append([]time.Time(nil), raw.deadlines...)
			raw.mu.Unlock()
			if len(ds) != 2 || ds[0].IsZero() || !ds[1].IsZero() {
				t.Errorf("deadline transitions=%v", ds)
			}
			if resetError {
				if err == nil {
					node.client.Close()
					t.Error("published transport with stale deadline")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer node.client.Close()
			cancel()
			if err := RunCommandOnClient(context.Background(), node.client, "true", Streams{}); err != nil {
				t.Fatalf("late cancellation closed reusable client: %v", err)
			}
		})
	}
}

func TestCancellationStopJoinsStartedCallback(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	entered, allow := make(chan struct{}), make(chan struct{})
	finish := stopCancellation(ctx, func() { close(entered); <-allow })
	cancel()
	<-entered
	done := make(chan struct{})
	go func() { finish(); close(done) }()
	select {
	case <-done:
		t.Error("finish returned before abort callback joined")
	case <-time.After(20 * time.Millisecond):
	}
	close(allow)
	waitLifecycle(t, done, "callback join")
	var calls atomic.Int32
	ctx2, cancel2 := context.WithCancel(context.Background())
	finish2 := stopCancellation(ctx2, func() { calls.Add(1) })
	if err := finish2(); err != nil {
		t.Fatal(err)
	}
	cancel2()
	finish2()
	if calls.Load() != 0 {
		t.Error("stopped callback ran after publication")
	}
}

type lateOpenConn struct {
	golangssh.Conn
	entered, abort chan struct{}
	once           sync.Once
	channel        *lateOpenChannel
}

func (c *lateOpenConn) Close() error { c.once.Do(func() { close(c.abort) }); return nil }
func (c *lateOpenConn) OpenChannel(string, []byte) (golangssh.Channel, <-chan *golangssh.Request, error) {
	close(c.entered)
	<-c.abort
	rs := make(chan *golangssh.Request)
	close(rs)
	return c.channel, rs, nil
}

type lateOpenChannel struct {
	golangssh.Channel
	closed atomic.Int32
}

func (c *lateOpenChannel) Close() error          { c.closed.Add(1); return nil }
func (c *lateOpenChannel) Stderr() io.ReadWriter { return bytes.NewBuffer(nil) }
func TestDialTCPContextClosesLateConfirmedChannel(t *testing.T) {
	ch := &lateOpenChannel{}
	transport := &lateOpenConn{entered: make(chan struct{}), abort: make(chan struct{}), channel: ch}
	client := &golangssh.Client{Conn: transport}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := DialTCPContext(ctx, client, "127.0.0.1:3306", func(string) { transport.Close() })
		done <- err
	}()
	<-transport.entered
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("error=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("late open did not return")
	}
	if ch.closed.Load() != 1 {
		t.Errorf("late channel close calls=%d", ch.closed.Load())
	}
}
