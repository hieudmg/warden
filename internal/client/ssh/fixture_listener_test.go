package ssh

import (
	"context"
	"net"
	"sync"
	"testing"
)

// sshFixtureListener owns accepted handlers as well as the listening socket.
// Only the accept loop adds handlers; shutdown joins it before waiting on them.
type sshFixtureListener struct {
	ctx        context.Context
	cancel     context.CancelFunc
	listener   net.Listener
	acceptDone chan struct{}
	once       sync.Once
	handlers   sync.WaitGroup
	mu         sync.Mutex
	conns      map[net.Conn]struct{}
	idle       chan struct{}
}

func newSSHFixtureListener(t *testing.T, listener net.Listener, serve func(context.Context, net.Conn)) *sshFixtureListener {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	f := &sshFixtureListener{ctx: ctx, cancel: cancel, listener: listener, acceptDone: make(chan struct{}), conns: make(map[net.Conn]struct{}), idle: make(chan struct{})}
	close(f.idle)
	go func() {
		defer close(f.acceptDone)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			f.mu.Lock()
			if len(f.conns) == 0 {
				f.idle = make(chan struct{})
			}
			f.conns[conn] = struct{}{}
			f.mu.Unlock()
			f.handlers.Add(1)
			go func() {
				defer f.handlers.Done()
				defer func() {
					conn.Close()
					f.mu.Lock()
					delete(f.conns, conn)
					if len(f.conns) == 0 {
						close(f.idle)
					}
					f.mu.Unlock()
				}()
				serve(ctx, conn)
			}()
		}
	}()
	t.Cleanup(f.close)
	return f
}

func (f *sshFixtureListener) close() {
	f.once.Do(func() {
		f.cancel()
		f.listener.Close()
		<-f.acceptDone
		f.mu.Lock()
		for conn := range f.conns {
			conn.Close()
		}
		f.mu.Unlock()
		f.handlers.Wait()
	})
}

// waitClosed observes natural handler/worker completion before forced cleanup.
// It does not Wait on a WaitGroup while the accept loop can still Add to it.
func (f *sshFixtureListener) waitClosed(t *testing.T) {
	t.Helper()
	f.mu.Lock()
	idle := f.idle
	f.mu.Unlock()
	waitFixtureDone(t, idle, "fixture connections and their workers before forced cleanup")
}

func TestSSHFixtureListenerShutdownJoinsLateAcceptedHandler(t *testing.T) {
	conn, peer := net.Pipe()
	defer peer.Close()
	defer conn.Close()
	listener := &lateFixtureListener{conn: conn, entered: make(chan struct{}), release: make(chan struct{}), closed: make(chan struct{})}
	var release sync.Once
	defer release.Do(func() { close(listener.release) })
	entered, finished := make(chan struct{}), make(chan struct{})
	fixture := newSSHFixtureListener(t, listener, func(ctx context.Context, _ net.Conn) {
		close(entered)
		<-ctx.Done()
		close(finished)
	})
	waitFixtureDone(t, listener.entered, "accept barrier")
	done := make(chan struct{})
	go func() { fixture.close(); close(done) }()
	waitFixtureDone(t, listener.closed, "listener close")
	select {
	case <-done:
		t.Error("shutdown returned before the late accept was registered")
	default:
	}
	release.Do(func() { close(listener.release) })
	waitFixtureDone(t, entered, "late accepted handler")
	waitFixtureDone(t, finished, "canceled late handler")
	waitFixtureDone(t, done, "accept loop and handler shutdown")
	assertFixtureEOF(t, peer)
}

// Accept may succeed concurrently with Close. Hold that result until shutdown
// is waiting, proving no handler can be added after the shutdown Wait starts.
type lateFixtureListener struct {
	conn                     net.Conn
	entered, release, closed chan struct{}
	calls                    int
	once                     sync.Once
}

func (l *lateFixtureListener) Accept() (net.Conn, error) {
	l.calls++
	if l.calls == 1 {
		close(l.entered)
		<-l.release
		return l.conn, nil
	}
	<-l.closed
	return nil, net.ErrClosed
}
func (l *lateFixtureListener) Close() error   { l.once.Do(func() { close(l.closed) }); return nil }
func (l *lateFixtureListener) Addr() net.Addr { return &net.TCPAddr{} }

func closeFixtureConnOnCancel(ctx context.Context, conn net.Conn) func() {
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { defer close(done); conn.Close() })
	return func() {
		if !stop() {
			<-done
		}
	}
}
