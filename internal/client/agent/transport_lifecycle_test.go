package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	golangssh "golang.org/x/crypto/ssh"
	clientdb "warden/internal/client/db"
	clientssh "warden/internal/client/ssh"
	"warden/internal/model"
)

// poolLifecyclePeer deliberately never confirms direct-tcpip opens. Session
// requests still work, so independent graphs can prove healthy concurrent use.
type poolLifecyclePeer struct {
	ln         net.Listener
	bundle     model.SSHBundle
	opened     chan struct{}
	finished   chan struct{}
	accepted   atomic.Int32
	completed  atomic.Int32
	drains     atomic.Int32
	mu         sync.Mutex
	conns      map[net.Conn]bool
	acceptDone chan struct{}
	handlers   sync.WaitGroup
}

func newPoolLifecyclePeer(t *testing.T, phase string) *poolLifecyclePeer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	host, portstr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portstr)
	p := &poolLifecyclePeer{ln: ln, bundle: model.SSHBundle{Target: model.SSHNode{Host: host, Port: port, Password: []byte("fixture")}}, opened: make(chan struct{}, 32), finished: make(chan struct{}, 32), conns: map[net.Conn]bool{}, acceptDone: make(chan struct{})}
	cfg := &golangssh.ServerConfig{NoClientAuth: true}
	_, private, _ := ed25519.GenerateKey(rand.Reader)
	signer, err := golangssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	cfg.AddHostKey(signer)
	go func() {
		defer close(p.acceptDone)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			p.mu.Lock()
			p.conns[c] = true
			p.mu.Unlock()
			p.accepted.Add(1)
			p.handlers.Add(1)
			go func() {
				defer p.handlers.Done()
				defer func() {
					c.Close()
					p.mu.Lock()
					delete(p.conns, c)
					p.mu.Unlock()
					p.completed.Add(1)
					p.finished <- struct{}{}
				}()
				if phase == "direct" || phase == "proxy" {
					var b [2048]byte
					c.Read(b[:])
					p.opened <- struct{}{}
					io.Copy(io.Discard, c)
					return
				}
				s, chs, rs, err := golangssh.NewServerConn(c, cfg)
				if err != nil {
					return
				}
				defer s.Close()
				var workers sync.WaitGroup
				workers.Add(1)
				p.drains.Add(1)
				go func() { defer workers.Done(); defer p.drains.Add(-1); golangssh.DiscardRequests(rs) }()
				for ch := range chs {
					if ch.ChannelType() == "direct-tcpip" {
						if phase == "handshake" {
							cc, rs, err := ch.Accept()
							if err != nil {
								continue
							}
							workers.Add(2)
							p.drains.Add(1)
							go func() { defer workers.Done(); defer p.drains.Add(-1); golangssh.DiscardRequests(rs) }()
							go func() {
								defer workers.Done()
								defer cc.Close()
								var b [256]byte
								cc.Read(b[:])
								p.opened <- struct{}{}
								io.Copy(io.Discard, cc)
							}()
						} else {
							p.opened <- struct{}{}
						}
						continue
					}
					cc, rs, err := ch.Accept()
					if err != nil {
						continue
					}
					workers.Add(1)
					p.drains.Add(1)
					go func() {
						defer workers.Done()
						defer p.drains.Add(-1)
						defer func() { cc.Close(); golangssh.DiscardRequests(rs) }()
						for r := range rs {
							r.Reply(true, nil)
							if r.Type == "exec" {
								cc.SendRequest("exit-status", false, golangssh.Marshal(struct{ Status uint32 }{0}))
								return
							}
						}
					}()
				}
				workers.Wait()
			}()
		}
	}()
	t.Cleanup(func() {
		ln.Close()
		<-p.acceptDone
		p.mu.Lock()
		for c := range p.conns {
			c.Close()
		}
		p.mu.Unlock()
		p.handlers.Wait()
		if p.accepted.Load() != p.completed.Load() {
			t.Errorf("fixture handlers accepted=%d completed=%d", p.accepted.Load(), p.completed.Load())
		}
	})
	return p
}
func lifecyclePoolDial(ctx context.Context, bundle model.SSHBundle) (*clientssh.Graph, error) {
	return clientssh.DialGraph(ctx, bundle, clientssh.DialOptions{HostKeyCallback: func(string, net.Addr, golangssh.PublicKey) error { return nil }})
}
func waitPoolPhase(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal("fixture phase not reached")
	}
}

func TestDBChannelCancellationInvalidatesOnlyRequiredGraph(t *testing.T) {
	peer := newPoolLifecyclePeer(t, "dial")
	clock := &poolClock{now: time.Unix(1, 0)}
	pool := NewPool(lifecyclePoolDial, clock.Now, time.Minute)
	defer pool.shutdown()
	bundle := peer.bundle
	a, err := pool.Acquire(context.Background(), bundle)
	if err != nil {
		t.Fatal(err)
	}
	b, err := pool.Acquire(context.Background(), bundle)
	if err != nil {
		t.Fatal(err)
	}
	healthyBundle := bundle
	healthyBundle.Target.ID = 42
	healthy, err := pool.Acquire(context.Background(), healthyBundle)
	if err != nil {
		t.Fatal(err)
	}
	d1 := clientdb.NewBorrowedTunnelDialer(a, "127.0.0.1:3306")
	defer d1.Close()
	d2 := clientdb.NewBorrowedTunnelDialer(b, "127.0.0.1:3306")
	defer d2.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r1, r2 := make(chan error, 1), make(chan error, 1)
	go func() { _, err := d1.DialContext(ctx, "tcp", ""); r1 <- err }()
	go func() { _, err := d2.DialContext(context.Background(), "tcp", ""); r2 <- err }()
	waitPoolPhase(t, peer.opened)
	waitPoolPhase(t, peer.opened)
	cancel()
	select {
	case err := <-r1:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("canceled caller=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled open did not join")
	}
	select {
	case err := <-r2:
		if err == nil {
			t.Error("same-connection pending open unexpectedly survived")
		}
	case <-time.After(time.Second):
		t.Fatal("same-graph open did not join")
	}
	pool.mu.Lock()
	reason := a.entry.invalidReason
	pool.mu.Unlock()
	if reason != clientssh.ChannelOpenCanceled {
		t.Errorf("invalidation reason=%q", reason)
	}
	if err := clientssh.RunCommandOnClient(context.Background(), healthy.Target(), "true", clientssh.Streams{}); err != nil {
		t.Fatalf("independent healthy graph disrupted: %v", err)
	}
	replacement, err := pool.Acquire(context.Background(), bundle)
	if err != nil {
		t.Fatal(err)
	}
	if replacement.Graph() == a.Graph() {
		t.Error("invalidated graph reused")
	}
	if err := clientssh.RunCommandOnClient(context.Background(), replacement.Target(), "true", clientssh.Streams{}); err != nil {
		t.Fatal(err)
	}
	a.Release()
	b.Release()
	healthy.Release()
	replacement.Release()
	clock.Advance(time.Minute)
	pool.Expire()
	if !pool.Empty() {
		t.Error("leases/reservations leaked after invalidation and replacement")
	}
	for i := int32(0); i < peer.accepted.Load(); i++ {
		waitPoolPhase(t, peer.finished)
	}
	if peer.accepted.Load() != peer.completed.Load() || peer.drains.Load() != 0 {
		t.Errorf("before fixture cleanup: accepted=%d completed=%d request drains=%d", peer.accepted.Load(), peer.completed.Load(), peer.drains.Load())
	}
}

func TestServerExternalCancellationDuringGraphEstablishment(t *testing.T) {
	for _, phase := range []string{"direct", "dial", "handshake", "proxy"} {
		t.Run(phase, func(t *testing.T) {
			peer := newPoolLifecyclePeer(t, phase)
			bundle := peer.bundle
			if phase == "dial" || phase == "handshake" {
				bundle.Jumps = []model.SSHNode{bundle.Target}
				bundle.Target = model.SSHNode{Host: "127.0.0.1", Port: 22}
			}
			if phase == "proxy" {
				bundle.Target.ProxyHost = bundle.Target.Host
				bundle.Target.ProxyPort = bundle.Target.Port
				bundle.Target.Host = "127.0.0.1"
				bundle.Target.Port = 22
			}
			pool := NewPool(lifecyclePoolDial, time.Now, time.Minute)
			runtime, err := NewRuntimeAt(filepath.Join(t.TempDir(), "agent"))
			if err != nil {
				t.Fatal(err)
			}
			server, err := NewRuntimeServer(runtime, pool)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			serveDone := make(chan error, 1)
			go func() { serveDone <- server.Serve(ctx) }()
			requestDone := make(chan error, 1)
			go func() {
				c, token, err := tryRuntime(context.Background(), runtime)
				if err == nil {
					err = relayRequest(context.Background(), c, token, Request{Operation: operationSSH, SSHBundle: mustJSON(bundle)}, clientssh.Streams{}, false)
				}
				requestDone <- err
			}()
			waitPoolPhase(t, peer.opened)
			cancel()
			select {
			case err := <-serveDone:
				if !errors.Is(err, context.Canceled) {
					t.Errorf("shutdown=%v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("daemon did not join pending establishment handler")
			}
			select {
			case <-requestDone:
			case <-time.After(time.Second):
				t.Fatal("IPC request did not finish")
			}
			if !pool.Empty() {
				t.Error("shutdown leaked in-progress entry")
			}
			waitPoolPhase(t, peer.finished)
			if peer.accepted.Load() != peer.completed.Load() || peer.drains.Load() != 0 {
				t.Errorf("external cancellation before fixture cleanup: accepted=%d completed=%d request drains=%d", peer.accepted.Load(), peer.completed.Load(), peer.drains.Load())
			}
		})
	}
}
