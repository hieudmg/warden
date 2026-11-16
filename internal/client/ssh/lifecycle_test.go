package ssh

import (
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	golangssh "golang.org/x/crypto/ssh"
	"warden/internal/model"
)

// lifecyclePeer joins its accept loop, SSH handlers and channel workers. Tests
// can abort real transports to reclaim a deliberately stalled baseline dial.
type lifecyclePeer struct {
	ln         net.Listener
	mu         sync.Mutex
	conns      map[net.Conn]struct{}
	acceptDone chan struct{}
	handlers   sync.WaitGroup
	opened     chan struct{}
	finished   chan struct{}
}

func newLifecyclePeer(t *testing.T, config *golangssh.ServerConfig, channel func(context.Context, golangssh.NewChannel)) *lifecyclePeer {
	t.Helper()
	config.AddHostKey(newTestSigner(t))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &lifecyclePeer{ln: ln, conns: make(map[net.Conn]struct{}), acceptDone: make(chan struct{}), opened: make(chan struct{}, 32), finished: make(chan struct{}, 32)}
	go func() {
		defer close(p.acceptDone)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			p.mu.Lock()
			p.conns[c] = struct{}{}
			p.mu.Unlock()
			p.handlers.Add(1)
			go func() {
				defer p.handlers.Done()
				defer func() { c.Close(); p.mu.Lock(); delete(p.conns, c); p.mu.Unlock(); p.finished <- struct{}{} }()
				s, chs, rs, err := golangssh.NewServerConn(c, config)
				if err != nil {
					return
				}
				defer s.Close()
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				var workers sync.WaitGroup
				workers.Add(1)
				go func() { defer workers.Done(); golangssh.DiscardRequests(rs) }()
				for ch := range chs {
					p.opened <- struct{}{}
					workers.Add(1)
					go func() { defer workers.Done(); channel(ctx, ch) }()
				}
				cancel()
				workers.Wait()
			}()
		}
	}()
	t.Cleanup(p.close)
	return p
}
func (p *lifecyclePeer) close() {
	p.ln.Close()
	<-p.acceptDone
	p.mu.Lock()
	for c := range p.conns {
		c.Close()
	}
	p.mu.Unlock()
	p.handlers.Wait()
}
func (p *lifecyclePeer) node() model.SSHNode {
	n := targetNode("fixture", p.ln.Addr().String())
	n.Username = "user"
	return n
}
func waitLifecycle(t *testing.T, done <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatalf("%s did not finish", what)
	}
}

func TestSecondHopDialAndHandshakeCancelWithoutDeadline(t *testing.T) {
	for _, phase := range []string{"dial", "handshake"} {
		for _, timeout := range []bool{false, true} {
			t.Run(phase+"/timeout="+strconv.FormatBool(timeout), func(t *testing.T) {
				entered := make(chan struct{})
				requestsDrained := make(chan struct{})
				var once sync.Once
				jump := newLifecyclePeer(t, &golangssh.ServerConfig{NoClientAuth: true}, func(ctx context.Context, ch golangssh.NewChannel) {
					if phase == "dial" {
						once.Do(func() { close(entered) })
						<-ctx.Done()
						return
					}
					c, rs, err := ch.Accept()
					if err != nil {
						return
					}
					go func() { defer close(requestsDrained); golangssh.DiscardRequests(rs) }()
					defer func() { c.Close(); <-requestsDrained }()
					// Consume the client identification, but never send an SSH banner.
					var b [256]byte
					c.Read(b[:])
					once.Do(func() { close(entered) })
					io.Copy(io.Discard, c)
				})
				ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
				defer cancel()
				done := make(chan struct{})
				var dialErr error
				go func() {
					g, err := DialGraph(ctx, model.SSHBundle{Target: model.SSHNode{Name: "stalled", Host: "127.0.0.1", Port: 22}, Jumps: []model.SSHNode{jump.node()}}, testOptions())
					dialErr = err
					if g != nil {
						g.Close()
					}
					close(done)
				}()
				waitLifecycle(t, entered, "second-hop "+phase)
				want := context.Canceled
				if timeout {
					want = context.DeadlineExceeded
				} else {
					cancel()
				}
				select {
				case <-done:
				case <-time.After(time.Second):
					t.Error("cancellation left second-hop establishment blocked")
					jump.close()
					<-done
				}
				waitLifecycle(t, jump.finished, "jump connection handler")
				if phase == "handshake" {
					select {
					case <-requestsDrained:
					default:
						t.Error("handler completion preceded channel request drain")
					}
				}
				if !errors.Is(dialErr, want) {
					t.Errorf("dial error=%v; want %v", dialErr, want)
				}
			})
		}
	}
}

func TestProxyCONNECTCancelWithoutDeadline(t *testing.T) {
	for _, throughHop := range []bool{false, true} {
		for _, timeout := range []bool{false, true} {
			t.Run(strconv.FormatBool(throughHop)+"/timeout="+strconv.FormatBool(timeout), func(t *testing.T) {
				entered := make(chan struct{})
				var once sync.Once
				var via *golangssh.Client
				var peerEnded <-chan struct{}
				var requestsDrained <-chan struct{}
				var abort func()
				var node model.SSHNode
				if throughHop {
					drained := make(chan struct{})
					requestsDrained = drained
					jump := newLifecyclePeer(t, &golangssh.ServerConfig{NoClientAuth: true}, func(ctx context.Context, ch golangssh.NewChannel) {
						c, rs, err := ch.Accept()
						if err != nil {
							return
						}
						go func() { defer close(drained); golangssh.DiscardRequests(rs) }()
						defer func() { c.Close(); <-drained }()
						var b [1024]byte
						c.Read(b[:])
						once.Do(func() { close(entered) })
						io.Copy(io.Discard, c)
					})
					g, err := DialGraph(context.Background(), model.SSHBundle{Target: jump.node()}, testOptions())
					if err != nil {
						t.Fatal(err)
					}
					defer g.Close()
					via = g.Target()
					abort = jump.close
					peerEnded = jump.finished
					node = model.SSHNode{ProxyHost: "127.0.0.1", ProxyPort: 8080}
				} else {
					ln, err := net.Listen("tcp", "127.0.0.1:0")
					if err != nil {
						t.Fatal(err)
					}
					defer ln.Close()
					peerDone := make(chan struct{})
					peerEnded = peerDone
					var peer net.Conn
					go func() {
						defer close(peerDone)
						peer, _ = ln.Accept()
						if peer == nil {
							return
						}
						defer peer.Close()
						var b [1024]byte
						peer.Read(b[:])
						close(entered)
						io.Copy(io.Discard, peer)
					}()
					h, p, _ := net.SplitHostPort(ln.Addr().String())
					port, _ := strconv.Atoi(p)
					node = model.SSHNode{ProxyHost: h, ProxyPort: port}
					abort = func() { <-entered; peer.Close(); <-peerDone }
					defer abort()
				}
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				done := make(chan struct{})
				var got error
				go func() {
					c, err := proxyConnect(ctx, via, node, "127.0.0.1:22", 250*time.Millisecond)
					got = err
					if c != nil {
						c.Close()
					}
					close(done)
				}()
				waitLifecycle(t, entered, "CONNECT request")
				want := context.Canceled
				if timeout {
					want = context.DeadlineExceeded
				} else {
					cancel()
				}
				select {
				case <-done:
				case <-time.After(time.Second):
					t.Error("CONNECT cancellation remained blocked")
					abort()
					<-done
				}
				waitLifecycle(t, peerEnded, "proxy connection handler")
				if throughHop {
					select {
					case <-requestsDrained:
					default:
						t.Error("proxy handler completion preceded channel request drain")
					}
				}
				if !errors.Is(got, want) {
					t.Errorf("CONNECT error=%v; want %v", got, want)
				}
			})
		}
	}
}
