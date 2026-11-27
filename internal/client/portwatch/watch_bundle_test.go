package portwatch

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	golangssh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"warden/internal/client/terminal"
	"warden/internal/model"
)

func TestWatchBundleNegotiatesFullScreenAfterEnteringRaw(t *testing.T) {
	rawErr := errors.New("raw setup failed")
	modeErr := errors.New("full-screen mode rejected")
	restoreErr := errors.New("restore failed")
	for _, tc := range []struct {
		name       string
		vt         bool
		rawErr     error
		modeErr    error
		restoreErr error
	}{
		{name: "full-screen mode enabled", vt: true},
		{name: "full-screen mode rejected", vt: true, modeErr: modeErr},
		{name: "full-screen mode rejected and restore failed", vt: true, modeErr: modeErr, restoreErr: restoreErr},
		{name: "VT unavailable"},
		{name: "VT unavailable and restore failed", restoreErr: restoreErr},
		{name: "raw setup failed", rawErr: rawErr},
		{name: "raw setup and restore failed", rawErr: rawErr, restoreErr: restoreErr},
	} {
		t.Run(tc.name, func(t *testing.T) {
			terminalFailed := tc.rawErr != nil || tc.restoreErr != nil
			var polls atomic.Int32
			peer := newWatchBundlePeer(t, watchKnownHosts(t), func(_ int, ch golangssh.NewChannel, _ chan struct{}) {
				polls.Add(1)
				if terminalFailed {
					_ = ch.Reject(golangssh.Prohibited, "polled despite terminal failure")
					return
				}
				// The full-screen worker can poll before the first render cancels.
				channel, reqs, err := ch.Accept()
				if err == nil {
					defer channel.Close()
					if req := <-reqs; req != nil {
						replyWatchListener(req, channel, 1) // outside the watched range
					}
				}
			}, false)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			session := &negotiatingWatchSession{vt: tc.vt, rawErr: tc.rawErr, modeErr: tc.modeErr, restoreErr: tc.restoreErr}
			var output bytes.Buffer
			out := watchOutputFunc(func(p []byte) (int, error) {
				if bytes.ContainsRune(p, '\x1b') {
					if !session.SupportsANSI() || !session.fullScreen {
						t.Errorf("escape sequence written before full-screen mode was enabled: %q", p)
					}
				} else if !session.restored {
					t.Errorf("plain output written before terminal restore: %q", p)
				}
				if !terminalFailed && (bytes.Contains(p, []byte("Host process name")) || bytes.Contains(p, []byte("port-watch: watching"))) {
					cancel()
				}
				return output.Write(p)
			})
			err := watchBundle(ctx, model.SSHBundle{Target: peer.node}, "3000", out, io.Discard, func() (terminal.Session, error) {
				return session, nil
			}, time.Second)
			if !terminalFailed && err != nil {
				t.Errorf("watchBundle error = %v, want nil", err)
			}
			var rejectedModeErr error
			if tc.restoreErr != nil {
				rejectedModeErr = tc.modeErr
			}
			for _, want := range []error{tc.rawErr, rejectedModeErr, tc.restoreErr} {
				if want != nil && !errors.Is(err, want) {
					t.Errorf("watchBundle error = %v, want it to include %v", err, want)
				}
			}
			got := output.String()
			switch {
			case tc.vt && tc.modeErr == nil:
				for _, want := range []string{"\x1b[?1049h", "Host process name", "\x1b[?1049l"} {
					if !strings.Contains(got, want) {
						t.Errorf("missing %q in %q", want, got)
					}
				}
			case terminalFailed:
				if got != "" || polls.Load() != 0 {
					t.Errorf("terminal failure started plain watch: output = %q, polls = %d", got, polls.Load())
				}
			default:
				if strings.ContainsRune(got, '\x1b') || !strings.Contains(got, "port-watch: watching") {
					t.Errorf("expected plain fallback without escapes, got %q", got)
				}
			}
			if want := tc.vt && tc.rawErr == nil; (session.modeCalls == 1) != want || session.modeCalls > 1 {
				t.Errorf("EnableFullScreenOutput called %d times; want one call = %v", session.modeCalls, want)
			}
			if session.rawCalls != 1 || session.restoreCalls != 1 {
				t.Errorf("EnterRaw called %d times, Restore called %d times; want one each", session.rawCalls, session.restoreCalls)
			}
		})
	}
}

type negotiatingWatchSession struct {
	viewSession
	vt, fullScreen                    bool
	rawErr, modeErr, restoreErr       error
	rawCalls, modeCalls, restoreCalls int
}

func (s *negotiatingWatchSession) EnterRaw() error {
	s.rawCalls++
	if s.rawErr != nil {
		return s.rawErr
	}
	return s.viewSession.EnterRaw()
}

func (s *negotiatingWatchSession) SupportsANSI() bool { return s.vt && s.raw && !s.restored }

func (s *negotiatingWatchSession) EnableFullScreenOutput() error {
	s.modeCalls++
	if !s.SupportsANSI() {
		return errors.New("attempted full-screen mode before VT was enabled")
	}
	s.fullScreen = s.modeErr == nil
	return s.modeErr
}

func (s *negotiatingWatchSession) Restore() error {
	s.restoreCalls++
	if s.restoreErr != nil {
		return s.restoreErr
	}
	return s.viewSession.Restore()
}

type watchOutputFunc func([]byte) (int, error)

func (f watchOutputFunc) Write(p []byte) (int, error) { return f(p) }

func TestWatchBundleIsolatesProcessLookupFromSingleSessionPolling(t *testing.T) {
	for _, mode := range []string{"stalled-exec", "rejected-exec", "rejected-auth", "unknown-host", "reuse", "plain"} {
		t.Run(mode, func(t *testing.T) {
			keys := watchKnownHosts(t)
			first, second := watchTestPorts(t)
			var listening atomic.Int32
			listening.Store(1) // start with an out-of-range listener
			scans := make(chan int, 32)
			probeStarted := make(chan struct{})
			var sawProbe sync.Once
			var probes atomic.Int32
			peer := newWatchBundlePeer(t, keys, func(id int, ch golangssh.NewChannel, slot chan struct{}) {
				if ch.ChannelType() == "direct-tcpip" && id == 1 {
					echoWatchChannel(ch)
					return
				}
				if ch.ChannelType() != "session" {
					_ = ch.Reject(golangssh.Prohibited, "wrong connection for forward")
					return
				}
				select {
				case slot <- struct{}{}:
				default:
					_ = ch.Reject(golangssh.ResourceShortage, "one session per connection")
					return
				}
				channel, reqs, err := ch.Accept()
				if err != nil {
					<-slot
					return
				}
				req := <-reqs
				var exec struct{ Command string }
				if req != nil && req.Type == "exec" && golangssh.Unmarshal(req.Payload, &exec) == nil {
					switch exec.Command {
					case remoteListenerCommand:
						if id != 1 {
							t.Error("authoritative scan used optional connection")
						}
						port := int(listening.Load())
						replyWatchListener(req, channel, port)
						select {
						case scans <- port:
						default:
						}
					case remoteListenerProcessCommand:
						if id == 1 {
							t.Error("process lookup used the authoritative connection")
						}
						sawProbe.Do(func() { close(probeStarted) })
						switch mode {
						case "reuse":
							port := int(listening.Load())
							name, status := "python", uint32(0)
							switch probes.Add(1) {
							case 1:
								name = "node"
							case 2:
								status = 1
							}
							_ = req.Reply(true, nil)
							fmt.Fprintf(channel, "LISTEN 0 128 *:%d *:* users:((%q,pid=1,fd=3))\nLISTEN 0 128 *:%d *:*\n", port, name, second)
							_, _ = channel.SendRequest("exit-status", false, golangssh.Marshal(struct{ Status uint32 }{status}))
						case "rejected-exec":
							_ = req.Reply(false, nil)
							return // Keep the peer's sole session slot even on rejection.
						default:
							return // Stall exec while holding the sole session slot.
						}
					default:
						t.Errorf("unexpected exec %q", exec.Command)
					}
				}
				<-slot
				_ = channel.Close()
			}, mode == "rejected-auth")
			watch := startBundleWatch(t, model.SSHBundle{Target: peer.node}, first, second, mode != "plain")
			for i := 0; i < 2; i++ {
				select {
				case state := <-scans:
					if state != 1 {
						t.Fatalf("scan state %d, want out-of-range listener", state)
					}
				case <-watch.done:
					t.Fatalf("watch exited early: %v", watch.err)
				case <-time.After(2 * time.Second):
					t.Fatal("missing initial authoritative scan")
				}
			}
			if got := peer.connections.Load(); got != 1 {
				t.Fatalf("opened %d SSH connections with no matching ports", got)
			}
			if mode == "unknown-host" {
				// Remove trust only after authoritative SSH is established. The
				// optional connection must still perform host-key verification.
				if err := os.WriteFile(keys, nil, 0600); err != nil {
					t.Fatal(err)
				}
			}
			listening.Store(int32(first))
			waitForWatch(t, watch, "first forward", func() bool { return watchEcho(first) })
			if mode == "rejected-auth" || mode == "unknown-host" {
				waitForWatch(t, watch, "failed optional handshake", func() bool { return peer.optionalClosed.Load() == 1 })
			} else if mode != "plain" {
				select {
				case <-probeStarted:
				case <-watch.done:
					t.Fatalf("watch exited before process lookup: %v", watch.err)
				case <-time.After(2 * time.Second):
					t.Fatal("optional exec never started")
				}
			}
			if mode == "reuse" {
				waitForWatch(t, watch, "retry after nonzero exit on optional connection", func() bool { return probes.Load() >= 4 })
				assertNoWatchForward(t, second) // Metadata also reported this port.
				waitForWatch(t, watch, "initial name, unavailable, then recovered name in the rendered deltas", func() bool {
					_, afterNode, foundNode := strings.Cut(watch.out.String(), "node")
					_, afterUnavailable, foundUnavailable := strings.Cut(afterNode, "—")
					return foundNode && foundUnavailable && strings.Contains(afterUnavailable, "python")
				})
			}
			listening.Store(int32(second))
			waitForWatch(t, watch, "replacement forward", func() bool { return watchEcho(second) })
			if mode == "stalled-exec" && peer.optionalClosed.Load() != 0 {
				t.Fatal("authoritative forwarding did not change until after the stalled optional transport closed")
			}
			assertNoWatchForward(t, first)
			watch.stop(t)
			assertNoWatchForward(t, second)
			if mode == "plain" {
				if peer.connections.Load() != 1 || !strings.Contains(watch.out.String(), "port-watch: watching") {
					t.Fatalf("redirected watch opened optional SSH or lost plain output: %q", watch.out.String())
				}
			} else {
				waitForWatch(t, nil, "optional transport shutdown", func() bool { return peer.optionalClosed.Load() == 1 })
				if got := peer.connections.Load(); got != 2 {
					t.Fatalf("got %d connections, want one authoritative and one optional", got)
				}
				out := watch.out.String()
				if !watch.view.restored || !strings.Contains(out, "—") || !strings.Contains(out, "closed") {
					t.Fatalf("missing unavailable name, closed row or restoration: %q", out)
				}
			}
		})
	}
}

func TestWatchBundleCancelsStalledOptionalJump(t *testing.T) {
	for _, mode := range []string{"setup-timeout", "setup-quit", "exec-timeout"} {
		t.Run(mode, func(t *testing.T) {
			keys := watchKnownHosts(t)
			first, second := watchTestPorts(t)
			stalled := make(chan struct{})
			target := newWatchBundlePeer(t, keys, func(id int, incoming golangssh.NewChannel, _ chan struct{}) {
				if incoming.ChannelType() == "direct-tcpip" {
					echoWatchChannel(incoming)
					return
				}
				ch, reqs, err := incoming.Accept()
				if err != nil {
					return
				}
				req := <-reqs
				var exec struct{ Command string }
				if req != nil && golangssh.Unmarshal(req.Payload, &exec) == nil {
					if id == 2 && mode == "exec-timeout" && exec.Command == remoteListenerProcessCommand {
						_ = req.Reply(true, nil)
						close(stalled)
						return // Keep the session open after acknowledging exec.
					}
					if id == 1 && exec.Command == remoteListenerCommand {
						replyWatchListener(req, ch, first)
					} else {
						t.Errorf("unexpected target command on connection %d: %s", id, exec.Command)
					}
				}
				_ = ch.Close()
			}, false)
			jump := newWatchBundlePeer(t, keys, func(id int, incoming golangssh.NewChannel, _ chan struct{}) {
				var direct struct {
					Host       string
					Port       uint32
					Origin     string
					OriginPort uint32
				}
				if incoming.ChannelType() != "direct-tcpip" || golangssh.Unmarshal(incoming.ExtraData(), &direct) != nil || direct.Host != target.node.Host || int(direct.Port) != target.node.Port {
					_ = incoming.Reject(golangssh.Prohibited, "invalid fixture destination")
					return
				}
				if id == 2 && mode != "exec-timeout" {
					close(stalled)
					return // Never answer the optional graph's jump channel open.
				}
				ch, reqs, err := incoming.Accept()
				if err != nil {
					return
				}
				defer ch.Close()
				go golangssh.DiscardRequests(reqs)
				tcp, err := net.DialTimeout("tcp", watchLocalAddr(target.node.Port), time.Second)
				if err != nil {
					return
				}
				defer tcp.Close()
				done := make(chan struct{})
				go func() { _, _ = io.Copy(tcp, ch); _ = tcp.Close(); close(done) }()
				_, _ = io.Copy(ch, tcp)
				_ = ch.Close()
				_ = tcp.Close()
				<-done
			}, false)
			watch := startBundleWatch(t, model.SSHBundle{Target: target.node, Jumps: []model.SSHNode{jump.node}}, first, second, true)
			select {
			case <-stalled:
			case <-watch.done:
				t.Fatalf("watch exited before optional SSH stalled: %v", watch.err)
			case <-time.After(2 * time.Second):
				t.Fatal("optional SSH did not reach the intended stall")
			}
			waitForWatch(t, watch, "authoritative forward through jump", func() bool { return watchEcho(first) })
			if mode != "setup-quit" {
				waitForWatch(t, watch, "stalled jump socket closed without quitting", func() bool { return jump.optionalClosed.Load() == 1 })
				if mode == "exec-timeout" {
					waitForWatch(t, watch, "optional target socket closed", func() bool { return target.optionalClosed.Load() == 1 })
				}
				if !watchEcho(first) || jump.connections.Load() != 2 {
					t.Fatal("optional timeout affected authoritative forwarding or opened more graphs")
				}
			}
			watch.stop(t)
			waitForWatch(t, nil, "stalled jump socket closed after quit", func() bool { return jump.optionalClosed.Load() == 1 })
			assertNoWatchForward(t, first)
		})
	}
}

func watchTestPorts(t *testing.T) (int, int) {
	t.Helper()
	a, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	return a.Addr().(*net.TCPAddr).Port, unusedLocalPort(t)
}

func replyWatchListener(req *golangssh.Request, ch golangssh.Channel, port int) {
	_ = req.Reply(true, nil)
	fmt.Fprintf(ch, "LISTEN 0 128 127.0.0.1:%d 0.0.0.0:*\n", port)
	_, _ = ch.SendRequest("exit-status", false, golangssh.Marshal(struct{ Status uint32 }{}))
}

func echoWatchChannel(incoming golangssh.NewChannel) {
	ch, reqs, err := incoming.Accept()
	if err == nil {
		defer ch.Close()
		go golangssh.DiscardRequests(reqs)
		_, _ = io.Copy(ch, ch)
	}
}

func watchKnownHosts(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	dir := filepath.Join(home, ".ssh")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(dir, "known_hosts")
}

type watchBundlePeer struct {
	node           model.SSHNode
	connections    atomic.Int32
	optionalClosed atomic.Int32
}

func newWatchBundlePeer(t *testing.T, keys string, handle func(int, golangssh.NewChannel, chan struct{}), rejectOptionalAuth bool) *watchBundlePeer {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := golangssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); _ = listener.Close(); wg.Wait() })
	f, err := os.OpenFile(keys, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, err = fmt.Fprintln(f, knownhosts.Line([]string{knownhosts.Normalize(listener.Addr().String())}, signer.PublicKey()))
	_ = f.Close()
	if err != nil {
		t.Fatal(err)
	}
	const password = "port-watch-fixture"
	addr := listener.Addr().(*net.TCPAddr)
	peer := &watchBundlePeer{node: model.SSHNode{Name: "fixture", Host: addr.IP.String(), Port: addr.Port, Username: "portwatch", Password: []byte(password)}}
	wg.Go(func() {
		for {
			socket, err := listener.Accept()
			if err != nil {
				return
			}
			id := int(peer.connections.Add(1))
			wg.Go(func() {
				defer socket.Close()
				stop := context.AfterFunc(ctx, func() { _ = socket.Close() })
				defer stop()
				if id > 1 {
					defer peer.optionalClosed.Add(1)
				}
				cfg := &golangssh.ServerConfig{PasswordCallback: func(meta golangssh.ConnMetadata, pwd []byte) (*golangssh.Permissions, error) {
					if meta.User() == peer.node.Username && string(pwd) == password && !(id > 1 && rejectOptionalAuth) {
						return nil, nil
					}
					return nil, errors.New("rejected by fixture")
				}}
				cfg.AddHostKey(signer)
				_, channels, reqs, err := golangssh.NewServerConn(socket, cfg)
				if err != nil {
					return
				}
				go golangssh.DiscardRequests(reqs)
				slot := make(chan struct{}, 1)
				for ch := range channels {
					wg.Go(func() { handle(id, ch, slot) })
				}
			})
		}
	})
	return peer
}

type bundleWatchRun struct {
	view   *quitPortWatchSession
	cancel context.CancelFunc
	quit   chan struct{}
	done   chan struct{}
	out    watchFrameBuffer
	err    error
}

func startBundleWatch(t *testing.T, bundle model.SSHBundle, first, second int, fullScreen bool) *bundleWatchRun {
	t.Helper()
	w := &bundleWatchRun{quit: make(chan struct{}), done: make(chan struct{})}
	var openTerminal func() (terminal.Session, error)
	if fullScreen {
		w.view = &quitPortWatchSession{quit: w.quit}
		openTerminal = func() (terminal.Session, error) { return w.view, nil }
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	w.cancel = cancel
	go func() {
		defer close(w.done)
		w.err = watchBundle(ctx, bundle, fmt.Sprintf("%d,%d", first, second), &w.out, io.Discard, openTerminal, 30*time.Millisecond)
	}()
	t.Cleanup(func() { cancel(); <-w.done })
	return w
}

func (w *bundleWatchRun) stop(t *testing.T) {
	t.Helper()
	if w.view == nil {
		w.cancel()
	} else {
		close(w.quit)
	}
	select {
	case <-w.done:
		if w.err != nil {
			t.Fatal(w.err)
		}
	case <-time.After(time.Second):
		t.Fatal("quit waited for optional SSH")
	}
}

func waitForWatch(t *testing.T, w *bundleWatchRun, reason string, reached func() bool) {
	t.Helper()
	var done <-chan struct{}
	if w != nil {
		done = w.done
	}
	timeout := time.NewTimer(2 * time.Second)
	defer timeout.Stop()
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	for !reached() {
		select {
		case <-done:
			t.Fatalf("watch exited awaiting %s: %v", reason, w.err)
		case <-timeout.C:
			t.Fatalf("did not observe %s", reason)
		case <-tick.C:
		}
	}
}

func watchEcho(port int) bool {
	conn, err := net.DialTimeout("tcp", watchLocalAddr(port), 100*time.Millisecond)
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(200 * time.Millisecond))
	if _, err := io.WriteString(conn, "ping"); err != nil {
		return false
	}
	var got [4]byte
	_, err = io.ReadFull(conn, got[:])
	return err == nil && string(got[:]) == "ping"
}

func watchLocalAddr(port int) string { return net.JoinHostPort("127.0.0.1", strconv.Itoa(port)) }

func assertNoWatchForward(t *testing.T, port int) {
	t.Helper()
	if conn, err := net.DialTimeout("tcp", watchLocalAddr(port), 100*time.Millisecond); err == nil {
		conn.Close()
		t.Fatalf("local forward %d still accepts connections", port)
	}
}
