package ssh

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	golangssh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"warden/internal/model"
)

func testAuthSocket(t *testing.T) (golangssh.PublicKey, *atomic.Int32, <-chan struct{}) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("Unix SSH_AUTH_SOCK fixture; native Windows execution pending")
	}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ring := agent.NewKeyring()
	if err := ring.Add(agent.AddedKey{PrivateKey: key}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "agent.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSH_AUTH_SOCK", path)
	count := &atomic.Int32{}
	done := make(chan struct{}, 32)
	acceptDone := make(chan struct{})
	var workers sync.WaitGroup
	var mu sync.Mutex
	conns := map[net.Conn]bool{}
	go func() {
		defer close(acceptDone)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns[c] = true
			mu.Unlock()
			count.Add(1)
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer func() {
					c.Close()
					count.Add(-1)
					mu.Lock()
					delete(conns, c)
					mu.Unlock()
					done <- struct{}{}
				}()
				agent.ServeAgent(ring, c)
			}()
		}
	}()
	t.Cleanup(func() {
		ln.Close()
		<-acceptDone
		mu.Lock()
		for c := range conns {
			c.Close()
		}
		mu.Unlock()
		workers.Wait()
	})
	k, err := golangssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return k, count, done
}

// forwardingTerminal needs no native console or platform-specific PTY fixture.
type forwardingTerminal struct{ events chan struct{} }

func (f *forwardingTerminal) EnterRaw() error                              { return nil }
func (f *forwardingTerminal) Restore() error                               { close(f.events); return nil }
func (f *forwardingTerminal) Stdin() io.Reader                             { return bytes.NewReader(nil) }
func (f *forwardingTerminal) Stdout() io.Writer                            { return io.Discard }
func (f *forwardingTerminal) Stderr() io.Writer                            { return io.Discard }
func (f *forwardingTerminal) Size() (int, int)                             { return 80, 24 }
func (f *forwardingTerminal) ResizeEvents() <-chan struct{}                { return f.events }
func (f *forwardingTerminal) SupportsANSI() bool                           { return true }
func (f *forwardingTerminal) StdinReadyWithin(time.Duration) (bool, error) { return true, nil }

func TestAgentAuthenticationDoesNotRequestForwarding(t *testing.T) {
	key, count, closed := testAuthSocket(t)
	var forwards, auths atomic.Int32
	peer := newLifecyclePeer(t, &golangssh.ServerConfig{PublicKeyCallback: func(_ golangssh.ConnMetadata, k golangssh.PublicKey) (*golangssh.Permissions, error) {
		if !bytes.Equal(k.Marshal(), key.Marshal()) {
			return nil, errAuthFailed
		}
		auths.Add(1)
		return nil, nil
	}}, func(ctx context.Context, ch golangssh.NewChannel) {
		if ch.ChannelType() != "session" {
			ch.Reject(golangssh.UnknownChannelType, "unsupported")
			return
		}
		c, rs, err := ch.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		for r := range rs {
			if r.Type == "auth-agent-req@openssh.com" {
				forwards.Add(1)
			}
			r.Reply(true, nil)
			if r.Type == "exec" {
				c.SendRequest("exit-status", false, golangssh.Marshal(struct{ Status uint32 }{0}))
				return
			}
		}
	})
	bundle := model.SSHBundle{Target: peer.node()}
	g, err := DialGraph(context.Background(), bundle, testOptions())
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := RunCommandOnClient(context.Background(), g.Target(), "true", Streams{}); err != nil {
			t.Fatal(err)
		}
	}
	if count.Load() != 1 {
		t.Errorf("live graph agent connections=%d; want 1", count.Load())
	}
	g.Close()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Error("graph close did not release agent connection")
	}
	term := &forwardingTerminal{events: make(chan struct{})}
	if err := runInteractive(context.Background(), bundle, term, testOptions()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Error("interactive graph did not release agent connection")
	}
	if auths.Load() == 0 {
		t.Error("SSH_AUTH_SOCK did not authenticate")
	}
	if forwards.Load() != 0 {
		t.Errorf("server accepted %d implicit agent-forwarding requests", forwards.Load())
	}
}

func TestGraphCancellationClosesBlockedAuthenticationAgent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix SSH_AUTH_SOCK fixture; native Windows pending")
	}
	path := filepath.Join(t.TempDir(), "agent.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	t.Setenv("SSH_AUTH_SOCK", path)
	entered, agentDone := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(agentDone)
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		var header [4]byte
		if _, err := io.ReadFull(c, header[:]); err != nil {
			return
		}
		close(entered)
		io.Copy(io.Discard, c) // Signers request deliberately never answered.
	}()
	peer := newLifecyclePeer(t, &golangssh.ServerConfig{PublicKeyCallback: func(golangssh.ConnMetadata, golangssh.PublicKey) (*golangssh.Permissions, error) { return nil, nil }}, func(ctx context.Context, ch golangssh.NewChannel) { ch.Reject(golangssh.Prohibited, "unused") })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		g, err := DialGraph(ctx, model.SSHBundle{Target: peer.node()}, testOptions())
		if g != nil {
			g.Close()
		}
		done <- err
	}()
	waitLifecycle(t, entered, "agent Signers request")
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("dial=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("agent auth blocked canceled graph establishment")
	}
	waitLifecycle(t, agentDone, "authentication agent handler")
}

type observedAgentConn struct {
	net.Conn
	entered, returned chan struct{}
	once              sync.Once
}

func (c *observedAgentConn) Read(p []byte) (int, error) {
	c.once.Do(func() { close(c.entered) })
	defer close(c.returned)
	return c.Conn.Read(p)
}

func TestAuthenticationAgentDoesNotStartUnownedIdleReader(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	conn := &observedAgentConn{Conn: a, entered: make(chan struct{}), returned: make(chan struct{})}
	_ = authenticationAgent(conn)
	// v0.55.0's optional pipeline reader can block on its private pending
	// channel after an unsolicited reply, beyond the reach of socket Close.
	// No forwarding/concurrent agent RPCs are needed for authentication: the
	// agent must not read until its synchronous auth RPC actually requests it.
	select {
	case <-conn.entered:
		t.Error("authentication started a background agent reader without an RPC")
		a.Close()
		waitLifecycle(t, conn.returned, "idle agent socket read")
	case <-time.After(20 * time.Millisecond):
	}
}

func TestGraphOwnsAgentConnectionsUntilClose(t *testing.T) {
	key, count, closed := testAuthSocket(t)
	peer := newLifecyclePeer(t, &golangssh.ServerConfig{PublicKeyCallback: func(_ golangssh.ConnMetadata, k golangssh.PublicKey) (*golangssh.Permissions, error) {
		if !bytes.Equal(k.Marshal(), key.Marshal()) {
			return nil, errAuthFailed
		}
		return nil, nil
	}}, func(ctx context.Context, ch golangssh.NewChannel) { ch.Reject(golangssh.Prohibited, "reject next hop") })
	_, err := DialGraph(context.Background(), model.SSHBundle{Target: model.SSHNode{Name: "unreachable", Host: "127.0.0.1", Port: 22}, Jumps: []model.SSHNode{peer.node()}}, testOptions())
	if err == nil {
		t.Fatal("expected failed graph")
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Error("partial graph leaked agent connection")
	}
	if count.Load() != 0 {
		t.Errorf("failed graph agent count=%d", count.Load())
	}
}
