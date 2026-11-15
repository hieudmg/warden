package ssh

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	golangssh "golang.org/x/crypto/ssh"
)

func TestSSHFixtureChannelEOFClosesUpstreamAndJoins(t *testing.T) {
	listener := fixtureTargetListener(t)
	channel, peer := fixtureTCPPair(t)
	ch := &relayFixtureChannel{TCPConn: channel, closed: make(chan struct{})}
	host, port, _ := net.SplitHostPort(listener.Addr().String())
	portNumber, _ := strconv.Atoi(port)
	request := &relayFixtureNewChannel{channel: ch, accepted: make(chan struct{}), extra: golangssh.Marshal(struct {
		Host       string
		Port       uint32
		OriginHost string
		OriginPort uint32
	}{Host: host, Port: uint32(portNumber)})}
	done := make(chan struct{})
	go func() { handleDirectTCPIP(context.Background(), request); close(done) }()
	target, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		// Failure cleanup must unblock and join the original copy workers too.
		peer.Close()
		target.Close()
		waitFixtureDone(t, ch.closed, "channel close after both copies")
		waitFixtureDone(t, done, "forwarding handler")
	})
	waitFixtureDone(t, request.accepted, "direct-tcpip acceptance")
	peer.Close()
	assertFixtureEOF(t, target)
	waitFixtureDone(t, done, "forwarding handler before forced cleanup")
	waitFixtureDone(t, ch.closed, "joined copies before forced cleanup")
}

func TestProxyFixtureClientEOFClosesUpstreamAndJoins(t *testing.T) {
	for _, name := range []string{"plain", "authenticated", "coalesced"} {
		t.Run(name, func(t *testing.T) {
			listener := fixtureTargetListener(t)
			proxyConn, client := fixtureTCPPair(t)
			var serve func(net.Conn)
			auth := ""
			if name == "coalesced" {
				proxy := startCoalescingProxy(t)
				serve = func(c net.Conn) { proxy.handleCoalesced(proxy.listener.ctx, c) }
			} else {
				if name == "authenticated" {
					auth = "Basic Zml4dHVyZTpwYXNz"
				}
				proxy := startTestProxy(t, auth)
				serve = func(c net.Conn) { proxy.handle(proxy.listener.ctx, c, auth) }
			}
			done := make(chan struct{})
			go func() { serve(proxyConn); close(done) }()
			if _, err := fmt.Fprintf(client, "CONNECT %s HTTP/1.1\r\nProxy-Authorization: %s\r\n\r\n", listener.Addr(), auth); err != nil {
				t.Fatal(err)
			}
			target, err := listener.Accept()
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				client.Close()
				target.Close()
				proxyConn.Close()
				waitFixtureDone(t, done, "proxy handler and both copies during failure cleanup")
			})
			const banner = "SSH-2.0-fixture-eof\r\n"
			if _, err := io.WriteString(target, banner); err != nil {
				t.Fatal(err)
			}
			client.SetReadDeadline(time.Now().Add(time.Second))
			br := bufio.NewReader(client)
			for _, want := range []string{"HTTP/1.1 200 Connection Established\r\n", "\r\n", banner} {
				line, err := br.ReadString('\n')
				if err != nil || line != want {
					t.Fatalf("proxy response=%q err=%v, want %q", line, err, want)
				}
			}
			client.Close()
			assertFixtureEOF(t, target)
			waitFixtureDone(t, done, "proxy handler and both copies before forced cleanup")
		})
	}
}

func TestSSHFixtureCleanupClosesAcceptedConnection(t *testing.T) {
	var client net.Conn
	t.Run("fixture", func(t *testing.T) {
		server := newTestSSHServer(t, "fixture-pass", nil)
		var err error
		client, err = net.Dial("tcp", server.addr)
		if err != nil {
			t.Fatal(err)
		}
		// A banner proves acceptance; listener closure alone cannot satisfy this.
		client.SetReadDeadline(time.Now().Add(time.Second))
		banner, err := bufio.NewReader(client).ReadString('\n')
		if err != nil || !strings.HasPrefix(banner, "SSH-2.0-") {
			t.Fatalf("banner=%q err=%v", banner, err)
		}
	})
	if client == nil {
		t.Fatal("fixture connection not established")
	}
	defer client.Close()
	assertFixtureEOF(t, client)
}

func fixtureTargetListener(t *testing.T) *net.TCPListener {
	t.Helper()
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	listener.SetDeadline(time.Now().Add(5 * time.Second))
	t.Cleanup(func() { listener.Close() })
	return listener
}

func fixtureTCPPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	listener := fixtureTargetListener(t)
	client, err := net.DialTCP("tcp", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	server, err := listener.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Close() })
	listener.Close()
	return server, client
}

func assertFixtureEOF(t *testing.T, conn net.Conn) {
	t.Helper()
	conn.SetReadDeadline(time.Now().Add(time.Second))
	var b [1]byte
	if _, err := conn.Read(b[:]); err != io.EOF {
		t.Errorf("upstream did not receive EOF before forced cleanup: %v", err)
	}
}

func waitFixtureDone(t *testing.T, done <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Errorf("%s did not join", what)
	}
}

// The TCP-backed channel retains real CloseWrite semantics; the relay uses only
// its ordinary data stream, not stderr or channel requests.
type relayFixtureChannel struct {
	*net.TCPConn
	closed chan struct{}
	once   sync.Once
}

func (c *relayFixtureChannel) Close() error {
	err := c.TCPConn.Close()
	c.once.Do(func() { close(c.closed) })
	return err
}
func (c *relayFixtureChannel) Stderr() io.ReadWriter                          { return c.TCPConn }
func (c *relayFixtureChannel) SendRequest(string, bool, []byte) (bool, error) { return false, nil }

type relayFixtureNewChannel struct {
	channel  *relayFixtureChannel
	extra    []byte
	accepted chan struct{}
}

func (c *relayFixtureNewChannel) Accept() (golangssh.Channel, <-chan *golangssh.Request, error) {
	requests := make(chan *golangssh.Request)
	close(requests)
	close(c.accepted)
	return c.channel, requests, nil
}
func (c *relayFixtureNewChannel) Reject(_ golangssh.RejectionReason, message string) error {
	return fmt.Errorf("fixture channel rejected: %s", message)
}
func (c *relayFixtureNewChannel) ChannelType() string { return "direct-tcpip" }
func (c *relayFixtureNewChannel) ExtraData() []byte   { return c.extra }
