package ssh

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"warden/internal/model"
)

// insecureHostKey disables host-key verification for transport tests;
// host-key verification itself is covered in hostkey_test.go.
var insecureHostKey = ssh.InsecureIgnoreHostKey()

func testOptions() DialOptions {
	return DialOptions{HostKeyCallback: insecureHostKey}
}

func targetNode(name, addr string) model.SSHNode {
	host, portStr, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(portStr)
	return model.SSHNode{Name: name, Host: host, Port: port}
}

func TestRunCommandPasswordAuth(t *testing.T) {
	t.Parallel()

	srv := newTestSSHServer(t, "s3cret", nil)
	target := targetNode("t", srv.addr)
	target.Username = "user"
	target.Password = []byte("s3cret")

	var stdout, stderr bytes.Buffer
	err := runCommand(context.Background(), model.SSHBundle{Target: target},
		"printf out && printf err >&2", Streams{Stdout: &stdout, Stderr: &stderr}, testOptions())
	if err != nil {
		t.Fatalf("runCommand: %v", err)
	}
	if stdout.String() != "out" || stderr.String() != "err" {
		t.Fatalf("stdout=%q stderr=%q, want out/err", stdout.String(), stderr.String())
	}
}

func TestRunCommandKeyAuth(t *testing.T) {
	t.Parallel()

	keyPEM, pub := newTestClientKey(t)
	srv := newTestSSHServer(t, "", pub)
	target := targetNode("s", srv.addr)
	target.Username = "user"
	target.PrivateKey = keyPEM

	var stdout bytes.Buffer
	err := runCommand(context.Background(), model.SSHBundle{Target: target}, "echo key-ok",
		Streams{Stdout: &stdout}, testOptions())
	if err != nil {
		t.Fatalf("runCommand: %v", err)
	}
	if strings.TrimSpace(stdout.String()) != "key-ok" {
		t.Fatalf("stdout = %q, want key-ok", stdout.String())
	}
}

func TestRunCommandEncryptedKeyAuth(t *testing.T) {
	t.Parallel()

	keyPEM, pub := newTestEncryptedClientKey(t, "pass-phrase")
	srv := newTestSSHServer(t, "", pub)
	target := targetNode("s", srv.addr)
	target.Username = "user"
	target.PrivateKey = keyPEM
	target.PrivateKeyPassphrase = []byte("pass-phrase")

	var stdout bytes.Buffer
	err := runCommand(context.Background(), model.SSHBundle{Target: target}, "echo enc-ok",
		Streams{Stdout: &stdout}, testOptions())
	if err != nil {
		t.Fatalf("runCommand: %v", err)
	}
	if strings.TrimSpace(stdout.String()) != "enc-ok" {
		t.Fatalf("stdout = %q, want enc-ok", stdout.String())
	}
}

func TestRunCommandWrongPasswordFails(t *testing.T) {
	t.Parallel()

	srv := newTestSSHServer(t, "right", nil)
	target := targetNode("s", srv.addr)
	target.Username = "user"
	target.Password = []byte("wrong")

	err := runCommand(context.Background(), model.SSHBundle{Target: target}, "echo hi", Streams{}, testOptions())
	if err == nil {
		t.Fatal("runCommand succeeded with wrong password, want auth failure")
	}
}

func TestRunCommandExitStatus(t *testing.T) {
	t.Parallel()

	srv := newTestSSHServer(t, "s3cret", nil)
	target := targetNode("s", srv.addr)
	target.Username = "user"
	target.Password = []byte("s3cret")

	err := runCommand(context.Background(), model.SSHBundle{Target: target}, "exit 7", Streams{}, testOptions())
	var exitErr *ExitStatusError
	if !errors.As(err, &exitErr) {
		t.Fatalf("runCommand err = %v, want *ExitStatusError", err)
	}
	if exitErr.Status != 7 {
		t.Fatalf("exit status = %d, want 7", exitErr.Status)
	}
}

func TestRunCommandStdinStreaming(t *testing.T) {
	t.Parallel()

	srv := newTestSSHServer(t, "s3cret", nil)
	target := targetNode("s", srv.addr)
	target.Username = "user"
	target.Password = []byte("s3cret")

	var stdout bytes.Buffer
	err := runCommand(context.Background(), model.SSHBundle{Target: target},
		"cat", Streams{Stdin: strings.NewReader("stdin-data"), Stdout: &stdout}, testOptions())
	if err != nil {
		t.Fatalf("runCommand: %v", err)
	}
	if stdout.String() != "stdin-data" {
		t.Fatalf("stdout = %q, want stdin-data", stdout.String())
	}
}

func TestRunCommandCancellation(t *testing.T) {
	t.Parallel()

	srv := newTestSSHServer(t, "s3cret", nil)
	target := targetNode("s", srv.addr)
	target.Username = "user"
	target.Password = []byte("s3cret")

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	start := time.Now()
	err := runCommand(ctx, model.SSHBundle{Target: target}, "sleep 30", Streams{}, testOptions())
	if err == nil {
		t.Fatal("runCommand succeeded, want cancellation error")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("runCommand err = %v, want context.DeadlineExceeded", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatalf("cancellation took %v, want prompt return", time.Since(start))
	}
}

func TestRunCommandJumpChain(t *testing.T) {
	t.Parallel()

	// target is reachable only through jump server A.
	jump := newTestSSHServer(t, "jump-pass", nil)
	target := newTestSSHServer(t, "targ-pass", nil)

	jumpNode := targetNode("jump", jump.addr)
	jumpNode.Username = "user"
	jumpNode.Password = []byte("jump-pass")

	targetNode := targetNode("targ", target.addr)
	targetNode.Username = "user"
	targetNode.Password = []byte("targ-pass")

	var stdout bytes.Buffer
	err := runCommand(context.Background(), model.SSHBundle{
		Target: targetNode,
		Jumps:  []model.SSHNode{jumpNode},
	}, "echo through-jump", Streams{Stdout: &stdout}, testOptions())
	if err != nil {
		t.Fatalf("runCommand: %v", err)
	}
	if strings.TrimSpace(stdout.String()) != "through-jump" {
		t.Fatalf("stdout = %q, want through-jump", stdout.String())
	}
}

func TestRunCommandThroughHTTPProxy(t *testing.T) {
	t.Parallel()

	srv := newTestSSHServer(t, "s3cret", nil)
	proxy := startTestProxy(t, "")

	target := targetNode("s", srv.addr)
	target.Username = "user"
	target.Password = []byte("s3cret")
	target.ProxyHost = proxy.host
	target.ProxyPort = proxy.port

	var stdout bytes.Buffer
	err := runCommand(context.Background(), model.SSHBundle{Target: target}, "echo proxied",
		Streams{Stdout: &stdout}, testOptions())
	if err != nil {
		t.Fatalf("runCommand: %v", err)
	}
	if strings.TrimSpace(stdout.String()) != "proxied" {
		t.Fatalf("stdout = %q, want proxied", stdout.String())
	}
	if got := proxy.sawConnect(); got != srv.addr {
		t.Fatalf("proxy CONNECT target = %q, want %q", got, srv.addr)
	}
}

func TestRunCommandThroughProxyWithAuth(t *testing.T) {
	t.Parallel()

	srv := newTestSSHServer(t, "s3cret", nil)
	proxy := startTestProxy(t, "Basic "+base64.StdEncoding.EncodeToString([]byte("proxy-user:proxy-pass")))

	target := targetNode("s", srv.addr)
	target.Username = "user"
	target.Password = []byte("s3cret")
	target.ProxyHost = proxy.host
	target.ProxyPort = proxy.port
	target.ProxyUsername = "proxy-user"
	target.ProxyPassword = []byte("proxy-pass")

	err := runCommand(context.Background(), model.SSHBundle{Target: target}, "echo auth-proxy", Streams{}, testOptions())
	if err != nil {
		t.Fatalf("runCommand: %v", err)
	}
}

func TestDialTargetFailsWhenJumpUnreachable(t *testing.T) {
	t.Parallel()

	srv := newTestSSHServer(t, "s3cret", nil)

	jumpNode := targetNode("dead", "127.0.0.1:1")
	jumpNode.Username = "user"
	jumpNode.Password = []byte("x")

	targetNode := targetNode("s", srv.addr)
	targetNode.Username = "user"
	targetNode.Password = []byte("s3cret")

	_, err := DialTarget(context.Background(), model.SSHBundle{
		Target: targetNode,
		Jumps:  []model.SSHNode{jumpNode},
	}, testOptions())
	if err == nil {
		t.Fatal("DialTarget succeeded through unreachable jump, want error")
	}
}

// TestRunCommandThroughHTTPProxyCoalescedBanner reproduces the coalesced
// TCP segment where the proxy's 200 response and the SSH server's banner
// arrive in one read before the client sends its version. The handshake
// must not lose the banner bytes read ahead by the proxy response parser.
func TestRunCommandThroughHTTPProxyCoalescedBanner(t *testing.T) {
	t.Parallel()

	srv := newTestSSHServer(t, "s3cret", nil)
	proxy := startCoalescingProxy(t)

	target := targetNode("s", srv.addr)
	target.Username = "user"
	target.Password = []byte("s3cret")
	target.ProxyHost = proxy.host
	target.ProxyPort = proxy.port

	var stdout bytes.Buffer
	err := runCommand(context.Background(), model.SSHBundle{Target: target}, "echo proxied-coalesced",
		Streams{Stdout: &stdout}, testOptions())
	if err != nil {
		t.Fatalf("runCommand: %v", err)
	}
	if strings.TrimSpace(stdout.String()) != "proxied-coalesced" {
		t.Fatalf("stdout = %q, want proxied-coalesced", stdout.String())
	}
	if got := proxy.sawConnect(); got != srv.addr {
		t.Fatalf("proxy CONNECT target = %q, want %q", got, srv.addr)
	}
}

// TestProxyConnectStuckProxyBoundedByDeadline verifies the CONNECT
// negotiation is bounded by the handshake deadline so a proxy that
// accepts but never answers cannot hang the client forever.
func TestProxyConnectStuckProxyBoundedByDeadline(t *testing.T) {
	t.Parallel()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			// Hold the connection open without ever replying.
			go func(c net.Conn) {
				time.Sleep(30 * time.Second)
				c.Close()
			}(conn)
		}
	}()

	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	node := model.SSHNode{Name: "stuck", ProxyHost: host, ProxyPort: mustAtoi(portStr)}

	start := time.Now()
	conn, err := proxyConnect(context.Background(), nil, node, "10.255.255.1:22", 300*time.Millisecond)
	elapsed := time.Since(start)
	if err == nil {
		if conn != nil {
			conn.Close()
		}
		t.Fatal("proxyConnect succeeded through a stalled proxy, want deadline error")
	}
	if elapsed > 5*time.Second {
		t.Fatalf("stuck proxy took %v to fail, want deadline-bound failure", elapsed)
	}
}

// testProxy is a minimal HTTP CONNECT proxy.
type testProxy struct {
	host string
	port int

	mu          sync.Mutex
	connectAddr string
}

func startTestProxy(t *testing.T, wantAuth string) *testProxy {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("proxy listen: %v", err)
	}
	p := &testProxy{}
	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	p.host, p.port = host, mustAtoi(portStr)

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go p.handle(conn, wantAuth)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return p
}

func (p *testProxy) handle(conn net.Conn, wantAuth string) {
	defer conn.Close()

	br := bufio.NewReader(conn)
	reqLine, err := br.ReadString('\n')
	if err != nil {
		return
	}
	parts := strings.Fields(reqLine)
	if len(parts) < 2 || parts[0] != "CONNECT" {
		return
	}

	var authHeader string
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		if strings.HasPrefix(strings.ToLower(line), "proxy-authorization:") {
			authHeader = strings.TrimSpace(line[len("proxy-authorization:"):])
		}
	}
	if wantAuth != "" && authHeader != wantAuth {
		io.WriteString(conn, "HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
		return
	}

	p.mu.Lock()
	p.connectAddr = parts[1]
	p.mu.Unlock()

	upstream, err := net.Dial("tcp", parts[1])
	if err != nil {
		io.WriteString(conn, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		return
	}
	io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); io.Copy(conn, upstream) }()
	go func() { defer wg.Done(); io.Copy(upstream, conn) }()
	wg.Wait()
	upstream.Close()
}

func (p *testProxy) sawConnect() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.connectAddr
}

// startCoalescingProxy starts an HTTP CONNECT proxy that answers the
// client with the 200 response and the upstream SSH banner in a single
// write, reproducing a coalesced TCP segment.
func startCoalescingProxy(t *testing.T) *testProxy {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("proxy listen: %v", err)
	}
	p := &testProxy{}
	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	p.host, p.port = host, mustAtoi(portStr)

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go p.handleCoalesced(conn)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return p
}

func (p *testProxy) handleCoalesced(conn net.Conn) {
	defer conn.Close()

	br := bufio.NewReader(conn)
	reqLine, err := br.ReadString('\n')
	if err != nil {
		return
	}
	parts := strings.Fields(reqLine)
	if len(parts) < 2 || parts[0] != "CONNECT" {
		return
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		if strings.TrimRight(line, "\r\n") == "" {
			break
		}
	}

	p.mu.Lock()
	p.connectAddr = parts[1]
	p.mu.Unlock()

	upstream, err := net.Dial("tcp", parts[1])
	if err != nil {
		io.WriteString(conn, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		return
	}
	defer upstream.Close()

	// The SSH server writes its banner immediately on accept, before
	// reading the client version. Capture it so the 200 response and
	// the banner reach the client in one write.
	banner := make([]byte, 256)
	n, err := upstream.Read(banner)
	if err != nil && n == 0 {
		return
	}

	resp := append([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"), banner[:n]...)
	if _, err := conn.Write(resp); err != nil {
		return
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); io.Copy(conn, upstream) }()
	go func() { defer wg.Done(); io.Copy(upstream, conn) }()
	wg.Wait()
}

func mustAtoi(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		panic(fmt.Sprintf("atoi %q: %v", s, err))
	}
	return n
}
