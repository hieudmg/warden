package ssh

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"warden/internal/client/ssh/hostkey"
	"warden/internal/model"
)

// handshakeTimeout bounds each network establishment phase, including channel
// opens and handshakes whose underlying transport does not support deadlines.
const handshakeTimeout = 15 * time.Second

// Graph owns the SSH clients that connect a target through its ordered jump
// chain. The target client is borrowed by operation-specific callers until
// Close is called.
type Graph struct {
	target *ssh.Client
	chain  []*ssh.Client
	once   sync.Once
	err    error
}

// DialGraph connects through the bundle's ordered jump chain and returns a
// reusable graph owning every established client. On failure all partially
// established clients are closed and no graph is returned.
func DialGraph(ctx context.Context, bundle model.SSHBundle, opts DialOptions) (*Graph, error) {
	target, chain, err := DialChain(ctx, bundle, opts)
	if err != nil {
		return nil, err
	}
	return &Graph{target: target, chain: chain}, nil
}

// Target returns the client connected to the bundle target. The graph owns
// the returned client; callers must not close it independently.
func (g *Graph) Target() *ssh.Client {
	return g.target
}

// Close disconnects the target and then each jump in reverse order. It is
// safe to call more than once and returns the first close error, if any.
func (g *Graph) Close() error {
	g.once.Do(func() {
		// A channel Close itself writes through the SSH connection. If the peer
		// stops reading, abort the root transport to unblock reverse teardown.
		ctx, cancel := context.WithTimeout(context.Background(), handshakeTimeout)
		finish := stopCancellation(ctx, func() { abortClient(g.target) })
		for i := len(g.chain) - 1; i >= 0; i-- {
			if err := g.chain[i].Close(); err != nil && g.err == nil {
				g.err = err
			}
		}
		finish()
		cancel()
	})
	return g.err
}

// Abort interrupts an unusable graph's transport before reverse-order logical
// teardown. This also interrupts other users of THIS graph, never other graphs.
func (g *Graph) Abort() {
	abortClient(g.target)
	_ = g.Close()
}

// DefaultKnownHostsPath returns the platform-standard known_hosts path.
func DefaultKnownHostsPath() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, ".ssh", "known_hosts")
}

// DialTarget connects through the bundle's ordered jump chain (first hop
// first) and returns an established client connected to the target. On
// failure all intermediate connections are closed and no partial client is
// returned.
func DialTarget(ctx context.Context, bundle model.SSHBundle, opts DialOptions) (*ssh.Client, error) {
	client, _, err := DialChain(ctx, bundle, opts)
	return client, err
}

// DialChain connects through the bundle's ordered jump chain (first hop
// first) and returns the established target client together with every
// client in the chain (jump hosts first, target last). Callers that must
// tear down the whole graph — such as long-lived tunnels — close every
// returned client. On failure all partially established clients are
// closed and nil is returned.
func DialChain(ctx context.Context, bundle model.SSHBundle, opts DialOptions) (*ssh.Client, []*ssh.Client, error) {
	cb, err := opts.hostKeyCallback()
	if err != nil {
		return nil, nil, err
	}

	var clients []*ssh.Client
	closeAll := func() {
		if len(clients) > 0 {
			abortClient(clients[0])
		}
		for i := len(clients) - 1; i >= 0; i-- {
			clients[i].Close()
		}
	}

	var via *ssh.Client
	for _, hop := range bundle.Jumps {
		reportProgress(opts.Progress, "Connecting to "+hop.Name+"...")
		nc, err := dialNode(ctx, hop, via, cb)
		if err != nil {
			closeAll()
			return nil, nil, fmt.Errorf("connect jump %q: %w", hop.Name, err)
		}
		clients = append(clients, nc.client)
		via = nc.client
	}

	reportProgress(opts.Progress, "Connecting to "+bundle.Target.Name+"...")
	nc, err := dialNode(ctx, bundle.Target, via, cb)
	if err != nil {
		closeAll()
		return nil, nil, fmt.Errorf("connect target %q: %w", bundle.Target.Name, err)
	}
	clients = append(clients, nc.client)
	if err := ctx.Err(); err != nil {
		closeAll()
		return nil, nil, err
	}
	return nc.client, clients, nil
}

// hostKeyCallback resolves the verification callback from DialOptions,
// defaulting to strict known_hosts verification.
func (o DialOptions) hostKeyCallback() (ssh.HostKeyCallback, error) {
	if o.HostKeyCallback != nil {
		return o.HostKeyCallback, nil
	}
	path := o.KnownHostsPath
	if path == "" {
		path = DefaultKnownHostsPath()
	}
	if path == "" {
		return nil, errors.New("cannot determine known_hosts path; set HOME or pass KnownHostsPath")
	}
	return hostkey.Callback(path, o.AcceptNew, o.Terminal)
}

type nodeClient struct{ client *ssh.Client }

// ownedClientConn binds authentication sockets to client/graph ownership, not
// forwarding. A spontaneous transport failure also releases its agent socket.
type ownedClientConn struct {
	ssh.Conn
	raw       *onceConn
	root      *onceConn
	agentConn *onceConn
}

func (c *ownedClientConn) closeAgent() {
	if c.agentConn != nil {
		c.agentConn.Close()
	}
}
func (c *ownedClientConn) Close() error { c.closeAgent(); return c.raw.Close() }
func abortClient(client *ssh.Client) {
	if client == nil {
		return
	}
	if owned, ok := client.Conn.(*ownedClientConn); ok {
		owned.closeAgent()
		owned.root.Close()
	} else {
		client.Close()
	}
}

func dialNode(ctx context.Context, node model.SSHNode, via *ssh.Client, cb ssh.HostKeyCallback) (*nodeClient, error) {
	ctx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	addr := net.JoinHostPort(node.Host, strconv.Itoa(node.Port))
	var transport net.Conn
	var err error
	switch {
	case node.ProxyHost != "":
		transport, err = dialProxy(ctx, via, node, addr)
	case via != nil:
		transport, err = DialTCPContext(ctx, via, addr, func(string) { abortClient(via) })
	default:
		transport, err = (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return nil, err
	}
	return handshakeNode(ctx, node, transport, via, cb)
}

func handshakeNode(ctx context.Context, node model.SSHNode, transport net.Conn, via *ssh.Client, cb ssh.HostKeyCallback) (*nodeClient, error) {
	addr := net.JoinHostPort(node.Host, strconv.Itoa(node.Port))
	raw := &onceConn{Conn: transport}
	root := raw
	if via != nil {
		if parent, ok := via.Conn.(*ownedClientConn); ok {
			root = parent.root
		}
	}
	var ag *onceConn
	var keyring agent.Agent
	if len(node.Password) == 0 && len(node.PrivateKey) == 0 {
		if sock := os.Getenv("SSH_AUTH_SOCK"); sock != "" {
			if c, err := (&net.Dialer{}).DialContext(ctx, "unix", sock); err == nil {
				ag = &onceConn{Conn: c}
				keyring = authenticationAgent(ag)
			}
		}
	}
	finish := stopCancellation(ctx, func() {
		root.Close()
		if ag != nil {
			ag.Close()
		}
		raw.Close()
	})
	deadline, _ := ctx.Deadline()
	deadlineSet := raw.SetDeadline(deadline) == nil
	config := &ssh.ClientConfig{User: node.Username, Auth: authMethods(node, keyring), HostKeyCallback: cb}
	conn, chans, reqs, err := ssh.NewClientConn(raw, addr, config)
	if canceled := finish(); canceled != nil {
		err = canceled
	} else if err == nil {
		err = finishNegotiation(ctx, raw, finish, deadlineSet)
	}
	if err != nil {
		root.Close()
		raw.Close()
		if ag != nil {
			ag.Close()
		}
		return nil, err
	}
	owned := &ownedClientConn{Conn: conn, raw: raw, root: root, agentConn: ag}
	client := ssh.NewClient(owned, chans, reqs)
	if ag != nil {
		go func() { conn.Wait(); owned.closeAgent() }()
	}
	return &nodeClient{client: client}, nil
}

func authenticationAgent(conn net.Conn) agent.Agent {
	// Authentication is serial; forwarding is disabled. Hide Closer only from
	// NewClient to select v0.55.0's synchronous RPC path, not its idle pipeline
	// reader (which can wait on an internal pending queue after unsolicited
	// replies). The graph still owns and closes the actual socket, including
	// cancellation during an auth RPC.
	return agent.NewClient(struct{ io.ReadWriter }{conn})
}

// authMethods returns the SSH authentication methods for a node: password,
// private key (with optional passphrase), then the local ssh-agent as a
// fallback when no explicit credential is configured.
func authMethods(node model.SSHNode, keyring agent.Agent) []ssh.AuthMethod {
	var methods []ssh.AuthMethod
	if len(node.Password) > 0 {
		methods = append(methods, ssh.Password(string(node.Password)))
	}
	if len(node.PrivateKey) > 0 {
		signer, err := parseSigner(node.PrivateKey, node.PrivateKeyPassphrase)
		if err == nil {
			methods = append(methods, ssh.PublicKeys(signer))
		}
	}
	if len(methods) == 0 && keyring != nil {
		methods = append(methods, ssh.PublicKeysCallback(keyring.Signers))
	}
	return methods
}

// parseSigner parses a PEM private key, trying the passphrase when the key
// is encrypted.
func parseSigner(keyPEM, passphrase []byte) (ssh.Signer, error) {
	if len(passphrase) > 0 {
		return ssh.ParsePrivateKeyWithPassphrase(keyPEM, passphrase)
	}
	return ssh.ParsePrivateKey(keyPEM)
}

// bufferedConn preserves bytes read ahead by a bufio.Reader so a reader
// handed the connection (e.g. the SSH handshake) still sees them.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// dialProxy negotiates an HTTP CONNECT tunnel to targetAddr through the
// node's proxy, bounded by the handshake deadline.
func dialProxy(ctx context.Context, via *ssh.Client, node model.SSHNode, targetAddr string) (net.Conn, error) {
	return proxyConnect(ctx, via, node, targetAddr, handshakeTimeout)
}

// proxyConnect establishes a TCP connection to the node's HTTP CONNECT
// proxy and negotiates a tunnel to targetAddr. When via is non-nil the
// proxy is reached through the previous hop. The whole negotiation is
// bounded by timeout so a proxy that accepts but never answers cannot hang
// the client forever. The returned connection preserves any bytes the
// proxy forwarded immediately after its 200 response, so the upstream
// protocol (SSH banner) is never truncated.
func proxyConnect(ctx context.Context, via *ssh.Client, node model.SSHNode, targetAddr string, timeout time.Duration) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	proxyAddr := net.JoinHostPort(node.ProxyHost, strconv.Itoa(node.ProxyPort))

	var conn net.Conn
	var err error
	if via != nil {
		conn, err = DialTCPContext(ctx, via, proxyAddr, func(string) { abortClient(via) })
	} else {
		conn, err = (&net.Dialer{}).DialContext(ctx, "tcp", proxyAddr)
	}
	if err != nil {
		return nil, fmt.Errorf("connect proxy %s: %w", proxyAddr, err)
	}

	return negotiateProxy(ctx, conn, via, node, targetAddr)
}

func negotiateProxy(ctx context.Context, conn net.Conn, via *ssh.Client, node model.SSHNode, targetAddr string) (net.Conn, error) {
	conn = &onceConn{Conn: conn}
	var abortOnce sync.Once
	abort := func() {
		abortOnce.Do(func() {
			if via != nil {
				abortClient(via)
			}
			conn.Close()
		})
	}
	finish := stopCancellation(ctx, abort)
	// The defer also joins cancellation on every error path.
	defer finish()
	deadline, _ := ctx.Deadline()
	deadlineSet := conn.SetDeadline(deadline) == nil

	established := false
	defer func() {
		if !established {
			// finishNegotiation may already have stopped cancellation before
			// a reset failure or late cancellation. Keep root abort available
			// through failed channel cleanup; channel Close itself can block.
			abort()
		}
	}()

	br := bufio.NewReader(conn)
	if err := writeConnectRequest(conn, targetAddr, node); err != nil {
		if canceled := contextError(ctx); canceled != nil {
			return nil, canceled
		}
		return nil, err
	}
	if err := expectProxyResponse(br); err != nil {
		if canceled := contextError(ctx); canceled != nil {
			return nil, canceled
		}
		return nil, err
	}
	if err := finishNegotiation(ctx, conn, finish, deadlineSet); err != nil {
		return nil, err
	}
	established = true
	return &bufferedConn{Conn: conn, r: br}, nil
}

func writeConnectRequest(w io.Writer, targetAddr string, node model.SSHNode) error {
	req := "CONNECT " + targetAddr + " HTTP/1.1\r\nHost: " + targetAddr + "\r\n"
	if node.ProxyUsername != "" {
		cred := node.ProxyUsername + ":" + string(node.ProxyPassword)
		req += "Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(cred)) + "\r\n"
	}
	req += "\r\n"
	if _, err := io.WriteString(w, req); err != nil {
		return fmt.Errorf("write CONNECT request: %w", err)
	}
	return nil
}

// expectProxyResponse parses the proxy's HTTP response from br directly
// (no wrapping reader) so bytes the proxy forwarded after its 200
// response — such as an upstream SSH banner coalesced into the same
// segment — stay buffered in br and reach the SSH handshake via the
// returned bufferedConn.
func expectProxyResponse(br *bufio.Reader) error {
	statusLine, err := br.ReadString('\n')
	if err != nil {
		return fmt.Errorf("read proxy response: %w", err)
	}
	fields := strings.Fields(statusLine)
	if len(fields) < 2 || fields[0] != "HTTP/1.1" {
		return fmt.Errorf("invalid proxy response %q", strings.TrimSpace(statusLine))
	}
	if fields[1] != "200" {
		return fmt.Errorf("proxy CONNECT failed: %s", strings.TrimSpace(statusLine))
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return fmt.Errorf("read proxy headers: %w", err)
		}
		if strings.TrimRight(line, "\r\n") == "" {
			return nil
		}
	}
}
