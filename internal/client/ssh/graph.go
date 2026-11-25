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

// handshakeTimeout bounds protocol exchanges on deadline-capable sockets.
// Forwarded SSH channels do not support deadlines; DialChain closes its
// outer socket on request cancellation to interrupt those exchanges.
const handshakeTimeout = 15 * time.Second

// clientAgents tracks the local ssh-agent keyring attached to each
// established client so sessions can request agent forwarding.
var clientAgents sync.Map // *ssh.Client -> agent.Agent

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

// Abort interrupts in-flight I/O by closing the outermost SSH connection
// first, even if an inner hop cannot complete its channel close. Only the
// exclusive owner of a graph may use it; Close still releases all clients.
func (g *Graph) Abort() {
	if len(g.chain) != 0 {
		_ = g.chain[0].Close()
	}
}

// Close disconnects the target and then each jump in reverse order. It is
// safe to call more than once and returns the first close error, if any.
func (g *Graph) Close() error {
	g.once.Do(func() {
		for i := len(g.chain) - 1; i >= 0; i-- {
			if err := g.chain[i].Close(); err != nil && g.err == nil {
				g.err = err
			}
			clientAgents.Delete(g.chain[i])
		}
	})
	return g.err
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
		for _, c := range clients {
			c.Close()
		}
	}

	var via *ssh.Client
	stopWatch := func() {}
	defer func() { stopWatch() }()
	dialTCP := func(addr string) (net.Conn, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if via != nil {
			return via.Dial("tcp", addr)
		}
		socket, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
		if err != nil {
			return nil, err
		}
		// This raw socket is still private to construction. Closing it
		// interrupts even an unanswered inner channel-open request or a
		// proxy negotiation before the target client exists.
		done := make(chan struct{})
		stop := context.AfterFunc(ctx, func() {
			defer close(done)
			_ = socket.Close()
		})
		stopWatch = sync.OnceFunc(func() {
			if !stop() {
				<-done
			}
		})
		return socket, nil
	}
	fail := func(kind string, node model.SSHNode, err error) (*ssh.Client, []*ssh.Client, error) {
		if canceled := ctx.Err(); canceled != nil {
			err = canceled
		}
		closeAll()
		return nil, nil, fmt.Errorf("connect %s %q: %w", kind, node.Name, err)
	}
	for _, hop := range bundle.Jumps {
		reportProgress(opts.Progress, "Connecting to "+hop.Name+"...")
		nc, err := dialNode(hop, dialTCP, cb)
		if err != nil {
			return fail("jump", hop, err)
		}
		clients = append(clients, nc.client)
		via = nc.client
	}

	reportProgress(opts.Progress, "Connecting to "+bundle.Target.Name+"...")
	nc, err := dialNode(bundle.Target, dialTCP, cb)
	if err != nil {
		return fail("target", bundle.Target, err)
	}
	clients = append(clients, nc.client)
	// Hand off a live graph only after disarming the construction watcher;
	// cancellation of a completed request must not close a reusable graph.
	stopWatch()
	if err := ctx.Err(); err != nil {
		return fail("target", bundle.Target, err)
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

// nodeClient is a dialed SSH client plus the optional local ssh-agent
// connection used to authenticate it.
type nodeClient struct {
	client    *ssh.Client
	agentConn net.Conn
	keyring   agent.Agent
}

// dialNode establishes one SSH connection: to node directly, through the
// previous hop's client (when via is non-nil), and optionally through the
// node's HTTP CONNECT proxy. When the node has no explicit credential, the
// local ssh-agent is tried and, on success, kept available for agent
// forwarding.
func dialNode(node model.SSHNode, dialTCP func(string) (net.Conn, error), cb ssh.HostKeyCallback) (*nodeClient, error) {
	addr := net.JoinHostPort(node.Host, strconv.Itoa(node.Port))

	var raw net.Conn
	var err error
	if node.ProxyHost != "" {
		raw, err = proxyConnect(dialTCP, node, addr, handshakeTimeout)
	} else {
		raw, err = dialTCP(addr)
	}
	if err != nil {
		return nil, err
	}

	nc := &nodeClient{}
	if len(node.Password) == 0 && len(node.PrivateKey) == 0 {
		if sock := os.Getenv("SSH_AUTH_SOCK"); sock != "" {
			if agConn, derr := net.Dial("unix", sock); derr == nil {
				nc.agentConn = agConn
				nc.keyring = agent.NewClient(agConn)
			}
		}
	}

	config := &ssh.ClientConfig{
		User:            node.Username,
		Auth:            authMethods(node, nc.keyring),
		HostKeyCallback: cb,
	}

	// Bound the handshake on transports with deadline support.
	if c, ok := raw.(interface{ SetDeadline(time.Time) error }); ok {
		c.SetDeadline(time.Now().Add(handshakeTimeout))
	}
	conn, chans, reqs, err := ssh.NewClientConn(raw, addr, config)
	if c, ok := raw.(interface{ SetDeadline(time.Time) error }); ok {
		c.SetDeadline(time.Time{})
	}
	if err != nil {
		if nc.agentConn != nil {
			nc.agentConn.Close()
		}
		raw.Close()
		return nil, err
	}

	nc.client = ssh.NewClient(conn, chans, reqs)
	if nc.keyring != nil {
		clientAgents.Store(nc.client, nc.keyring)
		go func() {
			nc.client.Wait()
			nc.agentConn.Close()
			clientAgents.Delete(nc.client)
		}()
	}
	return nc, nil
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

// proxyConnect reaches the HTTP proxy using the same dial path as a direct
// node. Preserve bytes the proxy forwards immediately after its 200 response
// so the upstream SSH banner is not truncated.
func proxyConnect(dialTCP func(string) (net.Conn, error), node model.SSHNode, targetAddr string, timeout time.Duration) (net.Conn, error) {
	proxyAddr := net.JoinHostPort(node.ProxyHost, strconv.Itoa(node.ProxyPort))
	conn, err := dialTCP(proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("connect proxy %s: %w", proxyAddr, err)
	}

	// Apply the timeout where the transport supports deadlines; forwarded
	// channels rely on the dial owner's cancellation of the outer socket.
	setDeadline, ok := conn.(interface{ SetDeadline(time.Time) error })
	if ok {
		setDeadline.SetDeadline(time.Now().Add(timeout))
	}

	established := false
	defer func() {
		if !established {
			conn.Close()
		}
	}()

	br := bufio.NewReader(conn)
	if err := writeConnectRequest(conn, targetAddr, node); err != nil {
		return nil, err
	}
	if err := expectProxyResponse(br); err != nil {
		return nil, err
	}
	// Tunnel established: clear the negotiation deadline; the SSH
	// handshake applies its own.
	if ok {
		setDeadline.SetDeadline(time.Time{})
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
