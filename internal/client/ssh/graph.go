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

// handshakeTimeout bounds each SSH handshake (TCP dial + protocol
// exchange). Inner hop dials cannot use the caller's context directly, so
// a deadline keeps stalled jumps from hanging forever.
const handshakeTimeout = 15 * time.Second

// clientAgents tracks the local ssh-agent keyring attached to each
// established client so sessions can request agent forwarding.
var clientAgents sync.Map // *ssh.Client -> agent.Agent

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
	for _, hop := range bundle.Jumps {
		nc, err := dialNode(ctx, hop, via, cb)
		if err != nil {
			closeAll()
			return nil, nil, fmt.Errorf("connect jump %q: %w", hop.Name, err)
		}
		clients = append(clients, nc.client)
		via = nc.client
	}

	nc, err := dialNode(ctx, bundle.Target, via, cb)
	if err != nil {
		closeAll()
		return nil, nil, fmt.Errorf("connect target %q: %w", bundle.Target.Name, err)
	}
	clients = append(clients, nc.client)
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
func dialNode(ctx context.Context, node model.SSHNode, via *ssh.Client, cb ssh.HostKeyCallback) (*nodeClient, error) {
	addr := net.JoinHostPort(node.Host, strconv.Itoa(node.Port))

	var raw net.Conn
	var err error
	switch {
	case node.ProxyHost != "":
		raw, err = dialProxy(ctx, via, node, addr)
	case via != nil:
		raw, err = via.Dial("tcp", addr)
	default:
		raw, err = (&net.Dialer{}).DialContext(ctx, "tcp", addr)
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

	// Bound the handshake even for chained dials that bypass ctx.
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
	proxyAddr := net.JoinHostPort(node.ProxyHost, strconv.Itoa(node.ProxyPort))

	var conn net.Conn
	var err error
	if via != nil {
		conn, err = via.Dial("tcp", proxyAddr)
	} else {
		conn, err = (&net.Dialer{}).DialContext(ctx, "tcp", proxyAddr)
	}
	if err != nil {
		return nil, fmt.Errorf("connect proxy %s: %w", proxyAddr, err)
	}

	// Bound the CONNECT exchange before writing the request so a proxy
	// that accepts but never answers fails instead of hanging. The
	// interface assertion fails silently for transports without
	// deadlines (e.g. an SSH channel); those are bounded by the hop's
	// own handshake rules.
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
