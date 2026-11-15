package ssh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"os/exec"
	"strconv"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
)

// errAuthFailed is returned by test server auth callbacks.
var errAuthFailed = errors.New("authentication failed")

// testSSHServer is an in-process SSH server used by transport tests. It
// supports password and public-key authentication, session exec (via
// /bin/sh), and direct-tcpip forwarding so jump chains can be tested.
type testSSHServer struct {
	addr     string
	hostKey  ssh.PublicKey
	listener *sshFixtureListener
}

// newTestSSHServer starts a server that authenticates either a fixed
// password or a fixed public key.
func newTestSSHServer(t *testing.T, password string, authorizedKey ssh.PublicKey) *testSSHServer {
	t.Helper()

	cfg := &ssh.ServerConfig{}
	if password != "" {
		cfg.PasswordCallback = func(conn ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if subtle.ConstantTimeCompare(pass, []byte(password)) == 1 {
				return nil, nil
			}
			return nil, errAuthFailed
		}
	}
	if authorizedKey != nil {
		cfg.PublicKeyCallback = func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if subtle.ConstantTimeCompare(key.Marshal(), authorizedKey.Marshal()) == 1 {
				return nil, nil
			}
			return nil, errAuthFailed
		}
	}

	hostSigner := newTestSigner(t)
	cfg.AddHostKey(hostSigner)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &testSSHServer{
		addr:    ln.Addr().String(),
		hostKey: hostSigner.PublicKey(),
	}
	srv.listener = newSSHFixtureListener(t, ln, func(ctx context.Context, conn net.Conn) {
		srv.handleConn(ctx, conn, cfg)
	})
	return srv
}

func (s *testSSHServer) handleConn(parent context.Context, conn net.Conn, cfg *ssh.ServerConfig) {
	sconn, chans, reqs, err := ssh.NewServerConn(conn, cfg)
	if err != nil {
		conn.Close()
		return
	}
	defer sconn.Close()
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	var workers sync.WaitGroup
	workers.Add(1)
	go func() { defer workers.Done(); ssh.DiscardRequests(reqs) }()

	for newCh := range chans {
		switch newCh.ChannelType() {
		case "session":
			ch, reqs, err := newCh.Accept()
			if err != nil {
				continue
			}
			workers.Add(1)
			go func() { defer workers.Done(); handleSession(ctx, ch, reqs) }()
		case "direct-tcpip":
			workers.Add(1)
			go func() { defer workers.Done(); handleDirectTCPIP(ctx, newCh) }()
		default:
			newCh.Reject(ssh.UnknownChannelType, "unsupported channel type")
		}
	}
	cancel()
	sconn.Close()
	workers.Wait()
}

// handleDirectTCPIP forwards a direct-tcpip channel to the requested host,
// enabling ssh.Client.Dial through a jump server.
func handleDirectTCPIP(ctx context.Context, newCh ssh.NewChannel) {
	var dest struct {
		Host       string
		Port       uint32
		OriginHost string
		OriginPort uint32
	}
	if err := ssh.Unmarshal(newCh.ExtraData(), &dest); err != nil {
		newCh.Reject(ssh.ConnectionFailed, "malformed direct-tcpip request")
		return
	}
	dialer := net.Dialer{}
	upstream, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(dest.Host, strconv.FormatUint(uint64(dest.Port), 10)))
	if err != nil {
		newCh.Reject(ssh.ConnectionFailed, "dial failed")
		return
	}
	defer closeFixtureConnOnCancel(ctx, upstream)()
	ch, reqs, err := newCh.Accept()
	if err != nil {
		upstream.Close()
		return
	}
	requestsDone := make(chan struct{})
	go func() { defer close(requestsDone); ssh.DiscardRequests(reqs) }()
	relaySSHFixture(ch, upstream)
	<-requestsDone
}

// A peer EOF must close upstream before joining the reverse read. Waiting for
// both copies before closing leaves the target SSH server waiting for TCP EOF.
func relaySSHFixture(ch io.ReadWriteCloser, upstream net.Conn) {
	defer ch.Close()
	defer upstream.Close()
	var copies sync.WaitGroup
	copies.Add(2)
	go func() { defer copies.Done(); io.Copy(ch, upstream); ch.Close(); upstream.Close() }()
	go func() { defer copies.Done(); io.Copy(upstream, ch); upstream.Close(); ch.Close() }()
	copies.Wait()
}

// handleSession answers exec requests by running the command via /bin/sh
// and reporting the exit status.
func handleSession(ctx context.Context, ch ssh.Channel, reqs <-chan *ssh.Request) {
	defer ch.Close()
	for req := range reqs {
		switch req.Type {
		case "exec":
			var payload struct {
				Command string
			}
			ssh.Unmarshal(req.Payload, &payload)
			req.Reply(true, nil)
			runShellCommand(ctx, ch, payload.Command)
			return
		case "shell", "pty-req", "window-change":
			req.Reply(true, nil)
		default:
			req.Reply(false, nil)
		}
	}
}

func runShellCommand(ctx context.Context, ch ssh.Channel, command string) {
	cmd := exec.CommandContext(ctx, "sh", "-c", command)
	cmd.Stdout = ch
	cmd.Stderr = ch.Stderr()
	cmd.Stdin = ch
	status := uint32(0)
	if err := cmd.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			status = uint32(ee.ExitCode())
		} else {
			status = 1
		}
	}
	ch.SendRequest("exit-status", false, ssh.Marshal(struct {
		Status uint32
	}{Status: status}))
}

// newTestSigner returns an ed25519 signer for test server host keys and
// test client identities.
func newTestSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("make signer: %v", err)
	}
	return signer
}

// newTestClientKey returns an unencrypted PEM-encoded ed25519 private key
// for client authentication.
func newTestClientKey(t *testing.T) ([]byte, ssh.PublicKey) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	pub, err := ssh.NewPublicKey(priv.Public())
	if err != nil {
		t.Fatalf("make public key: %v", err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "test")
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	return pem.EncodeToMemory(block), pub
}

// newTestEncryptedClientKey returns a PEM private key encrypted with
// passphrase.
func newTestEncryptedClientKey(t *testing.T, passphrase string) ([]byte, ssh.PublicKey) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	pub, err := ssh.NewPublicKey(priv.Public())
	if err != nil {
		t.Fatalf("make public key: %v", err)
	}
	block, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "test", []byte(passphrase))
	if err != nil {
		t.Fatalf("marshal encrypted private key: %v", err)
	}
	return pem.EncodeToMemory(block), pub
}
