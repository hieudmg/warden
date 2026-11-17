package ssh

import (
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
	addr    string
	hostKey ssh.PublicKey
	ln      net.Listener
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
		ln:      ln,
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go srv.handleConn(conn, cfg)
		}
	}()

	t.Cleanup(func() { ln.Close() })
	return srv
}

func (s *testSSHServer) handleConn(conn net.Conn, cfg *ssh.ServerConfig) {
	sconn, chans, reqs, err := ssh.NewServerConn(conn, cfg)
	if err != nil {
		conn.Close()
		return
	}
	defer sconn.Close()
	go ssh.DiscardRequests(reqs)

	for newCh := range chans {
		switch newCh.ChannelType() {
		case "session":
			ch, reqs, err := newCh.Accept()
			if err != nil {
				continue
			}
			go handleSession(ch, reqs)
		case "direct-tcpip":
			go handleDirectTCPIP(newCh)
		default:
			newCh.Reject(ssh.UnknownChannelType, "unsupported channel type")
		}
	}
}

// handleDirectTCPIP forwards a direct-tcpip channel to the requested host,
// enabling ssh.Client.Dial through a jump server.
func handleDirectTCPIP(newCh ssh.NewChannel) {
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
	upstream, err := net.Dial("tcp", net.JoinHostPort(dest.Host, strconv.FormatUint(uint64(dest.Port), 10)))
	if err != nil {
		newCh.Reject(ssh.ConnectionFailed, "dial failed")
		return
	}
	ch, reqs, err := newCh.Accept()
	if err != nil {
		upstream.Close()
		return
	}
	go ssh.DiscardRequests(reqs)
	go func() {
		defer ch.Close()
		defer upstream.Close()
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); io.Copy(ch, upstream) }()
		go func() { defer wg.Done(); io.Copy(upstream, ch) }()
		wg.Wait()
	}()
}

// handleSession answers exec requests by running the command via /bin/sh
// and reporting the exit status.
func handleSession(ch ssh.Channel, reqs <-chan *ssh.Request) {
	defer ch.Close()
	for req := range reqs {
		switch req.Type {
		case "exec":
			var payload struct {
				Command string
			}
			ssh.Unmarshal(req.Payload, &payload)
			req.Reply(true, nil)
			runShellCommand(ch, payload.Command)
			return
		case "shell", "pty-req", "window-change":
			req.Reply(true, nil)
		default:
			req.Reply(false, nil)
		}
	}
}

func runShellCommand(ch ssh.Channel, command string) {
	cmd := exec.Command("sh", "-c", command)
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
