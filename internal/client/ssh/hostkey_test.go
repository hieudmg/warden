package ssh

import (
	"bytes"
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"warden/internal/client/ssh/hostkey"
	"warden/internal/model"
)

// dialWithHostKey connects to the target using the given host-key callback
// so host-key verification behavior can be asserted end to end.
func dialWithHostKey(t *testing.T, srv *testSSHServer, cb ssh.HostKeyCallback) error {
	t.Helper()

	target := targetNode("s", srv.addr)
	target.Username = "user"
	target.Password = []byte("s3cret")

	client, err := DialTarget(context.Background(), model.SSHBundle{Target: target},
		DialOptions{HostKeyCallback: cb})
	if err != nil {
		return err
	}
	client.Close()
	return nil
}

func TestUnknownHostKeyRejectedByDefault(t *testing.T) {
	t.Parallel()

	srv := newTestSSHServer(t, "s3cret", nil)
	path := filepath.Join(t.TempDir(), "known_hosts")

	cb, err := hostkey.Callback(path, false, nil)
	if err != nil {
		t.Fatalf("Callback: %v", err)
	}
	err = dialWithHostKey(t, srv, cb)
	if err == nil {
		t.Fatal("dial succeeded with unknown host key, want rejection")
	}
	if !strings.Contains(err.Error(), "unknown host") {
		t.Fatalf("err = %v, want unknown-host message", err)
	}
}

func TestKnownHostKeyAccepted(t *testing.T) {
	t.Parallel()

	srv := newTestSSHServer(t, "s3cret", nil)
	path := writeKnownHosts(t, srv.addr, srv.hostKey)

	cb, err := hostkey.Callback(path, false, nil)
	if err != nil {
		t.Fatalf("Callback: %v", err)
	}
	if err := dialWithHostKey(t, srv, cb); err != nil {
		t.Fatalf("dial with known key: %v", err)
	}
}

func TestChangedHostKeyRejected(t *testing.T) {
	t.Parallel()

	srv := newTestSSHServer(t, "s3cret", nil)
	// Persist a different host key under the server's address, then
	// verify a connection to the real server is refused as changed.
	oldKey := newTestSigner(t).PublicKey()
	path := writeKnownHosts(t, srv.addr, oldKey)

	cb, err := hostkey.Callback(path, true, nil)
	if err != nil {
		t.Fatalf("Callback: %v", err)
	}
	err = dialWithHostKey(t, srv, cb)
	if err == nil {
		t.Fatal("dial succeeded with changed host key, want rejection")
	}
	if !strings.Contains(err.Error(), "changed") {
		t.Errorf("err = %v, want changed-key message", err)
	}
}

func TestAcceptNewPersistsKey(t *testing.T) {
	t.Parallel()

	srv := newTestSSHServer(t, "s3cret", nil)
	path := filepath.Join(t.TempDir(), "known_hosts")

	terminal := &fakeTerminal{in: bytes.NewBufferString("yes\n"), out: &bytes.Buffer{}}
	cb, err := hostkey.Callback(path, true, terminal)
	if err != nil {
		t.Fatalf("Callback: %v", err)
	}
	if err := dialWithHostKey(t, srv, cb); err != nil {
		t.Fatalf("dial with accept-new: %v", err)
	}
	if !strings.Contains(terminal.out.String(), "127.0.0.1") {
		t.Errorf("prompt = %q, want host shown", terminal.out.String())
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read known_hosts: %v", err)
	}
	host, port, _ := net.SplitHostPort(srv.addr)
	normalized := "[" + host + "]:" + port
	if !strings.Contains(string(data), normalized) {
		t.Fatalf("known_hosts does not contain accepted key: %q", data)
	}

	// Second connect without accept-new succeeds because the key is known.
	cb2, err := hostkey.Callback(path, false, nil)
	if err != nil {
		t.Fatalf("Callback: %v", err)
	}
	if err := dialWithHostKey(t, srv, cb2); err != nil {
		t.Fatalf("second dial with persisted key: %v", err)
	}
}

func TestAcceptNewRefused(t *testing.T) {
	t.Parallel()

	srv := newTestSSHServer(t, "s3cret", nil)
	path := filepath.Join(t.TempDir(), "known_hosts")

	term := &bytes.Buffer{}
	cb, err := hostkey.Callback(path, true, term)
	if err != nil {
		t.Fatalf("Callback: %v", err)
	}
	err = dialWithHostKey(t, srv, cb)
	if err == nil {
		t.Fatal("dial succeeded without confirmation, want rejection")
	}
	if data, readErr := os.ReadFile(path); readErr == nil && len(data) != 0 {
		t.Fatalf("known_hosts written despite refusal: %q", data)
	}
}

// TestConfirmHostAcceptsCRLineEnd verifies the CR-only confirmation
// path used in raw terminal mode where `term.MakeRaw` disables ICRNL.
// Without this, the prompt hangs because ReadString('\n') never sees LF.
func TestConfirmHostAcceptsCRLineEnd(t *testing.T) {
	t.Parallel()

	srv := newTestSSHServer(t, "s3cret", nil)
	path := filepath.Join(t.TempDir(), "known_hosts")

	terminal := &fakeTerminal{in: bytes.NewBufferString("yes\r"), out: &bytes.Buffer{}}
	cb, err := hostkey.Callback(path, true, terminal)
	if err != nil {
		t.Fatalf("Callback: %v", err)
	}
	if err := dialWithHostKey(t, srv, cb); err != nil {
		t.Fatalf("dial with CR-terminated yes: %v", err)
	}
}

// TestConfirmHostAcceptsLFLines (parity with CR case) confirms the LF
// path still works for pasted input or piped sources.
func TestConfirmHostAcceptsLFLineEnd(t *testing.T) {
	t.Parallel()

	srv := newTestSSHServer(t, "s3cret", nil)
	path := filepath.Join(t.TempDir(), "known_hosts")

	terminal := &fakeTerminal{in: bytes.NewBufferString("yes\n"), out: &bytes.Buffer{}}
	cb, err := hostkey.Callback(path, true, terminal)
	if err != nil {
		t.Fatalf("Callback: %v", err)
	}
	if err := dialWithHostKey(t, srv, cb); err != nil {
		t.Fatalf("dial with LF-terminated yes: %v", err)
	}
}

// blockingReader is an io.ReadWriter that delivers bytes from a queue
// one at a time and blocks on an empty queue until more bytes arrive.
// It mirrors a real raw terminal: bytes arrive one-by-one, and reading
// before a byte is available blocks (no EOF).
type blockingReader struct {
	ch chan byte
}

func newBlockingReader() *blockingReader {
	return &blockingReader{ch: make(chan byte, 16)}
}

func (b *blockingReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	v, ok := <-b.ch
	if !ok {
		return 0, io.EOF
	}
	p[0] = v
	return 1, nil
}

func (b *blockingReader) Write(p []byte) (int, error) { return len(p), nil }

func (b *blockingReader) Push(s string) {
	for i := 0; i < len(s); i++ {
		b.ch <- s[i]
	}
}

// TestConfirmHostRawTerminalCR verifies the byte-by-byte reader
// terminates on a CR-only response — the case the prior
// ReadString('\n') implementation would block forever on. Uses the
// production hostkey.Callback path (no custom HostKeyCallback) so the
// real confirmHost is invoked, and a blockingReader that delivers
// bytes one at a time so the prompt cannot accidentally EOF.
func TestConfirmHostRawTerminalCR(t *testing.T) {
	t.Parallel()

	srv := newTestSSHServer(t, "s3cret", nil)
	path := filepath.Join(t.TempDir(), "known_hosts")

	term := newBlockingReader()
	go func() { term.Push("yes\r") }()

	cb, err := hostkey.Callback(path, true, term)
	if err != nil {
		t.Fatalf("Callback: %v", err)
	}

	target := targetNode("s", srv.addr)
	target.Username = "user"
	target.Password = []byte("s3cret")

	done := make(chan error, 1)
	go func() {
		client, derr := DialTarget(context.Background(), model.SSHBundle{Target: target},
			DialOptions{HostKeyCallback: cb})
		if derr != nil {
			done <- derr
			return
		}
		client.Close()
		done <- nil
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("dial with raw-terminal CR response: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("confirmHost blocked on raw-terminal CR; ReadString bug regressed")
	}
}

func TestAcceptNewNonInteractiveRejected(t *testing.T) {
	t.Parallel()

	srv := newTestSSHServer(t, "s3cret", nil)
	path := filepath.Join(t.TempDir(), "known_hosts")

	// acceptNew is true but terminal is nil: must still fail.
	cb, err := hostkey.Callback(path, true, nil)
	if err != nil {
		t.Fatalf("Callback: %v", err)
	}
	if err := dialWithHostKey(t, srv, cb); err == nil {
		t.Fatal("dial succeeded in noninteractive mode, want rejection")
	}
}

func TestCallbackMissingFileDoesNotError(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "does-not-exist", "known_hosts")
	if _, err := hostkey.Callback(path, false, nil); err != nil {
		t.Fatalf("Callback on missing file: %v", err)
	}
}

// TestMalformedKnownHostsLinesSkipped verifies OpenSSH-compatible
// tolerance: malformed lines are skipped instead of failing every
// connection, while valid plain and hashed entries still verify.
func TestMalformedKnownHostsLinesSkipped(t *testing.T) {
	t.Parallel()

	srv := newTestSSHServer(t, "s3cret", nil)
	path := filepath.Join(t.TempDir(), "known_hosts")

	valid := knownhosts.Line([]string{srv.addr}, srv.hostKey)
	fields := strings.Fields(valid)
	keyType, blob := fields[len(fields)-2], fields[len(fields)-1]

	// A malformed entry for the same host with a wrong key type: the
	// blob parses as an ed25519 key but claims to be ssh-rsa.
	wrongType := srv.addr + " ssh-rsa " + blob

	// A valid hashed entry for the same host.
	hashedHost := knownhosts.HashHostname(knownhosts.Normalize(srv.addr))
	hashedLine := hashedHost + " " + keyType + " " + blob

	content := strings.Join([]string{
		"this line is not a valid known_hosts entry",
		valid,
		hashedLine,
		wrongType,
	}, "\n") + "\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("write known_hosts: %v", err)
	}

	cb, err := hostkey.Callback(path, false, nil)
	if err != nil {
		t.Fatalf("Callback with malformed lines: %v", err)
	}
	if err := dialWithHostKey(t, srv, cb); err != nil {
		t.Fatalf("dial with tolerated known_hosts: %v", err)
	}
}

func writeKnownHosts(t *testing.T, addr string, key ssh.PublicKey) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "known_hosts")
	line := knownhosts.Line([]string{addr}, key)
	if err := os.WriteFile(path, []byte(line+"\n"), 0600); err != nil {
		t.Fatalf("write known_hosts: %v", err)
	}
	return path
}

// fakeTerminal is an io.ReadWriter with separate input and captured
// output buffers, standing in for an interactive terminal.
type fakeTerminal struct {
	in  *bytes.Buffer
	out *bytes.Buffer
}

func (f *fakeTerminal) Read(p []byte) (int, error)  { return f.in.Read(p) }
func (f *fakeTerminal) Write(p []byte) (int, error) { return f.out.Write(p) }
