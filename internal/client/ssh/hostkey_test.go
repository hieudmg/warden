package ssh

import (
	"bytes"
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
