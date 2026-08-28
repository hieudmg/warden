package sftp

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pkgsftp "github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"warden/internal/model"
)

// errAuthFailed is returned by the test server's auth callbacks.
var errAuthFailed = errors.New("authentication failed")

var nextSFTPTestProfileID atomic.Int64

// sftpTestServer is an in-process password-authenticated SSH server that
// serves an isolated directory over the sftp subsystem and forwards
// direct-tcpip channels so jump chains can be tested. conns counts accepted
// SSH connections and returns to zero only after every connection has fully
// closed.
type sftpTestServer struct {
	addr                string
	root                string
	profileID           int64
	hostKey             ssh.PublicKey
	conns               atomic.Int64
	standardRenameCalls atomic.Int64
	posixRenameCalls    atomic.Int64
	posixRenameOnly     bool
	ln                  net.Listener
}

// newSFTPTestServer starts a server that authenticates the fixed password
// and serves t.TempDir() over SFTP. Remote paths in tests are relative:
// pkg/sftp's server resolves relative paths against the working directory
// but passes absolute paths through to the real filesystem root.
func newSFTPTestServer(t *testing.T, password string) *sftpTestServer {
	return newSFTPTestServerWithRenameMode(t, password, false)
}

func newSFTPPosixRenameTestServer(t *testing.T, password string) *sftpTestServer {
	return newSFTPTestServerWithRenameMode(t, password, true)
}

func newSFTPTestServerWithRenameMode(t *testing.T, password string, posixRenameOnly bool) *sftpTestServer {
	t.Helper()

	cfg := &ssh.ServerConfig{
		PasswordCallback: func(conn ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if subtle.ConstantTimeCompare(pass, []byte(password)) == 1 {
				return nil, nil
			}
			return nil, errAuthFailed
		},
	}
	signer := newTestSigner(t)
	cfg.AddHostKey(signer)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &sftpTestServer{
		addr:            ln.Addr().String(),
		root:            t.TempDir(),
		profileID:       nextSFTPTestProfileID.Add(1),
		hostKey:         signer.PublicKey(),
		posixRenameOnly: posixRenameOnly,
		ln:              ln,
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			srv.conns.Add(1)
			go srv.handleConn(conn, cfg)
		}
	}()

	t.Cleanup(func() { ln.Close() })
	return srv
}

func (s *sftpTestServer) handleConn(conn net.Conn, cfg *ssh.ServerConfig) {
	defer s.conns.Add(-1)
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
			go s.handleSession(ch, reqs)
		case "direct-tcpip":
			go handleDirectTCPIP(newCh)
		default:
			newCh.Reject(ssh.UnknownChannelType, "unsupported channel type")
		}
	}
}

// handleSession answers an sftp subsystem request by serving the server's
// root directory over the channel. Serve runs in a goroutine; the server
// (and the channel) are closed when Serve returns.
func (s *sftpTestServer) handleSession(ch ssh.Channel, reqs <-chan *ssh.Request) {
	for req := range reqs {
		if req.Type != "subsystem" {
			req.Reply(false, nil)
			continue
		}
		var payload struct{ Name string }
		if err := ssh.Unmarshal(req.Payload, &payload); err != nil {
			req.Reply(false, nil)
			continue
		}
		if payload.Name != "sftp" {
			req.Reply(false, nil)
			continue
		}
		req.Reply(true, nil)
		if s.posixRenameOnly {
			handlers := pkgsftp.InMemHandler()
			handlers.FileCmd = &renameTrackingHandler{
				Handlers:            handlers,
				standardRenameCalls: &s.standardRenameCalls,
				posixRenameCalls:    &s.posixRenameCalls,
			}
			server := pkgsftp.NewRequestServer(ch, handlers)
			go func() {
				defer server.Close()
				_ = server.Serve()
			}()
			return
		}
		server, err := pkgsftp.NewServer(ch, pkgsftp.WithServerWorkingDirectory(s.root))
		if err != nil {
			return
		}
		go func() {
			defer server.Close()
			_ = server.Serve()
		}()
		return
	}
}

// handleDirectTCPIP forwards a direct-tcpip channel to the requested host,
// enabling ssh.Client.Dial through a jump server. When the client closes
// the channel, the channel->upstream copy finishes and closes the upstream
// connection, which unblocks the other copy so the whole bridge tears down
// and the target server sees its connection close.
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
		go func() { defer wg.Done(); io.Copy(upstream, ch); upstream.Close() }()
		wg.Wait()
	}()
}

// renameTrackingHandler makes the overwrite regression test fail if the
// client sends the ordinary SFTP v3 Rename request instead of the
// posix-rename extension. The in-memory backend rejects ordinary replacement
// but implements the extension's overwrite semantics.
type renameTrackingHandler struct {
	pkgsftp.Handlers
	standardRenameCalls *atomic.Int64
	posixRenameCalls    *atomic.Int64
}

func (h *renameTrackingHandler) Filecmd(req *pkgsftp.Request) error {
	if req.Method == "Rename" {
		h.standardRenameCalls.Add(1)
		return errors.New("standard rename unsupported")
	}
	return h.Handlers.FileCmd.Filecmd(req)
}

func (h *renameTrackingHandler) PosixRename(req *pkgsftp.Request) error {
	h.posixRenameCalls.Add(1)
	posixRenamer, ok := h.Handlers.FileCmd.(interface {
		PosixRename(*pkgsftp.Request) error
	})
	if !ok {
		return errors.New("posix rename unsupported by test backend")
	}
	return posixRenamer.PosixRename(req)
}

// newTestSigner returns an ed25519 signer for the test server host key.
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

// node returns the SSH node describing this server for a bundle.
func (s *sftpTestServer) node(name string) model.SSHNode {
	host, portStr, err := net.SplitHostPort(s.addr)
	if err != nil {
		panic(err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		panic(err)
	}
	return model.SSHNode{
		ID:       s.profileID,
		Name:     name,
		Host:     host,
		Port:     port,
		Username: "user",
		Password: []byte("secret"),
	}
}

// bundle returns a single-hop bundle targeting this server.
func (s *sftpTestServer) bundle() model.SSHBundle {
	return model.SSHBundle{Target: s.node("target")}
}

// writeKnownHosts writes every server's host key into a fresh known_hosts
// file and points HOME at it so Dial's strict verification accepts them.
func writeKnownHosts(t *testing.T, servers ...*sftpTestServer) {
	t.Helper()
	home := t.TempDir()
	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatal(err)
	}
	var sb strings.Builder
	for _, srv := range servers {
		sb.WriteString(knownhosts.Line([]string{srv.addr}, srv.hostKey))
		sb.WriteString("\n")
	}
	if err := os.WriteFile(filepath.Join(sshDir, "known_hosts"), []byte(sb.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
}

// waitForZero waits until the connection counter reaches zero.
func waitForZero(t *testing.T, counter *atomic.Int64) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if counter.Load() == 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("connection counter did not reach zero; still %d", counter.Load())
}

// assertRemoteFile verifies content and mode of a remote file.
func assertRemoteFile(t *testing.T, fs Filesystem, path, want string, mode os.FileMode) {
	t.Helper()
	info, err := fs.Lstat(path)
	if err != nil {
		t.Fatalf("Lstat %s: %v", path, err)
	}
	if got := info.Mode().Perm(); got != mode {
		t.Fatalf("mode of %s: got %v, want %v", path, got, mode)
	}
	r, err := fs.Open(path)
	if err != nil {
		t.Fatalf("Open %s: %v", path, err)
	}
	defer r.Close()
	data, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("ReadAll %s: %v", path, err)
	}
	if string(data) != want {
		t.Fatalf("content of %s: got %q, want %q", path, data, want)
	}
}

// assertLocalFile verifies content and mode of a local file.
func assertLocalFile(t *testing.T, path, want string, mode os.FileMode) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("Lstat %s: %v", path, err)
	}
	if got := info.Mode().Perm(); got != mode {
		t.Fatalf("mode of %s: got %v, want %v", path, got, mode)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile %s: %v", path, err)
	}
	if string(data) != want {
		t.Fatalf("content of %s: got %q, want %q", path, data, want)
	}
}

func TestCopyLocalToRemoteAndBack(t *testing.T) {
	srv := newSFTPTestServer(t, "secret")
	writeKnownHosts(t, srv)

	remote, err := Dial(context.Background(), srv.bundle())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer remote.Close()

	src := filepath.Join(t.TempDir(), "src")
	if err := os.MkdirAll(filepath.Join(src, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "hello.txt"), []byte("hi"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "sub", "deep.txt"), []byte("deep"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Local -> remote: a missing destination becomes the copied root.
	local := Endpoint{FS: NewLocalFilesystem(), Path: src, Identity: "local"}
	if err := Copy(local, remote.Endpoint("dest")); err != nil {
		t.Fatalf("Copy local->remote: %v", err)
	}

	rfs := remote.Endpoint(".").FS
	assertRemoteFile(t, rfs, "dest/hello.txt", "hi", 0o600)
	assertRemoteFile(t, rfs, "dest/sub/deep.txt", "deep", 0o644)

	// Overwrite: a file copy replaces an existing remote file and its mode.
	single := filepath.Join(t.TempDir(), "single.txt")
	if err := os.WriteFile(single, []byte("new"), 0o640); err != nil {
		t.Fatal(err)
	}
	w, err := rfs.Create("single.txt")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := w.Write([]byte("old")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := Copy(Endpoint{FS: NewLocalFilesystem(), Path: single, Identity: "local"}, remote.Endpoint("single.txt")); err != nil {
		t.Fatalf("Copy overwrite: %v", err)
	}
	assertRemoteFile(t, rfs, "single.txt", "new", 0o640)

	// Remote -> local: bytes, placement, and modes survive the return trip.
	out := filepath.Join(t.TempDir(), "out")
	if err := Copy(remote.Endpoint("dest"), Endpoint{FS: NewLocalFilesystem(), Path: out, Identity: "local"}); err != nil {
		t.Fatalf("Copy remote->local: %v", err)
	}
	assertLocalFile(t, filepath.Join(out, "hello.txt"), "hi", 0o600)
	assertLocalFile(t, filepath.Join(out, "sub", "deep.txt"), "deep", 0o644)
}

func TestRemoteSameProfileRejectsDirectoryDescendants(t *testing.T) {
	srv := newSFTPTestServer(t, "secret")
	writeKnownHosts(t, srv)

	source, err := Dial(context.Background(), srv.bundle())
	if err != nil {
		t.Fatalf("Dial source: %v", err)
	}
	defer source.Close()
	destination, err := Dial(context.Background(), srv.bundle())
	if err != nil {
		t.Fatalf("Dial destination: %v", err)
	}
	defer destination.Close()

	wantIdentity := strconv.FormatInt(srv.profileID, 10)
	if got := source.Endpoint(".").Identity; got != wantIdentity {
		t.Fatalf("source identity: got %q, want profile ID %q", got, wantIdentity)
	}
	if got := destination.Endpoint(".").Identity; got != wantIdentity {
		t.Fatalf("destination identity: got %q, want profile ID %q", got, wantIdentity)
	}

	sfs := source.Endpoint(".").FS
	if err := sfs.MkdirAll("src", 0o755); err != nil {
		t.Fatal(err)
	}
	w, err := sfs.Create("src/file.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("source")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	// Existing files make the pre-fix implementation fail immediately rather
	// than walking a newly created descendant forever. Both targets are still
	// below the source directory and must be rejected before any destination
	// mutation.
	dfs := destination.Endpoint(".").FS
	for _, child := range []string{"child", "..child"} {
		t.Run(child, func(t *testing.T) {
			name := "src/" + child
			w, err := dfs.Create(name)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := w.Write([]byte("keep")); err != nil {
				t.Fatal(err)
			}
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}

			err = Copy(source.Endpoint("src"), destination.Endpoint(name))
			if err == nil {
				t.Fatal("Copy: expected self-copy rejection, got nil")
			}
			if !strings.Contains(err.Error(), "itself or a descendant") {
				t.Fatalf("Copy: error = %v, want self-copy rejection", err)
			}
		})
	}
}

func TestRemoteOverwriteUsesPosixRename(t *testing.T) {
	srv := newSFTPPosixRenameTestServer(t, "secret")
	writeKnownHosts(t, srv)

	remote, err := Dial(context.Background(), srv.bundle())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer remote.Close()

	fs := remote.Endpoint(".").FS
	w, err := fs.Create("target.txt")
	if err != nil {
		t.Fatalf("Create existing target: %v", err)
	}
	if _, err := w.Write([]byte("old")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	src := filepath.Join(t.TempDir(), "source.txt")
	if err := os.WriteFile(src, []byte("new"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := Copy(Endpoint{FS: NewLocalFilesystem(), Path: src, Identity: "local"}, remote.Endpoint("target.txt")); err != nil {
		t.Fatalf("Copy overwrite: %v", err)
	}
	reader, err := fs.Open("target.txt")
	if err != nil {
		t.Fatalf("Open overwritten target: %v", err)
	}
	data, err := io.ReadAll(reader)
	closeErr := reader.Close()
	if err != nil {
		t.Fatalf("Read overwritten target: %v", err)
	}
	if closeErr != nil {
		t.Fatalf("Close overwritten target: %v", closeErr)
	}
	if string(data) != "new" {
		t.Fatalf("overwritten target content: got %q, want %q", data, "new")
	}

	if got := srv.standardRenameCalls.Load(); got != 0 {
		t.Fatalf("ordinary Rename requests: got %d, want 0", got)
	}
	if got := srv.posixRenameCalls.Load(); got == 0 {
		t.Fatal("expected at least one PosixRename request")
	}
}

func TestCopyRemoteToRemoteRelaysThroughClient(t *testing.T) {
	srcSrv := newSFTPTestServer(t, "secret")
	dstSrv := newSFTPTestServer(t, "secret")
	writeKnownHosts(t, srcSrv, dstSrv)

	source, err := Dial(context.Background(), srcSrv.bundle())
	if err != nil {
		t.Fatalf("Dial source: %v", err)
	}
	defer source.Close()
	destination, err := Dial(context.Background(), dstSrv.bundle())
	if err != nil {
		t.Fatalf("Dial destination: %v", err)
	}
	defer destination.Close()

	// Seed the source tree through the source remote filesystem.
	sfs := source.Endpoint(".").FS
	if err := sfs.MkdirAll("src/sub", 0o755); err != nil {
		t.Fatal(err)
	}
	writeRemote := func(path, content string, mode os.FileMode) {
		t.Helper()
		w, err := sfs.Create(path)
		if err != nil {
			t.Fatalf("Create %s: %v", path, err)
		}
		if _, err := w.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		if err := sfs.Chmod(path, mode); err != nil {
			t.Fatalf("Chmod %s: %v", path, err)
		}
	}
	writeRemote("src/hello.txt", "hi", 0o600)
	writeRemote("src/sub/deep.txt", "deep", 0o644)

	// Remote -> remote relays bytes through the local client.
	if err := Copy(source.Endpoint("src"), destination.Endpoint("dst")); err != nil {
		t.Fatalf("Copy remote->remote: %v", err)
	}

	dfs := destination.Endpoint(".").FS
	assertRemoteFile(t, dfs, "dst/hello.txt", "hi", 0o600)
	assertRemoteFile(t, dfs, "dst/sub/deep.txt", "deep", 0o644)

	// Distinct connections must carry distinct identities.
	if source.Endpoint(".").Identity == destination.Endpoint(".").Identity {
		t.Fatal("expected distinct identities for distinct connections")
	}
}

func TestRemoteCloseClosesWholeJumpChain(t *testing.T) {
	jump := newSFTPTestServer(t, "secret")
	target := newSFTPTestServer(t, "secret")
	writeKnownHosts(t, jump, target)

	bundle := model.SSHBundle{
		Target: target.node("target"),
		Jumps:  []model.SSHNode{jump.node("jump")},
	}
	remote, err := Dial(context.Background(), bundle)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}

	if got := jump.conns.Load(); got != 1 {
		t.Fatalf("jump connections: got %d, want 1", got)
	}
	if got := target.conns.Load(); got != 1 {
		t.Fatalf("target connections: got %d, want 1", got)
	}

	if err := remote.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := remote.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}

	waitForZero(t, &jump.conns)
	waitForZero(t, &target.conns)
}
