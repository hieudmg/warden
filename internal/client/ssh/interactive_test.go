//go:build linux

package ssh

import (
	"bytes"
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	golangssh "golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"

	"warden/internal/client/terminal"
	"warden/internal/model"
)

// fakeTerminalSession is an in-memory terminal.Session used to drive
// interactive sessions without a real console.
//
// Compile-time assertion: the fake satisfies the transport's terminal
// contract.
var _ terminal.Session = (*fakeTerminalSession)(nil)

// lockedBuffer is a mutex-guarded bytes.Buffer for test output sinks
// written by the transport's stdout/stderr copy goroutines while the
// test goroutine polls the contents (bytes.Buffer is not safe for
// concurrent use).
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

type fakeTerminalSession struct {
	mu     sync.Mutex
	in     io.Reader
	out    io.Writer
	errOut io.Writer
	raw    bool
	sizeW  int
	sizeH  int
	events chan struct{}
}

func newFakeTerminalSession(in io.Reader, out, errOut io.Writer) *fakeTerminalSession {
	return &fakeTerminalSession{
		in:     in,
		out:    out,
		errOut: errOut,
		sizeW:  80,
		sizeH:  24,
		events: make(chan struct{}),
	}
}

func (f *fakeTerminalSession) EnterRaw() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.raw = true
	return nil
}

func (f *fakeTerminalSession) Stdin() io.Reader  { return f.in }
func (f *fakeTerminalSession) Stdout() io.Writer { return f.out }
func (f *fakeTerminalSession) Stderr() io.Writer { return f.errOut }

func (f *fakeTerminalSession) Restore() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.raw = false
	select {
	case <-f.events:
	default:
		close(f.events)
	}
	return nil
}

func (f *fakeTerminalSession) Size() (int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.sizeW, f.sizeH
}

func (f *fakeTerminalSession) isRaw() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.raw
}

func (f *fakeTerminalSession) setSize(w, h int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sizeW, f.sizeH = w, h
}

func (f *fakeTerminalSession) ResizeEvents() <-chan struct{} { return f.events }

func (f *fakeTerminalSession) SupportsANSI() bool { return true }

// StdinReadyWithin reports readiness immediately: the SSH transport feeds
// in-memory readers that never block, so the timed wait is never needed.
func (f *fakeTerminalSession) StdinReadyWithin(time.Duration) (bool, error) { return true, nil }

// interactiveTestServer is an in-process SSH server that records PTY,
// window-change, and signal requests and runs exec commands behind a real
// Linux pty, mirroring sshd's pty handling so remote output is delivered
// in real time (no block buffering).
type interactiveTestServer struct {
	addr    string
	hostKey golangssh.PublicKey

	mu           sync.Mutex
	ptySizes     []ptySize
	windowChange []ptySize
	signals      []string
	execStarted  bool
}

type ptySize struct {
	cols, rows uint32
}

// newInteractiveTestServer starts a server authenticating password "pw".
func newInteractiveTestServer(t *testing.T) *interactiveTestServer {
	t.Helper()

	cfg := &golangssh.ServerConfig{
		PasswordCallback: func(conn golangssh.ConnMetadata, pass []byte) (*golangssh.Permissions, error) {
			if subtle.ConstantTimeCompare(pass, []byte("pw")) == 1 {
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
	srv := &interactiveTestServer{
		addr:    ln.Addr().String(),
		hostKey: signer.PublicKey(),
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

func (s *interactiveTestServer) handleConn(conn net.Conn, cfg *golangssh.ServerConfig) {
	sconn, chans, reqs, err := golangssh.NewServerConn(conn, cfg)
	if err != nil {
		conn.Close()
		return
	}
	defer sconn.Close()
	go golangssh.DiscardRequests(reqs)

	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			newCh.Reject(golangssh.UnknownChannelType, "unsupported channel type")
			continue
		}
		ch, reqs, err := newCh.Accept()
		if err != nil {
			continue
		}
		go s.handleSession(ch, reqs)
	}
}

func (s *interactiveTestServer) handleSession(ch golangssh.Channel, reqs <-chan *golangssh.Request) {
	defer ch.Close()
	for req := range reqs {
		switch req.Type {
		case "pty-req":
			var payload struct {
				Term          string
				Columns, Rows uint32
				Width, Height uint32
				Modes         []byte
			}
			golangssh.Unmarshal(req.Payload, &payload)
			s.mu.Lock()
			s.ptySizes = append(s.ptySizes, ptySize{cols: payload.Columns, rows: payload.Rows})
			s.mu.Unlock()
			req.Reply(true, nil)
		case "window-change":
			var payload struct {
				Columns, Rows uint32
				Width, Height uint32
			}
			golangssh.Unmarshal(req.Payload, &payload)
			s.mu.Lock()
			s.windowChange = append(s.windowChange, ptySize{cols: payload.Columns, rows: payload.Rows})
			s.mu.Unlock()
			req.Reply(true, nil)
		case "signal":
			var payload struct {
				Signal string
			}
			golangssh.Unmarshal(req.Payload, &payload)
			s.mu.Lock()
			s.signals = append(s.signals, payload.Signal)
			s.mu.Unlock()
			req.Reply(true, nil)
		case "env":
			req.Reply(true, nil)
		case "exec":
			var payload struct {
				Command string
			}
			golangssh.Unmarshal(req.Payload, &payload)
			s.mu.Lock()
			s.execStarted = true
			s.mu.Unlock()
			req.Reply(true, nil)
			// The shell runs concurrently so the request loop keeps
			// handling window-change/signal requests while it lives.
			go runPTYShell(ch, payload.Command)
		default:
			req.Reply(false, nil)
		}
	}
}

func (s *interactiveTestServer) gotSignal(want string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, sig := range s.signals {
		if sig == want {
			return true
		}
	}
	return false
}

func (s *interactiveTestServer) lastWindowChange() (ptySize, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.windowChange) == 0 {
		return ptySize{}, false
	}
	return s.windowChange[len(s.windowChange)-1], true
}

func (s *interactiveTestServer) lastPTYSize() (ptySize, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.ptySizes) == 0 {
		return ptySize{}, false
	}
	return s.ptySizes[len(s.ptySizes)-1], true
}

func (s *interactiveTestServer) started() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.execStarted
}

// openPTY opens a Linux pty master/slave pair without external
// dependencies (mirrors the terminal package tests).
func openPTY() (master, slave *os.File, err error) {
	m, err := os.OpenFile("/dev/ptmx", os.O_RDWR, 0)
	if err != nil {
		return nil, nil, err
	}
	// TIOCSPTLCK expects a pointer to an int (unlock = 0); passing the
	// value directly yields EFAULT.
	if err := unix.IoctlSetPointerInt(int(m.Fd()), unix.TIOCSPTLCK, 0); err != nil {
		m.Close()
		return nil, nil, err
	}
	n, err := unix.IoctlGetInt(int(m.Fd()), unix.TIOCGPTN)
	if err != nil {
		m.Close()
		return nil, nil, err
	}
	s, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR, 0)
	if err != nil {
		m.Close()
		return nil, nil, err
	}
	return m, s, nil
}

// runPTYShell runs the exec payload with a real pty as the child's
// controlling terminal and relays the pty bytes to the SSH channel. The
// pty keeps the remote shell line-buffered so output streams in real
// time, exactly like a real sshd. When the client closes its stdin, EOF
// is delivered to the pty (as EOT in canonical mode), ending the shell.
func runPTYShell(ch golangssh.Channel, command string) {
	master, slave, err := openPTY()
	if err != nil {
		ch.SendRequest("exit-status", false, golangssh.Marshal(struct{ Status uint32 }{Status: 1}))
		return
	}
	defer master.Close()
	defer slave.Close()

	ws := &unix.Winsize{Row: 24, Col: 80}
	_ = unix.IoctlSetWinsize(int(slave.Fd()), unix.TIOCSWINSZ, ws)

	cmd := exec.Command("sh", "-c", command)
	// Force a deterministic login shell: the payload resolves
	// ${SHELL:-sh} against this env, and dash (like bash) honors the
	// EOT byte the client forwards for Ctrl-D. Inheriting a host SHELL
	// (e.g. fish) would make the session non-terminable.
	cmd.Env = append(os.Environ(), "SHELL=/bin/sh")
	cmd.Stdin = slave
	cmd.Stdout = slave
	cmd.Stderr = slave
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}

	if err := cmd.Start(); err != nil {
		ch.SendRequest("exit-status", false, golangssh.Marshal(struct{ Status uint32 }{Status: 1}))
		return
	}

	// Local input -> pty; pty output -> local stdout.
	inDone := make(chan struct{})
	go func() {
		defer close(inDone)
		io.Copy(master, ch)
		// Channel EOF: deliver EOF to the pty so the shell terminates.
		master.Write([]byte{0x04})
	}()
	outDone := make(chan struct{})
	go func() {
		defer close(outDone)
		io.Copy(ch, master)
	}()

	status := uint32(0)
	if err := cmd.Wait(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			status = uint32(ee.ExitCode())
		} else {
			status = 1
		}
	}
	ch.SendRequest("exit-status", false, golangssh.Marshal(struct {
		Status uint32
	}{Status: status}))
	// The client's session.Wait returns only when the channel closes, so
	// close it now; that also unblocks both copy goroutines.
	ch.Close()
	<-inDone
	<-outDone
}

// interactiveBundle builds a transport bundle pointing at the test server.
func interactiveBundle(srv *interactiveTestServer) model.SSHBundle {
	host, portStr, _ := net.SplitHostPort(srv.addr)
	port, _ := strconv.Atoi(portStr)
	return model.SSHBundle{
		Target: model.SSHNode{
			ID: 1, Name: "test", Host: host, Port: port,
			Username: "user", Password: []byte("pw"),
		},
	}
}

// startInteractive launches runInteractive with a fake terminal in a
// goroutine and returns the fake terminal and the result channel. The
// host-key callback accepts any key (test-only).
func startInteractive(t *testing.T, srv *interactiveTestServer, in io.Reader, out, errOut io.Writer) (*fakeTerminalSession, *chan error) {
	t.Helper()
	term := newFakeTerminalSession(in, out, errOut)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)

	done := make(chan error, 1)
	go func() {
		done <- runInteractive(ctx, interactiveBundle(srv), term, DialOptions{
			HostKeyCallback: func(string, net.Addr, golangssh.PublicKey) error { return nil },
		})
	}()
	return term, &done
}

// waitFor polls cond until it holds or the timeout expires.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// TestRunInteractiveReportsConnectionProgress verifies interactive
// connection stages are reported in order.
func TestRunInteractiveReportsConnectionProgress(t *testing.T) {
	srv := newInteractiveTestServer(t)
	inR, inW := io.Pipe()
	t.Cleanup(func() { inR.Close() })
	var out bytes.Buffer
	var progress []string

	term := newFakeTerminalSession(inR, &out, io.Discard)
	done := make(chan error, 1)
	go func() {
		done <- runInteractive(context.Background(), interactiveBundle(srv), term, DialOptions{
			HostKeyCallback: func(string, net.Addr, golangssh.PublicKey) error { return nil },
			Progress:        func(message string) { progress = append(progress, message) },
		})
	}()
	waitFor(t, "remote shell start", srv.started)
	if _, err := inW.Write([]byte{0x04}); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("runInteractive() err = %v, want nil", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("interactive session did not end")
	}

	want := []string{"Connecting to test...", "Opening interactive session..."}
	if !reflect.DeepEqual(progress, want) {
		t.Fatalf("progress = %#v, want %#v", progress, want)
	}
}

func TestWriteProgressUsesGreenOutput(t *testing.T) {
	var out bytes.Buffer
	WriteProgress(&out, "Fetching credentials...")
	if got, want := out.String(), "\x1b[32mFetching credentials...\x1b[0m\n"; got != want {
		t.Fatalf("WriteProgress() = %q, want %q", got, want)
	}
}

func TestWriteProgressEscapesControlCharacters(t *testing.T) {
	var out bytes.Buffer
	WriteProgress(&out, "bad\x00\a\b\x1b[31m\x7f")
	if got, want := out.String(), "\x1b[32mbad\\x00\\x07\\x08\\x1b[31m\\x7f\x1b[0m\n"; got != want {
		t.Fatalf("WriteProgress() = %q, want %q", got, want)
	}
}

// TestRunInteractiveRequestsPTYAndStreamsOutput verifies the full
// interactive flow: raw mode entered, PTY requested with the terminal
// size, remote output streamed locally in real time, and Ctrl-D ending
// the session cleanly.
func TestRunInteractiveRequestsPTYAndStreamsOutput(t *testing.T) {
	srv := newInteractiveTestServer(t)
	inR, inW := io.Pipe()
	t.Cleanup(func() { inR.Close() })
	out := &lockedBuffer{}
	var errOut bytes.Buffer

	term, done := startInteractive(t, srv, inR, out, &errOut)

	if _, err := inW.Write([]byte("echo pty-echo-ok\n")); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "remote shell output", func() bool {
		return strings.Contains(out.String(), "pty-echo-ok")
	})
	if !term.isRaw() {
		t.Fatal("terminal not in raw mode during interactive session")
	}

	if _, err := inW.Write([]byte{0x04}); err != nil { // Ctrl-D: EOF
		t.Fatal(err)
	}
	select {
	case err := <-*done:
		if err != nil {
			t.Fatalf("runInteractive() err = %v, want nil", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("interactive session did not end after Ctrl-D")
	}
	if term.isRaw() {
		t.Fatal("terminal still raw after session end")
	}

	size, ok := srv.lastPTYSize()
	if !ok {
		t.Fatal("server never received a pty-req")
	}
	if size.cols != 80 || size.rows != 24 {
		t.Fatalf("pty size = (%d, %d), want (80, 24)", size.cols, size.rows)
	}
}

// TestRunInteractiveSendsWindowChange verifies a resize event triggers a
// window-change request to the remote server.
func TestRunInteractiveSendsWindowChange(t *testing.T) {
	srv := newInteractiveTestServer(t)
	inR, inW := io.Pipe()
	t.Cleanup(func() { inR.Close() })
	var out bytes.Buffer

	term, session := startInteractive(t, srv, inR, &out, io.Discard)
	waitFor(t, "remote shell start", srv.started)

	term.setSize(100, 40)
	term.events <- struct{}{}
	waitFor(t, "window-change request", func() bool {
		size, ok := srv.lastWindowChange()
		return ok && size.cols == 100 && size.rows == 40
	})

	if _, err := inW.Write([]byte{0x04}); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-*session:
		if err != nil {
			t.Fatalf("runInteractive() err = %v, want nil", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("session did not end after Ctrl-D")
	}
}

// TestRunInteractiveCtrlCForwardsSIGINT verifies the 0x03 input byte is
// translated to a remote SIGINT signal request, not forwarded as a byte.
func TestRunInteractiveCtrlCForwardsSIGINT(t *testing.T) {
	srv := newInteractiveTestServer(t)
	inR, inW := io.Pipe()
	t.Cleanup(func() { inR.Close() })
	var out bytes.Buffer

	_, session := startInteractive(t, srv, inR, &out, io.Discard)
	waitFor(t, "remote shell start", srv.started)

	if _, err := inW.Write([]byte{0x03}); err != nil { // Ctrl-C
		t.Fatal(err)
	}
	waitFor(t, "SIGINT signal request", func() bool { return srv.gotSignal("INT") })

	if _, err := inW.Write([]byte{0x04}); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-*session:
		if err != nil {
			t.Fatalf("runInteractive() err = %v, want nil", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("session did not end after Ctrl-D")
	}
}

// TestRunInteractivePropagatesExitStatus verifies a remote shell exit
// status is surfaced as *ExitStatusError.
func TestRunInteractivePropagatesExitStatus(t *testing.T) {
	srv := newInteractiveTestServer(t)
	inR, inW := io.Pipe()
	t.Cleanup(func() { inR.Close() })
	var out bytes.Buffer

	_, session := startInteractive(t, srv, inR, &out, io.Discard)
	waitFor(t, "remote shell start", srv.started)

	if _, err := inW.Write([]byte("exit 3\n")); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-*session:
		var exitErr *ExitStatusError
		if !errors.As(err, &exitErr) || exitErr.Status != 3 {
			t.Fatalf("err = %v, want *ExitStatusError{3}", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("session did not end after remote exit")
	}
}

// TestRunInteractiveRestoresTerminalOnDialFailure verifies terminal
// restoration when the transport dial fails before any session starts.
func TestRunInteractiveRestoresTerminalOnDialFailure(t *testing.T) {
	// A port that nothing listens on.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	host, portStr, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(portStr)
	bundle := model.SSHBundle{
		Target: model.SSHNode{ID: 9, Name: "dead", Host: host, Port: port,
			Username: "user", Password: []byte("pw")},
	}

	inR, _ := io.Pipe()
	defer inR.Close()
	term := newFakeTerminalSession(inR, io.Discard, io.Discard)
	ctx := context.Background()
	err = runInteractive(ctx, bundle, term, DialOptions{
		HostKeyCallback: func(string, net.Addr, golangssh.PublicKey) error { return nil },
	})
	if err == nil {
		t.Fatal("runInteractive() err = nil, want dial failure")
	}
	if term.isRaw() {
		t.Fatal("terminal not restored after dial failure")
	}
}

// TestInteractiveShellCommand verifies the fixed remote command string
// stays the portable login-shell form (documented contract).
func TestInteractiveShellCommand(t *testing.T) {
	if interactiveShellCommand != "exec ${SHELL:-sh} -l" {
		t.Fatalf("interactiveShellCommand = %q, want %q", interactiveShellCommand, "exec ${SHELL:-sh} -l")
	}
}

// TestBuildInteractiveShellCommand verifies DefaultDir is wrapped in
// single quotes, embedded quotes are escaped, and an empty dir yields
// the bare login-shell command.
func TestBuildInteractiveShellCommand(t *testing.T) {
	if got := buildInteractiveShellCommand(""); got != "exec ${SHELL:-sh} -l" {
		t.Errorf("empty dir = %q, want bare login-shell", got)
	}
	if got := buildInteractiveShellCommand("/srv/app"); got != "cd '/srv/app' && exec ${SHELL:-sh} -l" {
		t.Errorf("plain dir = %q, want single-quoted prefix", got)
	}
	if got := buildInteractiveShellCommand("/srv/it's"); got != `cd '/srv/it'"'"'s' && exec ${SHELL:-sh} -l` {
		t.Errorf("quoted dir = %q, want embedded single quote escaped", got)
	}
}
