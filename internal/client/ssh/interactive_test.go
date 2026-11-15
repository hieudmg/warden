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
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	golangssh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
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

type partialWriter struct {
	buf bytes.Buffer
	max int
}

func (w *partialWriter) Write(p []byte) (int, error) {
	if len(p) > w.max {
		p = p[:w.max]
	}
	return w.buf.Write(p)
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
	addr       string
	hostKey    golangssh.PublicKey
	promptWord string

	mu            sync.Mutex
	ptySizes      []ptySize
	windowChange  []ptySize
	signals       []string
	input         []byte
	shellReady    bool
	traces        []*ptyFixtureTrace
	connections   map[net.Conn]struct{}
	acceptDone    chan struct{}
	finished      chan struct{}
	handlers      sync.WaitGroup
	beforeStart   func()
	shellLifetime context.Context
	cancelShells  context.CancelFunc
}

type ptySize struct {
	cols, rows uint32
}

type recordingReader struct {
	io.Reader
	record func([]byte)
}

func (r recordingReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	if n > 0 {
		r.record(p[:n])
	}
	return n, err
}

// newInteractiveTestServer starts a server authenticating password "pw".
func newInteractiveTestServer(t *testing.T) *interactiveTestServer {
	return newInteractiveTestServerWithStartup(t, nil)
}

func newInteractiveTestServerWithStartup(t *testing.T, beforeStart func()) *interactiveTestServer {
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
	lifetime, cancelShells := context.WithCancel(context.Background())
	srv := &interactiveTestServer{
		addr:          ln.Addr().String(),
		hostKey:       signer.PublicKey(),
		promptWord:    "warden-fixture-prompt-" + ln.Addr().String(),
		connections:   make(map[net.Conn]struct{}),
		acceptDone:    make(chan struct{}),
		finished:      make(chan struct{}, 32),
		beforeStart:   beforeStart,
		shellLifetime: lifetime,
		cancelShells:  cancelShells,
	}

	go func() {
		defer close(srv.acceptDone)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			srv.mu.Lock()
			srv.connections[conn] = struct{}{}
			srv.mu.Unlock()
			srv.handlers.Add(1)
			go srv.handleConn(conn, cfg)
		}
	}()
	t.Cleanup(func() {
		srv.cancelShells()
		ln.Close()
		<-srv.acceptDone
		srv.mu.Lock()
		for c := range srv.connections {
			c.Close()
		}
		traces := append([]*ptyFixtureTrace(nil), srv.traces...)
		srv.mu.Unlock()
		for _, p := range traces {
			p.forceClose()
		}
		srv.handlers.Wait()
	})
	return srv
}

func (s *interactiveTestServer) handleConn(conn net.Conn, cfg *golangssh.ServerConfig) {
	defer s.handlers.Done()
	defer func() {
		conn.Close()
		s.mu.Lock()
		delete(s.connections, conn)
		s.mu.Unlock()
		s.finished <- struct{}{}
	}()
	sconn, chans, reqs, err := golangssh.NewServerConn(conn, cfg)
	if err != nil {
		conn.Close()
		return
	}
	defer sconn.Close()
	var workers sync.WaitGroup
	workers.Add(1)
	go func() { defer workers.Done(); golangssh.DiscardRequests(reqs) }()
	defer workers.Wait()

	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			newCh.Reject(golangssh.UnknownChannelType, "unsupported channel type")
			continue
		}
		ch, reqs, err := newCh.Accept()
		if err != nil {
			continue
		}
		workers.Add(1)
		go func() { defer workers.Done(); s.handleSession(ch, reqs) }()
	}
}

func (s *interactiveTestServer) handleSession(ch golangssh.Channel, reqs <-chan *golangssh.Request) {
	trace := s.newTrace()
	var workers sync.WaitGroup
	defer func() { trace.event("session request drain ended"); ch.Close(); workers.Wait() }()
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
			req.Reply(true, nil)
			// The shell runs concurrently so the request loop keeps
			// handling window-change/signal requests while it lives.
			trace.event("exec accepted")
			workers.Add(1)
			go func() { defer workers.Done(); runPTYShell(s, ch, payload.Command, trace) }()
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

func (s *interactiveTestServer) recordInput(p []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.input = append(s.input, p...)
}

func (s *interactiveTestServer) gotInputByte(want byte) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return bytes.Contains(s.input, []byte{want})
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
	return s.shellReady
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
func runPTYShell(s *interactiveTestServer, ch golangssh.Channel, command string, trace *ptyFixtureTrace) {
	defer close(trace.done)
	var channelOnce sync.Once
	closeChannel := func() {
		channelOnce.Do(func() {
			trace.event("channel Close begin")
			trace.event("channel Close ended err=%v", ch.Close())
		})
	}
	defer closeChannel()
	master, slave, err := openPTY()
	if err != nil {
		ch.SendRequest("exit-status", false, golangssh.Marshal(struct{ Status uint32 }{Status: 1}))
		return
	}
	trace.mu.Lock()
	trace.master, trace.slave = master, slave
	trace.mu.Unlock()
	trace.event("PTY opened master=%d slave=%d", master.Fd(), slave.Fd())
	var masterOnce, slaveOnce sync.Once
	closeMaster := func() { masterOnce.Do(func() { trace.event("master close err=%v", master.Close()) }) }
	closeSlave := func() { slaveOnce.Do(func() { trace.event("slave close err=%v", slave.Close()) }) }
	defer closeMaster()
	defer closeSlave()

	ws := &unix.Winsize{Row: 24, Col: 80}
	_ = unix.IoctlSetWinsize(int(slave.Fd()), unix.TIOCSWINSZ, ws)

	// A handler registered after fixture shutdown cannot publish a late child.
	cmd := exec.CommandContext(s.shellLifetime, "sh", "-c", command)
	// Force a deterministic login shell: the payload resolves
	// ${SHELL:-sh} against this env, and dash (like bash) honors the
	// EOT byte the client forwards for Ctrl-D. Inheriting a host SHELL
	// (e.g. fish) would make the session non-terminable.
	cmd.Env = append(os.Environ(), "SHELL=/bin/sh")
	cmd.Stdin = slave
	cmd.Stdout = slave
	cmd.Stderr = slave
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}

	if s.beforeStart != nil {
		s.beforeStart()
	}
	if err := cmd.Start(); err != nil {
		trace.event("child Start err=%v", err)
		ch.SendRequest("exit-status", false, golangssh.Marshal(struct{ Status uint32 }{Status: 1}))
		return
	}

	trace.mu.Lock()
	trace.child = cmd.Process
	trace.mu.Unlock()
	pgid, groupErr := syscall.Getpgid(cmd.Process.Pid)
	foreground, foregroundErr := unix.IoctlGetInt(int(master.Fd()), unix.TIOCGPGRP)
	trace.event("child started pid=%d pgid=%d err=%v foreground=%d err=%v", cmd.Process.Pid, pgid, groupErr, foreground, foregroundErr)
	if attrs, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS); err == nil {
		trace.event("termios lflag=%x VINTR=%x VEOF=%x", attrs.Lflag, attrs.Cc[unix.VINTR], attrs.Cc[unix.VEOF])
	} else {
		trace.event("termios err=%v", err)
	}
	// Only the child owns a slave after Start. Retaining the parent's slave
	// prevents master EOF/EIO after child exit and deadlocks the output join.
	closeSlave()

	// The fixture's ready gate must describe an initialized foreground shell,
	// not merely an accepted exec or the first sh -c process. The shell itself
	// emits this marker after login profiles. Octal escapes prevent terminal
	// echo of the command from being mistaken for its output.
	ready, stopInput := make(chan struct{}), make(chan struct{})
	var readyOnce sync.Once
	markReady := func() {
		group, groupErr := unix.IoctlGetInt(int(master.Fd()), unix.TIOCGPGRP)
		attrs, attrsErr := unix.IoctlGetTermios(int(master.Fd()), unix.TCGETS)
		trace.event("shell marker foreground=%d pid=%d err=%v attrsErr=%v", group, cmd.Process.Pid, groupErr, attrsErr)
		if groupErr != nil || group != cmd.Process.Pid || attrsErr != nil || attrs.Lflag&(unix.ICANON|unix.ISIG) != unix.ICANON|unix.ISIG || attrs.Cc[unix.VINTR] != 3 || attrs.Cc[unix.VEOF] != 4 {
			return
		}
		readyOnce.Do(func() {
			s.mu.Lock()
			s.shellReady = true
			s.mu.Unlock()
			trace.event("initialized foreground shell ready")
			close(ready)
		})
	}

	// Local input waits until bootstrap completes; no client bytes interleave
	// with the fixture's private readiness command.
	inDone := make(chan struct{})
	trace.copies.Add(1)
	go func() {
		defer close(inDone)
		defer trace.copies.Add(-1)
		select {
		case <-ready:
		case <-stopInput:
			return
		}
		writer := tracedPTYInput{Writer: master, trace: trace}
		n, err := io.Copy(writer, recordingReader{Reader: ch, record: s.recordInput})
		trace.event("input copy ended n=%d err=%v", n, err)
		// Channel EOF: deliver EOF to the pty so the shell terminates.
		writer.Write([]byte{0x04})
	}()
	outDone := make(chan struct{})
	trace.copies.Add(1)
	go func() {
		defer close(outDone)
		defer trace.copies.Add(-1)
		n, err := io.Copy(&ptyReadinessWriter{Writer: ch, ready: markReady}, master)
		trace.event("output copy ended n=%d err=%v", n, err)
	}()
	// Set PS1 after login profiles. Its actual control-delimited output, unlike
	// the octal-escaped command echo, identifies each completed shell prompt.
	bootstrap := "PS1=\"$(printf '\\036" + s.promptWord + "\\037')\"; printf '\\036" + ptyReadyWord + "\\037\\n'\n"
	_, bootstrapErr := (tracedPTYInput{Writer: master, trace: trace}).Write([]byte(bootstrap))
	trace.event("bootstrap command written err=%v", bootstrapErr)

	status := uint32(0)
	trace.event("child Wait begin")
	if err := cmd.Wait(); err != nil {
		trace.event("child Wait err=%v state=%v", err, cmd.ProcessState)
		if ee, ok := err.(*exec.ExitError); ok {
			status = uint32(ee.ExitCode())
		} else {
			status = 1
		}
	}
	close(stopInput)
	trace.event("child Wait ended state=%v; exit-status send begin status=%d", cmd.ProcessState, status)
	_, statusErr := ch.SendRequest("exit-status", false, golangssh.Marshal(struct {
		Status uint32
	}{Status: status}))
	trace.event("exit-status send ended err=%v", statusErr)
	// The client's session.Wait returns only when the channel closes, so
	// close it now; that also unblocks both copy goroutines.
	closeChannel()
	// Channel Close cannot interrupt a worker reading the PTY master.
	closeMaster()
	<-inDone
	trace.event("input worker joined")
	<-outDone
	trace.event("output worker joined")
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

func TestRunInteractiveDoesNotForwardCRLFTerminator(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	srv := newInteractiveTestServer(t)
	term := newFakeTerminalSession(bytes.NewBufferString("yes\r\n\x04"), &lockedBuffer{}, io.Discard)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := RunInteractive(ctx, interactiveBundle(srv), term); err != nil {
		t.Fatalf("RunInteractive: %v", err)
	}
	srv.mu.Lock()
	gotInput := append([]byte(nil), srv.input...)
	srv.mu.Unlock()
	if bytes.Contains(gotInput, []byte{'\n'}) {
		t.Fatalf("remote input = %q, want CRLF from host-key confirmation consumed", gotInput)
	}
}

func TestRunInteractiveConfirmsUnknownHostByDefault(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	srv := newInteractiveTestServer(t)
	out := &lockedBuffer{}
	term := newFakeTerminalSession(bytes.NewBufferString("yes\r\x04"), out, io.Discard)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := RunInteractive(ctx, interactiveBundle(srv), term); err != nil {
		t.Fatalf("RunInteractive: %v", err)
	}
	if !strings.Contains(out.String(), "This key is not known by any other names.") {
		t.Fatalf("output = %q, want first-use host-key confirmation", out.String())
	}
	knownHostsPath := filepath.Join(home, ".ssh", "known_hosts")
	data, err := os.ReadFile(knownHostsPath)
	if err != nil {
		t.Fatalf("read known_hosts: %v", err)
	}
	want := knownhosts.Line([]string{srv.addr}, srv.hostKey) + "\n"
	if string(data) != want {
		t.Fatalf("known_hosts = %q, want accepted key %q", data, want)
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
	if got, want := out.String(), "\x1b[32mFetching credentials...\x1b[0m\r\n"; got != want {
		t.Fatalf("WriteProgress() = %q, want %q", got, want)
	}
}

func TestWriteProgressEscapesControlCharacters(t *testing.T) {
	var out bytes.Buffer
	WriteProgress(&out, "bad\x00\a\b\x1b[31m\x7f")
	if got, want := out.String(), "\x1b[32mbad\\x00\\x07\\x08\\x1b[31m\\x7f\x1b[0m\r\n"; got != want {
		t.Fatalf("WriteProgress() = %q, want %q", got, want)
	}
}

func TestPumpInteractiveInputForwardsEveryByte(t *testing.T) {
	want := make([]byte, 256)
	for i := range want {
		want[i] = byte(i)
	}
	out := &partialWriter{max: 7}

	pumpInteractiveInput(context.Background(), out, bytes.NewReader(want), make(chan struct{}))

	if !bytes.Equal(out.buf.Bytes(), want) {
		t.Fatalf("forwarded %d bytes, want all %d bytes", out.buf.Len(), len(want))
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

// TestRunInteractiveCtrlCForwardsByte verifies Ctrl-C is forwarded through
// the remote PTY as a control byte, matching direct ssh -t behavior. The
// remote PTY's line discipline then turns the byte into SIGINT for its
// foreground process group.
func TestRunInteractiveCtrlCForwardsByte(t *testing.T) {
	checkPTYResourceCeilings(t)
	defer checkPTYResourceCeilings(t)
	srv := newInteractiveTestServer(t)
	defer func() {
		t.Logf("%s", srv.diagnostics())
		if t.Failed() {
			t.Logf("%s", allPTYStacks())
		}
	}()
	inR, inW := io.Pipe()
	t.Cleanup(func() { inR.Close() })
	out := &lockedBuffer{}

	prompts := &ptyPromptOutput{Writer: out, marker: []byte("\x1e" + srv.promptWord + "\x1f")}
	_, session := startInteractive(t, srv, inR, prompts, io.Discard)
	waitFor(t, "remote shell start", srv.started)
	waitFor(t, "initial controlled shell prompt", func() bool { return prompts.generation() != 0 })
	initialPrompt := prompts.generation()

	if err := sendInteractiveInterruptThenEOF(inW, func() {
		waitFor(t, "Ctrl-C byte written to remote PTY", func() bool {
			return srv.gotInputByte(0x03) && srv.wrotePTYByte(0x03)
		})
		if srv.gotSignal("INT") {
			t.Fatal("Ctrl-C sent as an SSH signal request; want PTY input byte")
		}
	}, func() {
		// PTY byte delivery is not SIGINT acknowledgment: EOT can be consumed
		// before pending SIGINT returns the shell to another prompt/read.
		waitFor(t, "new shell prompt after Ctrl-C", func() bool {
			return prompts.generation() > initialPrompt
		})
	}); err != nil {
		t.Fatal(err)
	}

	select {
	case err := <-*session:
		if err != nil {
			var exitErr *ExitStatusError
			if !errors.As(err, &exitErr) || exitErr.Status != 130 {
				t.Fatalf("runInteractive() err = %v, want nil or Ctrl-C exit status 130", err)
			}
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("session did not end after Ctrl-D (remote received Ctrl-D=%t, output=%q)\n%s\n%s", srv.gotInputByte(0x04), out.String(), srv.diagnostics(), allPTYStacks())
	}
	assertPTYFixtureJoined(t, srv)
	srv.mu.Lock()
	forwarded := append([]byte(nil), srv.input...)
	srv.mu.Unlock()
	if !bytes.Equal(forwarded, []byte{0x03, 0x04}) || srv.gotSignal("INT") {
		t.Fatalf("forwarded input=%x, SSH INT=%t; want one Ctrl-C byte, one EOT, no SSH INT", forwarded, srv.gotSignal("INT"))
	}
}

// sendInteractiveInterruptThenEOF is the input sequence exercised by the
// real-shell test and the controlled acknowledgment regression.
func sendInteractiveInterruptThenEOF(input io.Writer, delivered, acknowledged func()) error {
	if _, err := input.Write([]byte{0x03}); err != nil {
		return err
	}
	delivered()
	acknowledged()
	_, err := input.Write([]byte{0x04})
	return err
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
	if interactiveShellCommand != `exec "$SHELL" -l` {
		t.Fatalf("interactiveShellCommand = %q, want %q", interactiveShellCommand, `exec "$SHELL" -l`)
	}
}

// TestBuildInteractiveShellCommand verifies DefaultDir is wrapped in
// single quotes, embedded quotes are escaped, and an empty dir yields
// the bare login-shell command.
func TestBuildInteractiveShellCommand(t *testing.T) {
	if got := buildInteractiveShellCommand(""); got != `exec "$SHELL" -l` {
		t.Errorf("empty dir = %q, want bare login-shell", got)
	}
	if got := buildInteractiveShellCommand("/srv/app"); got != `cd '/srv/app' && exec "$SHELL" -l` {
		t.Errorf("plain dir = %q, want single-quoted prefix", got)
	}
	if got := buildInteractiveShellCommand("/srv/it's"); got != `cd '/srv/it'"'"'s' && exec "$SHELL" -l` {
		t.Errorf("quoted dir = %q, want embedded single quote escaped", got)
	}
}
