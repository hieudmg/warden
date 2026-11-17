//go:build linux

package terminal

import (
	"fmt"
	"os"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// newPtyPair opens a Linux pty master/slave pair using only x/sys ioctls
// (no external pty dependency). Both ends are opened non-blocking so the
// netpoller enforces SetReadDeadline in tests; a blocking pty fd ignores
// deadlines and would hang the suite forever on a missed echo. Tests skip
// when /dev/ptmx is unavailable.
func newPtyPair(t *testing.T) (master, slave *os.File) {
	t.Helper()
	m, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NONBLOCK, 0)
	if err != nil {
		t.Skipf("cannot open /dev/ptmx: %v", err)
	}
	// TIOCSPTLCK expects a pointer to an int (unlock = 0); passing the
	// value directly yields EFAULT.
	if err := unix.IoctlSetPointerInt(int(m.Fd()), unix.TIOCSPTLCK, 0); err != nil {
		m.Close()
		t.Skipf("unlock pty master: %v", err)
	}
	n, err := unix.IoctlGetInt(int(m.Fd()), unix.TIOCGPTN)
	if err != nil {
		m.Close()
		t.Skipf("TIOCGPTN: %v", err)
	}
	s, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR|syscall.O_NONBLOCK, 0)
	if err != nil {
		m.Close()
		t.Skipf("open pty slave: %v", err)
	}
	t.Cleanup(func() {
		m.Close()
		s.Close()
	})
	return m, s
}

// TestUnixSizeDetectsWindowSize verifies Size() reports the pty window
// size from the TIOCGWINSZ ioctl, and returns 0,0 for non-terminals.
func TestUnixSizeDetectsWindowSize(t *testing.T) {
	_, slave := newPtyPair(t)
	s := &unixSession{in: slave}

	ws := &unix.Winsize{Row: 41, Col: 123}
	if err := unix.IoctlSetWinsize(int(slave.Fd()), unix.TIOCSWINSZ, ws); err != nil {
		t.Fatalf("set winsize: %v", err)
	}
	w, h := s.Size()
	if w != 123 || h != 41 {
		t.Fatalf("Size() = (%d, %d), want (123, 41)", w, h)
	}

	// A pipe fd has no window size: Size must report 0,0, not error.
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer pr.Close()
	defer pw.Close()
	s2 := &unixSession{in: pr}
	w, h = s2.Size()
	if w != 0 || h != 0 {
		t.Fatalf("Size() on non-terminal = (%d, %d), want (0, 0)", w, h)
	}
}

// TestUnixRawModeRestoration verifies EnterRaw disables pty echo, Restore
// re-enables it, and a second Restore is harmless.
func TestUnixRawModeRestoration(t *testing.T) {
	master, slave := newPtyPair(t)
	s := &unixSession{in: slave}

	// Pty echo test: input is typed on the master and, in canonical mode
	// with ECHO, echoed back to the master; raw mode (ECHO off) forwards
	// nothing, so the master read times out.
	assertEcho := func(want bool) {
		t.Helper()
		master.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := master.Write([]byte{'x'}); err != nil {
			t.Fatalf("write input to master: %v", err)
		}
		buf := make([]byte, 1)
		n, err := master.Read(buf)
		got := n == 1 && buf[0] == 'x'
		if got != want {
			t.Fatalf("echo behavior: got %v, want %v (read err: %v)", got, want, err)
		}
	}

	assertEcho(true) // canonical mode echoes
	if err := s.EnterRaw(); err != nil {
		t.Fatalf("EnterRaw: %v", err)
	}
	assertEcho(false) // raw mode does not echo
	if err := s.EnterRaw(); err != nil {
		t.Fatalf("EnterRaw (idempotent): %v", err)
	}
	if err := s.Restore(); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	assertEcho(true) // restored canonical mode echoes again
	if err := s.Restore(); err != nil {
		t.Fatalf("Restore (idempotent): %v", err)
	}
}

// TestRestoreSafeAfterEnterRawFailure verifies EnterRaw on a non-terminal
// fails cleanly and Restore afterwards is a no-op, not an error.
func TestRestoreSafeAfterEnterRawFailure(t *testing.T) {
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer pr.Close()
	defer pw.Close()
	s := &unixSession{in: pr}

	if err := s.EnterRaw(); err == nil {
		t.Fatal("EnterRaw on non-terminal: err = nil, want error")
	}
	if err := s.Restore(); err != nil {
		t.Fatalf("Restore after failed EnterRaw: %v", err)
	}
}

// TestRawModeDeliversCtrlCAsByte verifies the raw-mode precondition for
// Ctrl-C forwarding: with ISIG disabled, 0x03 typed on the master is
// delivered to the slave as an input byte instead of raising a process
// signal.
func TestRawModeDeliversCtrlCAsByte(t *testing.T) {
	master, slave := newPtyPair(t)
	s := &unixSession{in: slave}
	if err := s.EnterRaw(); err != nil {
		t.Fatalf("EnterRaw: %v", err)
	}
	defer s.Restore()

	slave.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := master.Write([]byte{0x03}); err != nil {
		t.Fatalf("write ctrl-c byte: %v", err)
	}
	buf := make([]byte, 4)
	n, err := slave.Read(buf)
	if err != nil {
		t.Fatalf("read ctrl-c byte: %v", err)
	}
	if n != 1 || buf[0] != 0x03 {
		t.Fatalf("read %d bytes %v, want single 0x03 byte", n, buf[:n])
	}
}

// TestUnixStdinReadyWithin verifies the timed stdin readiness wait
// reports false after the grace window with no input and true as soon as
// a byte arrives, without ever blocking past the window or leaving a
// reader goroutine behind on the pty. It runs in raw mode, matching the
// picker's use: canonical mode would hold a partial line unreadable.
func TestUnixStdinReadyWithin(t *testing.T) {
	master, slave := newPtyPair(t)
	s := &unixSession{in: slave}
	if err := s.EnterRaw(); err != nil {
		t.Fatalf("EnterRaw: %v", err)
	}
	defer s.Restore()

	start := time.Now()
	ok, err := s.StdinReadyWithin(30 * time.Millisecond)
	if err != nil {
		t.Fatalf("StdinReadyWithin with no input: %v", err)
	}
	if ok {
		t.Fatal("StdinReadyWithin = true with no input, want false")
	}
	if elapsed := time.Since(start); elapsed < 20*time.Millisecond {
		t.Fatalf("StdinReadyWithin returned after %v, want ~30ms wait", elapsed)
	}

	if _, err := master.Write([]byte{'x'}); err != nil {
		t.Fatalf("write to master: %v", err)
	}
	ok, err = s.StdinReadyWithin(2 * time.Second)
	if err != nil {
		t.Fatalf("StdinReadyWithin with pending input: %v", err)
	}
	if !ok {
		t.Fatal("StdinReadyWithin = false with pending input, want true")
	}
}

// TestUnixStdinReadyWithinBoundedUnderEINTR proves an EINTR burst cannot
// stretch the readiness wait: every retry must poll for only the
// remaining time, not restart the full timeout, so the picker's bounded
// ESC grace stays bounded under repeated interruptions. The poll seam is
// injected to force EINTR deterministically: the Go runtime installs its
// signal handlers with SA_RESTART, so runtime-delivered signals restart
// poll instead of returning EINTR and cannot be relied on to exercise the
// retry path. The injected poll reports EINTR until well past the grace,
// then reports no input; a timeout-restarting implementation keeps
// polling until the injection stops and exceeds the grace.
func TestUnixStdinReadyWithinBoundedUnderEINTR(t *testing.T) {
	orig := poll
	defer func() { poll = orig }()

	_, slave := newPtyPair(t)
	s := &unixSession{in: slave}

	const grace = 30 * time.Millisecond
	const storm = 150 * time.Millisecond
	const bound = storm - 10*time.Millisecond // margin for clock anchoring
	stormEnd := time.Now().Add(storm)
	poll = func(_ []unix.PollFd, _ int) (int, error) {
		if time.Now().After(stormEnd) {
			return 0, nil // storm over: report no input
		}
		return 0, unix.EINTR
	}

	begin := time.Now()
	ok, err := s.StdinReadyWithin(grace)
	elapsed := time.Since(begin)
	if err != nil {
		t.Fatalf("StdinReadyWithin under EINTR burst: %v", err)
	}
	if ok {
		t.Fatal("StdinReadyWithin = true with no input, want false")
	}
	if elapsed >= bound {
		t.Fatalf("StdinReadyWithin ran %v under a %s EINTR burst, want the %v grace bounded", elapsed, storm, grace)
	}
}

// TestResizeEventsPropagate verifies SIGWINCH while raw is active is
// delivered on the ResizeEvents channel.
func TestResizeEventsPropagate(t *testing.T) {
	_, slave := newPtyPair(t)
	s := &unixSession{in: slave, events: make(chan struct{})}
	if err := s.EnterRaw(); err != nil {
		t.Fatalf("EnterRaw: %v", err)
	}
	defer s.Restore()

	if err := syscall.Kill(os.Getpid(), syscall.SIGWINCH); err != nil {
		t.Fatalf("raise SIGWINCH: %v", err)
	}
	select {
	case <-s.ResizeEvents():
	case <-time.After(2 * time.Second):
		t.Fatal("no resize event after SIGWINCH")
	}
}

// TestRestoreClosesResizeEvents verifies Restore stops resize delivery and
// closes the events channel so consumers unblock.
func TestRestoreClosesResizeEvents(t *testing.T) {
	_, slave := newPtyPair(t)
	s := &unixSession{in: slave, events: make(chan struct{})}
	if err := s.EnterRaw(); err != nil {
		t.Fatalf("EnterRaw: %v", err)
	}
	if err := s.Restore(); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	select {
	case _, ok := <-s.ResizeEvents():
		if ok {
			t.Fatal("ResizeEvents channel still open after Restore")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ResizeEvents channel not closed after Restore")
	}
}
