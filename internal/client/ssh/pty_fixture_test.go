//go:build linux

package ssh

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ptyFixtureTrace retains bounded, synthetic-session diagnostics, never live
// transport secrets. Worker completion is separate from forced test cleanup.
type ptyFixtureTrace struct {
	mu            sync.Mutex
	id            int
	start         time.Time
	events        []string
	masterInput   []byte
	dropped       int
	master, slave *os.File
	child         *os.Process
	copies        atomic.Int32
	done          chan struct{}
}

func (p *ptyFixtureTrace) event(format string, args ...any) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.events) >= 256 {
		p.dropped++
		return
	}
	p.events = append(p.events, fmt.Sprintf("%s %s", time.Since(p.start).Round(time.Microsecond), fmt.Sprintf(format, args...)))
}
func (p *ptyFixtureTrace) snapshot() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return fmt.Sprintf("PTY session %d copies=%d dropped=%d\n%s", p.id, p.copies.Load(), p.dropped, strings.Join(p.events, "\n"))
}
func (p *ptyFixtureTrace) forceClose() {
	p.mu.Lock()
	master, slave, child := p.master, p.slave, p.child
	p.mu.Unlock()
	p.event("FORCED fixture cleanup")
	if master != nil {
		master.Close()
	}
	if slave != nil {
		slave.Close()
	}
	if child != nil {
		child.Kill()
	}
}
func (s *interactiveTestServer) newTrace() *ptyFixtureTrace {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := &ptyFixtureTrace{id: len(s.traces) + 1, start: time.Now(), done: make(chan struct{})}
	s.traces = append(s.traces, p)
	return p
}
func (s *interactiveTestServer) diagnostics() string {
	s.mu.Lock()
	traces := append([]*ptyFixtureTrace(nil), s.traces...)
	s.mu.Unlock()
	var out strings.Builder
	for _, p := range traces {
		out.WriteString(p.snapshot())
		out.WriteByte('\n')
	}
	return out.String()
}

// These are diagnostic safety ceilings, not goroutine/FD leak proofs. Resource
// ownership is asserted separately via closed files and joined fixture workers.
func checkPTYResourceCeilings(t *testing.T) {
	t.Helper()
	fds, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	goroutines := runtime.NumGoroutine()
	if len(fds) > 512 || goroutines > 512 || mem.Alloc > 256<<20 {
		t.Fatalf("PTY diagnostic resource ceiling: fds=%d goroutines=%d heap=%d\n%s", len(fds), goroutines, mem.Alloc, allPTYStacks())
	}
}

func allPTYStacks() string {
	buf := make([]byte, 1<<20)
	n := runtime.Stack(buf, true)
	return string(buf[:n])
}

type tracedPTYInput struct {
	io.Writer
	trace *ptyFixtureTrace
}

func (w tracedPTYInput) Write(p []byte) (int, error) {
	shown := p
	if len(shown) > 64 {
		shown = shown[:64]
	}
	w.trace.event("master write begin len=%d first64=%x", len(p), shown)
	n, err := w.Writer.Write(p)
	w.trace.mu.Lock()
	keep := min(n, 256-len(w.trace.masterInput))
	w.trace.masterInput = append(w.trace.masterInput, p[:keep]...)
	w.trace.mu.Unlock()
	w.trace.event("master write end n=%d err=%v", n, err)
	return n, err
}

const ptyReadyWord = "warden-fixture-ready"

type ptyReadinessWriter struct {
	io.Writer
	tail  []byte
	seen  bool
	ready func()
}

func (w *ptyReadinessWriter) Write(p []byte) (int, error) {
	marker := []byte("\x1e" + ptyReadyWord + "\x1f")
	if !w.seen {
		window := append(w.tail, p...)
		if bytes.Contains(window, marker) {
			w.seen = true
			w.ready()
		}
		keep := min(len(window), len(marker)-1)
		w.tail = append(w.tail[:0], window[len(window)-keep:]...)
	}
	return w.Writer.Write(p)
}

func TestPTYReadinessMarkerRequiresOutputNotCommandEcho(t *testing.T) {
	var out bytes.Buffer
	calls := 0
	w := &ptyReadinessWriter{Writer: &out, ready: func() { calls++ }}
	echo := "printf '\\036" + ptyReadyWord + "\\037\\n'\r\n"
	w.Write([]byte(echo))
	if calls != 0 {
		t.Fatal("command echo satisfied readiness")
	}
	marker := "\x1e" + ptyReadyWord + "\x1f"
	w.Write([]byte(marker[:4]))
	if calls != 0 {
		t.Fatal("partial marker satisfied readiness")
	}
	w.Write([]byte(marker[4:]))
	w.Write([]byte(marker))
	if calls != 1 {
		t.Errorf("ready calls=%d", calls)
	}
	if out.String() != echo+marker+marker {
		t.Error("readiness observation changed output")
	}
}

// ptyPromptOutput counts only complete, shell-emitted PS1 markers accepted by
// the client output sink. A saved generation distinguishes startup from a new
// prompt after SIGINT; kernel echo and bootstrap echo contain no such marker.
type ptyPromptOutput struct {
	io.Writer
	mu      sync.Mutex
	marker  []byte
	tail    []byte
	prompts int
}

func (w *ptyPromptOutput) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	n, err := w.Writer.Write(p)
	window := append(w.tail, p[:n]...)
	w.prompts += bytes.Count(window, w.marker)
	keep := min(len(window), len(w.marker)-1)
	w.tail = append(w.tail[:0], window[len(window)-keep:]...)
	return n, err
}

func (w *ptyPromptOutput) generation() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.prompts
}

func TestPTYShellPromptGenerationsRejectEchoAndStalePrompt(t *testing.T) {
	const word = "warden-fixture-prompt-127.0.0.1:12345"
	marker := "\x1e" + word + "\x1f"
	var out bytes.Buffer
	w := &ptyPromptOutput{Writer: &out, marker: []byte(marker)}
	var want strings.Builder
	write := func(p string) {
		t.Helper()
		want.WriteString(p)
		if _, err := w.Write([]byte(p)); err != nil {
			t.Fatal(err)
		}
	}
	write("PS1=\"$(printf '\\036" + word + "\\037')\"; printf '\\036" + ptyReadyWord + "\\037\\n'\r\n")
	write("\x1e" + ptyReadyWord + "\x1f\r\n$ ")
	if got := w.generation(); got != 0 {
		t.Fatalf("bootstrap/command echo counted as %d shell prompts", got)
	}
	write(marker[:5])
	if w.generation() != 0 {
		t.Fatal("partial initial prompt accepted")
	}
	write(marker[5:])
	initial := w.generation()
	if initial != 1 {
		t.Fatalf("initial generation=%d, want 1", initial)
	}
	write("^C\r\n$ \x1e" + ptyReadyWord + "\x1f")
	write("\x1ewarden-fixture-prompt-other\x1f")
	write(marker[:len(marker)-1])
	if w.generation() > initial {
		t.Fatal("stale initial prompt, Ctrl-C echo, bootstrap, other fixture or partial prompt acknowledged SIGINT")
	}
	write(marker[len(marker)-1:])
	if got := w.generation(); got != initial+1 {
		t.Fatalf("post-SIGINT prompt generation=%d, want %d", got, initial+1)
	}
	write("unrelated output")
	if w.generation() != initial+1 {
		t.Fatal("retained tail recounted a completed prompt")
	}
	write(marker + marker)
	if got := w.generation(); got != initial+3 {
		t.Fatalf("coalesced prompt generation=%d, want %d", got, initial+3)
	}
	if out.String() != want.String() {
		t.Fatal("prompt observation changed shell output")
	}
}

type ptySequenceWriter struct{ events chan<- string }

func (w ptySequenceWriter) Write(p []byte) (int, error) {
	w.events <- fmt.Sprintf("input:%x", p)
	return len(p), nil
}

func TestInteractiveCtrlCSequenceWaitsForShellAcknowledgment(t *testing.T) {
	events := make(chan string, 8)
	allowAck := make(chan struct{})
	var release sync.Once
	defer release.Do(func() { close(allowAck) })
	done := make(chan error, 1)
	defer func() {
		release.Do(func() { close(allowAck) })
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("input sequence did not join during cleanup")
		}
	}()
	go func() {
		defer close(done)
		done <- sendInteractiveInterruptThenEOF(ptySequenceWriter{events}, func() {
			events <- "delivered"
		}, func() {
			events <- "awaiting-shell-ack"
			<-allowAck
		})
	}()
	for _, want := range []string{"input:03", "delivered", "awaiting-shell-ack"} {
		select {
		case got := <-events:
			if got != want {
				t.Errorf("sequence event=%q, want %q; EOT must wait while shell acknowledgment is held", got, want)
			}
		case <-time.After(time.Second):
			t.Fatal("input sequence made no progress to the held acknowledgment")
		}
	}
	select {
	case got := <-events:
		t.Errorf("early event while acknowledgment held: %q", got)
	default:
	}
	release.Do(func() { close(allowAck) })
	if !t.Failed() {
		select {
		case got := <-events:
			if got != "input:04" {
				t.Errorf("after acknowledgment event=%q, want one EOT", got)
			}
		case <-time.After(time.Second):
			t.Error("acknowledgment did not release EOT")
		}
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("input sequence did not join")
	}
	if len(events) != 0 {
		t.Fatalf("extra input events=%d; want exactly one Ctrl-C and one EOT", len(events))
	}
}

func (s *interactiveTestServer) wrotePTYByte(b byte) bool {
	s.mu.Lock()
	traces := append([]*ptyFixtureTrace(nil), s.traces...)
	s.mu.Unlock()
	for _, p := range traces {
		p.mu.Lock()
		found := bytes.Contains(p.masterInput, []byte{b})
		p.mu.Unlock()
		if found {
			return true
		}
	}
	return false
}

func TestInteractiveFixtureReadyRequiresInitializedForegroundShell(t *testing.T) {
	entered, allow := make(chan struct{}), make(chan struct{})
	var release sync.Once
	defer release.Do(func() { close(allow) })
	srv := newInteractiveTestServerWithStartup(t, func() { close(entered); <-allow })
	inR, inW := io.Pipe()
	t.Cleanup(func() { inR.Close() })
	_, done := startInteractive(t, srv, inR, &lockedBuffer{}, io.Discard)
	waitLifecycle(t, entered, "controlled child startup barrier")
	if srv.started() {
		t.Error("fixture reported ready while child startup was still blocked")
	}
	release.Do(func() { close(allow) })
	waitFor(t, "initialized foreground shell", srv.started)
	if _, err := inW.Write([]byte{0x04}); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-*done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("ready shell did not terminate on Ctrl-D\n%s\n%s", srv.diagnostics(), allPTYStacks())
	}
}

func TestInteractiveFixtureCanceledStartupCannotRetainLateChild(t *testing.T) {
	entered, allow := make(chan struct{}), make(chan struct{})
	var release sync.Once
	defer release.Do(func() { close(allow) })
	srv := newInteractiveTestServerWithStartup(t, func() { close(entered); <-allow })
	inR, _ := io.Pipe()
	t.Cleanup(func() { inR.Close() })
	_, done := startInteractive(t, srv, inR, &lockedBuffer{}, io.Discard)
	waitLifecycle(t, entered, "child startup barrier")
	srv.cancelShells()
	release.Do(func() { close(allow) })
	select {
	case err := <-*done:
		if err == nil {
			t.Error("canceled fixture startup succeeded")
		}
	case <-time.After(100 * time.Millisecond):
		t.Errorf("canceled fixture retained a late child\n%s", srv.diagnostics())
		srv.mu.Lock()
		traces := append([]*ptyFixtureTrace(nil), srv.traces...)
		srv.mu.Unlock()
		for _, p := range traces {
			p.forceClose()
		}
		select {
		case <-*done:
		case <-time.After(time.Second):
			t.Fatalf("forced late-child cleanup did not finish\n%s", allPTYStacks())
		}
	}
	srv.mu.Lock()
	traces := append([]*ptyFixtureTrace(nil), srv.traces...)
	srv.mu.Unlock()
	for _, p := range traces {
		waitLifecycle(t, p.done, "canceled PTY fixture")
		if p.child != nil {
			t.Error("canceled startup published a child process")
		}
		if p.copies.Load() != 0 {
			t.Error("canceled startup retained copy workers")
		}
	}
	waitLifecycle(t, srv.finished, "canceled fixture SSH handler")
}

func TestInteractiveFixtureClosesPTYAndJoinsAfterChildExit(t *testing.T) {
	srv := newInteractiveTestServer(t)
	inR, inW := io.Pipe()
	t.Cleanup(func() { inR.Close() })
	_, done := startInteractive(t, srv, inR, &lockedBuffer{}, io.Discard)
	waitFor(t, "initialized foreground shell", srv.started)
	if _, err := inW.Write([]byte("exit 0\n")); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-*done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatalf("client did not exit\n%s\n%s", srv.diagnostics(), allPTYStacks())
	}
	assertPTYFixtureJoined(t, srv)
}

func assertPTYFixtureJoined(t *testing.T, srv *interactiveTestServer) {
	t.Helper()
	srv.mu.Lock()
	traces := append([]*ptyFixtureTrace(nil), srv.traces...)
	srv.mu.Unlock()
	if len(traces) != 1 {
		t.Fatalf("sessions=%d", len(traces))
	}
	p := traces[0]
	select {
	case <-p.done:
	case <-time.After(100 * time.Millisecond):
		t.Errorf("PTY endpoints/workers retained after child and client exit\n%s", p.snapshot())
		p.forceClose()
		select {
		case <-p.done:
		case <-time.After(time.Second):
			t.Fatalf("forced cleanup did not join\n%s", allPTYStacks())
		}
	}
	if p.copies.Load() != 0 {
		t.Errorf("PTY copies=%d", p.copies.Load())
	}
	for name, f := range map[string]*os.File{"master": p.master, "slave": p.slave} {
		if f == nil {
			t.Fatalf("missing %s", name)
		}
		if _, err := f.Stat(); !errors.Is(err, os.ErrClosed) {
			t.Errorf("%s Stat=%v; want closed file", name, err)
		}
	}
	select {
	case <-srv.finished:
	case <-time.After(time.Second):
		t.Fatalf("SSH fixture handler did not join\n%s\n%s", srv.diagnostics(), allPTYStacks())
	}
	t.Logf("before forced cleanup: files closed, copies and SSH handler joined\n%s", p.snapshot())
}
