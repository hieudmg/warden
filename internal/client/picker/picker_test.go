package picker

import (
	"bytes"
	"io"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"warden/internal/model"
)

func TestStateFiltersNameAndHostCaseInsensitively(t *testing.T) {
	conns := []model.SSHConnection{
		{ID: 1, Name: "prod-web", Host: "10.0.0.1"},
		{ID: 2, Name: "bastion", Host: "edge.example.test"},
	}
	state := NewState(conns)
	state = state.Apply(DecodedKey{Kind: KeyRune, Rune: 'E'})
	state = state.Apply(DecodedKey{Kind: KeyRune, Rune: 'D'})
	state = state.Apply(DecodedKey{Kind: KeyRune, Rune: 'G'})
	if got := state.Filtered(); len(got) != 1 || got[0].ID != 2 {
		t.Fatalf("Filtered() = %#v, want bastion", got)
	}
}

func TestStateNavigationAndQueryReset(t *testing.T) {
	state := NewState([]model.SSHConnection{{ID: 1, Name: "alpha"}, {ID: 2, Name: "beta"}})
	state = state.Apply(DecodedKey{Kind: KeyDown})
	selected, ok := state.Selected()
	if !ok || selected.ID != 2 {
		t.Fatalf("selected = %#v, %t; want beta, true", selected, ok)
	}
	state = state.Apply(DecodedKey{Kind: KeyRune, Rune: 'a'})
	state = state.Apply(DecodedKey{Kind: KeyBackspace})
	selected, ok = state.Selected()
	if !ok || selected.ID != 1 {
		t.Fatalf("selection after filter reset = %#v, %t; want alpha, true", selected, ok)
	}
}

func TestNewStateCopiesCallerOwnedSource(t *testing.T) {
	conns := []model.SSHConnection{{ID: 1, Name: "prod-web", Host: "10.0.0.1"}}
	state := NewState(conns)
	conns[0] = model.SSHConnection{ID: 9, Name: "renamed", Host: "9.9.9.9"}
	state = state.Apply(DecodedKey{Kind: KeyRune, Rune: 'p'})
	if got := state.Filtered(); len(got) != 1 || got[0].ID != 1 {
		t.Fatalf("Filtered() after caller mutation = %#v, want original conn ID 1", got)
	}
	selected, ok := state.Selected()
	if !ok || selected.ID != 1 {
		t.Fatalf("Selected() after caller mutation = %#v, %t; want original conn ID 1", selected, ok)
	}
}

func TestDecodeBytesRecognizesNavigationAndCancel(t *testing.T) {
	got := DecodeBytes([]byte("a\x7f\x1b[A\x1b[B\r\x03\x1b"))
	want := []DecodedKey{
		{Kind: KeyRune, Rune: 'a'}, {Kind: KeyBackspace}, {Kind: KeyUp},
		{Kind: KeyDown}, {Kind: KeyEnter}, {Kind: KeyCancel}, {Kind: KeyCancel},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("DecodeBytes() = %#v, want %#v", got, want)
	}
}

func TestStreamDecoderBuffersPartialArrow(t *testing.T) {
	var d StreamDecoder
	if got := d.Feed([]byte("\x1b[")); len(got) != 0 {
		t.Fatalf("Feed(\"\\x1b[\") = %#v, want no keys yet", got)
	}
	if got := d.Feed([]byte("A")); len(got) != 1 || got[0].Kind != KeyUp {
		t.Fatalf("Feed(\"A\") = %#v, want KeyUp", got)
	}
}

// lockedBuffer is a mutex-protected output buffer so the resize goroutine
// and the Select caller can write concurrently without racing the test's
// assertions.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func (l *lockedBuffer) Count(sub string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Count(l.b.String(), sub)
}

// fakeSession implements terminal.Session for picker interaction tests:
// a bytes.Reader (or pipe) input, a locked output buffer, fixed size,
// a resize channel, an ANSI capability flag, and raw/restore counters.
type fakeSession struct {
	input         io.Reader
	output        *lockedBuffer
	width, height int
	resize        chan struct{}
	ansi          bool
	rawCalls      int
	restoreCalls  int
}

func newFakeSession(input string, width, height int, ansi bool) *fakeSession {
	return &fakeSession{
		input:  bytes.NewReader([]byte(input)),
		output: &lockedBuffer{},
		width:  width,
		height: height,
		resize: make(chan struct{}),
		ansi:   ansi,
	}
}

func (f *fakeSession) EnterRaw() error               { f.rawCalls++; return nil }
func (f *fakeSession) Restore() error                { f.restoreCalls++; return nil }
func (f *fakeSession) Size() (int, int)              { return f.width, f.height }
func (f *fakeSession) ResizeEvents() <-chan struct{} { return f.resize }
func (f *fakeSession) Stdin() io.Reader              { return f.input }
func (f *fakeSession) Stdout() io.Writer             { return f.output }
func (f *fakeSession) Stderr() io.Writer             { return io.Discard }
func (f *fakeSession) SupportsANSI() bool            { return f.ansi }

// fieldsText joins each field's label and value for preview assertions.
func fieldsText(fields []Field) string {
	var b strings.Builder
	for _, f := range fields {
		b.WriteString(f.Label)
		b.WriteString(": ")
		b.WriteString(f.Value)
		b.WriteString("\n")
	}
	return b.String()
}

func TestFormatConnectionRedactsSecretsAndShowsAllFields(t *testing.T) {
	c := model.SSHConnection{
		ID: 7, Name: "prod", Host: "db.example.test", Port: 2222, Username: "deploy",
		HasPassword: true, HasPrivateKey: false, HasPrivateKeyPassphrase: true,
		ProxyHost: "proxy.example.test", ProxyPort: 8080, ProxyUsername: "proxy-user",
		HasProxyPassword: true, JumpConnectionIDs: "[1,2]", DefaultDir: "/srv/app",
	}
	output := fieldsText(FormatConnection(c))
	for _, want := range []string{"ID", "prod", "Host", "db.example.test", "Password", "[configured]", "Private key", "[not configured]", "Proxy password", "Jump connection IDs", "Default directory"} {
		if !strings.Contains(output, want) {
			t.Fatalf("preview missing %q: %q", want, output)
		}
	}
}

func TestRenderUsesWideAndStackedLayouts(t *testing.T) {
	state := NewState([]model.SSHConnection{{ID: 1, Name: "prod", Host: "host"}})
	var wide, narrow bytes.Buffer
	Render(&wide, state, 100, 20)
	Render(&narrow, state, 79, 20)
	if !strings.Contains(wide.String(), "│") {
		t.Fatalf("wide render lacks column separator: %q", wide.String())
	}
	if strings.Contains(narrow.String(), "│") {
		t.Fatalf("narrow render has column separator: %q", narrow.String())
	}
	if !strings.Contains(wide.String(), "\x1b[") {
		t.Fatalf("wide render lacks ANSI color: %q", wide.String())
	}
}

func TestRenderNarrowLayoutStaysWithinViewport(t *testing.T) {
	state := NewState([]model.SSHConnection{{ID: 1, Name: "prod"}, {ID: 2, Name: "staging"}})
	for _, height := range []int{3, 4, 6, 8} {
		var out bytes.Buffer
		Render(&out, state, 79, height)
		if rows := strings.Count(out.String(), "\r\n"); rows > height {
			t.Fatalf("height %d: render emitted %d rows, exceeds viewport: %q", height, rows, out.String())
		}
	}
}

func TestRenderNarrowLayoutKeepsListAndPreviewVisible(t *testing.T) {
	state := NewState([]model.SSHConnection{{ID: 1, Name: "prod"}, {ID: 2, Name: "staging"}})
	var out bytes.Buffer
	Render(&out, state, 79, 6)
	s := out.String()
	for _, want := range []string{"Search: ", "prod", "staging", "ID", ": 1"} {
		if !strings.Contains(s, want) {
			t.Fatalf("narrow render missing %q: %q", want, s)
		}
	}
}

func TestRenderClampsTitleAndQueryToWidth(t *testing.T) {
	state := NewState([]model.SSHConnection{{ID: 1, Name: "prod"}})
	for _, r := range strings.Repeat("q", 200) {
		state = state.Apply(DecodedKey{Kind: KeyRune, Rune: r})
	}
	for _, width := range []int{20, 100} {
		var out bytes.Buffer
		Render(&out, state, width, 20)
		for i, line := range strings.Split(strings.TrimSuffix(out.String(), "\r\n"), "\r\n") {
			if n := visibleLength(line); n > width {
				t.Fatalf("width %d: line %d has %d visible runes, would wrap: %q", width, i, n, line)
			}
		}
		if !strings.Contains(out.String(), "Search: ") || !strings.Contains(out.String(), "qqq") {
			t.Fatalf("width %d: clamped render lost the query prompt: %q", width, out.String())
		}
		if width == 20 && strings.Contains(out.String(), "pick a connection") {
			t.Fatalf("width 20: full title not clamped: %q", out.String())
		}
	}
}

func TestRenderFinalRowHasNoTrailingNewline(t *testing.T) {
	state := NewState([]model.SSHConnection{
		{ID: 1, Name: "prod", Host: "db.example.test"},
		{ID: 2, Name: "staging", Host: "stage.example.test"},
	})
	for _, tc := range []struct {
		width, height int
	}{
		{100, 24}, // wide layout, rows fill the viewport
		{79, 24},  // narrow layout, rows fill the viewport
		{100, 2},  // wide layout, headers only
		{79, 4},   // narrow layout, minimal body
	} {
		var out bytes.Buffer
		Render(&out, state, tc.width, tc.height)
		s := out.String()
		if rows := strings.Count(s, "\r\n"); rows != tc.height-1 {
			t.Fatalf("width %d height %d: emitted %d CRLF-separated rows, want exactly %d rows filling the viewport: %q", tc.width, tc.height, rows+1, tc.height, s)
		}
		if strings.HasSuffix(s, "\r\n") {
			t.Fatalf("width %d height %d: render ends with CRLF after the final viewport row; that trailing newline would scroll the alternate screen: %q", tc.width, tc.height, s)
		}
	}
}

// visibleLength counts the visible runes in a rendered line, ignoring
// ANSI escape sequences.
func visibleLength(line string) int {
	n := 0
	for i := 0; i < len(line); {
		if line[i] == 0x1b {
			i++
			for i < len(line) && line[i] != 'm' {
				i++
			}
			i++
			continue
		}
		_, size := utf8.DecodeRuneInString(line[i:])
		n++
		i += size
	}
	return n
}

func TestSelectRestoresTerminalAndReturnsHighlightedConnection(t *testing.T) {
	session := newFakeSession("\x1b[B\r", 100, 24, true)
	got, err := Select(session, []model.SSHConnection{{ID: 1, Name: "one"}, {ID: 2, Name: "two"}})
	if err != nil || got.ID != 2 {
		t.Fatalf("Select() = %#v, %v; want ID 2, nil", got, err)
	}
	if session.rawCalls != 1 || session.restoreCalls != 1 {
		t.Fatalf("raw/restore = %d/%d, want 1/1", session.rawCalls, session.restoreCalls)
	}
	if !strings.Contains(session.output.String(), "\x1b[?1049h") || !strings.Contains(session.output.String(), "\x1b[?1049l") {
		t.Fatal("alternate screen was not entered and restored")
	}
}

func TestSelectRejectsEmptyListBeforeRawMode(t *testing.T) {
	session := newFakeSession("", 100, 24, true)
	_, err := Select(session, nil)
	if err == nil || !strings.Contains(err.Error(), "no ssh connections configured") {
		t.Fatalf("Select() err = %v, want 'no ssh connections configured'", err)
	}
	if session.rawCalls != 0 {
		t.Fatalf("EnterRaw called %d times for empty list, want 0", session.rawCalls)
	}
}

func TestSelectCtrlCCancelsAndRestores(t *testing.T) {
	session := newFakeSession("\x03", 100, 24, true)
	_, err := Select(session, []model.SSHConnection{{ID: 1, Name: "one"}})
	if err == nil || !strings.Contains(err.Error(), "selection aborted") {
		t.Fatalf("Select() err = %v, want 'selection aborted'", err)
	}
	if session.rawCalls != 1 || session.restoreCalls != 1 {
		t.Fatalf("raw/restore = %d/%d, want 1/1", session.rawCalls, session.restoreCalls)
	}
}

func TestSelectBareESCCancels(t *testing.T) {
	session := newFakeSession("\x1b", 100, 24, true)
	_, err := Select(session, []model.SSHConnection{{ID: 1, Name: "one"}})
	if err == nil || !strings.Contains(err.Error(), "selection aborted") {
		t.Fatalf("Select() err = %v, want 'selection aborted'", err)
	}
	if session.restoreCalls != 1 {
		t.Fatalf("Restore called %d times, want 1", session.restoreCalls)
	}
}

func TestSelectRejectsANSIIncapableTerminal(t *testing.T) {
	session := newFakeSession("", 100, 24, false)
	_, err := Select(session, []model.SSHConnection{{ID: 1, Name: "one"}})
	if err == nil || !strings.Contains(err.Error(), "does not support ANSI") {
		t.Fatalf("Select() err = %v, want 'does not support ANSI'", err)
	}
	if session.restoreCalls != 1 {
		t.Fatalf("Restore called %d times, want 1", session.restoreCalls)
	}
}

func TestSanitizeEscapesControlCharacters(t *testing.T) {
	got := sanitize("a\x1b[31mred\r\n\tb")
	want := `a\x1b[31mred\r\n\tb`
	if got != want {
		t.Fatalf("sanitize() = %q, want %q", got, want)
	}
}

func TestSelectRedrawsOnResize(t *testing.T) {
	pr, pw := io.Pipe()
	session := &fakeSession{
		input:  pr,
		output: &lockedBuffer{},
		width:  100,
		height: 24,
		resize: make(chan struct{}),
		ansi:   true,
	}
	done := make(chan struct{})
	var got model.SSHConnection
	var err error
	go func() {
		got, err = Select(session, []model.SSHConnection{{ID: 1, Name: "one"}, {ID: 2, Name: "two"}})
		close(done)
	}()
	waitFor(t, func() bool { return session.output.Count("\x1b[2J") >= 1 })
	before := session.output.Count("\x1b[2J")
	session.resize <- struct{}{}
	waitFor(t, func() bool { return session.output.Count("\x1b[2J") > before })
	if _, err := pw.Write([]byte("\r")); err != nil {
		t.Fatalf("write enter: %v", err)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Select did not return after Enter")
	}
	if err != nil || got.ID != 1 {
		t.Fatalf("Select() = %#v, %v; want ID 1, nil", got, err)
	}
	if session.rawCalls != 1 || session.restoreCalls != 1 {
		t.Fatalf("raw/restore = %d/%d, want 1/1", session.rawCalls, session.restoreCalls)
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not met within 5s")
}
