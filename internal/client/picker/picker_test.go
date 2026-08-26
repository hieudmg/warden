package picker

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"warden/internal/model"
)

func TestStateFiltersNameHostAndGroupCaseInsensitively(t *testing.T) {
	conns := []model.SSHConnection{
		{ID: 1, Name: "web-front", Host: "10.0.0.1"},
		{ID: 2, Name: "bastion", Host: "edge.example.test"},
		{ID: 3, Name: "storefront", Host: "10.0.0.2", GroupName: "Production"},
	}
	state := NewState(conns)
	state = state.Apply(DecodedKey{Kind: KeyRune, Rune: 'E'})
	state = state.Apply(DecodedKey{Kind: KeyRune, Rune: 'D'})
	state = state.Apply(DecodedKey{Kind: KeyRune, Rune: 'G'})
	if got := state.Filtered(); len(got) != 1 || got[0].ID != 2 {
		t.Fatalf("Filtered() = %#v, want bastion", got)
	}

	// A query also matches a connection's group name, case-insensitively:
	// "prod" finds only the storefront via its group, not by name or host.
	groupState := NewState(conns)
	for _, r := range []rune{'p', 'r', 'o', 'd'} {
		groupState = groupState.Apply(DecodedKey{Kind: KeyRune, Rune: r})
	}
	if got := groupState.Filtered(); len(got) != 1 || got[0].ID != 3 {
		t.Fatalf("Filtered() = %#v, want storefront (group match)", got)
	}
}

func TestStateSortsByGroupThenConnectionName(t *testing.T) {
	state := NewState([]model.SSHConnection{
		{ID: 1, Name: "zulu", Host: "host-a", GroupName: "Group B"},
		{ID: 2, Name: "bravo", Host: "host-z", GroupName: "Group A"},
		{ID: 3, Name: "alpha", Host: "host-z", GroupName: "Group A"},
		{ID: 4, Name: "alpha", Host: "host-a", GroupName: "Group B"},
		{ID: 5, Name: "first", Host: "host-q"},
	})

	got := state.Filtered()
	wantIDs := []int64{3, 2, 4, 1, 5}
	if len(got) != len(wantIDs) {
		t.Fatalf("Filtered() returned %d connections, want %d", len(got), len(wantIDs))
	}
	for i, wantID := range wantIDs {
		if got[i].ID != wantID {
			t.Fatalf("Filtered()[%d].ID = %d, want %d", i, got[i].ID, wantID)
		}
	}
}

func TestRenderGroupsRowsAndSkipsGroupHighlight(t *testing.T) {
	state := NewState([]model.SSHConnection{
		{ID: 1, Name: "zulu", GroupName: "Group B"},
		{ID: 2, Name: "bravo", GroupName: "Group A"},
		{ID: 3, Name: "alpha", GroupName: "Group A"},
		{ID: 4, Name: "first"},
	})
	state = state.Apply(DecodedKey{Kind: KeyDown})

	var out bytes.Buffer
	if err := Render(&out, state, 100, 12); err != nil {
		t.Fatalf("Render() error = %v", err)
	}
	s := out.String()
	for _, want := range []string{"Group A", "Group B", "(Ungrouped)", ">   bravo"} {
		if !strings.Contains(s, want) {
			t.Fatalf("render missing %q: %q", want, s)
		}
	}
	if strings.Index(s, "Group A") > strings.Index(s, "Group B") ||
		strings.Index(s, "Group B") > strings.Index(s, "(Ungrouped)") {
		t.Fatalf("group headers are not ordered: %q", s)
	}
	for _, line := range strings.Split(s, "\r\n") {
		if strings.HasPrefix(line, "  Group A") || strings.HasPrefix(line, "  Group B") || strings.HasPrefix(line, "  (Ungrouped)") {
			if strings.Contains(line, ">") {
				t.Fatalf("group header highlighted: %q", line)
			}
		}
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

// outBuffer is the subset of the lockedBuffer surface the picker tests
// inspect: writes are recorded, and the rendered text can be read back.
type outBuffer interface {
	Write(p []byte) (int, error)
	String() string
	Count(sub string) int
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

// failingBuffer fails the failAfter-th write (and every write after it)
// with err, letting tests prove Select propagates terminal failures
// instead of reporting a successful selection.
type failingBuffer struct {
	*lockedBuffer
	failAfter int
	err       error
}

func (f *failingBuffer) Write(p []byte) (int, error) {
	if f.failAfter > 0 {
		f.failAfter--
		if f.failAfter == 0 {
			return 0, f.err
		}
	}
	return f.lockedBuffer.Write(p)
}

// fakeSession implements terminal.Session for picker interaction tests:
// a bytes.Reader (or pipe) input, a locked output buffer, fixed size,
// a resize channel, an ANSI capability flag, and raw/restore counters.
type fakeSession struct {
	input         io.Reader
	output        outBuffer
	width, height int
	resize        chan struct{}
	ansi          bool
	rawCalls      int
	restoreCalls  int
	restoreErr    error
	// stdinReady overrides StdinReadyWithin. When nil, the fake reports
	// stdin always ready, matching its non-blocking in-memory readers;
	// tests that exercise the escape grace timeout inject a blocking
	// reader and a readiness function that reports not ready.
	stdinReady func(time.Duration) (bool, error)
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
func (f *fakeSession) Restore() error                { f.restoreCalls++; return f.restoreErr }
func (f *fakeSession) Size() (int, int)              { return f.width, f.height }
func (f *fakeSession) ResizeEvents() <-chan struct{} { return f.resize }
func (f *fakeSession) Stdin() io.Reader              { return f.input }
func (f *fakeSession) Stdout() io.Writer             { return f.output }
func (f *fakeSession) Stderr() io.Writer             { return io.Discard }
func (f *fakeSession) SupportsANSI() bool            { return f.ansi }

// StdinReadyWithin reports whether stdin has data available within d.
// The fake's default readers never block, so the default reports ready
// immediately; the escape-grace timeout tests inject a custom function.
func (f *fakeSession) StdinReadyWithin(d time.Duration) (bool, error) {
	if f.stdinReady != nil {
		return f.stdinReady(d)
	}
	return true, nil
}

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
		HasPassword: true, KeyPairID: 11, KeyPairName: "deploy-key",
		ProxyHost: "proxy.example.test", ProxyPort: 8080, ProxyUsername: "proxy-user",
		HasProxyPassword: true, JumpConnectionIDs: "[1,2]", DefaultDir: "/srv/app",
		GroupID: 3, GroupName: "prod",
	}
	output := fieldsText(FormatConnection(c))
	for _, want := range []string{"ID", "prod", "Host", "db.example.test", "Password", "[configured]", "Key pair", "deploy-key", "Proxy password", "Jump connection IDs", "Default directory", "Group: prod"} {
		if !strings.Contains(output, want) {
			t.Fatalf("preview missing %q: %q", want, output)
		}
	}
	for _, obsolete := range []string{"Private key", "Private-key passphrase"} {
		if strings.Contains(output, obsolete) {
			t.Fatalf("preview renders obsolete field %q: %q", obsolete, output)
		}
	}
}

func TestFormatConnectionMissingKeyPairReference(t *testing.T) {
	c := model.SSHConnection{ID: 7, KeyPairID: 9}
	output := fieldsText(FormatConnection(c))
	if !strings.Contains(output, "Key pair: Missing key pair #9") {
		t.Fatalf("preview missing dangling key-pair marker: %q", output)
	}
	if strings.Contains(output, "PRIVATE-KEY-MATERIAL") || strings.Contains(output, "PHRASE-MATERIAL") {
		t.Fatalf("preview renders key material: %q", output)
	}
}

func TestFormatConnectionGroupDisplay(t *testing.T) {
	cases := []struct {
		name      string
		c         model.SSHConnection
		wantValue string
	}{
		{"grouped", model.SSHConnection{ID: 7, GroupID: 3, GroupName: "prod"}, "prod"},
		{"missing reference", model.SSHConnection{ID: 8, GroupID: 9}, "Missing group #9"},
		{"ungrouped", model.SSHConnection{ID: 9, GroupID: 0}, "(not set)"},
	}
	for _, tc := range cases {
		output := fieldsText(FormatConnection(tc.c))
		if !strings.Contains(output, "Group: "+tc.wantValue) {
			t.Fatalf("%s: preview missing %q: %q", tc.name, "Group: "+tc.wantValue, output)
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
	Render(&out, state, 79, 8)
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
			if n := visibleWidth(line); n > width {
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

// visibleColumnOf returns the visible-column index (ANSI sequences
// ignored) of the first occurrence of target, or -1.
func visibleColumnOf(line string, target rune) int {
	col := 0
	for i := 0; i < len(line); {
		if line[i] == 0x1b {
			i++
			for i < len(line) && line[i] != 'm' {
				i++
			}
			i++
			continue
		}
		r, size := utf8.DecodeRuneInString(line[i:])
		if r == target {
			return col
		}
		col++
		i += size
	}
	return -1
}

// recallReader serves its data in the requested chunk sizes and records
// how much was consumed, so a test can inspect exactly which bytes the
// picker left behind for the SSH session that follows it.
type recallReader struct {
	data []byte
	pos  int
}

func (r *recallReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}

func (r *recallReader) Remaining() []byte { return r.data[r.pos:] }

// oneByteReader returns exactly one byte per Read call, simulating
// terminal input that delivers an escape sequence one byte at a time.
type oneByteReader struct {
	data []byte
	pos  int
}

func (r *oneByteReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	p[0] = r.data[r.pos]
	r.pos++
	return 1, nil
}

// TestSelectLeavesTypedAheadInputForSSH proves the picker never consumes
// bytes past the confirming Enter: a keystroke burst delivered in one
// chunk (as a terminal paste or type-ahead would be) must leave the
// trailing bytes readable for the SSH session that follows Select, not
// swallowed in a picker-side read buffer.
func TestSelectLeavesTypedAheadInputForSSH(t *testing.T) {
	in := &recallReader{data: []byte("a\rb")}
	session := &fakeSession{
		input:  in,
		output: &lockedBuffer{},
		width:  100,
		height: 24,
		resize: make(chan struct{}),
		ansi:   true,
	}
	got, err := Select(session, []model.SSHConnection{{ID: 1, Name: "alpha"}})
	if err != nil || got.ID != 1 {
		t.Fatalf("Select() = %#v, %v; want ID 1, nil", got, err)
	}
	if rem := in.Remaining(); string(rem) != "b" {
		t.Fatalf("bytes left for the SSH session after Enter = %q, want \"b\": the picker must not buffer keystrokes typed beyond Enter", rem)
	}
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

// TestSelectDecodesSplitArrowSequence proves a raw arrow sequence split
// across reads (ESC, then [, then B) still navigates instead of
// canceling: the pending ESC must never be flushed just because the
// continuation byte has not arrived yet.
func TestSelectDecodesSplitArrowSequence(t *testing.T) {
	session := &fakeSession{
		input:  &oneByteReader{data: []byte("\x1b[B\r")},
		output: &lockedBuffer{},
		width:  100,
		height: 24,
		resize: make(chan struct{}),
		ansi:   true,
	}
	got, err := Select(session, []model.SSHConnection{{ID: 1, Name: "one"}, {ID: 2, Name: "two"}})
	if err != nil || got.ID != 2 {
		t.Fatalf("Select() = %#v, %v; want ID 2, nil", got, err)
	}
	if session.restoreCalls != 1 {
		t.Fatalf("Restore called %d times, want 1", session.restoreCalls)
	}
}

// TestSelectDecodesSplitUpArrow is the Up variant of the split-sequence
// regression: ESC, [, A arriving one byte at a time must select the first
// connection on Enter, never cancel.
func TestSelectDecodesSplitUpArrow(t *testing.T) {
	session := &fakeSession{
		input:  &oneByteReader{data: []byte("\x1b[A\r")},
		output: &lockedBuffer{},
		width:  100,
		height: 24,
		resize: make(chan struct{}),
		ansi:   true,
	}
	got, err := Select(session, []model.SSHConnection{{ID: 1, Name: "one"}, {ID: 2, Name: "two"}})
	if err != nil || got.ID != 1 {
		t.Fatalf("Select() = %#v, %v; want ID 1, nil", got, err)
	}
}

// TestSelectBareESCSplitFromArrow: a lone ESC followed by a non-arrow byte
// (here the Enter after a split) must cancel rather than feed the byte
// into the query.
func TestSelectBareESCBeforeEnterCancels(t *testing.T) {
	session := &fakeSession{
		input:  &oneByteReader{data: []byte("\x1b\r")},
		output: &lockedBuffer{},
		width:  100,
		height: 24,
		resize: make(chan struct{}),
		ansi:   true,
	}
	_, err := Select(session, []model.SSHConnection{{ID: 1, Name: "one"}})
	if err == nil || !strings.Contains(err.Error(), "selection aborted") {
		t.Fatalf("Select() err = %v, want 'selection aborted'", err)
	}
}

// TestSelectBareESCTimeoutLeavesNoReaderGoroutine proves the bounded
// escape wait cannot strand a stdin reader: when the grace elapses with
// no continuation byte, the bare ESC cancels and no goroutine remains
// blocked on stdin to consume input meant for the subsequent SSH session.
// The input is a pipe that delivers ESC and then stays silent, so any
// background reader spawned by the wait would stay blocked forever and
// keep the goroutine count elevated.
func TestSelectBareESCTimeoutLeavesNoReaderGoroutine(t *testing.T) {
	pr, pw := io.Pipe()
	session := &fakeSession{
		input:  pr,
		output: &lockedBuffer{},
		width:  100,
		height: 24,
		resize: make(chan struct{}),
		ansi:   true,
		stdinReady: func(time.Duration) (bool, error) {
			return false, nil // the grace elapses with no continuation
		},
	}

	before := runtime.NumGoroutine()
	done := make(chan struct{})
	var err error
	go func() {
		_, err = Select(session, []model.SSHConnection{{ID: 1, Name: "one"}})
		close(done)
	}()
	waitFor(t, func() bool { return session.output.Count("\x1b[2J") >= 1 })
	if _, err := pw.Write([]byte{0x1b}); err != nil {
		t.Fatalf("write esc: %v", err)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Select did not return after bare ESC timeout")
	}
	if err == nil || !strings.Contains(err.Error(), "selection aborted") {
		t.Fatalf("Select() err = %v, want 'selection aborted'", err)
	}
	if session.restoreCalls != 1 {
		t.Fatalf("Restore called %d times, want 1", session.restoreCalls)
	}
	deadline := time.Now().Add(2 * time.Second)
	for runtime.NumGoroutine() > before && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if runtime.NumGoroutine() > before {
		t.Fatalf("Select left %d goroutines behind (baseline %d): the ESC wait must not strand a stdin reader", runtime.NumGoroutine(), before)
	}
}

func TestDecodeBytesRecognizesTab(t *testing.T) {
	got := DecodeBytes([]byte("\t"))
	want := []DecodedKey{{Kind: KeyTab}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("DecodeBytes() = %#v, want %#v", got, want)
	}
}

func TestStateTabFocusTogglesAndArrowsMoveDetail(t *testing.T) {
	state := NewState([]model.SSHConnection{{ID: 1, Name: "alpha"}, {ID: 2, Name: "beta"}, {ID: 3, Name: "gamma"}})
	state = state.Apply(DecodedKey{Kind: KeyDown})
	selected, ok := state.Selected()
	if !ok || selected.ID != 2 {
		t.Fatalf("selected = %#v, %t; want beta, true", selected, ok)
	}
	state = state.Apply(DecodedKey{Kind: KeyTab}) // focus the detail pane
	state = state.Apply(DecodedKey{Kind: KeyDown})
	selected, ok = state.Selected()
	if !ok || selected.ID != 2 {
		t.Fatalf("selection moved while detail focused: %#v, %t; want beta", selected, ok)
	}
	if state.detailOffset != 1 {
		t.Fatalf("detailOffset = %d, want 1", state.detailOffset)
	}
	state = state.Apply(DecodedKey{Kind: KeyTab}) // focus the list again
	state = state.Apply(DecodedKey{Kind: KeyDown})
	selected, ok = state.Selected()
	if !ok || selected.ID != 3 {
		t.Fatalf("selected = %#v, %t; want gamma, true", selected, ok)
	}
}

// TestRenderWideSeparatorPosition proves every body row of the wide layout
// pads to leftWidth visible columns so the │ separator always sits at the
// leftWidth column, even for short or empty rows.
func TestRenderWideSeparatorPosition(t *testing.T) {
	state := NewState([]model.SSHConnection{
		{ID: 1, Name: "prod"}, {ID: 2, Name: "a very long connection profile name here"},
	})
	var out bytes.Buffer
	Render(&out, state, 100, 20)
	leftWidth := 100 * 45 / 100
	lines := strings.Split(strings.TrimSuffix(out.String(), "\r\n"), "\r\n")
	if len(lines) != 20 {
		t.Fatalf("render emitted %d rows, want 20", len(lines))
	}
	// Body rows run from the search prompt down to, but excluding, the
	// final focus-hint row.
	for i := 2; i < len(lines)-1; i++ {
		if col := visibleColumnOf(lines[i], '│'); col != leftWidth {
			t.Fatalf("body row %d: separator at visible column %d, want %d: %q", i, col, leftWidth, lines[i])
		}
	}
}

// TestRenderShowsFocusedPaneHint proves the picker UI exposes the Tab
// control: the bottom hint names the pane that currently owns Up/Down and
// changes when Tab toggles focus, in both the wide and narrow layouts.
func TestRenderShowsFocusedPaneHint(t *testing.T) {
	state := NewState([]model.SSHConnection{{ID: 1, Name: "prod", Host: "db"}})
	for _, tc := range []struct{ width, height int }{
		{100, 10}, // wide layout
		{79, 10},  // narrow layout
	} {
		var listFocused bytes.Buffer
		Render(&listFocused, state, tc.width, tc.height)
		if !strings.Contains(listFocused.String(), "list focused") {
			t.Fatalf("width %d: list-focus render lacks the focus hint: %q", tc.width, listFocused.String())
		}
		if strings.Contains(listFocused.String(), "detail focused") {
			t.Fatalf("width %d: list-focus render claims detail focus: %q", tc.width, listFocused.String())
		}
		state = state.Apply(DecodedKey{Kind: KeyTab})
		var detailFocused bytes.Buffer
		Render(&detailFocused, state, tc.width, tc.height)
		if !strings.Contains(detailFocused.String(), "detail focused") {
			t.Fatalf("width %d: detail-focus render lacks the focus hint: %q", tc.width, detailFocused.String())
		}
		if strings.Contains(detailFocused.String(), "list focused") {
			t.Fatalf("width %d: detail-focus render claims list focus: %q", tc.width, detailFocused.String())
		}
		state = state.Apply(DecodedKey{Kind: KeyTab}) // back to list for the next case
	}
}

// TestRenderNarrowListScrollsToSelected proves a selection past the
// visible window scrolls the list so the selected row is always on screen.
func TestRenderNarrowListScrollsToSelected(t *testing.T) {
	conns := make([]model.SSHConnection, 20)
	for i := range conns {
		conns[i] = model.SSHConnection{ID: int64(i + 1), Name: fmt.Sprintf("conn-%02d", i+1)}
	}
	state := NewState(conns)
	for i := 0; i < 19; i++ {
		state = state.Apply(DecodedKey{Kind: KeyDown})
	}
	var out bytes.Buffer
	Render(&out, state, 79, 8)
	s := out.String()
	if !strings.Contains(s, ">   conn-20") {
		t.Fatalf("selected row off screen: %q", s)
	}
	if strings.Contains(s, "conn-01") {
		t.Fatalf("list window did not scroll past the top: %q", s)
	}
}

// TestRenderDetailPagingReachesAllFields proves the wide detail viewport
// pages through every field of the selected connection.
func TestRenderDetailPagingReachesAllFields(t *testing.T) {
	state := NewState([]model.SSHConnection{{ID: 1, Name: "prod", Host: "db.example.test"}})
	var first bytes.Buffer
	Render(&first, state, 100, 8)
	if !strings.Contains(first.String(), "ID") {
		t.Fatalf("wide render missing first field: %q", first.String())
	}
	state = state.Apply(DecodedKey{Kind: KeyTab})
	for i := 0; i < 20; i++ {
		state = state.Apply(DecodedKey{Kind: KeyDown})
	}
	var out bytes.Buffer
	Render(&out, state, 100, 8)
	if !strings.Contains(out.String(), "Updated at") {
		t.Fatalf("wide render cannot reach the last field: %q", out.String())
	}
	if !strings.Contains(out.String(), "(not set)") {
		t.Fatalf("wide render lost the timestamp marker: %q", out.String())
	}
}

// TestRenderNarrowDetailPagingReachesAllFields proves the stacked layout
// also pages through every field of the selected connection.
func TestRenderNarrowDetailPagingReachesAllFields(t *testing.T) {
	state := NewState([]model.SSHConnection{{ID: 1, Name: "prod", Host: "db"}})
	state = state.Apply(DecodedKey{Kind: KeyTab})
	for i := 0; i < 20; i++ {
		state = state.Apply(DecodedKey{Kind: KeyDown})
	}
	var out bytes.Buffer
	Render(&out, state, 79, 8)
	if !strings.Contains(out.String(), "Updated at") {
		t.Fatalf("narrow render detail not paged to the last field: %q", out.String())
	}
}

// TestSelectReturnsRenderErrorOnFailingWriter proves a broken output
// stream during the initial render is propagated instead of returning a
// successful selection.
func TestSelectReturnsRenderErrorOnFailingWriter(t *testing.T) {
	session := &fakeSession{
		input:  bytes.NewReader([]byte("\r")),
		output: &failingBuffer{lockedBuffer: &lockedBuffer{}, failAfter: 2, err: errors.New("disk full")},
		width:  100,
		height: 24,
		resize: make(chan struct{}),
		ansi:   true,
	}
	got, err := Select(session, []model.SSHConnection{{ID: 1, Name: "one"}})
	if err == nil || !strings.Contains(err.Error(), "render picker") {
		t.Fatalf("Select() err = %v, want render failure", err)
	}
	if got.ID != 0 {
		t.Fatalf("Select() returned a selection %#v despite render failure", got)
	}
	if session.restoreCalls != 1 {
		t.Fatalf("Restore called %d times, want 1", session.restoreCalls)
	}
}

// TestSelectReturnsRenderErrorOnKeyHandling proves a render failure while
// applying a key is also propagated instead of a successful selection.
func TestSelectReturnsRenderErrorOnKeyRender(t *testing.T) {
	session := &fakeSession{
		input:  bytes.NewReader([]byte("\x1b[B\r")),
		output: &failingBuffer{lockedBuffer: &lockedBuffer{}, failAfter: 3, err: errors.New("tty gone")},
		width:  100,
		height: 24,
		resize: make(chan struct{}),
		ansi:   true,
	}
	_, err := Select(session, []model.SSHConnection{{ID: 1, Name: "one"}, {ID: 2, Name: "two"}})
	if err == nil || !strings.Contains(err.Error(), "render picker") {
		t.Fatalf("Select() err = %v, want render failure during key handling", err)
	}
}

// TestSelectReturnsLeaveError proves a failed leave-alternate-screen write
// during cleanup is reported instead of a successful selection.
func TestSelectReturnsLeaveAlternateScreenError(t *testing.T) {
	session := &fakeSession{
		input:  bytes.NewReader([]byte("\r")),
		output: &failingBuffer{lockedBuffer: &lockedBuffer{}, failAfter: 3, err: errors.New("broken pipe")},
		width:  100,
		height: 24,
		resize: make(chan struct{}),
		ansi:   true,
	}
	got, err := Select(session, []model.SSHConnection{{ID: 1, Name: "one"}})
	if err == nil || !strings.Contains(err.Error(), "leave alternate screen") {
		t.Fatalf("Select() err = %v, want 'leave alternate screen' failure", err)
	}
	if got.ID != 0 {
		t.Fatalf("Select() returned a connection %#v despite cleanup failure", got)
	}
}

// TestSelectReturnsRestoreError proves a failing terminal Restore is
// reported even though the selection itself succeeded.
func TestSelectReturnsRestoreError(t *testing.T) {
	session := newFakeSession("\r", 100, 24, true)
	session.restoreErr = errors.New("terminal lost")
	got, err := Select(session, []model.SSHConnection{{ID: 1, Name: "one"}})
	if err == nil || !strings.Contains(err.Error(), "restore picker raw mode") {
		t.Fatalf("Select() err = %v, want 'restore picker raw mode' failure", err)
	}
	if got.ID != 0 {
		t.Fatalf("Select() returned a connection %#v despite restore failure", got)
	}
	if session.restoreCalls != 1 {
		t.Fatalf("Restore called %d times, want 1", session.restoreCalls)
	}
}
