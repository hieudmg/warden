// Package picker implements the dependency-free state and input decoding
// for the interactive xssh connection picker. It has no dependencies beyond
// the standard library and the redacted model types, so the TUI can run in
// raw mode without fzf, Bubble Tea, or bundled binaries.
package picker

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"unicode/utf8"

	"warden/internal/client/terminal"
	"warden/internal/model"
)

// State is the picker's query and selection state. The source connection
// slice is immutable; matches holds indexes into it so Filtered always
// returns results in the original ordering.
type State struct {
	conns    []model.SSHConnection
	query    string
	matches  []int
	selected int
}

// NewState returns a State over conns with all connections matching the
// empty query and the first one selected. The caller-owned slice is copied
// so the State's source stays immutable even if the caller mutates it
// afterwards.
func NewState(conns []model.SSHConnection) State {
	src := make([]model.SSHConnection, len(conns))
	copy(src, conns)
	return State{conns: src}.rebuild()
}

// Filtered returns the connections matching the current query in source
// order.
func (s State) Filtered() []model.SSHConnection {
	out := make([]model.SSHConnection, len(s.matches))
	for i, idx := range s.matches {
		out[i] = s.conns[idx]
	}
	return out
}

// Selected returns the currently selected connection and true, or the zero
// value and false when no connection matches the query.
func (s State) Selected() (model.SSHConnection, bool) {
	if len(s.matches) == 0 || s.selected >= len(s.matches) {
		return model.SSHConnection{}, false
	}
	return s.conns[s.matches[s.selected]], true
}

// Apply returns the state after processing one decoded key. Runes and
// backspace edit the query and reset the selection to the first match; up
// and down move the selection, clamped to the filtered result count.
func (s State) Apply(k DecodedKey) State {
	switch k.Kind {
	case KeyRune:
		s.query += string(k.Rune)
		s = s.rebuild()
		s.selected = 0
	case KeyBackspace:
		if s.query == "" {
			return s
		}
		_, size := utf8.DecodeLastRuneInString(s.query)
		s.query = s.query[:len(s.query)-size]
		s = s.rebuild()
		s.selected = 0
	case KeyUp:
		if len(s.matches) > 0 && s.selected > 0 {
			s.selected--
		}
	case KeyDown:
		if len(s.matches) > 0 && s.selected < len(s.matches)-1 {
			s.selected++
		}
	}
	return s
}

// Select runs the interactive picker on session until the user confirms a
// connection or cancels. It enters raw mode, switches to the alternate
// screen, and returns the selected redacted connection only after the
// terminal is fully restored, so no picker goroutine remains to consume
// input meant for the subsequent SSH session.
func Select(session terminal.Session, conns []model.SSHConnection) (model.SSHConnection, error) {
	if len(conns) == 0 {
		return model.SSHConnection{}, errors.New("no ssh connections configured")
	}
	if err := session.EnterRaw(); err != nil {
		return model.SSHConnection{}, fmt.Errorf("enter picker raw mode: %w", err)
	}
	defer session.Restore()
	if !session.SupportsANSI() {
		return model.SSHConnection{}, errors.New("terminal does not support ANSI rendering; use a modern terminal")
	}
	enterAlternateScreen(session.Stdout())
	defer leaveAlternateScreen(session.Stdout())

	state := NewState(conns)
	width, height := session.Size()
	if width < 1 || height < 1 {
		width, height = 80, 24
	}

	// One resize-render goroutine. State snapshots and stdout writes are
	// guarded by mu; the goroutine stops via done before the alternate
	// screen is left and raw mode restored, so no picker goroutine
	// outlives Select to consume input meant for the SSH session.
	var mu sync.Mutex
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-session.ResizeEvents():
				mu.Lock()
				w, h := session.Size()
				if w < 1 || h < 1 {
					w, h = 80, 24
				}
				width, height = w, h
				Render(session.Stdout(), state, width, height)
				mu.Unlock()
			case <-done:
				return
			}
		}
	}()
	defer func() {
		close(done)
		wg.Wait()
	}()

	render := func() {
		mu.Lock()
		Render(session.Stdout(), state, width, height)
		mu.Unlock()
	}
	render()

	// All input reads stay in this goroutine: a blocked stdin reader must
	// never outlive selection and consume keys from the SSH session.
	reader := bufio.NewReader(session.Stdin())
	var dec StreamDecoder
	for {
		b, err := reader.ReadByte()
		if err != nil {
			return model.SSHConnection{}, fmt.Errorf("read picker input: %w", err)
		}
		keys := dec.Feed([]byte{b})
		// A leading ESC is normally the start of an arrow sequence; only
		// cancel when no continuation byte is already buffered.
		if len(keys) == 0 && len(dec.Pending()) > 0 && dec.Pending()[0] == 0x1b && reader.Buffered() == 0 {
			keys = append(keys, dec.Flush()...)
		}
		for _, k := range keys {
			switch k.Kind {
			case KeyEnter:
				mu.Lock()
				conn, ok := state.Selected()
				mu.Unlock()
				if ok {
					return conn, nil
				}
			case KeyCancel:
				return model.SSHConnection{}, errors.New("selection aborted")
			default:
				mu.Lock()
				state = state.Apply(k)
				Render(session.Stdout(), state, width, height)
				mu.Unlock()
			}
		}
	}
}

// enterAlternateScreen switches to the alternate screen, clears it, homes
// the cursor, and hides it.
func enterAlternateScreen(w io.Writer) {
	io.WriteString(w, "\x1b[?1049h\x1b[2J\x1b[H\x1b[?25l")
}

// leaveAlternateScreen shows the cursor again and returns to the normal
// screen.
func leaveAlternateScreen(w io.Writer) {
	io.WriteString(w, "\x1b[?25h\x1b[?1049l")
}

// rebuild recomputes matches for the current query. A connection matches
// when the lowercased query is contained in its lowercased Name or Host.
func (s State) rebuild() State {
	needle := strings.ToLower(s.query)
	matches := make([]int, 0, len(s.conns))
	for i, c := range s.conns {
		if strings.Contains(strings.ToLower(c.Name), needle) ||
			strings.Contains(strings.ToLower(c.Host), needle) {
			matches = append(matches, i)
		}
	}
	s.matches = matches
	return s
}
