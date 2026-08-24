// Package picker implements the dependency-free state and input decoding
// for the interactive xssh connection picker. It has no dependencies beyond
// the standard library and the redacted model types, so the TUI can run in
// raw mode without fzf, Bubble Tea, or bundled binaries.
package picker

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"warden/internal/client/terminal"
	"warden/internal/model"
)

// Focus selects which viewport owns Up/Down navigation in a rendered
// picker: the connection list or the connection detail fields.
type Focus uint8

const (
	// FocusList gives Up/Down to the filtered connection list.
	FocusList Focus = iota
	// FocusDetail gives Up/Down to the detail field viewport.
	FocusDetail
)

// State is the picker's query and selection state. The source connection
// slice is immutable; matches holds indexes into it so Filtered always
// returns results in the original ordering.
type State struct {
	conns        []model.SSHConnection
	query        string
	matches      []int
	selected     int
	focus        Focus
	detailOffset int
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
// and down move the selection (or the detail viewport when it has focus),
// clamped to the filtered result count or the selected connection's field
// count; tab toggles which viewport owns the arrows.
func (s State) Apply(k DecodedKey) State {
	switch k.Kind {
	case KeyRune:
		s.query += string(k.Rune)
		s = s.rebuild()
		s.selected = 0
		s.detailOffset = 0
	case KeyBackspace:
		if s.query == "" {
			return s
		}
		_, size := utf8.DecodeLastRuneInString(s.query)
		s.query = s.query[:len(s.query)-size]
		s = s.rebuild()
		s.selected = 0
		s.detailOffset = 0
	case KeyTab:
		if s.focus == FocusList {
			s.focus = FocusDetail
		} else {
			s.focus = FocusList
		}
	case KeyUp:
		if s.focus == FocusDetail {
			if s.detailOffset > 0 {
				s.detailOffset--
			}
		} else if len(s.matches) > 0 && s.selected > 0 {
			s.selected--
		}
	case KeyDown:
		if s.focus == FocusDetail {
			if c, ok := s.Selected(); ok && s.detailOffset < len(FormatConnection(c))-1 {
				s.detailOffset++
			}
		} else if len(s.matches) > 0 && s.selected < len(s.matches)-1 {
			s.selected++
		}
	}
	return s
}

// escGrace bounds how long Select waits for the byte that follows a lone
// ESC before treating the ESC as cancellation. Real terminals deliver an
// arrow sequence (ESC [ A) in one write, but a sequence can arrive split
// across reads; the grace window lets the continuation arrive while a
// bare ESC still cancels promptly.
const escGrace = 50 * time.Millisecond

// Select runs the interactive picker on session until the user confirms a
// connection or cancels. It enters raw mode, switches to the alternate
// screen, and returns the selected redacted connection only after the
// terminal is fully restored, so no picker goroutine remains to consume
// input meant for the subsequent SSH session. Every terminal failure
// (render, alternate screen, restore) is returned instead of reporting a
// successful selection; best-effort cleanup never replaces a primary
// error.
func Select(session terminal.Session, conns []model.SSHConnection) (conn model.SSHConnection, retErr error) {
	if len(conns) == 0 {
		return model.SSHConnection{}, errors.New("no ssh connections configured")
	}
	if err := session.EnterRaw(); err != nil {
		return model.SSHConnection{}, fmt.Errorf("enter picker raw mode: %w", err)
	}
	// Cleanup runs on every exit path below. A cleanup failure only sets
	// the return error when no primary error exists, so it can never hide
	// the real cause (cancel, read failure, render failure, ...).
	defer func() {
		if err := leaveAlternateScreen(session.Stdout()); err != nil && retErr == nil {
			retErr = fmt.Errorf("leave alternate screen: %w", err)
			conn = model.SSHConnection{}
		}
		if err := session.Restore(); err != nil && retErr == nil {
			retErr = fmt.Errorf("restore picker raw mode: %w", err)
			conn = model.SSHConnection{}
		}
	}()
	if !session.SupportsANSI() {
		return model.SSHConnection{}, errors.New("terminal does not support ANSI rendering; use a modern terminal")
	}
	if err := enterAlternateScreen(session.Stdout()); err != nil {
		return model.SSHConnection{}, fmt.Errorf("enter alternate screen: %w", err)
	}

	state := NewState(conns)
	width, height := session.Size()
	if width < 1 || height < 1 {
		width, height = 80, 24
	}

	// One resize-render goroutine. State snapshots, stdout writes, and the
	// render-error slot are guarded by mu; the goroutine stops via done
	// before the alternate screen is left and raw mode restored, so no
	// picker goroutine outlives Select to consume input meant for the SSH
	// session.
	var mu sync.Mutex
	var resizeErr error
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
				if err := Render(session.Stdout(), state, width, height); err != nil && resizeErr == nil {
					resizeErr = err
				}
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

	render := func() error {
		mu.Lock()
		defer mu.Unlock()
		return Render(session.Stdout(), state, width, height)
	}
	if err := render(); err != nil {
		return model.SSHConnection{}, fmt.Errorf("render picker: %w", err)
	}

	// All input reads stay in this goroutine: a blocked stdin reader must
	// never outlive selection and consume keys from the SSH session. A
	// lone ESC is resolved by waiting a bounded escGrace for a
	// continuation byte; the wait is fd-level readiness polling with no
	// background reader, so no goroutine can survive Select and consume
	// input meant for the subsequent SSH session.
	//
	// Bytes are consumed one at a time with no intermediate buffer: a
	// buffered reader could absorb keystrokes typed past the confirming
	// Enter and silently discard them when Select returns, stealing input
	// from the SSH session that follows. Every byte past Enter stays in
	// the underlying reader for that session.
	var dec StreamDecoder
	for {
		mu.Lock()
		rErr := resizeErr
		mu.Unlock()
		if rErr != nil {
			return model.SSHConnection{}, fmt.Errorf("render picker: %w", rErr)
		}
		b, err := readByte(session.Stdin())
		if err != nil {
			return model.SSHConnection{}, fmt.Errorf("read picker input: %w", err)
		}
		keys := dec.Feed([]byte{b})
		// A leading ESC is normally the start of an arrow sequence. Never
		// flush it just because the continuation byte has not arrived
		// yet: with byte-at-a-time delivery it may simply be delayed.
		// Wait a bounded grace for the next byte via the session's
		// readiness poll; the poll spawns no reader, so a timed-out bare
		// ESC cancels with nothing left blocked on stdin.
		if len(keys) == 0 && len(dec.Pending()) > 0 && dec.Pending()[0] == 0x1b {
			ok, err := session.StdinReadyWithin(escGrace)
			if err != nil {
				return model.SSHConnection{}, fmt.Errorf("read picker input: %w", err)
			}
			if !ok {
				// The grace elapsed with no continuation byte: the ESC
				// stands alone and cancels.
				keys = dec.Flush()
			} else {
				nb, rerr := readByte(session.Stdin())
				if rerr == io.EOF {
					keys = dec.Flush() // lone ESC at end of stream cancels
				} else if rerr != nil {
					return model.SSHConnection{}, fmt.Errorf("read picker input: %w", rerr)
				} else {
					keys = dec.Feed([]byte{nb})
				}
			}
		}
		for _, k := range keys {
			switch k.Kind {
			case KeyEnter:
				mu.Lock()
				got, ok := state.Selected()
				rErr := resizeErr
				mu.Unlock()
				if rErr != nil {
					return model.SSHConnection{}, fmt.Errorf("render picker: %w", rErr)
				}
				if ok {
					return got, nil
				}
			case KeyCancel:
				return model.SSHConnection{}, errors.New("selection aborted")
			default:
				mu.Lock()
				state = state.Apply(k)
				err := Render(session.Stdout(), state, width, height)
				mu.Unlock()
				if err != nil {
					return model.SSHConnection{}, fmt.Errorf("render picker: %w", err)
				}
			}
		}
	}
}

// readByte reads exactly one byte from r without any buffering. Select
// consumes input through this helper so the picker can never hold bytes
// typed beyond the confirming Enter: everything past that key stays in
// the underlying reader for the subsequent SSH session.
func readByte(r io.Reader) (byte, error) {
	var b [1]byte
	_, err := io.ReadFull(r, b[:])
	return b[0], err
}

// enterAlternateScreen switches to the alternate screen, clears it, homes
// the cursor, and hides it.
func enterAlternateScreen(w io.Writer) error {
	_, err := io.WriteString(w, "\x1b[?1049h\x1b[2J\x1b[H\x1b[?25l")
	return err
}

// leaveAlternateScreen shows the cursor again and returns to the normal
// screen.
func leaveAlternateScreen(w io.Writer) error {
	_, err := io.WriteString(w, "\x1b[?25h\x1b[?1049l")
	return err
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
