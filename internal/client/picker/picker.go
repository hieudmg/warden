// Package picker implements the dependency-free state and input decoding
// for the interactive xssh connection picker. It has no dependencies beyond
// the standard library and the redacted model types, so the TUI can run in
// raw mode without fzf, Bubble Tea, or bundled binaries.
package picker

import (
	"strings"
	"unicode/utf8"

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
