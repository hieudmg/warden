// Package picker implements the full-screen connection picker for xssh.
package picker

import (
	"sort"
	"strings"
	"unicode/utf8"

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
// slice is immutable; matches holds indexes into it so Filtered returns
// results in grouped, connection-name order.
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

// Filtered returns the connections matching the current query in grouped,
// connection-name order.
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

// rebuild recomputes matches for the current query. A connection matches
// when the lowercased query is contained in its lowercased Name, Host, or
// GroupName. An empty GroupName never matches a nonempty query. Matches are
// sorted by group name, then connection name; ungrouped connections sort
// after named groups.
func (s State) rebuild() State {
	needle := strings.ToLower(s.query)
	matches := make([]int, 0, len(s.conns))
	for i, c := range s.conns {
		if strings.Contains(strings.ToLower(c.Name), needle) ||
			strings.Contains(strings.ToLower(c.Host), needle) ||
			strings.Contains(strings.ToLower(c.GroupName), needle) {
			matches = append(matches, i)
		}
	}
	sort.SliceStable(matches, func(i, j int) bool {
		left := s.conns[matches[i]]
		right := s.conns[matches[j]]
		if left.GroupName == "" && right.GroupName != "" {
			return false
		}
		if left.GroupName != "" && right.GroupName == "" {
			return true
		}
		if groupOrder(left.GroupName) != groupOrder(right.GroupName) {
			return groupOrder(left.GroupName) < groupOrder(right.GroupName)
		}
		return connectionNameOrder(left.Name) < connectionNameOrder(right.Name)
	})
	s.matches = matches
	return s
}

func groupOrder(name string) string {
	return strings.ToLower(name) + "\x00" + name
}

func connectionNameOrder(name string) string {
	return strings.ToLower(name) + "\x00" + name
}
