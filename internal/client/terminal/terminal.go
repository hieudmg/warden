// Package terminal abstracts the caller's terminal for interactive SSH
// sessions (warden xssh). It provides platform implementations for
// Linux/Unix (termios + SIGWINCH) and Windows consoles (console modes +
// size polling), so the interactive transport never depends on native
// ssh, fzf, or third-party PTY helpers.
//
// The session is single-use: after Restore it must not be re-entered.
package terminal

import (
	"io"
	"time"
)

// Session exposes the terminal primitives required to run an interactive
// remote shell: raw-mode input, window size, resize notifications, and the
// terminal byte streams.
type Session interface {
	// EnterRaw switches the terminal into raw mode: input is not echoed
	// and is delivered without line buffering. It is safe to call
	// repeatedly; only the first call changes terminal state. After
	// Restore it returns an error.
	EnterRaw() error
	// Restore returns the terminal to its pre-raw state and stops resize
	// delivery. It is safe to call after EnterRaw errors and more than
	// once.
	Restore() error
	// Size reports the terminal size in character cells (columns, rows).
	// It returns 0, 0 for non-terminals.
	Size() (width, height int)
	// ResizeEvents delivers one notification per terminal resize while
	// raw mode is active; Size reports the new size by the time an event
	// is received. The channel is closed by Restore.
	ResizeEvents() <-chan struct{}
	// Stdin, Stdout and Stderr expose the terminal byte streams. In raw
	// mode Ctrl-C (0x03) and Ctrl-D (0x04) are delivered as input bytes,
	// not as signals.
	Stdin() io.Reader
	Stdout() io.Writer
	Stderr() io.Writer
	// SupportsANSI reports whether the terminal can render ANSI/VT escape
	// sequences. The picker requires them; interactive SSH does not.
	SupportsANSI() bool
	// StdinReadyWithin waits up to d for stdin handle readiness. On Windows
	// the handle signals queued console records, which may not yield bytes.
	// The wait itself never reads stdin or leaves a reader blocked after
	// returning.
	StdinReadyWithin(d time.Duration) (bool, error)
}

// Console keys without a standalone Unicode representation.
const (
	KeyUp rune = -1 - iota
	KeyDown
	PickerKeyEscape
	KeyLeft
	KeyRight
)

const (
	PickerKeyUp   = KeyUp
	PickerKeyDown = KeyDown
)

// NewSession returns a Session bound to the process standard streams. It
// fails when stdin is not a terminal: interactive mode must never silently
// fall back to line-buffered input.
func NewSession() (Session, error) { return newSession() }

// EnableFullScreenOutput configures output for the full-screen renderer after
// EnterRaw and a successful SupportsANSI check, but before writing any escapes.
// The caller still owns Restore, even when this fails.
func EnableFullScreenOutput(session Session) error {
	if s, ok := session.(interface{ EnableFullScreenOutput() error }); ok {
		return s.EnableFullScreenOutput()
	}
	return nil
}
