package terminal

import (
	"os"
	"testing"

	"golang.org/x/term"
)

// TestNewSessionRequiresInteractiveTerminal verifies the platform
// constructor rejects non-terminal stdin: interactive mode must never
// silently fall back to line-buffered input.
func TestNewSessionRequiresInteractiveTerminal(t *testing.T) {
	if term.IsTerminal(int(os.Stdin.Fd())) {
		t.Skip("stdin is a terminal in this environment; non-terminal behavior not exercisable")
	}
	s, err := NewSession()
	if err == nil {
		t.Fatal("NewSession() err = nil, want error for non-terminal stdin")
	}
	if s != nil {
		t.Fatal("NewSession() returned a non-nil session on error")
	}
}
