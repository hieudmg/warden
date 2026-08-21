//go:build windows

package terminal

import (
	"os"
	"testing"
)

// TestWindowsEnterRawFailsOnNonConsole verifies raw mode fails cleanly on
// a redirected (non-console) stdin and that Restore afterwards is a
// harmless no-op.
func TestWindowsEnterRawFailsOnNonConsole(t *testing.T) {
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer pr.Close()
	defer pw.Close()

	s := &windowsSession{
		in:         pr,
		out:        pw,
		stopResize: make(chan struct{}),
		events:     make(chan struct{}),
	}
	if err := s.EnterRaw(); err == nil {
		t.Fatal("EnterRaw on non-console: err = nil, want error")
	}
	if err := s.Restore(); err != nil {
		t.Fatalf("Restore after failed EnterRaw: %v", err)
	}
}

// TestWindowsSizeOnNonConsole verifies Size reports 0, 0 for handles
// without console screen buffer information.
func TestWindowsSizeOnNonConsole(t *testing.T) {
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer pr.Close()
	defer pw.Close()

	s := &windowsSession{in: pr, out: pw}
	w, h := s.Size()
	if w != 0 || h != 0 {
		t.Fatalf("Size() on non-console = (%d, %d), want (0, 0)", w, h)
	}
}

// TestWindowsRestoreClosesResizeEvents verifies Restore closes the events
// channel even when raw mode was never entered.
func TestWindowsRestoreClosesResizeEvents(t *testing.T) {
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer pr.Close()
	defer pw.Close()

	s := &windowsSession{
		in:         pr,
		out:        pw,
		stopResize: make(chan struct{}),
		events:     make(chan struct{}),
	}
	if err := s.Restore(); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if _, ok := <-s.ResizeEvents(); ok {
		t.Fatal("ResizeEvents channel still open after Restore")
	}
}
