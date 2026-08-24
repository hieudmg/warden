//go:build windows

package terminal

import (
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// TestWindowsSessionReportsANSICapability verifies SupportsANSI reflects
// whether VT output processing was enabled during EnterRaw.
func TestWindowsSessionReportsANSICapability(t *testing.T) {
	s := &windowsSession{ansi: true}
	if !s.SupportsANSI() {
		t.Fatal("SupportsANSI() = false, want true")
	}
	s.ansi = false
	if s.SupportsANSI() {
		t.Fatal("SupportsANSI() = true, want false")
	}
}

// TestWindowsEnterRawRollsBackModesOnHandlerFailure verifies that when
// console-handler registration fails after the output VT mode was already
// changed, EnterRaw restores the original output mode and clears the ANSI
// flag instead of leaving the console in VT state.
func TestWindowsEnterRawRollsBackModesOnHandlerFailure(t *testing.T) {
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

	origGet := winGetConsoleMode
	origSet := winSetConsoleMode
	origHandler := winSetCtrlHandler
	t.Cleanup(func() {
		winGetConsoleMode = origGet
		winSetConsoleMode = origSet
		winSetCtrlHandler = origHandler
	})

	inH := windows.Handle(pr.Fd())
	const (
		origInput  = uint32(3)
		origOutput = uint32(7)
	)
	var inModeCalls, outModeCalls []uint32
	winGetConsoleMode = func(h windows.Handle, mode *uint32) error {
		if h == inH {
			*mode = origInput
		} else {
			*mode = origOutput
		}
		return nil
	}
	winSetConsoleMode = func(h windows.Handle, mode uint32) error {
		if h == inH {
			inModeCalls = append(inModeCalls, mode)
		} else {
			outModeCalls = append(outModeCalls, mode)
		}
		return nil
	}
	winSetCtrlHandler = func(cb uintptr, add bool) (bool, error) {
		return false, errors.New("handler denied")
	}

	err = s.EnterRaw()
	if err == nil || !strings.Contains(err.Error(), "register console ctrl handler") {
		t.Fatalf("EnterRaw() = %v, want handler registration failure", err)
	}
	wantIn := []uint32{winRawInputMode, origInput}
	if !reflect.DeepEqual(inModeCalls, wantIn) {
		t.Fatalf("input mode calls = %#v, want %#v", inModeCalls, wantIn)
	}
	wantOut := []uint32{origOutput | winOutputVTExtra, origOutput}
	if !reflect.DeepEqual(outModeCalls, wantOut) {
		t.Fatalf("output mode calls = %#v, want %#v (VT enabled then rolled back)", outModeCalls, wantOut)
	}
	if s.ansi {
		t.Fatal("ansi = true after failed EnterRaw, want false")
	}
	if s.origOut != 0 {
		t.Fatalf("origOut = %d after rollback, want 0", s.origOut)
	}
	if s.raw {
		t.Fatal("raw = true after failed EnterRaw, want false")
	}
	if err := s.Restore(); err != nil {
		t.Fatalf("Restore after failed EnterRaw: %v", err)
	}
}

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
