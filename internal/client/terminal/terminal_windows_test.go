//go:build windows

package terminal

import (
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"testing/synctest"
	"time"

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

// TestWindowsStdinReadyWithin verifies the console-input readiness wait
// reports false within the timeout when no input is pending and true as
// soon as input is available, using a pipe handle as a waitable stand-in
// for a console input handle.
func TestWindowsStdinReadyWithin(t *testing.T) {
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer pr.Close()
	defer pw.Close()
	s := &windowsSession{in: pr}

	start := time.Now()
	ok, err := s.StdinReadyWithin(30 * time.Millisecond)
	if err != nil {
		t.Fatalf("StdinReadyWithin with no input: %v", err)
	}
	if ok {
		t.Fatal("StdinReadyWithin = true with no input, want false")
	}
	if elapsed := time.Since(start); elapsed < 20*time.Millisecond {
		t.Fatalf("StdinReadyWithin returned after %v, want ~30ms wait", elapsed)
	}

	if _, err := pw.Write([]byte{'x'}); err != nil {
		t.Fatalf("write to pipe: %v", err)
	}
	ok, err = s.StdinReadyWithin(2 * time.Second)
	if err != nil {
		t.Fatalf("StdinReadyWithin with pending input: %v", err)
	}
	if !ok {
		t.Fatal("StdinReadyWithin = false with pending input, want true")
	}
}

func TestWindowsPollKeySkipsNonCharacterRecordsAndKeepsQueuedKeys(t *testing.T) {
	origRead := winReadConsoleInputNowait
	t.Cleanup(func() { winReadConsoleInputNowait = origRead })
	records := []consoleInputRecord{
		{eventType: 0x0010},              // Focus
		{eventType: 0x0004},              // Resize
		{eventType: 1, unicodeChar: 'q'}, // Ordinary key release
		{eventType: 1, keyDown: 1},       // Modifier without a character
	}
	winReadConsoleInputNowait = func(_ windows.Handle, record *consoleInputRecord) (bool, error) {
		if len(records) == 0 {
			return false, nil
		}
		*record, records = records[0], records[1:]
		return true, nil
	}
	s := &windowsSession{in: os.Stdin}
	if key, repeat, err := s.PollKey(); key != 0 || repeat != 0 || err != nil || len(records) != 0 {
		t.Fatalf("non-character records: key = %q, repeat = %d, err = %v, records left = %d", key, repeat, err, len(records))
	}
	records = []consoleInputRecord{
		{eventType: 1, keyDown: 1, unicodeChar: '\u0171'}, // Not an ASCII 'q'.
		{eventType: 1, keyDown: 1, unicodeChar: 'j', repeatCount: 3},
		{eventType: 1, virtualKey: 0x12, unicodeChar: 'g', repeatCount: 1}, // Alt+numpad composition on release.
		{eventType: 1, keyDown: 1, unicodeChar: 3, repeatCount: 1},
		{eventType: 1, keyDown: 1, unicodeChar: 'q', repeatCount: 1},
		{eventType: 1, keyDown: 1, unicodeChar: 'k', repeatCount: 1},
	}
	for _, want := range []struct {
		key    rune
		repeat int
	}{{'j', 3}, {'g', 1}, {3, 1}, {'q', 1}} {
		if key, repeat, err := s.PollKey(); key != want.key || repeat != want.repeat || err != nil {
			t.Fatalf("PollKey() = (%q, %d, %v), want (%q, %d, nil)", key, repeat, err, want.key, want.repeat)
		}
	}
	if len(records) != 1 || records[0].unicodeChar != 'k' {
		t.Fatalf("poll read ahead past quit: records left = %+v", records)
	}
}

func TestWindowsPollKeyDecodesNativeArrowsAndRepeats(t *testing.T) {
	origRead := winReadConsoleInputNowait
	t.Cleanup(func() { winReadConsoleInputNowait = origRead })
	records := []consoleInputRecord{
		{eventType: 1, virtualKey: 0x26}, // Up key release.
		{eventType: 1, keyDown: 1, virtualKey: 0x28, repeatCount: 3},
		{eventType: 1, keyDown: 1, virtualKey: 0x26, repeatCount: 2},
		{eventType: 1, keyDown: 1, virtualKey: 0x27},
		{eventType: 1, keyDown: 1, virtualKey: 0x25, repeatCount: 1},
		{eventType: 1, keyDown: 1, unicodeChar: 'q'},
		{eventType: 1, keyDown: 1, unicodeChar: 'X'},
	}
	winReadConsoleInputNowait = func(_ windows.Handle, record *consoleInputRecord) (bool, error) {
		if len(records) == 0 {
			return false, nil
		}
		*record, records = records[0], records[1:]
		return true, nil
	}
	s := &windowsSession{in: os.Stdin}
	for _, want := range []struct {
		key    rune
		repeat int
	}{{KeyDown, 3}, {KeyUp, 2}, {KeyRight, 1}, {KeyLeft, 1}, {'q', 1}} {
		if key, repeat, err := s.PollKey(); key != want.key || repeat != want.repeat || err != nil {
			t.Fatalf("PollKey() = (%U, %d, %v), want (%U, %d, nil)", key, repeat, err, want.key, want.repeat)
		}
	}
	if len(records) != 1 || records[0].unicodeChar != 'X' {
		t.Fatalf("poll read ahead past quit: records left = %+v", records)
	}
}

func TestWindowsPollPickerKeyDecodesUnicodeAndKeepsRecordBoundary(t *testing.T) {
	origRead := winReadConsoleInputNowait
	t.Cleanup(func() { winReadConsoleInputNowait = origRead })
	records := []consoleInputRecord{
		{eventType: 0x0004},              // Resize, not a key.
		{eventType: 1, unicodeChar: 'x'}, // Ordinary key release.
		{eventType: 1, keyDown: 1, unicodeChar: '界', repeatCount: 2},
		{eventType: 1, keyDown: 1, unicodeChar: 0xd83d, repeatCount: 2},
		{eventType: 1, keyDown: 1, unicodeChar: 0xde80, repeatCount: 2},
		{eventType: 1, virtualKey: 0x12, unicodeChar: 'é'}, // Alt+numpad composition.
		{eventType: 1, keyDown: 1, virtualKey: 0x28, repeatCount: 3},
		{eventType: 1, keyDown: 1, virtualKey: 0x1b, unicodeChar: 0x1b},
		{eventType: 1, keyDown: 1, unicodeChar: 'z'},
	}
	winReadConsoleInputNowait = func(_ windows.Handle, record *consoleInputRecord) (bool, error) {
		if len(records) == 0 {
			return false, nil
		}
		*record, records = records[0], records[1:]
		return true, nil
	}
	s := &windowsSession{in: os.Stdin}
	for _, want := range []struct {
		key    rune
		repeat int
	}{{'界', 2}, {'🚀', 2}, {'é', 1}, {PickerKeyDown, 3}, {PickerKeyEscape, 1}} {
		if key, repeat, err := s.PollPickerKey(); key != want.key || repeat != want.repeat || err != nil {
			t.Fatalf("PollPickerKey() = (%U, %d, %v), want (%U, %d, nil)", key, repeat, err, want.key, want.repeat)
		}
	}
	if len(records) != 1 || records[0].unicodeChar != 'z' {
		t.Fatalf("consumed input beyond Escape: records left = %+v", records)
	}
}

// TestWindowsEnterRawRollsBackModesOnHandlerFailure verifies that when
// console-handler registration fails, EnterRaw attempts both mode
// restorations, reports their errors, and clears its ANSI flag.
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
	handlerErr := errors.New("handler denied")
	inputErr := errors.New("input rollback denied")
	outputErr := errors.New("output rollback denied")
	winSetConsoleMode = func(h windows.Handle, mode uint32) error {
		if h == inH {
			inModeCalls = append(inModeCalls, mode)
			if len(inModeCalls) == 2 {
				return inputErr
			}
		} else {
			outModeCalls = append(outModeCalls, mode)
			if len(outModeCalls) == 2 {
				return outputErr
			}
		}
		return nil
	}
	winSetCtrlHandler = func(cb uintptr, add bool) (bool, error) {
		return false, handlerErr
	}

	err = s.EnterRaw()
	if err == nil || !strings.Contains(err.Error(), "register console ctrl handler") {
		t.Fatalf("EnterRaw() = %v, want handler registration failure", err)
	}
	for _, want := range []error{handlerErr, inputErr, outputErr} {
		if !errors.Is(err, want) {
			t.Errorf("EnterRaw() = %v, want it to include %v", err, want)
		}
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

	s := &windowsSession{in: pr, out: pw, events: make(chan struct{})}
	if err := s.Restore(); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	assertWindowsResizeEventsClosed(t, s.ResizeEvents())
}

func TestWindowsRestoreZeroSession(t *testing.T) {
	var s windowsSession
	for range 2 {
		if err := s.Restore(); err != nil {
			t.Fatalf("Restore: %v", err)
		}
	}
	if err := s.EnterRaw(); err == nil {
		t.Fatal("EnterRaw succeeded after Restore")
	}
}

func TestWindowsRestoreConsoleModes(t *testing.T) {
	handlerErr := errors.New("handler removal denied")
	inputErr := errors.New("input restore denied")
	outputErr := errors.New("output restore denied")
	modeErr := errors.New("DISABLE_NEWLINE_AUTO_RETURN denied")
	const noAutoReturn = windows.DISABLE_NEWLINE_AUTO_RETURN
	for _, tc := range []struct {
		name       string
		origOutput uint32
		vtDenied   bool
		fullScreen bool
		modeDenied bool
		fail       bool
	}{
		{name: "restore zero output mode"},
		{name: "do not restore unchanged output mode", origOutput: 2, vtDenied: true},
		{name: "cleanup errors do not stop restoration", origOutput: 2, fail: true},
		{name: "full screen restores zero output mode", fullScreen: true},
		{name: "full screen preserves existing bits", origOutput: 2 | noAutoReturn, fullScreen: true},
		{name: "full-screen rejection restores both modes", origOutput: 2, fullScreen: true, modeDenied: true},
		{name: "full-screen rejection still attempts both restores on errors", origOutput: 2, fullScreen: true, modeDenied: true, fail: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pr, pw, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer pr.Close()
			defer pw.Close()
			s := &windowsSession{in: pr, out: pw, stopResize: make(chan struct{}), events: make(chan struct{})}
			origGet, origSet, origHandler := winGetConsoleMode, winSetConsoleMode, winSetCtrlHandler
			t.Cleanup(func() {
				winGetConsoleMode, winSetConsoleMode, winSetCtrlHandler = origGet, origSet, origHandler
			})
			const origInput = uint32(3)
			inH := windows.Handle(pr.Fd())
			winGetConsoleMode = func(h windows.Handle, mode *uint32) error {
				*mode = tc.origOutput
				if h == inH {
					*mode = origInput
				}
				return nil
			}
			var inModes, outModes []uint32
			winSetConsoleMode = func(h windows.Handle, mode uint32) error {
				if h == inH {
					inModes = append(inModes, mode)
					if mode == origInput && tc.fail {
						return inputErr
					}
				} else {
					outModes = append(outModes, mode)
					if mode != tc.origOutput && tc.vtDenied {
						return errors.New("VT unavailable")
					}
					if mode&noAutoReturn != 0 && tc.modeDenied {
						return modeErr
					}
					if mode == tc.origOutput && tc.fail {
						return outputErr
					}
				}
				return nil
			}
			var handlerCalls []bool
			winSetCtrlHandler = func(_ uintptr, add bool) (bool, error) {
				handlerCalls = append(handlerCalls, add)
				if !add && tc.fail {
					return false, handlerErr
				}
				return true, nil
			}
			if err := s.EnterRaw(); err != nil {
				t.Fatalf("EnterRaw: %v", err)
			}
			if s.SupportsANSI() == tc.vtDenied {
				t.Errorf("SupportsANSI() = %v, want %v", s.SupportsANSI(), !tc.vtDenied)
			}
			if tc.fullScreen {
				err := EnableFullScreenOutput(s)
				if tc.modeDenied && !errors.Is(err, modeErr) || !tc.modeDenied && err != nil {
					t.Errorf("EnableFullScreenOutput() = %v, want rejection = %v", err, tc.modeDenied)
				}
			}
			err = s.Restore()
			if tc.fail {
				for _, want := range []error{handlerErr, inputErr, outputErr} {
					if !errors.Is(err, want) {
						t.Errorf("Restore() = %v, want it to include %v", err, want)
					}
				}
			} else if err != nil {
				t.Errorf("Restore() = %v, want nil", err)
			}
			assertWindowsResizeEventsClosed(t, s.ResizeEvents())
			if err := s.Restore(); err != nil {
				t.Errorf("second Restore() = %v, want nil", err)
			}
			if want := []bool{true, false}; !reflect.DeepEqual(handlerCalls, want) {
				t.Errorf("handler calls = %v, want %v", handlerCalls, want)
			}
			if want := []uint32{winRawInputMode, origInput}; !reflect.DeepEqual(inModes, want) {
				t.Errorf("input modes = %v, want %v", inModes, want)
			}
			wantOut := []uint32{tc.origOutput | winOutputVTExtra}
			if tc.fullScreen {
				wantOut = append(wantOut, tc.origOutput|winOutputVTExtra|noAutoReturn)
			}
			if !tc.vtDenied {
				wantOut = append(wantOut, tc.origOutput)
			}
			if !reflect.DeepEqual(outModes, wantOut) {
				t.Errorf("output modes = %v, want %v", outModes, wantOut)
			}
		})
	}
}

func TestWindowsRestoreImmediatelyAfterResizeStartup(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var s windowsSession // startResize owns missing channels in partial sessions.
		started := time.Now()
		s.startResize()
		if err := s.Restore(); err != nil {
			t.Fatalf("Restore: %v", err)
		}
		if elapsed := time.Since(started); elapsed != 0 {
			t.Errorf("Restore waited %v for resize polling", elapsed)
		}
		assertWindowsResizeEventsClosed(t, s.ResizeEvents())
	})
}

func TestWindowsRestoreJoinsResizePoller(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := &windowsSession{stopResize: make(chan struct{}), events: make(chan struct{})}
		inPoll, releasePoll := make(chan struct{}), make(chan struct{})
		origSize := winGetConsoleScreenBufferInfo
		defer func() { winGetConsoleScreenBufferInfo = origSize }()
		reads := 0
		winGetConsoleScreenBufferInfo = func(_ windows.Handle, _ *windows.ConsoleScreenBufferInfo) error {
			reads++
			if reads == 2 {
				close(inPoll)
				<-releasePoll
			}
			return nil
		}
		s.startResize()
		<-inPoll
		var restoreErr error
		restored := make(chan struct{})
		go func() {
			restoreErr = s.Restore()
			close(restored)
		}()
		synctest.Wait()
		select {
		case <-s.stopResize:
		default:
			t.Error("Restore did not cancel the resize poller")
		}
		select {
		case <-restored:
			t.Error("Restore returned before the in-flight size poll finished")
		default:
		}
		select {
		case <-s.ResizeEvents():
			t.Error("ResizeEvents closed before the in-flight size poll finished")
		default:
		}
		close(releasePoll)
		<-restored
		if restoreErr != nil {
			t.Errorf("Restore: %v", restoreErr)
		}
		assertWindowsResizeEventsClosed(t, s.ResizeEvents())
		synctest.Wait()
	})
}

func assertWindowsResizeEventsClosed(t *testing.T, events <-chan struct{}) {
	t.Helper()
	select {
	case _, ok := <-events:
		if ok {
			t.Error("unexpected resize event after Restore")
		}
	default:
		t.Error("ResizeEvents not closed after Restore")
	}
}
