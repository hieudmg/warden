//go:build windows

package terminal

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
)

// Console input mode flags used for raw mode. ENABLE_PROCESSED_INPUT is
// cleared so Ctrl-C arrives as byte 0x03 on the input stream and is
// forwarded unchanged to the remote PTY instead of terminating the process.
const (
	winRawInputMode  = windows.ENABLE_EXTENDED_FLAGS | windows.ENABLE_VIRTUAL_TERMINAL_INPUT
	winInputToClear  = windows.ENABLE_PROCESSED_INPUT | windows.ENABLE_LINE_INPUT | windows.ENABLE_ECHO_INPUT
	winOutputVTExtra = windows.ENABLE_PROCESSED_OUTPUT | windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING
)

var kernel32 = syscall.NewLazyDLL("kernel32.dll")

// procSetConsoleCtrlHandler is SetConsoleCtrlHandler, which x/sys/windows
// does not expose; used to claim console control events so a raw-mode
// session is never terminated out from under deferred restoration.
var procSetConsoleCtrlHandler = kernel32.NewProc("SetConsoleCtrlHandler")

// Console calls go through these variables so Windows-only tests can
// exercise mode changes and resize polling without a real console.
var (
	winGetConsoleMode             = windows.GetConsoleMode
	winSetConsoleMode             = windows.SetConsoleMode
	winGetConsoleScreenBufferInfo = windows.GetConsoleScreenBufferInfo
	winSetCtrlHandler             = func(cb uintptr, add bool) (ok bool, callErr error) {
		var addArg uintptr
		if add {
			addArg = 1
		}
		r, _, err := procSetConsoleCtrlHandler.Call(cb, addArg)
		return r != 0, err
	}
)

// consoleCtrlHandler claims console control events (Ctrl-C, close, logoff,
// etc.), returning TRUE so the process keeps running and the interactive
// layer's deferred Restore always runs. Ctrl-C is normally delivered as
// byte 0x03 in raw input mode and handled by the input pump; this handler
// is the fallback for events that arrive as signals.
func consoleCtrlHandler(ctrlType uint32) uintptr {
	return 1
}

// windowsSession implements Session on Windows consoles using
// GetConsoleMode/SetConsoleMode, size polling, and SetConsoleCtrlHandler.
type windowsSession struct {
	in  *os.File
	out *os.File

	mu      sync.Mutex
	raw     bool
	done    bool
	origIn  uint32
	origOut uint32
	handler uintptr
	ansi    bool

	stopResize chan struct{}
	resizeDone chan struct{}
	events     chan struct{}
}

// newSession constructs the platform Session for Windows targets.
func newSession() (Session, error) {
	var mode uint32
	if err := windows.GetConsoleMode(windows.Handle(os.Stdin.Fd()), &mode); err != nil {
		return nil, errors.New("stdin is not a console; interactive mode requires one")
	}
	return &windowsSession{
		in:         os.Stdin,
		out:        os.Stdout,
		stopResize: make(chan struct{}),
		events:     make(chan struct{}),
	}, nil
}

// EnterRaw switches the console into raw input mode, enables VT output
// processing, and registers the console control handler. If registration
// fails, it attempts to restore both modes and reports any rollback errors.
func (s *windowsSession) EnterRaw() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.raw {
		return nil
	}
	if s.done {
		return errors.New("terminal session already restored")
	}

	inH := windows.Handle(s.in.Fd())
	outH := windows.Handle(s.out.Fd())

	if err := winGetConsoleMode(inH, &s.origIn); err != nil {
		return fmt.Errorf("get console input mode: %w", err)
	}
	if err := winSetConsoleMode(inH, winRawInputMode); err != nil {
		return fmt.Errorf("set raw console input mode: %w", err)
	}
	// Output VT processing is best-effort: raw input still works if it
	// cannot be enabled, and SupportsANSI reports false so the picker
	// rejects the session later.
	if err := winGetConsoleMode(outH, &s.origOut); err == nil {
		s.ansi = winSetConsoleMode(outH, s.origOut|winOutputVTExtra) == nil
	}

	cb := syscall.NewCallback(consoleCtrlHandler)
	if ok, callErr := winSetCtrlHandler(cb, true); !ok {
		restoreErr := s.restoreModes()
		s.origOut = 0
		s.ansi = false
		return errors.Join(fmt.Errorf("register console ctrl handler: %w", callErr), restoreErr)
	}
	s.handler = cb

	s.raw = true
	s.startResize()
	return nil
}

// restoreModes rolls back input and any successful output mode write.
// The saved output mode can legitimately be zero.
func (s *windowsSession) restoreModes() error {
	var err error
	if mErr := winSetConsoleMode(windows.Handle(s.in.Fd()), s.origIn); mErr != nil {
		err = fmt.Errorf("restore console input mode: %w", mErr)
	}
	if s.ansi {
		if mErr := winSetConsoleMode(windows.Handle(s.out.Fd()), s.origOut); mErr != nil {
			err = errors.Join(err, fmt.Errorf("restore console output mode: %w", mErr))
		}
	}
	return err
}

// Restore stops resize delivery, unregisters the control handler and
// returns the console to its original modes.
func (s *windowsSession) Restore() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.done {
		return nil
	}
	if s.stopResize != nil {
		close(s.stopResize)
	}
	if s.resizeDone != nil {
		<-s.resizeDone // The poller, including Size, does not acquire s.mu.
	}
	var err error
	if s.raw {
		if ok, callErr := winSetCtrlHandler(s.handler, false); !ok {
			err = fmt.Errorf("unregister console ctrl handler: %w", callErr)
		}
		s.handler = 0
		err = errors.Join(err, s.restoreModes())
		s.raw = false
	}
	if s.events != nil {
		close(s.events)
	}
	s.done = true
	return err
}

// startResize polls the visible console window size because Windows does
// not deliver resize notifications on the byte stream.
func (s *windowsSession) startResize() {
	if s.stopResize == nil {
		s.stopResize = make(chan struct{})
	}
	if s.events == nil {
		s.events = make(chan struct{})
	}
	s.resizeDone = make(chan struct{})
	go func() {
		defer close(s.resizeDone)
		select {
		case <-s.stopResize:
			return
		default:
		}
		lastW, lastH := s.Size()
		t := time.NewTicker(200 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				w, h := s.Size()
				if w != lastW || h != lastH {
					lastW, lastH = w, h
					select {
					case <-s.stopResize:
						return
					case s.events <- struct{}{}:
					default:
					}
				}
			case <-s.stopResize:
				return
			}
		}
	}()
}

// Size reports the visible console window dimensions in character cells.
func (s *windowsSession) Size() (int, int) {
	var info windows.ConsoleScreenBufferInfo
	if err := winGetConsoleScreenBufferInfo(windows.Handle(s.out.Fd()), &info); err != nil {
		return 0, 0
	}
	cols := int(info.Window.Right - info.Window.Left + 1)
	rows := int(info.Window.Bottom - info.Window.Top + 1)
	if cols < 0 || rows < 0 {
		return 0, 0
	}
	return cols, rows
}

func (s *windowsSession) ResizeEvents() <-chan struct{} { return s.events }
func (s *windowsSession) Stdin() io.Reader              { return s.in }
func (s *windowsSession) Stdout() io.Writer             { return s.out }
func (s *windowsSession) Stderr() io.Writer             { return os.Stderr }

// SupportsANSI reports whether VT output processing was successfully
// enabled on the console during EnterRaw.
func (s *windowsSession) SupportsANSI() bool { return s.ansi }

// StdinReadyWithin waits up to d for console input using
// WaitForSingleObject on the console input handle, which is signaled
// whenever input events are pending. The wait is pure readiness polling,
// so a timed-out wait leaves no reader blocked on stdin and cannot
// consume bytes meant for a later session.
func (s *windowsSession) StdinReadyWithin(d time.Duration) (bool, error) {
	ms := uint32(d / time.Millisecond)
	if d > 0 && ms == 0 {
		ms = 1
	}
	ev, err := windows.WaitForSingleObject(windows.Handle(s.in.Fd()), ms)
	if err != nil {
		return false, err
	}
	switch ev {
	case windows.WAIT_OBJECT_0:
		return true, nil
	case uint32(windows.WAIT_TIMEOUT):
		return false, nil
	}
	return false, nil
}
