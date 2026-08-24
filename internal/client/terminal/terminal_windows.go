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
// forwarded as a remote SIGINT by the interactive layer instead of
// terminating the process.
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
	stopOnce   sync.Once
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
// processing, and registers the console control handler.
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

	if err := windows.GetConsoleMode(inH, &s.origIn); err != nil {
		return fmt.Errorf("get console input mode: %w", err)
	}
	if err := windows.SetConsoleMode(inH, winRawInputMode); err != nil {
		return fmt.Errorf("set raw console input mode: %w", err)
	}
	if err := windows.GetConsoleMode(outH, &s.origOut); err == nil {
		if err := windows.SetConsoleMode(outH, s.origOut|winOutputVTExtra); err != nil {
			s.origOut = 0 // output VT processing is best-effort
		} else {
			s.ansi = true
		}
	}

	cb := syscall.NewCallback(consoleCtrlHandler)
	if r, _, callErr := procSetConsoleCtrlHandler.Call(cb, 1); r == 0 {
		_ = windows.SetConsoleMode(inH, s.origIn)
		return fmt.Errorf("register console ctrl handler: %v", callErr)
	}
	s.handler = cb

	s.raw = true
	s.startResize()
	return nil
}

// Restore unregisters the control handler and returns the console to its
// original modes, then stops resize delivery and closes ResizeEvents.
func (s *windowsSession) Restore() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var err error
	if s.raw {
		if r, _, callErr := procSetConsoleCtrlHandler.Call(s.handler, 0); r == 0 && err == nil {
			err = fmt.Errorf("unregister console ctrl handler: %v", callErr)
		}
		s.handler = 0
		if mErr := windows.SetConsoleMode(windows.Handle(s.in.Fd()), s.origIn); mErr != nil && err == nil {
			err = fmt.Errorf("restore console input mode: %w", mErr)
		}
		if s.origOut != 0 {
			_ = windows.SetConsoleMode(windows.Handle(s.out.Fd()), s.origOut)
		}
		s.raw = false
	}
	s.stopOnce.Do(func() { close(s.stopResize) })
	if !s.done {
		s.done = true
		close(s.events)
	}
	return err
}

// startResize polls the visible console window size because Windows does
// not deliver resize notifications on the byte stream.
func (s *windowsSession) startResize() {
	go func() {
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
	if err := windows.GetConsoleScreenBufferInfo(windows.Handle(s.out.Fd()), &info); err != nil {
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
