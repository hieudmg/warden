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
	"unsafe"

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

var procReadConsoleInputEx = windows.NewLazySystemDLL("kernel32.dll").NewProc("ReadConsoleInputExW")

// Console calls go through these variables so Windows-only tests can
// exercise mode changes and resize polling without a real console.
var (
	winGetConsoleMode             = windows.GetConsoleMode
	winSetConsoleMode             = windows.SetConsoleMode
	winGetConsoleScreenBufferInfo = windows.GetConsoleScreenBufferInfo
	winReadConsoleInputNowait     = readConsoleInputNowait
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

	pickerHighSurrogate rune

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

func (s *windowsSession) EnableFullScreenOutput() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.raw || !s.ansi {
		return errors.New("full-screen output requires a raw console with VT enabled")
	}
	// Bubble Tea emits bare LF for relative cursor moves on Windows. Keep
	// the column on LF without changing the raw mode used by remote SSH.
	mode := s.origOut | winOutputVTExtra | windows.DISABLE_NEWLINE_AUTO_RETURN
	if err := winSetConsoleMode(windows.Handle(s.out.Fd()), mode); err != nil {
		return fmt.Errorf("enable DISABLE_NEWLINE_AUTO_RETURN: %w", err)
	}
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

// consoleInputRecord is Win32 INPUT_RECORD with its union represented as
// KEY_EVENT_RECORD. The union starts at offset 4 and occupies 16 bytes.
type consoleInputRecord struct {
	eventType   uint16
	_           uint16
	keyDown     uint32
	repeatCount uint16
	virtualKey  uint16
	_           uint16 // Virtual scan code.
	unicodeChar uint16
	_           uint32 // Control key state.
}

func readConsoleInputNowait(in windows.Handle, record *consoleInputRecord) (bool, error) {
	const consoleReadNowait = 0x0002
	if err := procReadConsoleInputEx.Find(); err != nil {
		return false, err
	}
	var count uint32
	r, _, err := procReadConsoleInputEx.Call(uintptr(in), uintptr(unsafe.Pointer(record)), 1, uintptr(unsafe.Pointer(&count)), consoleReadNowait)
	if r == 0 {
		return false, err
	}
	return count != 0, nil
}

// PollKey reads an ASCII key or native arrow and its repeat count without waiting.
// A zero count means no key was available. Use in place of, not alongside,
// reads from Stdin while port-watch owns the raw console.
func (s *windowsSession) PollKey() (key rune, repeat int, err error) {
	const (
		keyEvent = 0x0001
		vkMenu   = 0x12
		vkLeft   = 0x25
		vkUp     = 0x26
		vkRight  = 0x27
		vkDown   = 0x28
	)
	in := windows.Handle(s.in.Fd())
	// Read one record at a time to leave keys after quit in the console queue.
	// Bound ignored records per poll so a busy console can't starve redraws.
	for range 32 {
		var record consoleInputRecord
		ok, err := winReadConsoleInputNowait(in, &record)
		if !ok || err != nil {
			return 0, 0, err
		}
		// Alt+numpad composition can deliver a character on Alt release.
		if record.eventType != keyEvent || (record.keyDown == 0 && record.virtualKey != vkMenu) {
			continue
		}
		code := rune(record.unicodeChar)
		switch {
		case code == 0:
			switch record.virtualKey {
			case vkUp:
				code = KeyUp
			case vkDown:
				code = KeyDown
			case vkLeft:
				code = KeyLeft
			case vkRight:
				code = KeyRight
			default:
				continue
			}
		case code > 0x7f:
			continue
		case code == 0x1a: // Match os.File's console EOF (Ctrl-Z).
			return 0, 0, io.EOF
		}
		return code, max(1, int(record.repeatCount)), nil
	}
	return 0, 0, nil
}

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
