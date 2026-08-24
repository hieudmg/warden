//go:build !windows

package terminal

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

// unixSession implements Session on Linux and other Unix-like systems
// using termios raw mode and SIGWINCH notifications.
type unixSession struct {
	in  *os.File
	out *os.File

	mu    sync.Mutex
	raw   bool
	done  bool
	state *term.State

	stopResize chan struct{}
	stopOnce   sync.Once
	events     chan struct{}
}

// newSession constructs the platform Session for non-Windows targets.
func newSession() (Session, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return nil, errors.New("stdin is not a terminal; interactive mode requires one")
	}
	return &unixSession{
		in:         os.Stdin,
		out:        os.Stdout,
		stopResize: make(chan struct{}),
		events:     make(chan struct{}),
	}, nil
}

// EnterRaw switches the pty slave into raw mode via term.MakeRaw.
func (s *unixSession) EnterRaw() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.raw {
		return nil
	}
	if s.done {
		return errors.New("terminal session already restored")
	}
	state, err := term.MakeRaw(int(s.in.Fd()))
	if err != nil {
		return fmt.Errorf("enter raw mode: %w", err)
	}
	s.state = state
	s.raw = true
	s.startResize()
	return nil
}

// Restore returns the terminal to its pre-raw state, stops resize
// delivery, and closes the ResizeEvents channel.
func (s *unixSession) Restore() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var err error
	if s.raw && s.state != nil {
		err = term.Restore(int(s.in.Fd()), s.state)
		s.state = nil
		s.raw = false
	}
	s.stopOnce.Do(func() {
		if s.stopResize != nil {
			close(s.stopResize)
		}
	})
	if !s.done {
		s.done = true
		if s.events != nil {
			close(s.events)
		}
	}
	return err
}

// startResize forwards SIGWINCH notifications to the ResizeEvents
// channel. The send is non-blocking so a slow consumer never stalls the
// signal loop; Restore stops the goroutine via stopResize. The send is
// also guarded against sending on a closed channel by checking s.done
// under s.mu, which Restore holds while closing events.
func (s *unixSession) startResize() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGWINCH)
	go func() {
		defer signal.Stop(ch)
		for {
			select {
			case <-ch:
				s.mu.Lock()
				done := s.done
				s.mu.Unlock()
				if done {
					return
				}
				select {
				case s.events <- struct{}{}:
				default:
				}
			case <-s.stopResize:
				return
			}
		}
	}()
}

// Size reports the terminal window size from the TIOCGWINSZ ioctl.
func (s *unixSession) Size() (int, int) {
	ws, err := unix.IoctlGetWinsize(int(s.in.Fd()), unix.TIOCGWINSZ)
	if err != nil {
		return 0, 0
	}
	return int(ws.Col), int(ws.Row)
}

func (s *unixSession) ResizeEvents() <-chan struct{} { return s.events }
func (s *unixSession) Stdin() io.Reader              { return s.in }
func (s *unixSession) Stdout() io.Writer             { return s.out }
func (s *unixSession) Stderr() io.Writer             { return os.Stderr }
