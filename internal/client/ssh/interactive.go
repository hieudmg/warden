package ssh

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	golangssh "golang.org/x/crypto/ssh"

	"warden/internal/client/terminal"
	"warden/internal/model"
)

// interactiveShellCommand is the remote command started for interactive
// sessions. It is interpreted by the user's shell on the remote host and
// re-execs a fresh login shell so login rc files load. -l is the portable
// login flag accepted by sh, bash, zsh, dash, and fish; ${SHELL:-sh}
// guards the rare case where the remote environment does not set $SHELL.
// A profile default directory can be prefixed as a cd once the profile
// schema carries one.
const interactiveShellCommand = "exec ${SHELL:-sh} -l"

// termReadWriter adapts a terminal.Session to the io.ReadWriter used for
// interactive host-key confirmation prompts.
type termReadWriter struct{ term terminal.Session }

func (t termReadWriter) Read(p []byte) (int, error)  { return t.term.Stdin().Read(p) }
func (t termReadWriter) Write(p []byte) (int, error) { return t.term.Stdout().Write(p) }

// RunInteractive attaches the caller's terminal to an interactive remote
// shell over the bundle's jump chain. It enters raw mode, requests a PTY
// sized to the local terminal, streams bytes both ways, translates local
// Ctrl-C into a remote SIGINT request, forwards Ctrl-D as a byte so the
// remote shell/tty interprets it as EOF (OpenSSH semantics), delivers
// resize changes as window-change requests, and restores the terminal on
// every exit path. acceptNew enables interactive first-use host-key
// confirmation on the terminal; changed and unconfirmed keys always fail.
func RunInteractive(ctx context.Context, bundle model.SSHBundle, term terminal.Session, acceptNew bool) error {
	return runInteractive(ctx, bundle, term, DialOptions{AcceptNew: acceptNew, Terminal: termReadWriter{term}})
}

// runInteractive is RunInteractive with explicit dial options (tests
// inject host-key callbacks).
func runInteractive(ctx context.Context, bundle model.SSHBundle, term terminal.Session, opts DialOptions) error {
	if err := term.EnterRaw(); err != nil {
		return fmt.Errorf("enter raw mode: %w", err)
	}
	defer term.Restore()

	client, clients, err := DialChain(ctx, bundle, opts)
	if err != nil {
		return err
	}
	defer func() {
		for _, c := range clients {
			c.Close()
		}
	}()

	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("open ssh session: %w", err)
	}
	defer session.Close()

	// Non-secret terminal metadata only; env failures are non-fatal
	// because servers may reject env requests.
	termType := os.Getenv("TERM")
	if termType == "" {
		termType = "xterm-256color"
	}
	_ = session.Setenv("TERM", termType)
	if v := os.Getenv("COLORTERM"); v != "" {
		_ = session.Setenv("COLORTERM", v)
	}

	w, h := term.Size()
	if err := session.RequestPty(termType, h, w, golangssh.TerminalModes{}); err != nil {
		return fmt.Errorf("request pty: %w", err)
	}
	forwardAgent(client, session)

	stdinPipe, err := session.StdinPipe()
	if err != nil {
		return fmt.Errorf("open remote stdin: %w", err)
	}
	session.Stdout = term.Stdout()
	session.Stderr = term.Stderr()

	if err := session.Start(interactiveShellCommand); err != nil {
		return fmt.Errorf("start remote shell: %w", err)
	}

	// Input pump: forward terminal bytes and translate Ctrl-C to a
	// remote SIGINT request. Ctrl-D (0x04) is forwarded as a byte, like
	// OpenSSH: the remote pty/shell interprets it as EOF. Closing local
	// stdin instead would leave a real sshd pty session running (channel
	// EOF does not end a pty shell). The pump exits on session end via
	// stopPump; a read blocked on the terminal unwinds only when the
	// process exits (or the reader closes), which is fine for a one-shot
	// CLI.
	stopPump := make(chan struct{})
	go func() {
		pumpInteractiveInput(ctx, session, stdinPipe, term.Stdin(), stopPump)
	}()

	// Resize pump: forward local size changes as window-change requests.
	// Restore closes ResizeEvents, ending this loop.
	go func() {
		for range term.ResizeEvents() {
			w, h := term.Size()
			if w > 0 && h > 0 {
				_ = session.WindowChange(h, w)
			}
		}
	}()

	waitCh := make(chan error, 1)
	go func() { waitCh <- session.Wait() }()

	var result error
	select {
	case err := <-waitCh:
		close(stopPump)
		stdinPipe.Close()
		if err == nil {
			result = nil
		} else {
			var exitErr *golangssh.ExitError
			if errors.As(err, &exitErr) {
				result = &ExitStatusError{Status: exitErr.ExitStatus()}
			} else {
				result = fmt.Errorf("remote shell failed: %w", err)
			}
		}
	case <-ctx.Done():
		close(stopPump)
		session.Close()
		<-waitCh
		stdinPipe.Close()
		result = ctx.Err()
	}
	return result
}

// readResult carries one stdin read outcome.
type readResult struct {
	n   int
	err error
}

// pumpInteractiveInput forwards local input bytes to the remote session's
// stdin pipe. Byte 0x03 (Ctrl-C) is translated to a remote SIGINT signal
// request instead of being forwarded; byte 0x04 (Ctrl-D) is forwarded as a
// byte so the remote shell/tty interprets it as EOF, exactly like OpenSSH
// in raw mode. All other bytes pass through unchanged. Signal request
// failures are ignored: aborting the session because the remote rejected a
// signal would be worse than a missed interrupt.
//
// The pump never closes pipe: runInteractive owns the stdin pipe and
// closes it once after the session ends or the context is cancelled.
// Closing from two goroutines would race on x/crypto's channel state.
// A read blocked on the terminal unwinds only when the process exits (or
// the reader closes), which is fine for a one-shot CLI.
func pumpInteractiveInput(ctx context.Context, session *golangssh.Session, pipe io.Writer, stdin io.Reader, stop <-chan struct{}) {
	buf := make([]byte, 256)
	for {
		readCh := make(chan readResult, 1)
		go func() {
			n, err := stdin.Read(buf)
			readCh <- readResult{n: n, err: err}
		}()

		var r readResult
		select {
		case r = <-readCh:
		case <-ctx.Done():
			return
		case <-stop:
			return
		}

		start := 0
		for i, b := range buf[:r.n] {
			if b == 0x03 { // Ctrl-C
				if i > start {
					pipe.Write(buf[start:i])
				}
				_ = session.Signal(golangssh.SIGINT)
				start = i + 1
			}
		}
		if start < r.n {
			if _, err := pipe.Write(buf[start:r.n]); err != nil {
				return
			}
		}
		if r.err != nil {
			return
		}
	}
}
