package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"

	"warden/internal/client/agent"
	clientssh "warden/internal/client/ssh"
	"warden/internal/client/terminal"
	"warden/internal/model"
)

func assertSafeDiagnostic(t *testing.T, s string) {
	t.Helper()
	if !utf8.ValidString(s) {
		t.Fatalf("invalid UTF-8: %q", s)
	}
	for _, r := range strings.TrimSuffix(s, "\n") {
		if unicode.IsControl(r) {
			t.Fatalf("raw diagnostic control %U: %q", r, s)
		}
	}
	if len(s) > 1100 {
		t.Fatalf("unbounded diagnostic: %d bytes", len(s))
	}
}

func TestCLIErrorRendersEscapeControls(t *testing.T) {
	const hostile = "héllo世界\x1b]52;c;synthetic\a\r\n\u009b\xff"
	sentinel := errors.New(hostile)
	previous := agentAuthorization
	defer func() { agentAuthorization = previous }()
	agentAuthorization = func(context.Context, string, string, time.Duration, string, string) (agent.Enrollment, error) {
		return agent.Enrollment{}, fmt.Errorf("relay: %w", sentinel)
	}
	var out, errout bytes.Buffer
	if code := run([]string{"-n", "login"}, &out, &errout, func(key string) (string, bool) {
		if key == "WARDEN_CLIENT_API_BASE_URL" {
			return "https://warden.example", true
		}
		return "", false
	}); code != 1 {
		t.Fatalf("code=%d", code)
	}
	assertSafeDiagnostic(t, errout.String())
	if !strings.Contains(errout.String(), `héllo世界\x1b]52;c;synthetic\u0007\r\n\u009b`) {
		t.Fatalf("unexpected error: %q", errout.String())
	}
	sentinel = errors.New(strings.Repeat("\x1b", 2048))
	out.Reset()
	errout.Reset()
	lookupHTTPS := func(key string) (string, bool) {
		if key == "WARDEN_CLIENT_API_BASE_URL" {
			return "https://warden.example", true
		}
		return "", false
	}
	if code := run([]string{"-n", "login"}, &out, &errout, lookupHTTPS); code != 1 {
		t.Fatalf("code=%d", code)
	}
	assertSafeDiagnostic(t, errout.String())
	if len(errout.String()) > len("login: ")+terminal.MaxErrorBytes+1 {
		t.Fatal("CLI error exceeded encoded-byte cap")
	}

	for _, args := range [][]string{{"ssh", "prod", "true"}, {"db", "prod", "SELECT 1"}, {"xssh", "prod"}, {"cp", "prod:/x", "/y"}, {"port-watch", "prod", "80"}, {"config", "search", "prod"}, {"report", "create", "prod", "--title", "t", "--summary", "s", "--agent-model", "m"}} {
		t.Run(args[0], func(t *testing.T) {
			srv := newCLITestAPI(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(400)
				json.NewEncoder(w).Encode(map[string]string{"code": "validation", "message": hostile})
			}))
			defer srv.Close()
			lookup := func(key string) (string, bool) {
				if key == "WARDEN_CLIENT_API_BASE_URL" {
					return srv.URL, true
				}
				return "", false
			}
			out.Reset()
			errout.Reset()
			if code := run(args, &out, &errout, lookup); code != 1 {
				t.Fatalf("code=%d error=%q", code, errout.String())
			}
			assertSafeDiagnostic(t, errout.String())
		})
	}
}

func TestCLIErrorBoundaryPreservesSSHStreamsAndExitClassification(t *testing.T) {
	srv := newCLITestAPI(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "transport") {
			fmt.Fprint(w, `{"target":{"id":7,"name":"prod","host":"ssh.example","port":22,"username":"user"},"jumps":[]}`)
		} else {
			fmt.Fprint(w, `[{"id":7,"name":"prod","host":"ssh.example","port":22,"username":"user"}]`)
		}
	}))
	defer srv.Close()
	lookup := func(key string) (string, bool) {
		if key == "WARDEN_CLIENT_API_BASE_URL" {
			return srv.URL, true
		}
		return "", false
	}
	previous := runAgentSSH
	defer func() { runAgentSSH = previous }()
	const raw = "\x00\xff\x1b]52;c;raw\a\r\n\u009b"
	exit := &clientssh.ExitStatusError{Status: 23}
	runAgentSSH = func(_ context.Context, _ model.SSHBundle, _ string, streams clientssh.Streams) error {
		fmt.Fprint(streams.Stdout, raw)
		fmt.Fprint(streams.Stderr, raw)
		return fmt.Errorf("typed: %w", exit)
	}
	var out, errout bytes.Buffer
	if code := run([]string{"ssh", "prod", "true"}, &out, &errout, lookup); code != 23 {
		t.Fatalf("typed status lost: %d", code)
	}
	if out.String() != raw || errout.String() != raw {
		t.Fatalf("SSH bytes changed: %q / %q", out.String(), errout.String())
	}

	// The remote data remains untouched even when a final relay diagnostic is
	// rendered afterward. The diagnostic alone is escaped and bounded.
	sentinel := errors.New("remote\x1b]52;c;synthetic\a\r\n\u009b\xff")
	runAgentSSH = func(_ context.Context, _ model.SSHBundle, _ string, streams clientssh.Streams) error {
		fmt.Fprint(streams.Stdout, raw)
		fmt.Fprint(streams.Stderr, raw)
		return fmt.Errorf("relay: %w", sentinel)
	}
	out.Reset()
	errout.Reset()
	if code := run([]string{"ssh", "prod", "true"}, &out, &errout, lookup); code != 1 {
		t.Fatalf("relay code=%d", code)
	}
	if out.String() != raw || !strings.HasPrefix(errout.String(), raw) {
		t.Fatal("relay data changed")
	}
	assertSafeDiagnostic(t, strings.TrimPrefix(errout.String(), raw))

	// xssh passes the actual terminal session through unchanged, not a global
	// filtering stdout/stderr wrapper. Real SSH/PTY tests cover its transport.
	oldNew, oldRun := newTerminalSession, runInteractiveXSSH
	defer func() { newTerminalSession = oldNew; runInteractiveXSSH = oldRun }()
	var terminalOut, terminalErr bytes.Buffer
	session := &diagnosticStreamSession{out: &terminalOut, err: &terminalErr}
	newTerminalSession = func() (terminal.Session, error) { return session, nil }
	runInteractiveXSSH = func(_ context.Context, _ model.SSHBundle, term terminal.Session) error {
		if term != session {
			t.Fatal("terminal session wrapped")
		}
		fmt.Fprint(term.Stdout(), raw)
		fmt.Fprint(term.Stderr(), raw)
		return fmt.Errorf("interactive: %w", exit)
	}
	out.Reset()
	errout.Reset()
	if code := run([]string{"xssh", "prod"}, &out, &errout, lookup); code != 23 {
		t.Fatalf("interactive classification lost: %d", code)
	}
	if terminalOut.String() != raw || terminalErr.String() != raw {
		t.Fatal("interactive bytes changed")
	}
}

type diagnosticStreamSession struct {
	terminal.Session
	out, err io.Writer
}

func (s *diagnosticStreamSession) Stdout() io.Writer { return s.out }
func (s *diagnosticStreamSession) Stderr() io.Writer { return s.err }
