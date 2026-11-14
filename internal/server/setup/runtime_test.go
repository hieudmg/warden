package setup

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"testing"
	"testing/fstest"
	"time"

	"warden/internal/config"
)

func TestInitFailedBindDisclosesNoPassword(t *testing.T) {
	var terminal bytes.Buffer
	opts := Options{Config: config.Setup{PublicOrigin: "https://warden.example", RPID: "warden.example", Mode: "proxy", BackendAuthority: "127.0.0.1:8080"}, Bind: "127.0.0.1:8080", DBPath: t.TempDir() + "/vault.db", Assets: fstest.MapFS{}}
	called := false
	err := run(context.Background(), opts, &terminal, runtimeDeps{listen: func(string, string) (net.Listener, error) { return nil, errors.New("bind failed") }, password: func() (string, error) { called = true; return "23456789", nil }, now: time.Now})
	if err == nil || called || terminal.Len() != 0 {
		t.Fatal("password generated/disclosed on failed bind", err, called, terminal.String())
	}
}

func TestInitReadyDeadlineDoesNotMoveDuringPasswordGeneration(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	opts := Options{Config: config.Setup{PublicOrigin: "https://warden.example", RPID: "warden.example", Mode: "proxy", BackendAuthority: listener.Addr().String()}, Bind: listener.Addr().String(), DBPath: t.TempDir() + "/vault.db", Assets: fstest.MapFS{}}
	clock := time.Now()
	var terminal bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	err = run(ctx, opts, &terminal, runtimeDeps{listen: func(string, string) (net.Listener, error) { return listener, nil }, password: func() (string, error) { clock = clock.Add(16 * time.Minute); return "23456789", nil }, now: func() time.Time { return clock }})
	if err == nil || terminal.Len() != 0 {
		t.Fatal("deadline moved after readiness/password generation", err)
	}
}

type blockedTerminal struct{ started, release chan struct{} }

func (w blockedTerminal) Write(b []byte) (int, error) {
	close(w.started)
	<-w.release
	return len(b), nil
}
func TestInitDeadlineIncludesBlockedTerminalOutput(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	terminal := blockedTerminal{make(chan struct{}), make(chan struct{})}
	defer close(terminal.release)
	opts := Options{Config: config.Setup{PublicOrigin: "https://warden.example", RPID: "warden.example", Mode: "proxy", BackendAuthority: listener.Addr().String()}, Bind: listener.Addr().String(), DBPath: t.TempDir() + "/vault.db", Assets: fstest.MapFS{}}
	finished := make(chan error, 1)
	go func() {
		finished <- run(context.Background(), opts, terminal, runtimeDeps{listen: func(string, string) (net.Listener, error) { return listener, nil }, password: func() (string, error) { return "23456789", nil }, now: func() time.Time { return time.Now().Add(-15*time.Minute + 50*time.Millisecond) }})
	}()
	select {
	case <-terminal.started:
	case <-time.After(time.Second):
		t.Fatal("terminal writer not started")
	}
	select {
	case err := <-finished:
		if err == nil {
			t.Fatal("expiry reported success")
		}
	case <-time.After(time.Second):
		t.Fatal("blocked terminal output extended setup lifetime")
	}
}

func TestInitExpirationDoesNotReportInitialization(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	opts := Options{Config: config.Setup{PublicOrigin: "https://warden.example", RPID: "warden.example", Mode: "proxy", BackendAuthority: listener.Addr().String()}, Bind: listener.Addr().String(), DBPath: t.TempDir() + "/vault.db", Assets: fstest.MapFS{}}
	err = run(context.Background(), opts, &bytes.Buffer{}, runtimeDeps{listen: func(string, string) (net.Listener, error) { return listener, nil }, password: func() (string, error) { return "23456789", nil }, now: func() time.Time { return time.Now().Add(-15 * time.Minute) }})
	if err == nil {
		t.Fatal("expired setup reported success")
	}
	if _, err := os.Stat(opts.DBPath); !os.IsNotExist(err) {
		t.Fatal("expired setup initialized storage")
	}
}

type failingListener struct{}

func (failingListener) Accept() (net.Conn, error) { return nil, errors.New("listener failed") }
func (failingListener) Close() error              { return nil }
func (failingListener) Addr() net.Addr            { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080} }
func TestInitListenerFailureExitsImmediately(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	opts := Options{Config: config.Setup{PublicOrigin: "https://warden.example", RPID: "warden.example", Mode: "proxy", BackendAuthority: "127.0.0.1:8080"}, Bind: "127.0.0.1:8080", DBPath: t.TempDir() + "/vault.db", Assets: fstest.MapFS{}}
	err := run(ctx, opts, &bytes.Buffer{}, runtimeDeps{listen: func(string, string) (net.Listener, error) { return failingListener{}, nil }, password: func() (string, error) { return "23456789", nil }, now: time.Now})
	if err == nil || ctx.Err() != nil {
		t.Fatal("listener failure waited for process deadline", err, ctx.Err())
	}
}

func TestInitRejectsRedirectedTerminal(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "redirected")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := Run(context.Background(), Options{}, f); err == nil {
		t.Fatal("accepted redirected terminal")
	}
	info, _ := f.Stat()
	if info.Size() != 0 {
		t.Fatal("secret in redirected output")
	}
}
