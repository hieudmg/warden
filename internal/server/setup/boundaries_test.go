package setup

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"warden/internal/config"
)

type boundaryBody struct{ reads int }

func (b *boundaryBody) Read([]byte) (int, error) { b.reads++; return 0, io.EOF }
func (*boundaryBody) Close() error               { return nil }
func TestCrossOriginTextPlainPOSTRejected(t *testing.T) {
	p, _ := plane(t)
	cookie, csrf := authorize(t, p)
	for _, target := range []string{"/api/v1/setup/password", "/api/v1/setup/registration/begin", "/api/v1/setup/unknown", "/api/v1/unknown"} {
		for _, bad := range []string{"foreign", "null", "missing", "plain", "duplicate", "csrf"} {
			t.Run(target+"/"+bad, func(t *testing.T) {
				if bad == "csrf" && target == "/api/v1/setup/password" {
					return
				}
				body := &boundaryBody{}
				r := httptest.NewRequest("POST", "https://warden.example"+target, body)
				r.Header.Set("Origin", p.cfg.PublicOrigin)
				r.Header.Set("Content-Type", "application/json")
				r.Header.Set("Cookie", cookie)
				r.Header.Set("X-CSRF-Token", csrf)
				switch bad {
				case "foreign":
					r.Header.Set("Origin", "https://attacker.example")
				case "null":
					r.Header.Set("Origin", "null")
				case "missing":
					r.Header.Del("Origin")
				case "plain":
					r.Header.Set("Content-Type", "text/plain")
				case "duplicate":
					r.Header.Add("Origin", p.cfg.PublicOrigin)
				case "csrf":
					r.Header.Del("X-CSRF-Token")
				}
				w := httptest.NewRecorder()
				p.ServeHTTP(w, r)
				if w.Code != 403 || body.reads != 0 || w.Header().Get("Cache-Control") != "no-store" {
					t.Fatalf("status=%d body reads=%d", w.Code, body.reads)
				}
			})
		}
	}
}

type readyTerminal chan struct{}

func (c readyTerminal) Write(b []byte) (int, error) { close(c); return len(b), nil }
func TestSetupOptionsStarCannotBypassHostAndCacheGates(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(readyTerminal)
	done := make(chan error, 1)
	o := Options{Config: config.Setup{PublicOrigin: "https://warden.example", RPID: "warden.example", Mode: "proxy", BackendAuthority: l.Addr().String()}, Bind: l.Addr().String(), DBPath: t.TempDir() + "/vault.db", Assets: fstest.MapFS{}}
	go func() {
		done <- run(ctx, o, ready, runtimeDeps{listen: func(string, string) (net.Listener, error) { return l, nil }, password: func() (string, error) { return "23456789", nil }, now: time.Now})
	}()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("setup did not stop")
		}
	}()
	select {
	case <-ready:
	case <-time.After(time.Second):
		t.Fatal("not ready")
	}
	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(time.Second))
	io.WriteString(c, "OPTIONS * HTTP/1.1\r\nHost: attacker.example\r\nConnection: close\r\n\r\n")
	res, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != 403 || res.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("OPTIONS bypass", res.StatusCode, res.Header)
	}
}

func TestSetupDeadlineNotExtendedBySlowRequest(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(readyTerminal)
	done := make(chan error, 1)
	o := Options{Config: config.Setup{PublicOrigin: "https://warden.example", RPID: "warden.example", Mode: "proxy", BackendAuthority: l.Addr().String()}, Bind: l.Addr().String(), DBPath: t.TempDir() + "/vault.db", Assets: fstest.MapFS{}}
	// Inject only readiness time: the production fixed 15-minute watchdog has
	// 300ms remaining. Request traffic must not move its absolute deadline.
	now := func() time.Time { return time.Now().Add(-15*time.Minute + 300*time.Millisecond) }
	go func() {
		done <- run(ctx, o, ready, runtimeDeps{listen: func(string, string) (net.Listener, error) { return l, nil }, password: func() (string, error) { return "23456789", nil }, now: now})
	}()
	select {
	case <-ready:
	case <-time.After(time.Second):
		t.Fatal("not ready")
	}
	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(2 * time.Second))
	io.WriteString(c, "POST /api/v1/setup/password HTTP/1.1\r\nHost: warden.example\r\nOrigin: https://warden.example\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{")
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expiry reported success")
		}
	case <-time.After(time.Second):
		t.Fatal("slow upload extended absolute setup lifetime")
	}
	raw, _ := io.ReadAll(c)
	if strings.Contains(string(raw), "200 OK") {
		t.Fatal("unfinished setup succeeded")
	}
}
