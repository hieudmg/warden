package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"warden/internal/client/api"
	"warden/internal/model"
	"warden/internal/server"
	"warden/internal/server/audit"
	"warden/internal/server/profiles"
	"warden/internal/store"
)

func TestHTTPCLIProductionJourney(t *testing.T) {
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatal(err)
	}
	s, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "fixture.db"), key)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RequestURI() != "/items?limit=2" {
			t.Errorf("path=%s", r.URL.RequestURI())
		}
		if r.Header.Get("Authorization") != "Bearer server-only" {
			t.Errorf("auth=%q", r.Header.Get("Authorization"))
		}
		b, _ := io.ReadAll(r.Body)
		if r.Method == "POST" {
			if string(b) != `{"n":2}` || r.Header.Get("Content-Type") != "application/json" {
				t.Errorf("request body/type %q %q", b, r.Header.Get("Content-Type"))
			}
			w.WriteHeader(201)
			fmt.Fprint(w, "created")
			return
		}
		if r.Method == "PATCH" {
			if len(b) != 0 || r.Header.Get("Content-Type") != "application/json" {
				t.Error("empty BODY lost default content type")
			}
			fmt.Fprint(w, "empty")
			return
		}
		if r.Method == "PUT" {
			if string(b) != "hello" || r.Header.Get("Content-Type") != "text/plain" {
				t.Error("custom type")
			}
			fmt.Fprint(w, "updated")
			return
		}
		w.WriteHeader(409)
		fmt.Fprint(w, "upstream conflict\n")
	}))
	defer up.Close()
	mux := http.NewServeMux()
	profiles.New(s, audit.New(s)).Register(mux)
	srv := httptest.NewServer(server.New("", mux).Handler())
	defer srv.Close()
	client := api.New(srv.URL, nil)
	token := "server-only"
	created, err := client.CreateHTTP(context.Background(), model.HTTPConnectionRequest{Name: "service", Origin: up.URL, AuthType: "bearer", Credential: &token, Note: "operations"})
	if err != nil {
		t.Fatal(err)
	}
	if !created.HasCredential {
		t.Fatal("secret presence")
	}
	home := t.TempDir()
	env := func(k string) (string, bool) {
		switch k {
		case "HOME":
			return home, true
		case "WARDEN_CLIENT_API_BASE_URL":
			return srv.URL, true
		case "WARDEN_CLIENT_TIMEOUT":
			return "5s", true
		}
		return "", false
	}
	for _, tc := range []struct {
		args            []string
		code            int
		out, diagnostic string
	}{
		{[]string{"http", "POST", "service", "/items?limit=2", `{"n":2}`}, 0, "created", ""},
		{[]string{"http", "--content-type", "text/plain", "PUT", "service", "/items?limit=2", "hello"}, 0, "updated", ""},
		{[]string{"http", "GET", "service", "/items?limit=2"}, 1, "upstream conflict\n", "409"},
		{[]string{"http", "PATCH", "service", "/items?limit=2", ""}, 0, "empty", ""},
		{[]string{"http", "GET", "missing", "/items?limit=2"}, 1, "", "not found"},
	} {
		var out, diag bytes.Buffer
		code := run(tc.args, &out, &diag, env)
		if code != tc.code || out.String() != tc.out || (tc.diagnostic == "" && diag.Len() != 0) || (tc.diagnostic != "" && !strings.Contains(diag.String(), tc.diagnostic)) {
			t.Fatalf("%v: code=%d out=%q diag=%q", tc.args, code, out.String(), diag.String())
		}
		if strings.Contains(out.String()+diag.String(), token) {
			t.Fatal("CLI secret leaked")
		}
	}
	if err := client.SetHTTPArchived(context.Background(), created.ID, true); err != nil {
		t.Fatal(err)
	}
	var out, diag bytes.Buffer
	if code := run([]string{"http", "GET", "service", "/items?limit=2"}, &out, &diag, env); code != 1 || !strings.Contains(diag.String(), "not found") {
		t.Fatalf("archive code=%d %q", code, diag.String())
	}
}

func TestHTTPCLIAllAuthenticationModesPreserveAndRotate(t *testing.T) {
	ctx := context.Background()
	var key [32]byte
	s, err := store.Open(ctx, filepath.Join(t.TempDir(), "fixture.db"), key)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var calls atomic.Int32
	received := make(chan http.Header, 6)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		received <- r.Header.Clone()
		fmt.Fprint(w, "ok")
	}))
	defer up.Close()
	mux := http.NewServeMux()
	profiles.New(s, audit.New(s)).Register(mux)
	srv := httptest.NewServer(server.New("", mux).Handler())
	defer srv.Close()
	client := api.New(srv.URL, nil)
	home := t.TempDir()
	env := func(k string) (string, bool) {
		switch k {
		case "HOME":
			return home, true
		case "WARDEN_CLIENT_API_BASE_URL":
			return srv.URL, true
		}
		return "", false
	}
	for _, mode := range []string{"bearer", "x_api_key", "basic"} {
		t.Run(mode, func(t *testing.T) {
			secret, user, password := "initial-token", "initial-user", "initial-password"
			req := model.HTTPConnectionRequest{Name: mode, Origin: up.URL, AuthType: mode}
			if mode == "basic" {
				req.Username = &user
				req.Password = &password
			} else {
				req.Credential = &secret
			}
			p, err := client.CreateHTTP(ctx, req)
			if err != nil {
				t.Fatal(err)
			}
			req.Credential = nil
			req.Username = nil
			req.Password = nil
			req.Note = "metadata edit"
			if _, err := client.UpdateHTTP(ctx, p.ID, req); err != nil {
				t.Fatal(err)
			}
			invoke := func() {
				t.Helper()
				var out, diag bytes.Buffer
				if code := run([]string{"http", "GET", mode, "/auth"}, &out, &diag, env); code != 0 || out.String() != "ok" {
					t.Fatalf("CLI=%d %q %q", code, out.String(), diag.String())
				}
				headers := <-received
				switch mode {
				case "bearer":
					if headers.Get("Authorization") != "Bearer "+secret || headers.Get("X-API-Key") != "" {
						t.Fatal("bearer not preserved/rotated")
					}
				case "x_api_key":
					if headers.Get("X-API-Key") != secret || headers.Get("Authorization") != "" {
						t.Fatal("API key not preserved/rotated")
					}
				case "basic":
					request := &http.Request{Header: headers}
					u, p, ok := request.BasicAuth()
					if !ok || u != user || p != password || headers.Get("X-API-Key") != "" {
						t.Fatal("basic credentials not preserved/rotated")
					}
				}
			}
			invoke()
			secret, user, password = "rotated-token", "rotated-user", "rotated-password"
			if mode == "basic" {
				req.Username = &user
				req.Password = &password
			} else {
				req.Credential = &secret
			}
			if _, err := client.UpdateHTTP(ctx, p.ID, req); err != nil {
				t.Fatal(err)
			}
			invoke()
			req.Credential = nil
			req.Username = nil
			req.Password = nil
			if mode == "basic" {
				req.AuthType = "bearer"
			} else {
				req.AuthType = "basic"
			}
			if _, err := client.UpdateHTTP(ctx, p.ID, req); err != nil {
				t.Fatal(err)
			}
			before := calls.Load()
			var out, diag bytes.Buffer
			if code := run([]string{"http", "GET", mode, "/auth"}, &out, &diag, env); code != 1 || !strings.Contains(diag.String(), "credentials are incomplete") || calls.Load() != before {
				t.Fatalf("auth switch reused old credentials: %d %q", code, diag.String())
			}
		})
	}
}

func TestHTTPCLIHelpAndUsageOffline(t *testing.T) {
	for _, args := range [][]string{{"http", "--help"}, {"http", "-h"}} {
		var out, diag bytes.Buffer
		code := run(args, &out, &diag, func(string) (string, bool) { t.Fatal("help read config/environment"); return "", false })
		if code != 0 || !strings.Contains(out.String(), "warden http") || !strings.Contains(out.String(), "PATH") {
			t.Fatalf("help=%d %q %q", code, out.String(), diag.String())
		}
	}
	for _, args := range [][]string{{"http"}, {"http", "GET", "service"}, {"http", "GET", "service", "relative"}, {"http", "GET", "service", "//host"}, {"http", "GET", "service", "/", "a", "b"}, {"http", "TRACE", "service", "/"}, {"http", "GET", "service", "/bad%zz"}, {"http", "--content-type", "text/plain\r\nX: bad", "POST", "service", "/", "x"}} {
		var out, diag bytes.Buffer
		if code := run(args, &out, &diag, func(string) (string, bool) {
			t.Fatal("invalid usage must not read configuration/environment")
			return "", false
		}); code != 2 {
			t.Fatalf("usage %v: %d %q", args, code, diag.String())
		}
	}
}

func TestHTTPConfigSearchProductionMetadata(t *testing.T) {
	var key [32]byte
	s, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "fixture.db"), key)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for _, p := range []model.HTTPProfile{{Name: "api-prod", Origin: "http://localhost:9000", AuthType: "x_api_key", Credential: []byte("unsearchable-secret"), Note: "operations\x1b[31m"}, {Name: "api-archived", Origin: "https://example.test", AuthType: "basic"}} {
		p, err = s.CreateHTTP(context.Background(), p)
		if err != nil {
			t.Fatal(err)
		}
		if p.Name == "api-archived" {
			if err := s.SetHTTPArchived(context.Background(), p.ID, true); err != nil {
				t.Fatal(err)
			}
		}
	}
	mux := http.NewServeMux()
	profiles.New(s, audit.New(s)).Register(mux)
	srv := httptest.NewServer(server.New("", mux).Handler())
	defer srv.Close()
	home := t.TempDir()
	env := func(k string) (string, bool) {
		switch k {
		case "HOME":
			return home, true
		case "WARDEN_CLIENT_API_BASE_URL":
			return srv.URL, true
		}
		return "", false
	}
	for _, query := range []string{"api", "localhost", "unsearchable-secret"} {
		var out, diag bytes.Buffer
		code := run([]string{"-n", "config", "search", query}, &out, &diag, env)
		if code != 0 {
			t.Fatal(code, diag.String())
		}
		if query == "unsearchable-secret" {
			if out.String() != "No matching connections.\n" {
				t.Fatal(out.String())
			}
			continue
		}
		if !strings.Contains(out.String(), "HTTP\n- api-prod — http://localhost:9000 — Note: operations") || strings.Contains(out.String(), "api-archived") || strings.Contains(out.String(), "\x1b") || strings.Contains(out.String(), "unsearchable-secret") {
			t.Fatalf("search=%q", out.String())
		}
	}
}
