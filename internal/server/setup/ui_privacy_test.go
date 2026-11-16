package setup

import (
	"context"
	"encoding/json"
	"io"
	"io/fs"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"warden/internal/config"
	"warden/internal/server/auth"
	"warden/internal/web"
)

func TestUIFramingAndCSPProductionAssets(t *testing.T) {
	assets, err := web.SetupDistribution()
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Setup{PublicOrigin: "https://localhost", RPID: "localhost", Mode: "tls"}
	verifier, err := auth.NewVerifier(cfg.PublicOrigin, cfg.RPID)
	if err != nil {
		t.Fatal(err)
	}
	p, err := newPlane(cfg, assets, verifier, func(context.Context, []byte) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	p.ready(time.Now(), "23456789")
	names, err := fs.ReadFile(web.Distribution(), "setup-assets.json")
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	if err = json.Unmarshal(names, &paths); err != nil {
		t.Fatal(err)
	}
	paths = append(paths, "", "assets/missing.js")
	for _, path := range paths {
		req := httptest.NewRequest("GET", "https://localhost/"+path, nil)
		rec := httptest.NewRecorder()
		p.ServeHTTP(rec, req)
		for key, want := range map[string]string{"X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer"} {
			if rec.Header().Get(key) != want {
				t.Fatalf("%s %s", path, key)
			}
		}
		csp := rec.Header().Get("Content-Security-Policy")
		for _, want := range []string{"default-src 'none'", "script-src 'self'", "frame-ancestors 'none'", "base-uri 'none'", "object-src 'none'", "form-action 'self'"} {
			if !strings.Contains(csp, want) {
				t.Fatal(path, csp)
			}
		}
		if strings.Contains(csp, "unsafe-") {
			t.Fatal("setup does not need inline policy", csp)
		}
		if path == "assets/missing.js" {
			if rec.Code != 404 || rec.Header().Get("Cache-Control") != "no-store" {
				t.Fatal(rec.Code, rec.Header())
			}
		} else if rec.Code != 200 {
			t.Fatal(path, rec.Code)
		}
	}
}

// Opt-in disposable browser fixture ONLY. No production route/verifier bypass.
// The synthetic password is accepted through the unchanged setup cookie/CSRF flow.
func TestUIBrowserSetupFixture(t *testing.T) {
	dir := os.Getenv("WARDEN_UI_BROWSER_DIR")
	if dir == "" {
		t.Skip("requires opt-in disposable browser runner")
	}
	if !filepath.IsAbs(dir) || !strings.HasPrefix(filepath.Base(dir), "warden-t9-browser-") {
		t.Fatal("not a disposable browser directory")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	cfg := config.Setup{PublicOrigin: "https://localhost:" + strings.Split(listener.Addr().String(), ":")[1], RPID: "localhost", Mode: "tls", TLSCertificate: filepath.Join(dir, "cert.pem"), TLSKey: filepath.Join(dir, "key.pem")}
	raw, _ := json.Marshal(cfg)
	if err = os.WriteFile(filepath.Join(dir, "config.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	assets, err := web.SetupDistribution()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	err = run(ctx, Options{Config: cfg, Bind: listener.Addr().String(), DBPath: filepath.Join(dir, "vault.db"), Assets: assets}, io.Discard, runtimeDeps{listen: func(string, string) (net.Listener, error) { return listener, nil }, password: func() (string, error) { return "23456789", nil }, now: time.Now})
	if err != nil {
		t.Fatal(err)
	}
}
