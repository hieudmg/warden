package runtime

import (
	"context"
	"encoding/json"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"warden/internal/config"
	"warden/internal/server"
	"warden/internal/web"
)

func TestUIFramingAndCSPProductionAssets(t *testing.T) {
	p, _, _, key, _ := runtimeFixture(t)
	p.managed = server.ServeUI(http.NotFoundHandler(), web.Distribution())
	paths := []string{"/", "/ssh", "/databases", "/key-pairs", "/projects", "/assets/missing.js"}
	err := fs.WalkDir(web.Distribution(), "assets", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			paths = append(paths, "/"+path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, unlocked := range []bool{false, true} {
		if unlocked {
			if err = p.vault.Unlock(key, p.vault.Generation()); err != nil {
				t.Fatal(err)
			}
		}
		for _, path := range paths {
			req := httptest.NewRequest("GET", "https://warden.example"+path, nil)
			rec := httptest.NewRecorder()
			p.ServeHTTP(rec, req)
			for key, want := range map[string]string{"X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer"} {
				if rec.Header().Get(key) != want {
					t.Fatal(path, key)
				}
			}
			csp := rec.Header().Get("Content-Security-Policy")
			for _, want := range []string{"default-src 'none'", "script-src 'self';", "connect-src 'self'", "font-src 'self'", "frame-ancestors 'none'", "base-uri 'none'", "object-src 'none'", "form-action 'self'"} {
				if !strings.Contains(csp, want) {
					t.Fatal(path, csp)
				}
			}
			if strings.Contains(csp, "unsafe-eval") || strings.Contains(csp, "script-src 'self' 'unsafe-inline'") {
				t.Fatal(csp)
			}
			if path == "/assets/missing.js" {
				if rec.Code != 404 || rec.Header().Get("Cache-Control") != "no-store" {
					t.Fatal(rec.Code, rec.Header())
				}
			} else {
				if rec.Code != 200 || rec.Body.Len() == 0 {
					t.Fatal(path, rec.Code)
				}
				cache := "no-store"
				if strings.HasPrefix(path, "/assets/") {
					cache = "public, max-age=31536000, immutable"
				}
				if rec.Header().Get("Cache-Control") != cache {
					t.Fatal(path, rec.Header())
				}
			}
		}
	}
}

// Starts the real runtime against ONLY the preceding setup fixture's new DB.
// The browser uses real signed synthetic credentials; no cookies/tokens are seeded.
func TestUIBrowserAccountRuntimeFixture(t *testing.T) { TestUIBrowserRuntimeFixture(t) }
func TestUIBrowserRuntimeFixture(t *testing.T) {
	dir := os.Getenv("WARDEN_UI_BROWSER_DIR")
	if dir == "" {
		t.Skip("requires opt-in disposable browser runner")
	}
	if !filepath.IsAbs(dir) || !strings.HasPrefix(filepath.Base(dir), "warden-t9-browser-") {
		t.Fatal("not a disposable browser directory")
	}
	raw, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cfg config.Setup
	if err = json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	public, err := url.Parse(cfg.PublicOrigin)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, Options{Config: cfg, Bind: "127.0.0.1:" + public.Port(), DBPath: filepath.Join(dir, "vault.db"), Assets: web.Distribution()})
	}()
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case err := <-done:
			if err != nil && err != context.Canceled {
				t.Fatal(err)
			}
			return
		case <-ticker.C:
			if _, err = os.Stat(filepath.Join(dir, "stop")); err == nil {
				cancel()
			}
		case <-ctx.Done():
			if err = <-done; err != nil && err != context.Canceled {
				t.Fatal(err)
			}
			return
		}
	}
}
