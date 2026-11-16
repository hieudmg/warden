package runtime

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"warden/internal/server"
)

func TestExpensiveErrorsAndPanicReleaseSlotsAndConsumeAdmittedGrants(t *testing.T) {
	for _, panicHandler := range []bool{false, true} {
		t.Run(map[bool]string{false: "error", true: "panic"}[panicHandler], func(t *testing.T) {
			p, _, _, key, signer := runtimeFixture(t)
			browser, csrf := sessionFor(t, p)
			p.vault.Unlock(key, p.vault.Generation())
			p.managed = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if panicHandler {
					w.Write([]byte("synthetic-private-buffer"))
					panic("synthetic")
				}
				server.WriteError(w, 500, "internal_error", "internal error")
			})
			g := requestGrant(t, p, signer, browser, csrf, "import", "POST", "/api/v1/data/import", "{}")
			r := httptest.NewRequest("POST", "https://warden.example/api/v1/data/import", strings.NewReader("{}"))
			r.AddCookie(browser)
			r.Header.Set("Origin", p.cfg.PublicOrigin)
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("X-CSRF-Token", csrf)
			r.Header.Set("X-Warden-Action", g)
			w := httptest.NewRecorder()
			server.New("", p).Handler().ServeHTTP(w, r)
			if w.Code != 500 || w.Header().Get("Cache-Control") != "no-store" || strings.Contains(w.Body.String(), "synthetic-private-buffer") || len(p.transfers) != 0 {
				t.Fatal("error retained state", w.Code, len(p.transfers))
			}
			p.mu.Lock()
			_, present := p.grants[hash(g)]
			p.mu.Unlock()
			if present {
				t.Fatal("admitted grant survived failure")
			}
			done := make(chan struct{})
			go func() { p.vault.Lock(); close(done) }()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("error retained lease")
			}
		})
	}
}
