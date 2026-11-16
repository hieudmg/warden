package runtime

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestExpensiveConcurrencySaturationAndCleanup(t *testing.T) {
	for _, tc := range []struct {
		name, path, method, purpose, body string
		limit                             int
	}{{"transfer", "/api/v1/data/import", "POST", "import", "{}", 2}, {"crypto", "/api/v1/key-pairs/1", "GET", "key_reveal", "", 4}, {"transfer-injected", "/api/v1/data/import", "POST", "import", "{}", 1}} {
		t.Run(tc.name, func(t *testing.T) {
			p, _, _, key, signer := runtimeFixture(t)
			browser, csrf := sessionFor(t, p)
			p.vault.Unlock(key, p.vault.Generation())
			if tc.name == "transfer-injected" {
				p.transfers = make(chan struct{}, tc.limit)
			}
			entered := make(chan struct{}, tc.limit)
			var calls atomic.Int32
			p.managed = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if calls.Add(1) <= int32(tc.limit) {
					entered <- struct{}{}
					<-r.Context().Done()
				}
				w.WriteHeader(204)
			})
			// All grants are genuine signed assertions, not manually seeded verdicts.
			grants := make([]string, tc.limit+1)
			for n := range grants {
				grants[n] = requestGrant(t, p, signer, browser, csrf, tc.purpose, tc.method, tc.path, tc.body)
			}
			makeRequest := func(ctx context.Context, g string) *http.Request {
				r := httptest.NewRequest(tc.method, "https://warden.example"+tc.path, strings.NewReader(tc.body)).WithContext(ctx)
				r.AddCookie(browser)
				r.Header.Set("Origin", p.cfg.PublicOrigin)
				r.Header.Set("Content-Type", "application/json")
				r.Header.Set("X-CSRF-Token", csrf)
				r.Header.Set("X-Warden-Action", g)
				return r
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan struct{}, tc.limit)
			for n := 0; n < tc.limit; n++ {
				go func(n int) { p.ServeHTTP(httptest.NewRecorder(), makeRequest(ctx, grants[n])); done <- struct{}{} }(n)
			}
			for n := 0; n < tc.limit; n++ {
				select {
				case <-entered:
				case <-time.After(time.Second):
					t.Fatal("request did not enter")
				}
			}
			if w := call(p, "GET", "/api/v1/auth/status", nil, browser, csrf); w.Code != 200 {
				t.Fatal("saturation blocked status", w.Code)
			}
			if w := call(p, "GET", "/api/v1/groups", nil, browser, csrf); w.Code != 204 {
				t.Fatal("saturation serialized ordinary CRUD", w.Code)
			}
			w := httptest.NewRecorder()
			p.ServeHTTP(w, makeRequest(context.Background(), grants[tc.limit]))
			if w.Code != 429 || w.Header().Get("Retry-After") == "" || w.Header().Get("Cache-Control") != "no-store" {
				t.Errorf("saturation status=%d calls=%d", w.Code, calls.Load())
			}
			// Saturation must not consume the rejected grant; admitted requests do.
			p.mu.Lock()
			_, retained := p.grants[hash(grants[tc.limit])]
			p.mu.Unlock()
			if !retained {
				t.Error("saturation consumed fresh grant")
			}
			cancel()
			for n := 0; n < tc.limit; n++ {
				select {
				case <-done:
				case <-time.After(time.Second):
					t.Fatal("canceled operation retained slot/lease")
				}
			}
			// Lock completion proves all held leases were released; unlock then retry.
			p.vault.Lock()
			if err := p.vault.Unlock(key, p.vault.Generation()); err != nil {
				t.Fatal(err)
			}
			// Generation changed, so old grants cannot authorize a retry after lock.
			g := requestGrant(t, p, signer, browser, csrf, tc.purpose, tc.method, tc.path, tc.body)
			w = httptest.NewRecorder()
			p.ServeHTTP(w, makeRequest(context.Background(), g))
			if w.Code != 204 {
				t.Fatal("slot not released", w.Code, w.Body)
			}
			w = httptest.NewRecorder()
			p.ServeHTTP(w, makeRequest(context.Background(), g))
			if w.Code != 403 {
				t.Fatal("successful grant reused", w.Code)
			}
		})
	}
}
