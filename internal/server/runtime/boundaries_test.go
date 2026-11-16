package runtime

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"warden/internal/server"
	"warden/internal/store"
)

type unreadBoundaryBody struct{ reads int }

func (b *unreadBoundaryBody) Read([]byte) (int, error) { b.reads++; return 0, io.EOF }
func (*unreadBoundaryBody) Close() error               { return nil }

func TestCrossOriginTextPlainPOSTRejected(t *testing.T) {
	p, _, _, key, _ := runtimeFixture(t)
	browser, csrf := sessionFor(t, p)
	if err := p.vault.Unlock(key, p.vault.Generation()); err != nil {
		t.Fatal(err)
	}
	calls := 0
	p.managed = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; w.WriteHeader(204) })
	for _, target := range []string{"/api/v1/ssh-connections", "/api/v1/data/import", "/api/v1/reports", "/api/v1/auth/login/begin", "/api/v1/unknown"} {
		for _, bad := range []string{"foreign", "null", "missing-origin", "duplicate-origin", "plain", "form", "missing-csrf", "wrong-csrf", "duplicate-content-type"} {
			t.Run(target+"/"+bad, func(t *testing.T) {
				body := &unreadBoundaryBody{}
				r := httptest.NewRequest("POST", "https://warden.example"+target, body)
				r.AddCookie(browser)
				r.Header.Set("Origin", p.cfg.PublicOrigin)
				r.Header.Set("Content-Type", "application/json")
				r.Header.Set("X-CSRF-Token", csrf)
				switch bad {
				case "foreign":
					r.Header.Set("Origin", "https://attacker.example")
				case "null":
					r.Header.Set("Origin", "null")
				case "missing-origin":
					r.Header.Del("Origin")
				case "duplicate-origin":
					r.Header.Add("Origin", p.cfg.PublicOrigin)
				case "plain":
					r.Header.Set("Content-Type", "text/plain")
				case "form":
					r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				case "missing-csrf":
					r.Header.Del("X-CSRF-Token")
				case "wrong-csrf":
					r.Header.Set("X-CSRF-Token", "wrong")
				case "duplicate-content-type":
					r.Header.Add("Content-Type", "application/json")
				}
				// Public login is intentionally CSRF-free; its Origin+JSON gates remain mandatory.
				if strings.Contains(target, "login") && strings.Contains(bad, "csrf") {
					return
				}
				w := httptest.NewRecorder()
				p.ServeHTTP(w, r)
				if w.Code != 403 || body.reads != 0 || w.Header().Get("Cache-Control") != "no-store" {
					t.Fatalf("status=%d reads=%d", w.Code, body.reads)
				}
			})
		}
	}
	if calls != 0 {
		t.Fatal("rejected request reached managed handler")
	}
	if w := call(p, "POST", "/api/v1/ssh-connections", map[string]any{}, browser, csrf); w.Code != 204 || calls != 1 {
		t.Fatal("valid mutation rejected", w.Code)
	}
}

func TestHostAndDNSRebindingRejectedBeforeRouting(t *testing.T) {
	for _, mode := range []string{"proxy", "tls"} {
		t.Run(mode, func(t *testing.T) {
			p, _, _, _, _ := runtimeFixture(t)
			p.cfg.Mode = mode
			for _, host := range []string{"attacker.example", "warden.example:444", "warden.example:443", "warden.example.", "warden.example@attacker.example", "warden.example,attacker.example", "127.0.0.1:9090", ""} {
				for _, target := range []string{"/", "/api/v1/auth/login/begin", "/api/v1/unknown"} {
					r := httptest.NewRequest("GET", "https://warden.example"+target, nil)
					r.Host = host
					r.Header.Set("Forwarded", "host=warden.example;proto=https")
					r.Header.Set("X-Forwarded-Host", "warden.example")
					r.Header.Set("X-Forwarded-Proto", "https")
					w := httptest.NewRecorder()
					p.ServeHTTP(w, r)
					if w.Code != 403 || w.Header().Get("Cache-Control") != "no-store" {
						t.Fatalf("%q %s: %d", host, target, w.Code)
					}
				}
			}
			for _, host := range []string{"warden.example", p.cfg.BackendAuthority} {
				r := httptest.NewRequest("POST", "https://warden.example/api/v1/auth/login/begin", strings.NewReader("{}"))
				r.Host = host
				r.Header.Set("Origin", p.cfg.PublicOrigin)
				r.Header.Set("Content-Type", "application/json")
				r.Header.Set("X-Forwarded-Host", "attacker.example")
				r.Header.Set("Forwarded", "host=attacker.example;proto=http")
				w := httptest.NewRecorder()
				p.ServeHTTP(w, r)
				if mode == "tls" && host != "warden.example" {
					if w.Code != 403 {
						t.Fatal(w.Code)
					}
					continue
				}
				if w.Code != 200 || !bytes.Contains(w.Body.Bytes(), []byte(`"rpId":"warden.example"`)) {
					t.Fatal("configured RP changed by headers", w.Code, w.Body)
				}
			}
		})
	}
}

func TestDataAndAuthResponsesNoStore(t *testing.T) {
	p, _, _, key, signer := runtimeFixture(t)
	browser, csrf := sessionFor(t, p)
	mountProfiles(p)
	assert := func(w *httptest.ResponseRecorder, status int) {
		t.Helper()
		if w.Code != status || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("status=%d want=%d cache=%q body=%s", w.Code, status, w.Header().Get("Cache-Control"), w.Body)
		}
	}
	assert(call(p, "GET", "/api/v1/auth/status", nil, nil, ""), 401)
	assert(call(p, "GET", "/api/v1/groups", nil, browser, csrf), 423)
	p.vault.Unlock(key, p.vault.Generation())
	assert(call(p, "POST", "/api/v1/groups", map[string]any{}, browser, csrf), 400)
	malformed := httptest.NewRequest("POST", "https://warden.example/api/v1/groups", strings.NewReader("{} {"))
	malformed.AddCookie(browser)
	malformed.Header.Set("Origin", p.cfg.PublicOrigin)
	malformed.Header.Set("Content-Type", "application/json")
	malformed.Header.Set("X-CSRF-Token", csrf)
	decoded := httptest.NewRecorder()
	p.ServeHTTP(decoded, malformed)
	assert(decoded, 400)
	assert(call(p, "GET", "/api/v1/groups/999", nil, browser, csrf), 404)
	assert(call(p, "GET", "/api/v1/transport/ssh/1", nil, browser, csrf), 403)
	for _, target := range []string{"/api/v1/data/export", "/api/v1/key-pairs/999"} {
		purpose := actionFor("GET", target)
		g := requestGrant(t, p, signer, browser, csrf, purpose, "GET", target, "")
		status := 200
		if purpose == "key_reveal" {
			status = 404
		}
		assert(callGranted(p, "GET", target, "", browser, csrf, g), status)
	}
	for _, method := range []string{"GET", "HEAD"} {
		r := httptest.NewRequest(method, "https://warden.example/api/v1/groups", nil)
		r.AddCookie(browser)
		r.Header.Set("If-None-Match", "*")
		r.Header.Set("If-Modified-Since", "Wed, 21 Oct 2099 07:28:00 GMT")
		w := httptest.NewRecorder()
		p.ServeHTTP(w, r)
		assert(w, 200)
	}
	p.managed = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { panic("synthetic panic") })
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "https://warden.example/api/v1/groups", nil)
	r.AddCookie(browser)
	server.New("", p).Handler().ServeHTTP(w, r)
	assert(w, 500)
	p.managed = server.ServeUI(http.NotFoundHandler(), fstest.MapFS{"index.html": {Data: []byte("index")}, "assets/app-hash.js": {Data: []byte("nonsecret")}})
	for _, target := range []string{"/assets/missing.js", "/missing"} {
		assert(call(p, "GET", target, nil, nil, ""), 404)
	}
	w = call(p, "GET", "/assets/app-hash.js", nil, nil, "")
	if w.Code != 200 || !strings.Contains(w.Header().Get("Cache-Control"), "immutable") {
		t.Fatal("static asset cache broken", w.Code, w.Header())
	}
	// Rate-limit failures are also covered without requiring vault access.
	p.tokens = 0
	p.refill = p.now()
	assert(call(p, "POST", "/api/v1/auth/login/begin", map[string]any{}, nil, ""), 429)
}

func TestBearerNoOriginOnlyClientAllowlist(t *testing.T) {
	p, _, i, key, _ := runtimeFixture(t)
	raw, _ := token()
	identity, _ := p.store.Installation(context.Background())
	if err := p.store.ApproveClient(context.Background(), identity, store.ClientCredential{ID: "boundary-client", Verifier: hash(raw), Label: "synthetic", Generation: i.AuthorizationGeneration, Created: p.now().Unix()}); err != nil {
		t.Fatal(err)
	}
	p.vault.Unlock(key, p.vault.Generation())
	for _, tc := range []struct {
		path, origin string
		status       int
	}{{"/api/v1/client/projects", "", 200}, {"/api/v1/client/data/export", "", 404}, {"/api/v1/data/export", "", 401}, {"/api/v1/auth/status", "", 401}, {"/api/v1/client/projects", "https://attacker.example", 403}, {"/api/v1/client/unknown", "https://attacker.example", 403}} {
		r := httptest.NewRequest("GET", "https://warden.example"+tc.path, nil)
		r.Header.Set("Authorization", "Bearer "+raw)
		if tc.origin != "" {
			r.Header.Set("Origin", tc.origin)
		}
		w := httptest.NewRecorder()
		p.ServeHTTP(w, r)
		if w.Code != tc.status || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal(tc, w.Code, w.Body)
		}
	}
}
