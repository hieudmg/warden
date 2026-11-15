package runtime

import (
	"crypto/ecdsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func requestGrant(t *testing.T, p *Plane, signer *ecdsa.PrivateKey, browser *http.Cookie, csrf, purpose, method, path, body string) string {
	t.Helper()
	begin := call(p, "POST", "/api/v1/auth/fresh/begin", map[string]string{"action": purpose, "credential_id": p.install.Passkey.CredentialID, "method": method, "path": path, "digest": hash(body)}, browser, csrf)
	if begin.Code != 200 {
		t.Fatalf("begin: %d %s", begin.Code, begin.Body)
	}
	var b struct {
		ID string `json:"id"`
	}
	json.Unmarshal(begin.Body.Bytes(), &b)
	c := p.challenges[hash(b.ID)]
	signed := fixtureAssertion(t, signer, p.install.Owner.Credentials[0].ID, p.install.Owner.ID, c.Session.Challenge, p.cfg.PublicOrigin, p.cfg.RPID, true)
	finish := call(p, "POST", "/api/v1/auth/fresh/finish", map[string]any{"id": b.ID, "credential": json.RawMessage(signed)}, browser, csrf)
	if finish.Code != 200 {
		t.Fatalf("finish: %d %s", finish.Code, finish.Body)
	}
	var g struct {
		Grant string `json:"grant"`
	}
	json.Unmarshal(finish.Body.Bytes(), &g)
	if g.Grant == "" {
		t.Fatal("no grant")
	}
	return g.Grant
}
func callGranted(p *Plane, method, path, body string, browser *http.Cookie, csrf, g string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "https://warden.example"+path, strings.NewReader(body))
	r.Host = "warden.example"
	r.Header.Set("Origin", p.cfg.PublicOrigin)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-CSRF-Token", csrf)
	r.Header.Set("X-Warden-Action", g)
	if browser != nil {
		r.AddCookie(browser)
	}
	w := httptest.NewRecorder()
	p.ServeHTTP(w, r)
	return w
}
func TestFreshActionGrantPurposeTargetSessionAndReplay(t *testing.T) {
	for _, variant := range []string{"success", "method", "path", "payload", "session", "expiry", "generation", "replay"} {
		t.Run(variant, func(t *testing.T) {
			p, _, _, key, signer := runtimeFixture(t)
			browser, csrf := sessionFor(t, p)
			p.vault.Unlock(key, p.vault.Generation())
			method, path, body := "PUT", "/api/v1/key-pairs/1", `{"private_key":"synthetic"}`
			g := requestGrant(t, p, signer, browser, csrf, "key_mutation", method, path, body)
			switch variant {
			case "method":
				method = "POST"
			case "path":
				path = "/api/v1/key-pairs/2"
			case "payload":
				body = `{"private_key":"other"}`
			case "session":
				browser, csrf = sessionFor(t, p)
			case "expiry":
				now := p.now()
				p.now = func() time.Time { return now.Add(60 * time.Second) }
			case "generation":
				p.vault.Lock()
				p.vault.Unlock(key, p.vault.Generation())
			}
			w := callGranted(p, method, path, body, browser, csrf, g)
			if variant == "success" || variant == "replay" {
				if w.Code != 200 {
					t.Fatal(w.Code, w.Body)
				}
				if w = callGranted(p, method, path, body, browser, csrf, g); w.Code != 403 {
					t.Fatal("replayed", w.Code)
				}
			} else if w.Code != 403 {
				t.Fatalf("accepted %s: %d", variant, w.Code)
			}
		})
	}
}
func TestSensitiveGETRequiresGrantAndIsNeverCached(t *testing.T) {
	for _, route := range []struct{ path, purpose string }{{"/api/v1/key-pairs/1", "key_reveal"}, {"/api/v1/data/export", "export"}} {
		t.Run(route.purpose, func(t *testing.T) {
			p, _, _, key, signer := runtimeFixture(t)
			browser, csrf := sessionFor(t, p)
			p.vault.Unlock(key, p.vault.Generation())
			g := requestGrant(t, p, signer, browser, csrf, route.purpose, "GET", route.path, "")
			w := callGranted(p, "GET", route.path, "", browser, csrf, g)
			if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal(w.Code, w.Body)
			}
		})
	}
}

type emptyBodyWriteObserver struct {
	*httptest.ResponseRecorder
	writes int
}

func (w *emptyBodyWriteObserver) Write(b []byte) (int, error) {
	w.writes++
	return w.ResponseRecorder.Write(b)
}

func TestManagedResponseEmptyBodyFlushesWithoutWrite(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusNoContent, http.StatusNotModified} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			w := &emptyBodyWriteObserver{ResponseRecorder: httptest.NewRecorder()}
			r := httptest.NewRequest("GET", "https://warden.example/", nil)
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Fatalf("empty response aborted: %v", recovered)
				}
			}()
			new(Plane).deliver(w, r, r.Context(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(status)
			}))
			if w.Code != status || w.writes != 0 || !w.Flushed || w.Body.Len() != 0 {
				t.Fatalf("status=%d writes=%d flushed=%v bytes=%d", w.Code, w.writes, w.Flushed, w.Body.Len())
			}
		})
	}
}

func TestFreshActionRejectsTransportEvenWithAssertion(t *testing.T) {
	p, _, _, key, _ := runtimeFixture(t)
	browser, csrf := sessionFor(t, p)
	p.vault.Unlock(key, p.vault.Generation())
	w := call(p, "POST", "/api/v1/auth/fresh/begin", map[string]string{"action": "export", "credential_id": p.install.Passkey.CredentialID, "method": "GET", "path": "/api/v1/transport/ssh/1", "digest": hash("")}, browser, csrf)
	if w.Code != 403 {
		t.Fatal("transport grant accepted", w.Code)
	}
}
