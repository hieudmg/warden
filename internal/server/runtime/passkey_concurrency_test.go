package runtime

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http/httptest"
	"reflect"
	"testing"
)

type enrollmentReadCounter struct {
	io.Reader
	reads int
}

func (b *enrollmentReadCounter) Read(p []byte) (int, error) { b.reads++; return b.Reader.Read(p) }

func TestPasskeyVerificationEndpointsRejectSaturationBeforeBodyAndPreserveEnrollment(t *testing.T) {
	for _, endpoint := range []string{"registration", "assertion"} {
		t.Run(endpoint, func(t *testing.T) {
			p, _, installation, key, signer := runtimeFixture(t)
			browser, csrf := sessionFor(t, p)
			if err := p.vault.Unlock(key, p.vault.Generation()); err != nil {
				t.Fatal(err)
			}
			grant := requestGrant(t, p, signer, browser, csrf, "passkey_add", "POST", "/api/v1/auth/passkeys/begin", "{}")
			begun := callGranted(p, "POST", "/api/v1/auth/passkeys/begin", "{}", browser, csrf, grant)
			if begun.Code != 200 {
				t.Fatal(begun.Code, begun.Body)
			}
			var begin struct {
				ID string `json:"id"`
			}
			if err := json.Unmarshal(begun.Body.Bytes(), &begin); err != nil || begin.ID == "" {
				t.Fatal("missing issued enrollment", err)
			}
			p.mu.Lock()
			enrolled, ok := p.pending[hash(begin.ID)]
			_, grantRetained := p.grants[hash(grant)]
			p.mu.Unlock()
			if !ok || grantRetained {
				t.Fatal("begin did not consume fresh grant and issue enrollment")
			}
			registration, newSigner, newID := secondRegistration(t, enrolled.Session.Challenge, p.cfg.PublicOrigin, p.cfg.RPID)
			credential := registration
			if endpoint == "assertion" {
				registered := call(p, "POST", "/api/v1/auth/passkeys/registration", map[string]any{"id": begin.ID, "credential": json.RawMessage(registration)}, browser, csrf)
				if registered.Code != 200 {
					t.Fatal(registered.Code, registered.Body)
				}
				p.mu.Lock()
				enrolled, ok = p.pending[hash(begin.ID)]
				p.mu.Unlock()
				if !ok || enrolled.Phase != "assertion" {
					t.Fatal("registration did not issue assertion phase")
				}
				credential = fixtureAssertion(t, newSigner, newID, installation.Owner.ID, enrolled.Session.Challenge, p.cfg.PublicOrigin, p.cfg.RPID, true)
			}
			payload, err := json.Marshal(map[string]any{"id": begin.ID, "credential": json.RawMessage(credential)})
			if err != nil {
				t.Fatal(err)
			}
			path := "/api/v1/auth/passkeys/" + endpoint
			body := &enrollmentReadCounter{Reader: bytes.NewReader(payload)}
			request := httptest.NewRequest("POST", "https://warden.example"+path, body)
			request.AddCookie(browser)
			request.Header.Set("Origin", p.cfg.PublicOrigin)
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("X-CSRF-Token", csrf)
			// Occupy every actual admission slot, not the unrelated 16-request auth cap.
			for n := 0; n < cap(p.keyOperations); n++ {
				p.keyOperations <- struct{}{}
			}
			response := httptest.NewRecorder()
			p.ServeHTTP(response, request)
			for n := 0; n < cap(p.keyOperations); n++ {
				<-p.keyOperations
			}
			if response.Code != 429 || response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("Retry-After") == "" {
				t.Errorf("saturation status=%d cache=%q retry=%q", response.Code, response.Header().Get("Cache-Control"), response.Header().Get("Retry-After"))
			}
			if body.reads != 0 {
				t.Errorf("saturated endpoint read body %d times", body.reads)
			}
			p.mu.Lock()
			after, retained := p.pending[hash(begin.ID)]
			p.mu.Unlock()
			if !retained || !reflect.DeepEqual(after, enrolled) {
				t.Errorf("saturated endpoint consumed or changed issued %s enrollment", enrolled.Phase)
			}
			// Identical valid credential must succeed through the real verifier once
			// capacity is available, then its original single-use phase must not replay.
			retry := callGranted(p, "POST", path, string(payload), browser, csrf, "")
			if retry.Code != 200 {
				t.Errorf("enrollment not retryable after release: %d %s", retry.Code, retry.Body)
			}
			replay := callGranted(p, "POST", path, string(payload), browser, csrf, "")
			if replay.Code != 403 {
				t.Errorf("original phase replay accepted: %d", replay.Code)
			}
			if len(p.keyOperations) != 0 {
				t.Fatal("endpoint retained expensive slot")
			}
		})
	}
}
