package runtime

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"
)

func TestAssertionConcurrencyBoundPreservesLockedMetadataAndPendingCeremony(t *testing.T) {
	p, verifier, installation, _, signer := runtimeFixture(t)
	browser, csrf := sessionFor(t, p)
	bodies := make([]map[string]any, 5)
	ids := make([]string, 5)
	for n := range bodies {
		begun := call(p, "POST", "/api/v1/auth/fresh/begin", map[string]string{"action": "unlock", "credential_id": installation.Passkey.CredentialID}, browser, csrf)
		if begun.Code != 200 {
			t.Fatal(begun.Code, begun.Body)
		}
		var b struct {
			ID string `json:"id"`
		}
		json.Unmarshal(begun.Body.Bytes(), &b)
		ids[n] = b.ID
		c := p.challenges[hash(b.ID)]
		signed := fixtureAssertion(t, signer, installation.Owner.Credentials[0].ID, installation.Owner.ID, c.Session.Challenge, p.cfg.PublicOrigin, p.cfg.RPID, true)
		bodies[n] = map[string]any{"id": b.ID, "credential": json.RawMessage(signed)}
	}
	entered := make(chan struct{}, 4)
	resume := make(chan struct{})
	p.verifier = afterAssertion{verifier, func() { entered <- struct{}{}; <-resume }}
	released := false
	defer func() {
		if !released {
			close(resume)
		}
	}()
	done := make(chan *httptest.ResponseRecorder, 4)
	for n := 0; n < 4; n++ {
		go func(n int) { done <- call(p, "POST", "/api/v1/auth/fresh/finish", bodies[n], browser, csrf) }(n)
	}
	for n := 0; n < 4; n++ {
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("verifier did not enter")
		}
	}
	rejected := call(p, "POST", "/api/v1/auth/fresh/finish", bodies[4], browser, csrf)
	if rejected.Code != 429 || rejected.Header().Get("Retry-After") == "" || rejected.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("verification saturation", rejected.Code)
	}
	p.mu.Lock()
	_, pending := p.challenges[hash(ids[4])]
	p.mu.Unlock()
	if !pending {
		t.Fatal("saturation consumed ceremony")
	}
	if w := call(p, "GET", "/api/v1/auth/status", nil, browser, csrf); w.Code != 200 || p.vault.Unlocked() {
		t.Fatal("locked metadata blocked or DEK acquired", w.Code)
	}
	close(resume)
	released = true
	for n := 0; n < 4; n++ {
		select {
		case w := <-done:
			if w.Code != 200 {
				t.Fatal(w.Code, w.Body)
			}
		case <-time.After(time.Second):
			t.Fatal("verification did not join")
		}
	}
	p.verifier = verifier
	if w := call(p, "POST", "/api/v1/auth/fresh/finish", bodies[4], browser, csrf); w.Code != 200 {
		t.Fatal("rejected ceremony not retryable", w.Code, w.Body)
	}
	if len(p.keyOperations) != 0 {
		t.Fatal("verification retained slot")
	}
}
