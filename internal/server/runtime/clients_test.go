package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"warden/internal/crypto"
)

func clientCall(p *Plane, method, path, body, bearer string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "https://warden.example"+path, strings.NewReader(body))
	r.Host = "warden.example"
	r.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		r.Header.Set("Authorization", "Bearer "+bearer)
	}
	w := httptest.NewRecorder()
	p.ServeHTTP(w, r)
	return w
}
func TestPairingCannotReadBeforeApproval(t *testing.T) {
	p, _, _, key, signer := runtimeFixture(t)
	browser, csrf := sessionFor(t, p)
	secret := crypto.Encode(bytes.Repeat([]byte{91}, 32))
	begin := clientCall(p, "POST", "/api/v1/client/pairing", `{"commitment":"`+hash(secret)+`","label":"fixture-device"}`, "")
	if begin.Code != 200 {
		t.Fatalf("pairing start: %d %s", begin.Code, begin.Body)
	}
	var b struct{ ID, PollSecret, Fingerprint, ApprovalURL string }
	var wire struct {
		ID          string `json:"id"`
		PollSecret  string `json:"poll_secret"`
		Fingerprint string `json:"fingerprint"`
		ApprovalURL string `json:"approval_url"`
	}
	if json.Unmarshal(begin.Body.Bytes(), &wire) != nil {
		t.Fatal("invalid pairing")
	}
	b.ID, b.PollSecret, b.Fingerprint, b.ApprovalURL = wire.ID, wire.PollSecret, wire.Fingerprint, wire.ApprovalURL
	if b.PollSecret == "" || b.ID == "" || b.Fingerprint != hash(secret) || strings.Contains(b.ApprovalURL, b.PollSecret) || strings.Contains(b.ApprovalURL, secret) {
		t.Fatal("unsafe enrollment metadata", b.ID)
	}
	if w := clientCall(p, "GET", "/api/v1/client/ssh-connections", "", secret); w.Code != 401 {
		t.Fatal("pending credential read", w.Code)
	}
	p.vault.Unlock(key, p.vault.Generation())
	body := `{"id":"` + b.ID + `","commitment":"` + hash(secret) + `"}`
	if w := callGranted(p, "POST", "/api/v1/auth/clients/approve", body, browser, csrf, ""); w.Code != 403 {
		t.Fatal("approval without fresh assertion", w.Code)
	}
	g := requestGrant(t, p, signer, browser, csrf, "client_approve", "POST", "/api/v1/auth/clients/approve", body)
	if w := callGranted(p, "POST", "/api/v1/auth/clients/approve", body, browser, csrf, g); w.Code != 200 {
		t.Fatal("approve", w.Code, w.Body)
	}
	if w := callGranted(p, "POST", "/api/v1/auth/clients/approve", body, browser, csrf, g); w.Code != 403 {
		t.Fatal("approval replay", w.Code)
	}
	poll := `{"id":"` + b.ID + `","poll_secret":"` + b.PollSecret + `"}`
	if w := clientCall(p, "POST", "/api/v1/client/poll", poll, ""); w.Code != 200 || !strings.Contains(w.Body.String(), `"approved"`) {
		t.Fatal("poll", w.Code, w.Body)
	}
	if w := clientCall(p, "GET", "/api/v1/client/ssh-connections", "", secret); w.Code != 200 {
		t.Fatal("approved data", w.Code, w.Body)
	}
	p.vault.Lock()
	if w := clientCall(p, "GET", "/api/v1/client/ssh-connections", "", secret); w.Code != 423 {
		t.Fatal("lock", w.Code)
	}
	if w := clientCall(p, "POST", "/api/v1/client/logout", `{}`, secret); w.Code != 200 {
		t.Fatal("locked logout", w.Code, w.Body)
	}
	if w := clientCall(p, "GET", "/api/v1/client/ssh-connections", "", secret); w.Code != 401 {
		t.Fatal("revocation", w.Code)
	}
}
func TestCredentialAudienceAndPerRequestRevocation(t *testing.T) {
	p, _, _, key, _ := runtimeFixture(t)
	p.vault.Unlock(key, p.vault.Generation())
	browser, csrf := sessionFor(t, p)
	if w := call(p, "GET", "/api/v1/client/ssh-connections", nil, browser, csrf); w.Code != 401 {
		t.Fatal("cookie authenticated client", w.Code)
	}
	if w := clientCall(p, "GET", "/api/v1/ssh-connections", "", "fake"); w.Code != 401 {
		t.Fatal("bearer management", w.Code)
	}
	for _, target := range []string{"/api/v1/client/groups", "/api/v1/client/key-pairs", "/api/v1/client/data/export", "/api/v1/client/auth/unlock"} {
		if w := clientCall(p, "GET", target, "", ""); w.Code != 401 {
			t.Fatal(target, w.Code)
		}
	}
	_ = context.Background()
}
func TestPairingGlobalAndPollingLimits(t *testing.T) {
	p, _, _, _, _ := runtimeFixture(t)
	now := time.Now()
	p.now = func() time.Time { return now }
	for n := 0; n < 21; n++ {
		if n > 0 {
			now = now.Add(time.Second)
		}
		w := clientCall(p, "POST", "/api/v1/client/pairing", `{"commitment":"`+hash("unique"+strings.Repeat("x", n))+`","label":"fixture"}`, "")
		want := 200
		if n == 20 {
			want = 429
		}
		if w.Code != want {
			t.Fatalf("pending %d: %d %s", n, w.Code, w.Body)
		}
	}
	now = now.Add(5 * time.Minute)
	if w := clientCall(p, "POST", "/api/v1/client/pairing", `{"commitment":"`+hash("new	ime")+`","label":"fixture"}`, ""); w.Code != 200 {
		t.Fatal("expired capacity", w.Code)
	}
}
