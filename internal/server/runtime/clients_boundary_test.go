package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"warden/internal/crypto"
	"warden/internal/server/setup"
)

func pairedFixture(t *testing.T, p *Plane, approve func(string, string), n byte) (secret, id, poll string) {
	t.Helper()
	secret = crypto.Encode(bytes.Repeat([]byte{n}, 32))
	w := clientCall(p, "POST", "/api/v1/client/pairing", `{"commitment":"`+hash(secret)+`","label":"test-device"}`, "")
	if w.Code != 200 {
		t.Fatal("begin", w.Code, w.Body)
	}
	var b struct {
		ID   string `json:"id"`
		Poll string `json:"poll_secret"`
	}
	json.Unmarshal(w.Body.Bytes(), &b)
	if approve != nil {
		approve(b.ID, hash(secret))
	}
	return secret, b.ID, b.Poll
}
func TestPairingApprovalBindsCredentialCommitment(t *testing.T) {
	for _, variant := range []string{"swapped_commitment", "expired", "denied", "generation", "concurrent"} {
		t.Run(variant, func(t *testing.T) {
			p, _, _, key, signer := runtimeFixture(t)
			browser, csrf := sessionFor(t, p)
			p.vault.Unlock(key, p.vault.Generation())
			secret, id, poll := pairedFixture(t, p, nil, 61)
			body := `{"id":"` + id + `","commitment":"` + hash(secret) + `"}`
			if variant == "swapped_commitment" {
				body = `{"id":"` + id + `","commitment":"` + hash("other") + `"}`
			}
			if variant == "denied" {
				body = `{"id":"` + id + `","commitment":"` + hash(secret) + `","deny":true}`
			}
			g := requestGrant(t, p, signer, browser, csrf, "client_approve", "POST", "/api/v1/auth/clients/approve", body)
			if variant == "expired" {
				now := p.now()
				p.mu.Lock()
				v := p.pairings[id]
				v.Expires = now
				p.pairings[id] = v
				p.mu.Unlock()
			}
			if variant == "generation" {
				if err := p.updateIdentity(context.Background(), func(*setup.Installation) error { return nil }, "", true); err != nil {
					t.Fatal(err)
				}
			}
			var successes atomic.Int32
			callApproval := func() {
				if w := callGranted(p, "POST", "/api/v1/auth/clients/approve", body, browser, csrf, g); w.Code == 200 {
					successes.Add(1)
				}
			}
			if variant == "concurrent" {
				var wg sync.WaitGroup
				for n := 0; n < 10; n++ {
					wg.Add(1)
					go func() { defer wg.Done(); callApproval() }()
				}
				wg.Wait()
				if successes.Load() != 1 {
					t.Fatal("approval winner count", successes.Load())
				}
			} else {
				callApproval()
			}
			if w := clientCall(p, "GET", "/api/v1/client/ssh-connections", "", secret); variant == "concurrent" && w.Code != 200 || variant != "concurrent" && w.Code != 401 {
				t.Fatal("activation", variant, w.Code)
			}
			if w := clientCall(p, "POST", "/api/v1/client/poll", `{"id":"`+id+`","poll_secret":"wrong"}`, ""); w.Code != 403 {
				t.Fatal("poll proof", w.Code)
			}
			if strings.Contains(poll, secret) {
				t.Fatal("poll and API credential conflated")
			}
		})
	}
}
func TestClientAdmissionRechecksGenerationAndRevocationAfterAcquire(t *testing.T) {
	for _, variant := range []string{"recovery_active", "replacement", "web_revoke"} {
		t.Run(variant, func(t *testing.T) {
			p, _, _, key, signer := runtimeFixture(t)
			browser, csrf := sessionFor(t, p)
			p.vault.Unlock(key, p.vault.Generation())
			secret, id, _ := pairedFixture(t, p, func(id, commitment string) {
				body := `{"id":"` + id + `","commitment":"` + commitment + `"}`
				g := requestGrant(t, p, signer, browser, csrf, "client_approve", "POST", "/api/v1/auth/clients/approve", body)
				if w := callGranted(p, "POST", "/api/v1/auth/clients/approve", body, browser, csrf, g); w.Code != 200 {
					t.Fatal(w.Code, w.Body)
				}
			}, 62)
			var dispatched atomic.Int32
			p.clientManaged = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				dispatched.Add(1)
				w.Write([]byte("forbidden stale secret"))
			})
			paused, resume := make(chan struct{}), make(chan struct{})
			p.beforeVaultAcquire = func(*http.Request) { close(paused); <-resume }
			result := make(chan *httptest.ResponseRecorder, 1)
			go func() { result <- clientCall(p, "GET", "/api/v1/client/ssh-connections", "", secret) }()
			<-paused
			want := 401
			switch variant {
			case "recovery_active":
				p.mu.Lock()
				p.recoveryRun = "reserved"
				p.mu.Unlock()
				want = 423
			case "replacement":
				if err := p.updateIdentity(context.Background(), func(*setup.Installation) error { return nil }, "", true); err != nil {
					t.Fatal(err)
				}
			case "web_revoke":
				if err := p.store.RevokeClient(context.Background(), id); err != nil {
					t.Fatal(err)
				}
			}
			p.vault.Lock()
			p.vault.Unlock(key, p.vault.Generation())
			close(resume)
			w := <-result
			if w.Code != want || dispatched.Load() != 0 || strings.Contains(w.Body.String(), "forbidden stale secret") {
				t.Fatal("stale admitted", w.Code, dispatched.Load())
			}
		})
	}
}
func TestClientTokenHasNoExpiryOrBrowserSessionDependency(t *testing.T) {
	p, _, _, key, signer := runtimeFixture(t)
	browser, csrf := sessionFor(t, p)
	p.vault.Unlock(key, p.vault.Generation())
	secret, _, _ := pairedFixture(t, p, func(id, commitment string) {
		body := `{"id":"` + id + `","commitment":"` + commitment + `"}`
		g := requestGrant(t, p, signer, browser, csrf, "client_approve", "POST", "/api/v1/auth/clients/approve", body)
		if w := callGranted(p, "POST", "/api/v1/auth/clients/approve", body, browser, csrf, g); w.Code != 200 {
			t.Fatal(w.Code, w.Body)
		}
	}, 95)
	if w := call(p, "POST", "/api/v1/auth/logout", struct{}{}, browser, csrf); w.Code != 200 {
		t.Fatal(w.Code)
	}
	now := p.now()
	p.now = func() time.Time { return now.Add(50 * 365 * 24 * time.Hour) }
	if w := clientCall(p, "GET", "/api/v1/client/ssh-connections", "", secret); w.Code != 200 {
		t.Fatal("approved credential silently expired", w.Code)
	}
	p.vault.Lock()
	if w := clientCall(p, "GET", "/api/v1/client/status", "", secret); w.Code != 200 {
		t.Fatal("locked credential lost authentication", w.Code)
	}
	if w := clientCall(p, "POST", "/api/v1/client/logout", `{}`, secret); w.Code != 200 {
		t.Fatal(w.Code)
	}
	if w := clientCall(p, "GET", "/api/v1/client/status", "", secret); w.Code != 401 {
		t.Fatal("captured credential survived explicit revocation", w.Code)
	}
}

func TestPairingPollingRateAndCreationBurst(t *testing.T) {
	p, _, _, _, _ := runtimeFixture(t)
	_, id, poll := pairedFixture(t, p, nil, 63)
	body := `{"id":"` + id + `","poll_secret":"` + poll + `"}`
	if w := clientCall(p, "POST", "/api/v1/client/poll", body, ""); w.Code != 200 {
		t.Fatal(w.Code)
	}
	if w := clientCall(p, "POST", "/api/v1/client/poll", body, ""); w.Code != 429 {
		t.Fatal("poll rate", w.Code)
	}
	for n := 0; n < 4; n++ {
		pairedFixture(t, p, nil, byte(70+n))
	}
	if w := clientCall(p, "POST", "/api/v1/client/pairing", `{"commitment":"`+hash("sixth")+`","label":"fixture"}`, ""); w.Code != 429 {
		t.Fatal("creation rate", w.Code)
	}
	now := p.now()
	p.now = func() time.Time { return now.Add(time.Second) }
	if w := clientCall(p, "POST", "/api/v1/client/poll", body, ""); w.Code != 200 {
		t.Fatal("poll refill", w.Code)
	}
}
