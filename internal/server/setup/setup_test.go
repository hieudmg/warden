package setup

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"warden/internal/config"
	"warden/internal/crypto"
	"warden/internal/server/auth"
	"warden/internal/store"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

type fakeVerifier struct{ afterRegistration, afterAssertion func() }

func (fakeVerifier) BeginRegistration(auth.Owner) (*protocol.CredentialCreation, *webauthn.SessionData, error) {
	return &protocol.CredentialCreation{}, &webauthn.SessionData{Challenge: "registration"}, nil
}
func (v fakeVerifier) FinishRegistration(o auth.Owner, s webauthn.SessionData, b []byte) (*webauthn.Credential, error) {
	if string(b) != `{"valid":true}` {
		return nil, errors.New("invalid")
	}
	if v.afterRegistration != nil {
		v.afterRegistration()
	}
	return &webauthn.Credential{ID: []byte("credential")}, nil
}
func (fakeVerifier) BeginAssertion(auth.Owner) (*protocol.CredentialAssertion, *webauthn.SessionData, error) {
	return &protocol.CredentialAssertion{}, &webauthn.SessionData{Challenge: "assertion"}, nil
}
func (v fakeVerifier) FinishAssertion(o auth.Owner, s webauthn.SessionData, b []byte) (*webauthn.Credential, error) {
	if string(b) != `{"valid":true}` {
		return nil, errors.New("invalid")
	}
	if v.afterAssertion != nil {
		v.afterAssertion()
	}
	return &o.Credentials[0], nil
}
func plane(t *testing.T) (*Plane, *time.Time) {
	t.Helper()
	now := time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC)
	p, err := newPlane(config.Setup{PublicOrigin: "https://warden.example", RPID: "warden.example", Mode: "proxy", BackendAuthority: "127.0.0.1:8080"}, fstest.MapFS{"setup.html": {Data: []byte("setup only")}, "setup.js": {Data: []byte("setup script")}}, fakeVerifier{}, func(context.Context, []byte) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	p.now = func() time.Time { return now }
	p.ready(now, "23456789")
	return p, &now
}
func request(p *Plane, path string, body any, cookie, csrf string) *httptest.ResponseRecorder {
	b, _ := json.Marshal(body)
	r := httptest.NewRequest("POST", "https://warden.example"+path, bytes.NewReader(b))
	r.Header.Set("Origin", "https://warden.example")
	r.Header.Set("Content-Type", "application/json")
	if cookie != "" {
		r.Header.Set("Cookie", cookie)
	}
	if csrf != "" {
		r.Header.Set("X-CSRF-Token", csrf)
	}
	w := httptest.NewRecorder()
	p.ServeHTTP(w, r)
	return w
}
func authorize(t *testing.T, p *Plane) (string, string) {
	t.Helper()
	w := request(p, "/api/v1/setup/password", map[string]string{"password": "23456789"}, "", "")
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	var b map[string]string
	json.Unmarshal(w.Body.Bytes(), &b)
	cookie := w.Result().Cookies()[0]
	if !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode {
		t.Fatal("unsafe cookie")
	}
	return cookie.Name + "=" + cookie.Value, b["csrf"]
}
func TestInitOnlySetupRoutesAndAssets(t *testing.T) {
	p, _ := plane(t)
	for _, path := range []string{"/ssh", "/databases", "/groups", "/key-pairs", "/projects", "/index.html", "/assets/management.js", "/api/v1/ssh", "/api/v1/db", "/api/v1/reports", "/api/v1/projects", "/api/v1/key-pairs", "/api/v1/export", "/api/v1/import", "/api/v1/ssh/a/transport", "/api/v1/client/ssh"} {
		r := httptest.NewRequest("GET", "https://warden.example"+path, nil)
		w := httptest.NewRecorder()
		p.ServeHTTP(w, r)
		if w.Code != 404 {
			t.Fatalf("route %s = %d", path, w.Code)
		}
	}
	for _, path := range []string{"/", "/setup.js"} {
		w := httptest.NewRecorder()
		p.ServeHTTP(w, httptest.NewRequest("GET", "https://warden.example"+path, nil))
		if w.Code != 200 {
			t.Fatal(path, w.Code)
		}
	}
}
func TestInitDeadlineStartsAtListenerReady(t *testing.T) {
	p, now := plane(t)
	cookie, csrf := authorize(t, p)
	*now = now.Add(15 * time.Minute)
	w := request(p, "/api/v1/setup/registration/begin", struct{}{}, cookie, csrf)
	if w.Code != 410 {
		t.Fatal("deadline extended", w.Code)
	}
	select {
	case <-p.Done():
	default:
		t.Fatal("not closed")
	}
}
func TestInitGlobalFailuresAndRateLimits(t *testing.T) {
	p, now := plane(t)
	for i := 0; i < 20; i++ {
		if i >= 5 {
			*now = now.Add(time.Second)
		}
		w := request(p, "/api/v1/setup/password", map[string]string{"password": "wrong"}, "", "")
		if w.Code != 401 {
			t.Fatalf("attempt %d status %d", i, w.Code)
		}
	}
	if w := request(p, "/api/v1/setup/password", map[string]string{"password": "23456789"}, "", ""); w.Code != 410 {
		t.Fatal("cap bypass", w.Code)
	}
	p, _ = plane(t)
	for i := 0; i < 5; i++ {
		request(p, "/api/v1/setup/password", map[string]string{"password": "wrong"}, "", "")
	}
	if w := request(p, "/api/v1/setup/password", map[string]string{"password": "wrong"}, "", ""); w.Code != 429 {
		t.Fatal("burst bypass", w.Code)
	}
}
func TestSetupHostOriginCSRFAndReplay(t *testing.T) {
	p, _ := plane(t)
	cookie, csrf := authorize(t, p)
	for _, mutate := range []func(*http.Request){func(r *http.Request) { r.Host = "attacker.example" }, func(r *http.Request) { r.Header.Set("Origin", "null") }, func(r *http.Request) { r.Header.Del("Origin") }, func(r *http.Request) { r.Header.Set("Content-Type", "text/plain") }, func(r *http.Request) { r.Header.Set("X-CSRF-Token", "wrong") }} {
		r := httptest.NewRequest("POST", "https://warden.example/api/v1/setup/registration/begin", strings.NewReader(`{}`))
		r.Header.Set("Origin", "https://warden.example")
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Cookie", cookie)
		r.Header.Set("X-CSRF-Token", csrf)
		mutate(r)
		w := httptest.NewRecorder()
		p.ServeHTTP(w, r)
		if w.Code != 403 || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("boundary bypass", w.Code)
		}
	}
	if w := request(p, "/api/v1/setup/registration/begin", struct{}{}, cookie, csrf); w.Code != 200 {
		t.Fatal(w.Code)
	}
	if w := request(p, "/api/v1/setup/registration/begin", struct{}{}, cookie, csrf); w.Code != 409 {
		t.Fatal("unbounded ceremony", w.Code)
	}
	if w := request(p, "/api/v1/setup/registration/finish", map[string]bool{"valid": false}, cookie, csrf); w.Code != 400 {
		t.Fatal(w.Code)
	}
	if w := request(p, "/api/v1/setup/registration/finish", map[string]bool{"valid": true}, cookie, csrf); w.Code != 409 {
		t.Fatal("replayed consumed ceremony", w.Code)
	}
}
func TestSetupCeremonyExpiryCheckedAfterVerification(t *testing.T) {
	for _, ceremony := range []string{"registration", "assertion"} {
		t.Run(ceremony, func(t *testing.T) {
			p, clock := plane(t)
			cookie, csrf := authorize(t, p)
			request(p, "/api/v1/setup/registration/begin", struct{}{}, cookie, csrf)
			advance := func() { *clock = clock.Add(6 * time.Minute) }
			if ceremony == "registration" {
				p.verifier = fakeVerifier{afterRegistration: advance}
			} else {
				request(p, "/api/v1/setup/registration/finish", map[string]bool{"valid": true}, cookie, csrf)
				p.verifier = fakeVerifier{afterAssertion: advance}
			}
			w := request(p, "/api/v1/setup/"+ceremony+"/finish", map[string]bool{"valid": true}, cookie, csrf)
			if w.Code != 409 {
				t.Fatal("ceremony accepted after five-minute expiry", w.Code)
			}
			if p.phase == "verified" || p.pending != nil {
				t.Fatal("expired proof can deliver a key")
			}
		})
	}
}

func TestSetupCloseDoesNotWaitForBlockedCeremony(t *testing.T) {
	p, _ := plane(t)
	p.mu.Lock()
	defer p.mu.Unlock()
	go p.Close()
	select {
	case <-p.Done():
	case <-time.After(100 * time.Millisecond):
		t.Fatal("closing setup blocked behind in-flight ceremony")
	}
}

func TestSetupRejectsAmbiguousOriginAndPlainDirectTransport(t *testing.T) {
	p, _ := plane(t)
	cookie, csrf := authorize(t, p)
	r := httptest.NewRequest("POST", "https://warden.example/api/v1/setup/registration/begin", strings.NewReader(`{}`))
	r.Header["Origin"] = []string{"https://warden.example", "https://attacker.example"}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Cookie", cookie)
	r.Header.Set("X-CSRF-Token", csrf)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("ambiguous Origin accepted", w.Code)
	}
	p, _ = plane(t)
	p.cfg.Mode = "tls"
	r = httptest.NewRequest("GET", "http://warden.example/", nil)
	w = httptest.NewRecorder()
	p.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("direct HTTP accepted", w.Code)
	}
}

func TestSetupRequiresSavedRecoveryRoundTrip(t *testing.T) {
	p, _ := plane(t)
	cookie, csrf := authorize(t, p)
	request(p, "/api/v1/setup/registration/begin", struct{}{}, cookie, csrf)
	request(p, "/api/v1/setup/registration/finish", map[string]bool{"valid": true}, cookie, csrf)
	request(p, "/api/v1/setup/assertion/finish", map[string]bool{"valid": true}, cookie, csrf)
	dek := bytes.Repeat([]byte{3}, 32)
	recovery := bytes.Repeat([]byte{4}, 32)
	pass, _ := crypto.Wrap(bytes.Repeat([]byte{2}, 32), dek, "passkey", p.vaultID, crypto.Encode([]byte("credential")), nil)
	pass.PRFInput = p.prfInput
	rec, _ := crypto.Wrap(recovery, dek, "recovery", p.vaultID, "", nil)
	salt, _ := crypto.Decode(rec.KDFSalt, 32)
	proof, _ := crypto.Derive(recovery, salt, "warden/v1/recovery-auth")
	prepare := Preparation{Passkey: pass, Recovery: rec, DEK: crypto.Encode(dek), RecoveryVerifier: hashToken(proof)}
	w := request(p, "/api/v1/setup/prepare", prepare, cookie, csrf)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	for _, b := range []any{map[string]bool{"saved": true}, Confirmation{RecoveryAuth: crypto.Encode(bytes.Repeat([]byte{9}, 32)), DEK: crypto.Encode(dek)}, Confirmation{RecoveryAuth: crypto.Encode(proof), DEK: crypto.Encode(bytes.Repeat([]byte{9}, 32))}} {
		w = request(p, "/api/v1/setup/finalize", b, cookie, csrf)
		if w.Code == 200 {
			t.Fatal("accepted absent/wrong saved proof")
		}
	}
	var mu sync.Mutex
	commits := 0
	p.commit = func(_ context.Context, b []byte) error {
		mu.Lock()
		defer mu.Unlock()
		commits++
		if bytes.Contains(b, []byte(crypto.Encode(dek))) || bytes.Contains(b, []byte(crypto.Encode(proof))) {
			t.Error("persisted key")
		}
		return nil
	}
	var wg sync.WaitGroup
	codes := make(chan int, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			codes <- request(p, "/api/v1/setup/finalize", Confirmation{RecoveryAuth: crypto.Encode(proof), DEK: crypto.Encode(dek)}, cookie, csrf).Code
		}()
	}
	wg.Wait()
	close(codes)
	wins := 0
	for code := range codes {
		if code == 200 {
			wins++
		}
	}
	if wins != 1 || commits != 1 {
		t.Fatal("not atomic", wins, commits)
	}
}
func TestSetupKeyCheckRequiresIndependentAssertion(t *testing.T) {
	p, _ := plane(t)
	cookie, csrf := authorize(t, p)
	request(p, "/api/v1/setup/registration/begin", struct{}{}, cookie, csrf)
	request(p, "/api/v1/setup/registration/finish", map[string]bool{"valid": true}, cookie, csrf)
	if w := request(p, "/api/v1/setup/prepare", Preparation{DEK: crypto.Encode(bytes.Repeat([]byte{3}, 32))}, cookie, csrf); w.Code != 409 {
		t.Fatal("key accepted without assertion", w.Code)
	}
	if w := request(p, "/api/v1/setup/assertion/finish", map[string]bool{"valid": false}, cookie, csrf); w.Code != 400 {
		t.Fatal("invalid assertion accepted", w.Code)
	}
	if w := request(p, "/api/v1/setup/prepare", Preparation{DEK: crypto.Encode(bytes.Repeat([]byte{3}, 32))}, cookie, csrf); w.Code != 409 || p.pending != nil {
		t.Fatal("key substituted for identity proof")
	}
}

func TestSetupFinalizationDisconnectExpiryAndCommitFailure(t *testing.T) {
	for _, failure := range []string{"disconnect", "expiry", "transaction"} {
		t.Run(failure, func(t *testing.T) {
			p, clock := plane(t)
			*clock = time.Now()
			p.deadline = clock.Add(time.Minute)
			cookie, csrf := authorize(t, p)
			dek := bytes.Repeat([]byte{3}, 32)
			proof := bytes.Repeat([]byte{4}, 32)
			check, err := crypto.NewKeyCheck(dek, p.vaultID)
			if err != nil {
				t.Fatal(err)
			}
			p.pending = &Installation{Format: 1, RecoveryVerifier: hashToken(proof), KeyCheck: check}
			p.phase = "prepared"
			path := filepath.Join(t.TempDir(), "vault.db")
			p.commit = func(ctx context.Context, b []byte) error {
				if failure == "transaction" {
					return errors.New("synthetic commit failure")
				}
				return store.CommitInstallation(ctx, path, b)
			}
			body, _ := json.Marshal(Confirmation{RecoveryAuth: crypto.Encode(proof), DEK: crypto.Encode(dek)})
			r := httptest.NewRequest("POST", "https://warden.example/api/v1/setup/finalize", bytes.NewReader(body))
			r.Header.Set("Origin", "https://warden.example")
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Cookie", cookie)
			r.Header.Set("X-CSRF-Token", csrf)
			if failure == "disconnect" {
				ctx, cancel := context.WithCancel(r.Context())
				cancel()
				r = r.WithContext(ctx)
			}
			if failure == "expiry" {
				*clock = p.deadline
			}
			w := httptest.NewRecorder()
			p.ServeHTTP(w, r)
			if w.Code == 200 {
				t.Fatal("failed finalization succeeded")
			}
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatal("unrecoverable partial identity")
			}
			select {
			case <-p.Done():
			default:
				t.Fatal("failed process did not close")
			}
		})
	}
}

func TestInitPasswordTerminalOnly(t *testing.T) {
	p, err := GeneratePassword(bytes.NewReader([]byte{0, 1, 2, 3, 4, 5, 6, 255}))
	if err != nil || len(p) != 8 {
		t.Fatal(p, err)
	}
	for _, c := range p {
		if !strings.ContainsRune(passwordAlphabet, c) {
			t.Fatal("bad alphabet")
		}
	}
	if _, err := GeneratePassword(bytes.NewReader(nil)); err == nil {
		t.Fatal("RNG failure ignored")
	}
}
