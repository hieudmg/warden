package runtime

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"

	"github.com/go-webauthn/webauthn/webauthn"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"warden/internal/config"
	"warden/internal/crypto"
	"warden/internal/server/auth"
	"warden/internal/server/setup"
	"warden/internal/store"
)

func runtimeFixture(t *testing.T) (*Plane, *auth.Verifier, setup.Installation, []byte, *ecdsa.PrivateKey) {
	t.Helper()
	v, err := auth.NewVerifier("https://warden.example", "warden.example")
	if err != nil {
		t.Fatal(err)
	}
	owner := auth.Owner{ID: bytes.Repeat([]byte{8}, 32)}
	_, reg, _ := v.BeginRegistration(owner)
	body, signingKey, _ := fixtureRegistration(t, reg.Challenge, "https://warden.example", "warden.example", true)
	cred, err := v.FinishRegistration(owner, *reg, body)
	if err != nil {
		t.Fatal(err)
	}
	owner.Credentials = append(owner.Credentials, *cred)
	key := bytes.Repeat([]byte{3}, 32)
	vault := crypto.Encode(bytes.Repeat([]byte{2}, 16))
	w, _ := crypto.Wrap(bytes.Repeat([]byte{4}, 32), key, "passkey", vault, crypto.Encode(cred.ID), nil)
	r, _ := crypto.Wrap(bytes.Repeat([]byte{5}, 32), key, "recovery", vault, "", nil)
	check, _ := crypto.NewKeyCheck(key, vault)
	i := setup.Installation{Format: 1, PublicOrigin: "https://warden.example", RPID: "warden.example", Owner: owner, Passkey: w, Recovery: r, RecoveryVerifier: crypto.Encode(bytes.Repeat([]byte{6}, 32)), KeyCheck: check}
	raw, _ := json.Marshal(i)
	path := filepath.Join(t.TempDir(), "vault.db")
	if err := store.CommitInstallation(context.Background(), path, raw); err != nil {
		t.Fatal(err)
	}
	vaultOwner := crypto.NewVault()
	s, err := store.OpenInitialized(context.Background(), path, func(b []byte) error {
		_, err := validateInstallation(b, config.Setup{PublicOrigin: i.PublicOrigin, RPID: i.RPID})
		return err
	}, vaultOwner)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { vaultOwner.Lock(); s.Close() })
	p, err := newPlane(config.Setup{PublicOrigin: i.PublicOrigin, RPID: i.RPID, Mode: "proxy", BackendAuthority: "127.0.0.1:8080"}, s, i, vaultOwner, v, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("synthetic secret")) }))
	if err != nil {
		t.Fatal(err)
	}
	return p, v, i, key, signingKey
}
func call(p *Plane, method, path string, body any, cookie *http.Cookie, csrf string) *httptest.ResponseRecorder {
	var b []byte
	if body != nil {
		b, _ = json.Marshal(body)
	}
	r := httptest.NewRequest(method, "https://warden.example"+path, bytes.NewReader(b))
	r.Host = "warden.example"
	r.Header.Set("Origin", "https://warden.example")
	r.Header.Set("Content-Type", "application/json")
	if cookie != nil {
		r.AddCookie(cookie)
	}
	if csrf != "" {
		r.Header.Set("X-CSRF-Token", csrf)
	}
	w := httptest.NewRecorder()
	p.ServeHTTP(w, r)
	return w
}
func sessionFor(t *testing.T, p *Plane) (*http.Cookie, string) {
	t.Helper()
	token, err := token()
	if err != nil {
		t.Fatal(err)
	}
	csrf := csrfToken(token)
	now := p.now().Unix()
	err = p.store.SaveSession(context.Background(), store.Session{Hash: hash(token), CSRFHash: hash(csrf), CredentialID: p.install.Passkey.CredentialID, Created: now, Seen: now})
	if err != nil {
		t.Fatal(err)
	}
	return &http.Cookie{Name: sessionCookie, Value: token}, csrf
}
func TestManagementRoutesRequireSessionAndUnlock(t *testing.T) {
	p, _, _, key, _ := runtimeFixture(t)
	cookie, csrf := sessionFor(t, p)
	routes := []string{"/api/v1/ssh-connections", "/api/v1/ssh-connections/1", "/api/v1/ssh-connections/1/archive", "/api/v1/ssh-connections/1/dependents", "/api/v1/db-connections", "/api/v1/db-connections/1", "/api/v1/db-connections/1/archive", "/api/v1/db-connections/1/dependents", "/api/v1/groups", "/api/v1/groups/1", "/api/v1/groups/1/dependents", "/api/v1/key-pairs", "/api/v1/key-pairs/1", "/api/v1/key-pairs/1/dependents", "/api/v1/data/export", "/api/v1/data/import", "/api/v1/transport/ssh/1", "/api/v1/transport/db/1", "/api/v1/projects", "/api/v1/projects/name/reports", "/api/v1/reports", "/api/v1/unknown"}
	for _, method := range []string{"GET", "HEAD", "POST", "PUT", "DELETE", "PATCH"} {
		for _, path := range routes {
			for _, alias := range []string{path, path + "/"} {
				w := call(p, method, alias, map[string]any{}, nil, "")
				if w.Code != 401 || w.Header().Get("Cache-Control") != "no-store" {
					t.Fatalf("anonymous %s %s: %d", method, alias, w.Code)
				}
				w = call(p, method, alias, map[string]any{}, cookie, csrf)
				if w.Code != 423 {
					t.Fatalf("locked %s %s: %d %s", method, alias, w.Code, w.Body)
				}
			}
		}
	}
	if err := p.vault.Unlock(key, p.vault.Generation()); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/api/v1/key-pairs/1", "/api/v1/data/export", "/api/v1/data/import"} {
		w := call(p, "GET", path, nil, cookie, csrf)
		if w.Code != 403 {
			t.Fatalf("sensitive ungated %s: %d", path, w.Code)
		}
	}
	if w := call(p, "GET", "/api/v1/ssh-connections", nil, cookie, csrf); w.Code != 200 {
		t.Fatal(w.Code)
	}
}
func TestLoginWhileLockedWithoutCodec(t *testing.T) {
	p, _, _, _, _ := runtimeFixture(t)
	w := call(p, "POST", "/api/v1/auth/login/begin", map[string]any{}, nil, "")
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	var b struct {
		ID      string `json:"id"`
		Options struct {
			PublicKey struct {
				Challenge string `json:"challenge"`
				UV        string `json:"userVerification"`
			} `json:"publicKey"`
		} `json:"options"`
	}
	json.Unmarshal(w.Body.Bytes(), &b)
	if b.ID == "" || b.Options.PublicKey.UV != "required" {
		t.Fatal(w.Body)
	}
	if p.vault.Unlocked() {
		t.Fatal("login start unlocked")
	}
}
func TestTransportCannotBypassVaultRevealGate(t *testing.T) {
	p, _, _, key, _ := runtimeFixture(t)
	session, csrf := sessionFor(t, p)
	p.vault.Unlock(key, p.vault.Generation())
	p.managed = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{"private_key":"synthetic vault key"}`)) })
	for _, path := range []string{"/api/v1/transport/ssh/1", "/api/v1/transport/db/1"} {
		w := call(p, "GET", path, nil, session, csrf)
		if w.Code != 403 || strings.Contains(w.Body.String(), "synthetic vault key") {
			t.Fatal("indirect vault reveal bypass", path, w.Code)
		}
	}
}

func TestUnlockRequiresFreshVerifiedCeremony(t *testing.T) {
	p, _, _, key, _ := runtimeFixture(t)
	cookie, csrf := sessionFor(t, p)
	for _, g := range []string{"", strings.Repeat("x", 43)} {
		w := call(p, "POST", "/api/v1/auth/unlock", map[string]string{"grant": g, "dek": crypto.Encode(key)}, cookie, csrf)
		if w.Code != 403 || p.vault.Unlocked() {
			t.Fatal("key possession accepted", w.Code)
		}
	}
}
func TestRuntimeLoginPersistsVerifierCounterAndCompleteIdentity(t *testing.T) {
	p, _, i, _, signer := runtimeFixture(t)
	begin := call(p, "POST", "/api/v1/auth/login/begin", struct{}{}, nil, "")
	var b struct {
		ID string `json:"id"`
	}
	json.Unmarshal(begin.Body.Bytes(), &b)
	c := p.challenges[hash(b.ID)]
	signed := fixtureAssertion(t, signer, i.Owner.Credentials[0].ID, i.Owner.ID, c.Session.Challenge, i.PublicOrigin, i.RPID, true, 1)
	var login *http.Cookie
	for _, cookie := range begin.Result().Cookies() {
		if cookie.Name == loginCookie {
			login = cookie
		}
	}
	result := call(p, "POST", "/api/v1/auth/login/finish", map[string]any{"id": b.ID, "credential": json.RawMessage(signed)}, login, "")
	if result.Code != 200 {
		t.Fatal(result.Code, result.Body)
	}
	var state struct {
		CSRF string `json:"csrf"`
	}
	json.Unmarshal(result.Body.Bytes(), &state)
	var issued *http.Cookie
	for _, c := range result.Result().Cookies() {
		if c.Name == sessionCookie {
			issued = c
		}
	}
	if issued == nil || !issued.Secure || !issued.HttpOnly || issued.SameSite != http.SameSiteStrictMode || issued.Path != "/" || issued.Domain != "" || issued.MaxAge != 43200 {
		t.Fatal("unsafe session cookie", issued)
	}
	stored, err := p.store.Session(context.Background(), hash(issued.Value))
	if err != nil || stored.Hash == issued.Value || stored.CSRFHash != hash(state.CSRF) {
		t.Fatal("session bearer/CSRF not hashed", err)
	}
	if _, err := p.store.Session(context.Background(), issued.Value); err == nil {
		t.Fatal("plaintext bearer indexed")
	}
	raw, err := p.store.Installation(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var saved setup.Installation
	if err = json.Unmarshal(raw, &saved); err != nil {
		t.Fatal(err)
	}
	if saved.Owner.Credentials[0].Authenticator.SignCount != 1 {
		t.Fatal("verified counter not persisted")
	}
	if saved.Passkey != i.Passkey || saved.Recovery != i.Recovery || saved.KeyCheck != i.KeyCheck || saved.RecoveryVerifier != i.RecoveryVerifier {
		t.Fatal("identity lost")
	}
}

func TestSessionCookieRotationRevokesPreviousAndSyncedZeroCountersWork(t *testing.T) {
	p, verifier, i, _, _ := runtimeFixture(t)
	owner := auth.Owner{ID: i.Owner.ID}
	_, registration, _ := verifier.BeginRegistration(owner)
	body, signer, id := fixtureRegistration(t, registration.Challenge, i.PublicOrigin, i.RPID, true, 0x18)
	credential, err := verifier.FinishRegistration(owner, *registration, body)
	if err != nil {
		t.Fatal(err)
	}
	owner.Credentials = append(owner.Credentials, *credential)
	if err := p.updateIdentity(context.Background(), func(current *setup.Installation) error { current.Owner = owner; return nil }, "", false); err != nil {
		t.Fatal(err)
	}
	old, _ := sessionFor(t, p)
	for range 2 {
		start := call(p, "POST", "/api/v1/auth/login/begin", struct{}{}, old, "")
		var begin struct {
			ID string `json:"id"`
		}
		json.Unmarshal(start.Body.Bytes(), &begin)
		var login *http.Cookie
		for _, c := range start.Result().Cookies() {
			if c.Name == loginCookie {
				login = c
			}
		}
		c := p.challenges[hash(begin.ID)]
		signed := fixtureAssertion(t, signer, id, owner.ID, c.Session.Challenge, i.PublicOrigin, i.RPID, true, 0, 0x18)
		payload, _ := json.Marshal(map[string]any{"id": begin.ID, "credential": json.RawMessage(signed)})
		request := httptest.NewRequest("POST", i.PublicOrigin+"/api/v1/auth/login/finish", bytes.NewReader(payload))
		request.Header.Set("Origin", i.PublicOrigin)
		request.Header.Set("Content-Type", "application/json")
		request.AddCookie(old)
		request.AddCookie(login)
		result := httptest.NewRecorder()
		p.ServeHTTP(result, request)
		if result.Code != 200 {
			t.Fatal("synced zero-counter login rejected", result.Code, result.Body)
		}
		var next *http.Cookie
		for _, cookie := range result.Result().Cookies() {
			if cookie.Name == sessionCookie {
				next = cookie
			}
		}
		if next == nil || next.Value == old.Value {
			t.Fatal("session not rotated")
		}
		if _, err := p.store.Session(context.Background(), hash(old.Value)); err == nil {
			t.Fatal("previous session still valid")
		}
		old = next
	}
	current, err := p.current(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !current.Owner.Credentials[0].Flags.BackupEligible || !current.Owner.Credentials[0].Flags.BackupState {
		t.Fatal("library backup state not retained")
	}
}

func TestFreshSignedUnlockGrantBindingsAndReplay(t *testing.T) {
	for _, variant := range []string{"valid", "wrong-key", "expired", "lock", "session", "purpose", "credential", "target"} {
		t.Run(variant, func(t *testing.T) {
			p, _, i, key, signer := runtimeFixture(t)
			session, csrf := sessionFor(t, p)
			w := call(p, "POST", "/api/v1/auth/fresh/begin", map[string]string{"action": "unlock", "credential_id": i.Passkey.CredentialID}, session, csrf)
			if w.Code != 200 {
				t.Fatal(w.Code, w.Body)
			}
			var b struct {
				ID string `json:"id"`
			}
			json.Unmarshal(w.Body.Bytes(), &b)
			c := p.challenges[hash(b.ID)]
			signed := fixtureAssertion(t, signer, i.Owner.Credentials[0].ID, i.Owner.ID, c.Session.Challenge, i.PublicOrigin, i.RPID, true)
			w = call(p, "POST", "/api/v1/auth/fresh/finish", map[string]any{"id": b.ID, "credential": json.RawMessage(signed)}, session, csrf)
			if w.Code != 200 {
				t.Fatal(w.Code, w.Body)
			}
			var g struct {
				Grant string `json:"grant"`
			}
			json.Unmarshal(w.Body.Bytes(), &g)
			replay := call(p, "POST", "/api/v1/auth/fresh/finish", map[string]any{"id": b.ID, "credential": json.RawMessage(signed)}, session, csrf)
			if replay.Code != 403 {
				t.Fatal("assertion replay", replay.Code)
			}
			data := p.grants[hash(g.Grant)]
			switch variant {
			case "wrong-key":
				key[0] ^= 1
			case "expired":
				data.Expires = p.now()
			case "lock":
				p.vault.Lock()
			case "session":
				data.Session = "other-session"
			case "purpose":
				data.Purpose = "export"
			case "credential":
				data.Credential = "other-credential"
			case "target":
				data.Target = "other-target"
			}
			p.grants[hash(g.Grant)] = data
			w = call(p, "POST", "/api/v1/auth/unlock", map[string]string{"grant": g.Grant, "dek": crypto.Encode(key)}, session, csrf)
			if variant == "valid" {
				if w.Code != 200 || !p.vault.Unlocked() {
					t.Fatal(w.Code, w.Body)
				}
			} else if w.Code == 200 || p.vault.Unlocked() {
				t.Fatal("invalid delivery accepted", variant, w.Code)
			}
			w = call(p, "POST", "/api/v1/auth/unlock", map[string]string{"grant": g.Grant, "dek": crypto.Encode(key)}, session, csrf)
			if w.Code != 403 {
				t.Fatal("grant replay", w.Code)
			}
		})
	}
}

func TestRuntimeSignedLoginRejectionAndConcurrentConsumption(t *testing.T) {
	for _, variant := range []string{"valid", "signature", "owner", "origin", "rp", "uv", "challenge", "expired", "purpose", "cross-origin", "unknown-credential"} {
		t.Run(variant, func(t *testing.T) {
			p, _, i, _, signer := runtimeFixture(t)
			start := call(p, "POST", "/api/v1/auth/login/begin", struct{}{}, nil, "")
			var b struct {
				ID string `json:"id"`
			}
			json.Unmarshal(start.Body.Bytes(), &b)
			var login *http.Cookie
			for _, c := range start.Result().Cookies() {
				if c.Name == loginCookie {
					login = c
				}
			}
			c := p.challenges[hash(b.ID)]
			owner := i.Owner.ID
			origin, rp := i.PublicOrigin, i.RPID
			challenge := c.Session.Challenge
			uv := true
			id := i.Owner.Credentials[0].ID
			switch variant {
			case "owner":
				owner = bytes.Repeat([]byte{9}, 32)
			case "origin":
				origin = "https://evil.example"
			case "rp":
				rp = "evil.example"
			case "uv":
				uv = false
			case "challenge":
				challenge = crypto.Encode(make([]byte, 32))
			case "expired":
				c.Expires = p.now()
				p.challenges[hash(b.ID)] = c
			case "purpose":
				c.Purpose = "unlock"
				p.challenges[hash(b.ID)] = c
			case "unknown-credential":
				id = []byte("unknown")
			}
			signed := fixtureAssertion(t, signer, id, owner, challenge, origin, rp, uv)
			if variant == "signature" || variant == "cross-origin" {
				var wire map[string]any
				json.Unmarshal(signed, &wire)
				response := wire["response"].(map[string]any)
				if variant == "signature" {
					response["signature"] = "AA"
				} else {
					raw, _ := crypto.Decode(response["clientDataJSON"].(string), -1)
					var client map[string]any
					json.Unmarshal(raw, &client)
					client["crossOrigin"] = true
					raw, _ = json.Marshal(client)
					response["clientDataJSON"] = crypto.Encode(raw)
				}
				signed, _ = json.Marshal(wire)
			}
			body := map[string]any{"id": b.ID, "credential": json.RawMessage(signed)}
			results := make(chan int, 2)
			for range 2 {
				go func() { results <- call(p, "POST", "/api/v1/auth/login/finish", body, login, "").Code }()
			}
			success := 0
			for range 2 {
				if <-results == 200 {
					success++
				}
			}
			if variant == "valid" && success != 1 || variant != "valid" && success != 0 {
				t.Fatal("wrong consume/signature outcome", success)
			}
			if p.vault.Unlocked() {
				t.Fatal("login enabled key")
			}
		})
	}
}

func TestRuntimeLockDiscardsPartialResponseAndDrains(t *testing.T) {
	p, _, _, key, _ := runtimeFixture(t)
	session, csrf := sessionFor(t, p)
	p.vault.Unlock(key, p.vault.Generation())
	entered := make(chan struct{})
	resume := make(chan struct{})
	p.managed = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("synthetic secret prefix"))
		close(entered)
		<-r.Context().Done()
		<-resume
		w.Write([]byte("suffix"))
	})
	response := make(chan *httptest.ResponseRecorder, 1)
	go func() { response <- call(p, "GET", "/api/v1/ssh-connections", nil, session, csrf) }()
	<-entered
	locked := make(chan *httptest.ResponseRecorder, 1)
	go func() { locked <- call(p, "POST", "/api/v1/auth/lock", struct{}{}, session, csrf) }()
	select {
	case <-locked:
		t.Fatal("ack before blocked operation drained")
	case <-time.After(20 * time.Millisecond):
	}
	close(resume)
	w := <-response
	if w.Code != 423 || strings.Contains(w.Body.String(), "synthetic secret") {
		t.Fatal("partial secret escaped", w.Code, w.Body)
	}
	if w = <-locked; w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
}

func TestRuntimeHostOriginCSRFFailClosedAndNoStore(t *testing.T) {
	p, _, _, key, _ := runtimeFixture(t)
	session, csrf := sessionFor(t, p)
	p.vault.Unlock(key, p.vault.Generation())
	for _, variant := range []string{"host", "forwarded", "origin", "missing-origin", "null-origin", "duplicate-origin", "csrf", "content-type", "plain-direct", "fetch-site"} {
		t.Run(variant, func(t *testing.T) {
			r := httptest.NewRequest("POST", "https://warden.example/api/v1/projects", strings.NewReader(`{}`))
			r.Header.Set("Origin", p.cfg.PublicOrigin)
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("X-CSRF-Token", csrf)
			r.AddCookie(session)
			switch variant {
			case "host", "forwarded":
				r.Host = "attacker.example"
				r.Header.Set("X-Forwarded-Host", "warden.example")
				r.Header.Set("X-Forwarded-Proto", "https")
			case "origin":
				r.Header.Set("Origin", "https://attacker.example")
			case "missing-origin":
				r.Header.Del("Origin")
			case "null-origin":
				r.Header.Set("Origin", "null")
			case "duplicate-origin":
				r.Header.Add("Origin", p.cfg.PublicOrigin)
			case "csrf":
				r.Header.Set("X-CSRF-Token", "wrong")
			case "content-type":
				r.Header.Set("Content-Type", "text/plain")
			case "plain-direct":
				p.cfg.Mode = "tls"
				r.TLS = nil
			case "fetch-site":
				r.Header.Set("Sec-Fetch-Site", "cross-site")
			}
			w := httptest.NewRecorder()
			p.ServeHTTP(w, r)
			p.cfg.Mode = "proxy"
			if w.Code != 403 || w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal(variant, w.Code, w.Body)
			}
		})
	}
}

func TestRuntimeGrantSaturationHasRetryAfter(t *testing.T) {
	p, _, i, _, signer := runtimeFixture(t)
	session, csrf := sessionFor(t, p)
	start := call(p, "POST", "/api/v1/auth/fresh/begin", map[string]string{"action": "unlock", "credential_id": i.Passkey.CredentialID}, session, csrf)
	var b struct {
		ID string `json:"id"`
	}
	json.Unmarshal(start.Body.Bytes(), &b)
	c := p.challenges[hash(b.ID)]
	for n := 0; n < 128; n++ {
		p.grants[fmt.Sprint(n)] = grant{Expires: p.now().Add(time.Minute)}
	}
	signed := fixtureAssertion(t, signer, i.Owner.Credentials[0].ID, i.Owner.ID, c.Session.Challenge, i.PublicOrigin, i.RPID, true)
	w := call(p, "POST", "/api/v1/auth/fresh/finish", map[string]any{"id": b.ID, "credential": json.RawMessage(signed)}, session, csrf)
	if w.Code != 429 || w.Header().Get("Retry-After") != "1" || len(p.grants) != 128 {
		t.Fatal("unbounded or nonretryable saturation", w.Code, w.Header())
	}
}

func TestRuntimeChallengeAndLoginLimits(t *testing.T) {
	p, _, _, _, _ := runtimeFixture(t)
	session, csrf := sessionFor(t, p)
	for n := 0; n < 9; n++ {
		w := call(p, "POST", "/api/v1/auth/fresh/begin", map[string]string{"action": "unlock", "credential_id": p.install.Passkey.CredentialID}, session, csrf)
		if n < 8 && w.Code != 200 || n == 8 && w.Code != 429 {
			t.Fatal("per-session cap", n, w.Code)
		}
	}
	for n := 0; n < 11; n++ {
		w := call(p, "POST", "/api/v1/auth/login/begin", struct{}{}, nil, "")
		if n < 10 && w.Code != 200 || n == 10 && w.Code != 429 {
			t.Fatal("rate burst", n, w.Code)
		}
	}
	p.mu.Lock()
	p.challenges = make(map[string]ceremony)
	p.mu.Unlock()
	now := time.Now()
	p.now = func() time.Time { return now }
	for n := 0; n < 129; n++ {
		now = now.Add(time.Second)
		w := call(p, "POST", "/api/v1/auth/login/begin", struct{}{}, nil, "")
		if n < 128 && w.Code != 200 || n == 128 && w.Code != 429 {
			t.Fatal("global cap", n, w.Code)
		}
	}
	if len(p.challenges) != 128 {
		t.Fatal("unbounded challenge state")
	}
}

type afterAssertion struct {
	assertionVerifier
	after func()
}

func (v afterAssertion) FinishAssertion(o auth.Owner, s webauthn.SessionData, b []byte) (*webauthn.Credential, error) {
	c, err := v.assertionVerifier.FinishAssertion(o, s, b)
	v.after()
	return c, err
}
func TestRuntimeCeremonyExpiryBeforeAndAfterVerification(t *testing.T) {
	for _, purpose := range []string{"login", "unlock"} {
		for _, after := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/after=%v", purpose, after), func(t *testing.T) {
				p, verifier, i, _, signer := runtimeFixture(t)
				var session *http.Cookie
				csrf := ""
				beginPath, finishPath := "login/begin", "login/finish"
				body := any(struct{}{})
				if purpose == "unlock" {
					session, csrf = sessionFor(t, p)
					beginPath = "fresh/begin"
					finishPath = "fresh/finish"
					body = map[string]string{"action": "unlock", "credential_id": i.Passkey.CredentialID}
				}
				start := call(p, "POST", "/api/v1/auth/"+beginPath, body, session, csrf)
				if purpose == "login" {
					for _, c := range start.Result().Cookies() {
						if c.Name == loginCookie {
							session = c
						}
					}
				}
				var b struct {
					ID string `json:"id"`
				}
				json.Unmarshal(start.Body.Bytes(), &b)
				c := p.challenges[hash(b.ID)]
				now := p.now()
				p.now = func() time.Time { return now }
				if after {
					p.verifier = afterAssertion{verifier, func() { now = now.Add(5 * time.Minute) }}
				} else {
					now = now.Add(5 * time.Minute)
				}
				signed := fixtureAssertion(t, signer, i.Owner.Credentials[0].ID, i.Owner.ID, c.Session.Challenge, i.PublicOrigin, i.RPID, true)
				w := call(p, "POST", "/api/v1/auth/"+finishPath, map[string]any{"id": b.ID, "credential": json.RawMessage(signed)}, session, csrf)
				if w.Code != 403 || len(p.grants) != 0 || p.vault.Unlocked() {
					t.Fatal("expired ceremony accepted", w.Code, w.Body)
				}
			})
		}
	}
}
func TestSessionAbsoluteExpiryAndIndependentBrowsers(t *testing.T) {
	p, _, _, key, _ := runtimeFixture(t)
	now := p.now()
	p.now = func() time.Time { return now }
	a, csrf := sessionFor(t, p)
	b, _ := sessionFor(t, p)
	p.vault.Unlock(key, p.vault.Generation())
	if w := call(p, "POST", "/api/v1/auth/logout", struct{}{}, a, csrf); w.Code != 200 {
		t.Fatal(w.Code)
	}
	if w := call(p, "GET", "/api/v1/ssh-connections", nil, b, ""); w.Code != 200 {
		t.Fatal("other browser logged out", w.Code)
	}
	for elapsed := 29 * time.Minute; elapsed < 12*time.Hour; elapsed += 29 * time.Minute {
		now = now.Add(29 * time.Minute)
		if w := call(p, "GET", "/api/v1/auth/status", nil, b, ""); w.Code != 200 {
			t.Fatal("early absolute expiry", elapsed, w.Code)
		}
	}
	now = now.Add(29 * time.Minute)
	if w := call(p, "GET", "/api/v1/auth/status", nil, b, ""); w.Code != 401 {
		t.Fatal("absolute expiry bypassed", w.Code)
	}
}

func TestSessionExpiryAndLogoutDoesNotGloballyLock(t *testing.T) {
	p, _, _, key, _ := runtimeFixture(t)
	cookie, csrf := sessionFor(t, p)
	p.vault.Unlock(key, p.vault.Generation())
	w := call(p, "POST", "/api/v1/auth/logout", map[string]any{}, cookie, csrf)
	if w.Code != 200 || !p.vault.Unlocked() {
		t.Fatal(w.Code, "logout locked vault")
	}
	if w = call(p, "GET", "/api/v1/auth/status", nil, cookie, ""); w.Code != 401 {
		t.Fatal("session not revoked", w.Code)
	}
	cookie, csrf = sessionFor(t, p)
	w = call(p, "POST", "/api/v1/auth/lock", map[string]any{}, cookie, csrf)
	if w.Code != 200 || p.vault.Unlocked() {
		t.Fatal("lock failed", w.Code)
	}
	if w = call(p, "GET", "/api/v1/auth/status", nil, cookie, ""); w.Code != 200 {
		t.Fatal("lock logged out", w.Code)
	}
	now := p.now()
	p.now = func() time.Time { return now.Add(30 * time.Minute) }
	if w = call(p, "GET", "/api/v1/auth/status", nil, cookie, ""); w.Code != 401 {
		t.Fatal("idle expiry", w.Code)
	}
}
