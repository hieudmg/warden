package runtime

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"warden/internal/crypto"
	"warden/internal/server"
)

func signedUnlockGrant(t *testing.T, p *Plane, browser *http.Cookie, csrf string, signer *ecdsa.PrivateKey, credential []byte) string {
	t.Helper()
	begin := call(p, "POST", "/api/v1/auth/fresh/begin", map[string]string{"action": "unlock", "credential_id": crypto.Encode(credential)}, browser, csrf)
	if begin.Code != 200 {
		t.Fatalf("unlock begin: %d %s", begin.Code, begin.Body)
	}
	var b struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(begin.Body.Bytes(), &b); err != nil {
		t.Fatal(err)
	}
	c := p.challenges[hash(b.ID)]
	signed := fixtureAssertion(t, signer, credential, p.install.Owner.ID, c.Session.Challenge, p.cfg.PublicOrigin, p.cfg.RPID, true)
	finish := call(p, "POST", "/api/v1/auth/fresh/finish", map[string]any{"id": b.ID, "credential": json.RawMessage(signed)}, browser, csrf)
	if finish.Code != 200 {
		t.Fatalf("unlock finish: %d %s", finish.Code, finish.Body)
	}
	var f struct {
		Grant string `json:"grant"`
	}
	if err := json.Unmarshal(finish.Body.Bytes(), &f); err != nil {
		t.Fatal(err)
	}
	return f.Grant
}

// The delayed request crosses the real net/http + middleware boundary. Only its
// scheduling is injected; session lookup, recovery, signatures and leases are real.
func TestRecoveryRejectsOrdinaryIngressDelayedBeforeAcquire(t *testing.T) {
	for _, transition := range []string{"recovery-unlock", "replacement-normal-unlock", "logout-normal-unlock"} {
		for _, route := range []string{"/api/v1/ssh-connections", "/api/v1/auth/passkeys/registration", "/api/v1/auth/passkeys/key", "/api/v1/auth/recovery/rotation/prepare", "/api/v1/auth/recovery/rotation/key"} {
			t.Run(transition+route, func(t *testing.T) {
				p, _, original, key, signer := runtimeFixture(t)
				_, proof := recoveryFixture(t, p, key)
				browser, csrf := sessionFor(t, p)
				if err := p.vault.Unlock(key, p.vault.Generation()); err != nil {
					t.Fatal(err)
				}
				entered, resume := make(chan struct{}), make(chan struct{})
				var once, release sync.Once
				p.beforeVaultAcquire = func(r *http.Request) {
					if r.Header.Get("X-Delayed-Ingress") == "1" {
						once.Do(func() { close(entered); <-resume })
					}
				}
				var managed atomic.Int32
				p.managed = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { managed.Add(1); io.WriteString(w, deliverySecret) })
				srv := httptest.NewServer(server.New("", p).Handler())
				defer srv.Close()
				defer release.Do(func() { close(resume) })
				client := &http.Client{Timeout: 5 * time.Second}
				defer client.CloseIdleConnections()
				method, body := "GET", ""
				if route != "/api/v1/ssh-connections" {
					method, body = "POST", `{"id":"missing"}`
				}
				req, _ := http.NewRequest(method, srv.URL+route, bytes.NewBufferString(body))
				req.Host = "warden.example"
				req.AddCookie(browser)
				req.Header.Set("Origin", p.cfg.PublicOrigin)
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("X-CSRF-Token", csrf)
				req.Header.Set("X-Delayed-Ingress", "1")
				type result struct {
					code int
					body string
					err  error
				}
				done := make(chan result, 1)
				go func() {
					res, err := client.Do(req)
					if err != nil {
						done <- result{err: err}
						return
					}
					b, err := io.ReadAll(res.Body)
					res.Body.Close()
					done <- result{res.StatusCode, string(b), err}
				}()
				waitDelivery(t, entered, "ordinary ingress after initial recovery check")
				expected := 423
				if transition == "logout-normal-unlock" {
					if w := call(p, "POST", "/api/v1/auth/logout", struct{}{}, browser, csrf); w.Code != 200 {
						t.Fatal(w.Code, w.Body)
					}
					// Independent current session can unlock; the delayed revoked one cannot.
					p.vault.Lock()
					fresh, freshCSRF := loginSigner(t, p, signer, original.Owner.Credentials[0].ID)
					g := signedUnlockGrant(t, p, fresh, freshCSRF, signer, original.Owner.Credentials[0].ID)
					if w := call(p, "POST", "/api/v1/auth/unlock", map[string]string{"grant": g, "dek": crypto.Encode(key)}, fresh, freshCSRF); w.Code != 200 {
						t.Fatal(w.Code, w.Body)
					}
					expected = 401
				} else {
					recovery, recoveryCSRF, g := startRecovery(t, p, proof)
					if w := call(p, "POST", "/api/v1/auth/recovery/unlock", map[string]string{"grant": g, "dek": crypto.Encode(key)}, recovery, recoveryCSRF); w.Code != 200 {
						t.Fatal(w.Code, w.Body)
					}
					if transition == "replacement-normal-unlock" {
						id, credential, replacement := prepareEnrollmentSigned(t, p, recovery, recoveryCSRF, nil, true)
						commitEnrollment(t, p, recovery, recoveryCSRF, id, credential, key, nil, true)
						if _, err := p.store.Session(context.Background(), hash(browser.Value)); err == nil {
							t.Fatal("old durable session survived replacement")
						}
						fresh, freshCSRF := loginSigner(t, p, replacement, credential)
						g := signedUnlockGrant(t, p, fresh, freshCSRF, replacement, credential)
						if w := call(p, "POST", "/api/v1/auth/unlock", map[string]string{"grant": g, "dek": crypto.Encode(key)}, fresh, freshCSRF); w.Code != 200 {
							t.Fatal(w.Code, w.Body)
						}
						expected = 401
					}
				}
				release.Do(func() { close(resume) })
				got := <-done
				if got.err != nil {
					t.Fatal(got.err)
				}
				if got.code != expected || managed.Load() != 0 || bytes.Contains([]byte(got.body), []byte(deliverySecret)) {
					t.Fatalf("delayed ingress: status=%d want=%d managed calls=%d body=%s", got.code, expected, managed.Load(), got.body)
				}
			})
		}
	}
}

// Withhold a real HTTP body after authentication, not a sleep or fake auth
// result. The observed second socket read is authHTTP waiting for that body.
type heldAuthRequest struct {
	peer net.Conn
	req  *http.Request
}

func holdAuthRequest(t *testing.T, p *Plane, browser *http.Cookie, csrf, path string) heldAuthRequest {
	t.Helper()
	listener := &deliveryPipeListener{connections: make(chan net.Conn), closed: make(chan struct{})}
	srv := &http.Server{ReadTimeout: 120 * time.Second, WriteTimeout: 120 * time.Second, Handler: server.New("", p).Handler()}
	serving := make(chan error, 1)
	go func() { serving <- srv.Serve(listener) }()
	backend, peer := net.Pipe()
	t.Cleanup(func() { peer.Close(); srv.Close(); <-serving })
	observed := &keyEmissionConn{Conn: backend, reading: make(chan struct{}), log: new(emissionLog)}
	listener.connections <- observed
	if err := peer.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest("POST", "https://warden.example"+path, bytes.NewReader(bytes.Repeat([]byte{' '}, 4096)))
	req.AddCookie(browser)
	req.Header.Set("Origin", p.cfg.PublicOrigin)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", csrf)
	var wire bytes.Buffer
	if err := req.Write(&wire); err != nil {
		t.Fatal(err)
	}
	headers := wire.Bytes()[:bytes.Index(wire.Bytes(), []byte("\r\n\r\n"))+4]
	if _, err := peer.Write(headers); err != nil {
		t.Fatal(err)
	}
	waitDelivery(t, observed.reading, "authenticated body read on actual net/http connection")
	return heldAuthRequest{peer, req}
}

func (h heldAuthRequest) finish(t *testing.T, body any) (int, []byte) {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil || len(b) > int(h.req.ContentLength) {
		t.Fatalf("held request body: %v", err)
	}
	b = append(b, bytes.Repeat([]byte{' '}, int(h.req.ContentLength)-len(b))...)
	if _, err = h.peer.Write(b); err != nil {
		t.Fatal(err)
	}
	res, err := http.ReadResponse(bufio.NewReader(h.peer), h.req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	out, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	return res.StatusCode, out
}

func TestRecoveryRejectsFreshBeginDelayedBeforeBodyRead(t *testing.T) {
	p, _, original, key, _ := runtimeFixture(t)
	_, proof := recoveryFixture(t, p, key)
	browser, csrf := sessionFor(t, p)
	held := holdAuthRequest(t, p, browser, csrf, "/api/v1/auth/fresh/begin")
	recovery, recoveryCSRF, g := startRecovery(t, p, proof)
	if w := call(p, "POST", "/api/v1/auth/recovery/unlock", map[string]string{"grant": g, "dek": crypto.Encode(key)}, recovery, recoveryCSRF); w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	code, body := held.finish(t, map[string]string{"action": "unlock", "credential_id": original.Passkey.CredentialID})
	if code != 423 {
		t.Fatalf("fresh begin during recovery: %d %s", code, body)
	}
	p.mu.Lock()
	count := len(p.challenges)
	p.mu.Unlock()
	if count != 0 {
		t.Fatalf("ordinary challenge allocated during recovery: %d", count)
	}
}

func TestRecoveryRejectsVerifiedFinishPublication(t *testing.T) {
	for _, purpose := range []string{"fresh", "login"} {
		t.Run(purpose, func(t *testing.T) {
			p, verifier, original, key, signer := runtimeFixture(t)
			_, proof := recoveryFixture(t, p, key)
			var browser *http.Cookie
			csrf := ""
			body := any(struct{}{})
			if purpose == "fresh" {
				browser, csrf = sessionFor(t, p)
				body = map[string]string{"action": "unlock", "credential_id": original.Passkey.CredentialID}
			}
			begin := call(p, "POST", "/api/v1/auth/"+purpose+"/begin", body, browser, csrf)
			var issued struct {
				ID string `json:"id"`
			}
			if begin.Code != 200 || json.Unmarshal(begin.Body.Bytes(), &issued) != nil || issued.ID == "" {
				t.Fatalf("%s begin: %d %s", purpose, begin.Code, begin.Body)
			}
			if purpose == "login" {
				for _, c := range begin.Result().Cookies() {
					if c.Name == loginCookie {
						browser = c
					}
				}
				if browser == nil {
					t.Fatal("missing login context cookie")
				}
			}
			p.mu.Lock()
			c, ok := p.challenges[hash(issued.ID)]
			p.mu.Unlock()
			if !ok {
				t.Fatal("begin did not issue ceremony")
			}
			signed := fixtureAssertion(t, signer, original.Owner.Credentials[0].ID, original.Owner.ID, c.Session.Challenge, p.cfg.PublicOrigin, p.cfg.RPID, true)
			// This seam delegates to the real verifier first. Independently verify
			// the exact input so a verifier failure cannot masquerade as a guard hit.
			if credential, err := verifier.FinishAssertion(original.Owner, c.Session, signed); err != nil || credential == nil {
				t.Fatalf("signed fixture verification: credential=%v err=%v", credential, err)
			}
			verified, resume := make(chan struct{}), make(chan struct{})
			var release sync.Once
			p.verifier = afterAssertion{verifier, func() { close(verified); <-resume }}
			done := make(chan *httptest.ResponseRecorder, 1)
			defer func() {
				release.Do(func() { close(resume) })
			}()
			go func() {
				done <- call(p, "POST", "/api/v1/auth/"+purpose+"/finish", map[string]any{"id": issued.ID, "credential": json.RawMessage(signed)}, browser, csrf)
			}()
			waitDelivery(t, verified, "real signature verification before publication")
			startRecovery(t, p, proof)
			p.mu.Lock()
			reserved := p.recoveryRun != ""
			p.mu.Unlock()
			if !reserved {
				t.Fatal("recovery not reserved while verification blocked")
			}
			release.Do(func() { close(resume) })
			var result *httptest.ResponseRecorder
			select {
			case result = <-done:
			case <-time.After(3 * time.Second):
				t.Fatal("verified finish did not complete")
			}
			for _, cookie := range result.Result().Cookies() {
				if cookie.Name == sessionCookie && cookie.Value != "" {
					_, err := p.store.Session(context.Background(), hash(cookie.Value))
					t.Errorf("login published session cookie during recovery (durable session lookup: %v)", err)
				}
			}
			p.mu.Lock()
			grants, challenges := len(p.grants), len(p.challenges)
			p.mu.Unlock()
			if result.Code != 403 || grants != 0 || challenges != 0 || bytes.Contains(result.Body.Bytes(), []byte(`"grant"`)) || bytes.Contains(result.Body.Bytes(), []byte(`"authenticated":true`)) {
				t.Fatalf("verified %s finish published during recovery: status=%d grants=%d challenges=%d body=%s", purpose, result.Code, grants, challenges, result.Body)
			}
		})
	}
}

func TestRecoveryRejectsQueuedOrdinaryUnlockAndFreshBegin(t *testing.T) {
	p, _, original, key, signer := runtimeFixture(t)
	_, proof := recoveryFixture(t, p, key)
	browser, csrf := sessionFor(t, p)
	oldGrant := signedUnlockGrant(t, p, browser, csrf, signer, original.Owner.Credentials[0].ID)
	// Both requests pass the original audience check before proof reserves
	// recovery. Their bodies are deliberately withheld on actual HTTP connections.
	begin := holdAuthRequest(t, p, browser, csrf, "/api/v1/auth/fresh/begin")
	unlock := holdAuthRequest(t, p, browser, csrf, "/api/v1/auth/unlock")
	startRecovery(t, p, proof)
	code, body := begin.finish(t, map[string]string{"action": "unlock", "credential_id": original.Passkey.CredentialID})
	if code != 423 {
		t.Fatalf("queued fresh begin: %d %s", code, body)
	}
	code, body = unlock.finish(t, map[string]string{"grant": oldGrant, "dek": crypto.Encode(key)})
	if code != 423 || p.vault.Unlocked() {
		t.Fatalf("ordinary stale-grant unlock during recovery: %d %s unlocked=%v", code, body, p.vault.Unlocked())
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for id := range p.grants {
		if id != hash(oldGrant) {
			t.Fatal("queued fresh flow published a new grant during recovery")
		}
	}
}

func TestOrdinaryUnlockRevalidatesSessionAfterBodyRead(t *testing.T) {
	p, _, original, key, signer := runtimeFixture(t)
	browser, csrf := sessionFor(t, p)
	g := signedUnlockGrant(t, p, browser, csrf, signer, original.Owner.Credentials[0].ID)
	held := holdAuthRequest(t, p, browser, csrf, "/api/v1/auth/unlock")
	if w := call(p, "POST", "/api/v1/auth/logout", struct{}{}, browser, csrf); w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	code, body := held.finish(t, map[string]string{"grant": g, "dek": crypto.Encode(key)})
	if code != 401 || p.vault.Unlocked() {
		t.Fatalf("revoked session enabled global key: %d %s unlocked=%v", code, body, p.vault.Unlocked())
	}
}

func TestRecoveryActivationDrainsValidatedOrdinaryHandler(t *testing.T) {
	p, _, _, key, _ := runtimeFixture(t)
	_, proof := recoveryFixture(t, p, key)
	browser, csrf := sessionFor(t, p)
	if err := p.vault.Unlock(key, p.vault.Generation()); err != nil {
		t.Fatal(err)
	}
	entered, resume := make(chan context.Context, 1), make(chan struct{})
	var release sync.Once
	var mutations atomic.Int32
	p.managed = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entered <- r.Context()
		<-resume
		if r.Context().Err() == nil {
			mutations.Add(1)
			io.WriteString(w, deliverySecret)
		}
	})
	srv := httptest.NewServer(server.New("", p).Handler())
	defer srv.Close()
	defer release.Do(func() { close(resume) })
	client := &http.Client{Timeout: 5 * time.Second}
	defer client.CloseIdleConnections()
	done := make(chan []byte, 1)
	go func() {
		req, _ := http.NewRequest("POST", srv.URL+"/api/v1/ssh-connections", bytes.NewBufferString("{}"))
		req.Host = "warden.example"
		req.AddCookie(browser)
		req.Header.Set("Origin", p.cfg.PublicOrigin)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-CSRF-Token", csrf)
		res, err := client.Do(req)
		if err != nil {
			done <- nil
			return
		}
		b, _ := io.ReadAll(res.Body)
		res.Body.Close()
		done <- b
	}()
	var leased context.Context
	select {
	case leased = <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("managed handler not entered")
	}
	begin := call(p, "POST", "/api/v1/auth/recovery/begin", struct{}{}, nil, "")
	var b struct {
		ID string `json:"id"`
	}
	if begin.Code != 200 || json.Unmarshal(begin.Body.Bytes(), &b) != nil {
		t.Fatal(begin.Code, begin.Body)
	}
	proofDone := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		proofDone <- call(p, "POST", "/api/v1/auth/recovery/proof", map[string]string{"id": b.ID, "proof": crypto.Encode(proof)}, nil, "")
	}()
	waitDelivery(t, leased.Done(), "recovery cancellation of validated handler")
	select {
	case w := <-proofDone:
		t.Fatalf("proof acknowledged before handler drain: %d", w.Code)
	default:
	}
	release.Do(func() { close(resume) })
	select {
	case w := <-proofDone:
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("recovery did not drain handler")
	}
	if out := <-done; bytes.Contains(out, []byte(deliverySecret)) || mutations.Load() != 0 {
		t.Fatalf("canceled handler mutated or delivered: mutations=%d body=%s", mutations.Load(), out)
	}
}
