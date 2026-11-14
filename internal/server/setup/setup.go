// Package setup owns the temporary, setup-only initialization plane. It never
// mounts management handlers or loads a disk master key.
package setup

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"warden/internal/config"
	"warden/internal/crypto"
	"warden/internal/server/auth"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

const passwordAlphabet = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"

func GeneratePassword(rng io.Reader) (string, error) {
	b := make([]byte, 8)
	if _, err := io.ReadFull(rng, b); err != nil {
		return "", err
	}
	for i := range b {
		b[i] = passwordAlphabet[b[i]&31]
	}
	return string(b), nil
}
func hashToken(b []byte) string  { h := sha256.Sum256(b); return crypto.Encode(h[:]) }
func equalHash(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }
func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return crypto.Encode(b), nil
}

type ceremonyVerifier interface {
	BeginRegistration(auth.Owner) (*protocol.CredentialCreation, *webauthn.SessionData, error)
	FinishRegistration(auth.Owner, webauthn.SessionData, []byte) (*webauthn.Credential, error)
	BeginAssertion(auth.Owner) (*protocol.CredentialAssertion, *webauthn.SessionData, error)
	FinishAssertion(auth.Owner, webauthn.SessionData, []byte) (*webauthn.Credential, error)
}

type Installation struct {
	Format       int        `json:"format"`
	PublicOrigin string     `json:"public_origin"`
	RPID         string     `json:"rp_id"`
	Owner        auth.Owner `json:"owner"`
	// Passkey is a source compatibility alias for the first wrapper only.
	// Runtime authorization uses the complete Passkeys collection.
	Passkey  crypto.Wrapper   `json:"-"`
	Passkeys []crypto.Wrapper `json:"passkey_wrappers,omitempty"`
	// AuthorizationGeneration invalidates future T4 client verifiers on recovery.
	// T4 must bind every durable verifier to this value and check it per request.
	AuthorizationGeneration uint64          `json:"authorization_generation,omitempty"`
	Recovery                crypto.Wrapper  `json:"recovery_wrapper"`
	RecoveryVerifier        string          `json:"recovery_verifier"`
	KeyCheck                crypto.KeyCheck `json:"key_check"`
}
type Preparation struct {
	Passkey          crypto.Wrapper `json:"passkey_wrapper"`
	Recovery         crypto.Wrapper `json:"recovery_wrapper"`
	RecoveryVerifier string         `json:"recovery_verifier"`
	DEK              string         `json:"dek"`
}
type Confirmation struct {
	RecoveryAuth string `json:"recovery_auth"`
	DEK          string `json:"dek"`
}

type Plane struct {
	mu                   sync.Mutex
	cfg                  config.Setup
	assets               fs.FS
	verifier             ceremonyVerifier
	commit               func(context.Context, []byte) error
	now                  func() time.Time
	done                 chan struct{}
	stopOnce             sync.Once
	initialized          atomic.Bool
	stopped              bool
	active               bool
	deadline             time.Time
	passwordHash         string
	failures             int
	tokens               float64
	refill               time.Time
	cookieHash, csrfHash string
	owner                auth.Owner
	vaultID, prfInput    string
	phase                string
	session              *webauthn.SessionData
	expires              time.Time
	verifiedUntil        time.Time
	pending              *Installation
	requests             chan struct{}
}

func newPlane(cfg config.Setup, assets fs.FS, v ceremonyVerifier, commit func(context.Context, []byte) error) (*Plane, error) {
	owner, err := randomToken(32)
	if err != nil {
		return nil, err
	}
	id, _ := crypto.Decode(owner, 32)
	vault, err := randomToken(16)
	if err != nil {
		return nil, err
	}
	input, err := randomToken(32)
	if err != nil {
		return nil, err
	}
	return &Plane{cfg: cfg, assets: assets, verifier: v, commit: commit, now: time.Now, done: make(chan struct{}), owner: auth.Owner{ID: id}, vaultID: vault, prfInput: input, requests: make(chan struct{}, 8)}, nil
}
func (p *Plane) ready(now time.Time, password string) {
	p.active = true
	p.deadline = now.Add(15 * time.Minute)
	p.refill = now
	p.tokens = 5
	p.passwordHash = hashToken([]byte(password))
}
func (p *Plane) Done() <-chan struct{} { return p.done }
func (p *Plane) stop() {
	if !p.stopped {
		p.stopped = true
		p.active = false
		p.passwordHash = ""
		p.cookieHash = ""
		p.csrfHash = ""
		p.session = nil
		p.pending = nil
		p.stopOnce.Do(func() { close(p.done) })
	}
}
func (p *Plane) closed() bool {
	select {
	case <-p.done:
		return true
	default:
		return false
	}
}

// Signal shutdown without waiting behind verifier CPU or a blocked request.
// The current request clears state on exit; no late result can commit.
func (p *Plane) Close() {
	p.stopOnce.Do(func() { close(p.done) })
	if p.mu.TryLock() {
		p.stop()
		p.mu.Unlock()
	}
}
func strict(body []byte, dst any) error {
	d := json.NewDecoder(bytes.NewReader(body))
	d.DisallowUnknownFields()
	if err := d.Decode(dst); err != nil {
		return err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return errors.New("invalid JSON")
	}
	return nil
}
func respond(w http.ResponseWriter, status int, b any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(b)
}
func reject(w http.ResponseWriter, status int) {
	respond(w, status, map[string]string{"error": http.StatusText(status)})
}
func (p *Plane) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; connect-src 'self'; style-src 'self'; font-src 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'; form-action 'self'")
	if p.cfg.Mode == "tls" && r.TLS == nil {
		reject(w, 403)
		return
	}
	public, _ := url.Parse(p.cfg.PublicOrigin)
	if r.Host != public.Host && !(p.cfg.Mode == "proxy" && r.Host == p.cfg.BackendAuthority) {
		reject(w, 403)
		return
	}
	if fetch := r.Header.Get("Sec-Fetch-Site"); fetch != "" && fetch != "same-origin" && fetch != "none" {
		reject(w, 403)
		return
	}
	select {
	case p.requests <- struct{}{}:
		defer func() { <-p.requests }()
	default:
		w.Header().Set("Retry-After", "1")
		reject(w, 429)
		return
	}
	var body []byte
	if strings.HasPrefix(r.URL.Path, "/api/v1/setup/") {
		if r.Method != "POST" {
			reject(w, 405)
			return
		}
		if len(r.Header.Values("Origin")) != 1 || r.Header.Get("Origin") != p.cfg.PublicOrigin {
			reject(w, 403)
			return
		}
		med, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || med != "application/json" || len(r.Header.Values("Content-Type")) != 1 {
			reject(w, 403)
			return
		}
		body, err = io.ReadAll(http.MaxBytesReader(w, r.Body, 64<<10))
		if err != nil {
			reject(w, 413)
			return
		}
		defer clear(body)
	}
	p.mu.Lock()
	defer func() {
		if p.closed() {
			p.stop()
		}
		p.mu.Unlock()
	}()
	if !p.active || p.stopped || p.closed() || !p.now().Before(p.deadline) {
		p.stop()
		reject(w, 410)
		return
	}
	if !strings.HasPrefix(r.URL.Path, "/api/v1/setup/") {
		if r.Method != "GET" && r.Method != "HEAD" {
			reject(w, 404)
			return
		}
		name := strings.TrimPrefix(r.URL.Path, "/")
		if name == "" {
			name = "setup.html"
		}
		if !fs.ValidPath(name) {
			reject(w, 404)
			return
		}
		data, err := fs.ReadFile(p.assets, name)
		if err != nil {
			reject(w, 404)
			return
		}
		w.Header().Set("Content-Type", mime.TypeByExtension(path.Ext(name)))
		if r.Method != "HEAD" {
			w.Write(data)
		}
		return
	}
	if r.URL.Path == "/api/v1/setup/password" {
		p.password(w, body)
		return
	}
	cookie, err := r.Cookie("__Host-warden-setup")
	if err != nil || p.cookieHash == "" || !equalHash(hashToken([]byte(cookie.Value)), p.cookieHash) || !equalHash(hashToken([]byte(r.Header.Get("X-CSRF-Token"))), p.csrfHash) {
		reject(w, 403)
		return
	}
	switch r.URL.Path {
	case "/api/v1/setup/registration/begin":
		if p.phase != "authorized" {
			reject(w, 409)
			return
		}
		var empty struct{}
		if strict(body, &empty) != nil {
			reject(w, 400)
			return
		}
		creation, session, err := p.verifier.BeginRegistration(p.owner)
		if err != nil {
			reject(w, 500)
			return
		}
		p.phase = "registration"
		p.setSession(session)
		respond(w, 200, creation)
	case "/api/v1/setup/registration/finish":
		session, ok := p.consume("registration")
		if !ok {
			reject(w, 409)
			return
		}
		cred, err := p.verifier.FinishRegistration(p.owner, *session, body)
		if err != nil {
			reject(w, 400)
			return
		}
		if p.closed() || !p.now().Before(p.deadline) {
			p.stop()
			reject(w, 410)
			return
		}
		if !p.now().Before(p.expires) {
			p.owner.Credentials = nil
			reject(w, 409)
			return
		}
		p.owner.Credentials = []webauthn.Credential{*cred}
		assertion, s, err := p.verifier.BeginAssertion(p.owner)
		if err != nil {
			p.owner.Credentials = nil
			reject(w, 500)
			return
		}
		p.phase = "assertion"
		p.setSession(s)
		respond(w, 200, map[string]any{"assertion": assertion, "vault_id": p.vaultID, "prf_input": p.prfInput, "credential_id": crypto.Encode(cred.ID)})
	case "/api/v1/setup/assertion/finish":
		session, ok := p.consume("assertion")
		if !ok {
			reject(w, 409)
			return
		}
		cred, err := p.verifier.FinishAssertion(p.owner, *session, body)
		if err != nil {
			p.owner.Credentials = nil
			reject(w, 400)
			return
		}
		if p.closed() || !p.now().Before(p.deadline) {
			p.stop()
			reject(w, 410)
			return
		}
		if !p.now().Before(p.expires) {
			p.owner.Credentials = nil
			reject(w, 409)
			return
		}
		p.owner.Credentials = []webauthn.Credential{*cred}
		p.phase = "verified"
		p.verifiedUntil = p.now().Add(time.Minute)
		respond(w, 200, map[string]bool{"verified": true})
	case "/api/v1/setup/prepare":
		p.prepare(w, body)
	case "/api/v1/setup/finalize":
		p.finalize(w, r, body)
	default:
		reject(w, 404)
	}
}
func (p *Plane) password(w http.ResponseWriter, body []byte) {
	now := p.now()
	p.tokens += now.Sub(p.refill).Seconds()
	if p.tokens > 5 {
		p.tokens = 5
	}
	p.refill = now
	if p.tokens < 1 {
		w.Header().Set("Retry-After", "1")
		reject(w, 429)
		return
	}
	p.tokens--
	var input struct {
		Password string `json:"password"`
	}
	if strict(body, &input) != nil || !equalHash(hashToken([]byte(input.Password)), p.passwordHash) {
		p.failures++
		if p.failures >= 20 {
			p.stop()
		}
		reject(w, 401)
		return
	}
	if p.cookieHash != "" {
		reject(w, 409)
		return
	} // One setup authorization; never extend/reset ceremonies.
	token, err := randomToken(32)
	if err != nil {
		reject(w, 500)
		return
	}
	csrf, err := randomToken(32)
	if err != nil {
		reject(w, 500)
		return
	}
	p.cookieHash = hashToken([]byte(token))
	p.csrfHash = hashToken([]byte(csrf))
	p.phase = "authorized"
	http.SetCookie(w, &http.Cookie{Name: "__Host-warden-setup", Value: token, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, Expires: p.deadline})
	respond(w, 200, map[string]string{"csrf": csrf})
}
func (p *Plane) setSession(s *webauthn.SessionData) {
	p.session = s
	p.expires = p.now().Add(5 * time.Minute)
	if p.deadline.Before(p.expires) {
		p.expires = p.deadline
	}
	s.Expires = p.expires
}
func (p *Plane) consume(purpose string) (*webauthn.SessionData, bool) {
	if p.phase != purpose || p.session == nil {
		return nil, false
	}
	s := p.session
	p.session = nil
	p.phase = "authorized"
	return s, p.now().Before(p.expires)
}
func (p *Plane) prepare(w http.ResponseWriter, body []byte) {
	if p.phase != "verified" || !p.now().Before(p.verifiedUntil) {
		reject(w, 409)
		return
	}
	// Consume the key-delivery authorization even on malformed preparation.
	p.phase = "authorized"
	var prep Preparation
	if strict(body, &prep) != nil {
		reject(w, 400)
		return
	}
	dek, err := crypto.Decode(prep.DEK, 32)
	if err != nil {
		reject(w, 400)
		return
	}
	defer clear(dek)
	id := crypto.Encode(p.owner.Credentials[0].ID)
	if prep.Passkey.Validate("passkey", p.vaultID, id) != nil || prep.Passkey.PRFInput != p.prfInput || prep.Recovery.Validate("recovery", p.vaultID, "") != nil {
		reject(w, 400)
		return
	}
	if _, err := crypto.Decode(prep.RecoveryVerifier, 32); err != nil {
		reject(w, 400)
		return
	}
	check, err := crypto.NewKeyCheck(dek, p.vaultID)
	if err != nil {
		reject(w, 500)
		return
	}
	p.pending = &Installation{Format: 1, PublicOrigin: p.cfg.PublicOrigin, RPID: p.cfg.RPID, Owner: p.owner, Passkey: prep.Passkey, Recovery: prep.Recovery, RecoveryVerifier: prep.RecoveryVerifier, KeyCheck: check}
	p.phase = "prepared"
	respond(w, 200, map[string]bool{"prepared": true})
}
func (p *Plane) finalize(w http.ResponseWriter, r *http.Request, body []byte) {
	if p.phase != "prepared" || p.pending == nil {
		reject(w, 409)
		return
	}
	var c Confirmation
	if strict(body, &c) != nil {
		reject(w, 400)
		return
	}
	proof, err := crypto.Decode(c.RecoveryAuth, 32)
	if err != nil {
		reject(w, 400)
		return
	}
	defer clear(proof)
	dek, err := crypto.Decode(c.DEK, 32)
	if err != nil {
		reject(w, 400)
		return
	}
	defer clear(dek)
	if !equalHash(hashToken(proof), p.pending.RecoveryVerifier) || p.pending.KeyCheck.Verify(dek, p.vaultID) != nil {
		reject(w, 400)
		return
	}
	record, err := json.Marshal(p.pending)
	if err != nil {
		reject(w, 500)
		return
	}
	if p.closed() || !p.now().Before(p.deadline) {
		p.stop()
		reject(w, 410)
		return
	}
	ctx, cancel := context.WithDeadline(r.Context(), p.deadline)
	defer cancel()
	if err = p.commit(ctx, record); err != nil {
		p.stop()
		reject(w, 500)
		return
	}
	p.initialized.Store(true)
	p.stop()
	respond(w, 200, map[string]bool{"initialized": true})
}
