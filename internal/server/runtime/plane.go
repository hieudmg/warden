// Package runtime owns the authenticated management audience. Setup and future
// client pairing are separate audiences, never aliases to this mux.
package runtime

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"

	"warden/internal/config"
	"warden/internal/crypto"
	"warden/internal/server"
	"warden/internal/server/auth"
	"warden/internal/server/setup"
	"warden/internal/store"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

const sessionCookie = "__Host-warden-session"
const loginCookie = "__Host-warden-login"

type assertionVerifier interface {
	BeginAssertion(auth.Owner) (*protocol.CredentialAssertion, *webauthn.SessionData, error)
	FinishAssertion(auth.Owner, webauthn.SessionData, []byte) (*webauthn.Credential, error)
}
type ceremony struct {
	Session                              webauthn.SessionData
	Context, Purpose, Credential, Target string
	Epoch                                uint64
	Expires                              time.Time
}
type grant struct {
	Session, Credential, Purpose, Target string
	Epoch                                uint64
	Expires                              time.Time
}
type Plane struct {
	mu         sync.Mutex
	cfg        config.Setup
	store      *store.Store
	install    setup.Installation
	vault      *crypto.Vault
	verifier   assertionVerifier
	managed    http.Handler
	now        func() time.Time
	challenges map[string]ceremony
	grants     map[string]grant
	tokens     float64
	refill     time.Time
	requests   chan struct{}
}

func validateInstallation(raw []byte, cfg config.Setup) (setup.Installation, error) {
	var i setup.Installation
	invalid := errors.New("incompatible initialized storage or RP/origin: retain rollback artifacts; export using the old release and run warden-server init with fresh storage; changed RP/origin requires recovery/re-enrollment")
	if strict(raw, &i) != nil || i.Format != 1 || i.PublicOrigin != cfg.PublicOrigin || i.RPID != cfg.RPID || len(i.Owner.ID) != 32 || len(i.Owner.Credentials) != 1 {
		return i, invalid
	}
	c := i.Owner.Credentials[0]
	id := crypto.Encode(c.ID)
	if len(c.ID) == 0 || len(c.ID) > 1024 || len(c.PublicKey) == 0 || len(c.PublicKey) > 4096 {
		return i, invalid
	}
	vault := i.Passkey.VaultID
	if i.Passkey.Validate("passkey", vault, id) != nil || i.Recovery.Validate("recovery", vault, "") != nil {
		return i, invalid
	}
	if _, err := crypto.Decode(i.RecoveryVerifier, 32); err != nil {
		return i, invalid
	}
	if i.KeyCheck.Version != 1 || i.KeyCheck.VaultID != vault {
		return i, invalid
	}
	if _, err := crypto.Decode(i.KeyCheck.IV, 12); err != nil {
		return i, invalid
	}
	if _, err := crypto.Decode(i.KeyCheck.Ciphertext, len("warden/v1/vault-key-check")+16); err != nil {
		return i, invalid
	}
	return i, nil
}
func newPlane(cfg config.Setup, s *store.Store, i setup.Installation, v *crypto.Vault, verifier assertionVerifier, managed http.Handler) (*Plane, error) {
	return &Plane{cfg: cfg, store: s, install: i, vault: v, verifier: verifier, managed: managed, now: time.Now, challenges: make(map[string]ceremony), grants: make(map[string]grant), tokens: 10, refill: time.Now(), requests: make(chan struct{}, 16)}, nil
}
func hash(s string) string          { h := sha256.Sum256([]byte(s)); return crypto.Encode(h[:]) }
func csrfToken(token string) string { return hash("warden/v1/web-csrf/" + token) }
func token() (string, error) {
	b := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return crypto.Encode(b), nil
}
func strict(b []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return err
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("invalid JSON")
	}
	return nil
}
func fail(w http.ResponseWriter, status int, code string) {
	if status == http.StatusTooManyRequests {
		w.Header().Set("Retry-After", "1")
	}
	server.WriteError(w, status, code, code)
}
func cookie(w http.ResponseWriter, name, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: maxAge})
}
func readCookie(r *http.Request, name string) string {
	var value string
	n := 0
	for _, c := range r.Cookies() {
		if c.Name == name {
			value = c.Value
			n++
		}
	}
	if n != 1 {
		return ""
	}
	return value
}
func (p *Plane) session(r *http.Request) (store.Session, bool) {
	raw := readCookie(r, sessionCookie)
	if _, err := crypto.Decode(raw, 32); err != nil {
		return store.Session{}, false
	}
	x, err := p.store.Session(r.Context(), hash(raw))
	now := p.now().Unix()
	if err != nil || x.CredentialID != p.install.Passkey.CredentialID || now >= x.Seen+1800 || now >= x.Created+43200 {
		if err == nil {
			p.store.RevokeSession(r.Context(), x.Hash)
		}
		return x, false
	}
	if err = p.store.TouchSession(r.Context(), x.Hash, now); err != nil {
		return x, false
	}
	return x, true
}
func (p *Plane) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	// Existing Radix components set inline style attributes, not executable script.
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; connect-src 'self'; style-src 'self' 'unsafe-inline'; font-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; object-src 'none'; form-action 'self'")
	public, _ := url.Parse(p.cfg.PublicOrigin)
	if (p.cfg.Mode == "tls" && r.TLS == nil) || r.Host != public.Host && !(p.cfg.Mode == "proxy" && r.Host == p.cfg.BackendAuthority) {
		fail(w, 403, "forbidden")
		return
	}
	if f := r.Header.Get("Sec-Fetch-Site"); f != "" && f != "same-origin" && f != "none" {
		fail(w, 403, "forbidden")
		return
	}
	if origins := r.Header.Values("Origin"); len(origins) > 0 && (len(origins) != 1 || origins[0] != p.cfg.PublicOrigin) {
		fail(w, 403, "forbidden")
		return
	}
	if !strings.HasPrefix(r.URL.Path, "/api/") {
		p.managed.ServeHTTP(w, r)
		return
	}
	x, authenticated := p.session(r)
	publicLogin := r.URL.Path == "/api/v1/auth/login/begin" || r.URL.Path == "/api/v1/auth/login/finish"
	if !authenticated && !publicLogin {
		fail(w, 401, "unauthorized")
		return
	}
	if r.Method != "GET" && r.Method != "HEAD" {
		origins := r.Header.Values("Origin")
		cts := r.Header.Values("Content-Type")
		media := ""
		if len(cts) == 1 {
			media, _, _ = mime.ParseMediaType(cts[0])
		}
		if len(origins) != 1 || origins[0] != p.cfg.PublicOrigin || media != "application/json" {
			fail(w, 403, "forbidden")
			return
		}
		if !publicLogin && subtle.ConstantTimeCompare([]byte(hash(r.Header.Get("X-CSRF-Token"))), []byte(x.CSRFHash)) != 1 {
			fail(w, 403, "forbidden")
			return
		}
	}
	if strings.HasPrefix(r.URL.Path, "/api/v1/auth/") {
		select {
		case p.requests <- struct{}{}:
			defer func() { <-p.requests }()
		default:
			w.Header().Set("Retry-After", "1")
			fail(w, 429, "rate_limited")
			return
		}
		p.authHTTP(w, r, x)
		return
	}
	// Auth/lock checks precede canonical-path and route/method handling, so aliases,
	// redirects, unknown API paths and future registrations cannot bypass them.
	ctx, release, err := p.vault.Acquire(r.Context())
	if err != nil {
		fail(w, 423, "vault_locked")
		return
	}
	defer release()
	if path.Clean(r.URL.Path) != r.URL.Path || r.URL.RawPath != "" || strings.HasSuffix(r.URL.Path, "/") {
		fail(w, 404, "not_found")
		return
	}
	if strings.HasPrefix(r.URL.Path, "/api/v1/client/") {
		fail(w, 404, "not_found")
		return
	}
	// T3 will supply action-bound fresh grants for these exact sensitive routes.
	// Until then deny rather than accidentally exposing legacy reveal/mutations.
	// Transport bundles also inject vault private keys and must not become an
	// indirect bypass of the disabled vault reveal route. Client audience is T4.
	if strings.HasPrefix(r.URL.Path, "/api/v1/transport/") || strings.HasPrefix(r.URL.Path, "/api/v1/data/") || strings.HasPrefix(r.URL.Path, "/api/v1/key-pairs") && !(r.Method == "GET" && r.URL.Path == "/api/v1/key-pairs") {
		fail(w, 403, "fresh_action_required")
		return
	}
	// Buffer until the entire operation completes. Cancellation discards even a
	// handler's partially-written secret response. Lease covers actual delivery.
	buffered := &responseBuffer{header: make(http.Header), code: 200}
	p.managed.ServeHTTP(buffered, r.WithContext(ctx))
	if ctx.Err() != nil {
		fail(w, 423, "vault_locked")
		return
	}
	for k, values := range buffered.Header() {
		if strings.EqualFold(k, "Cache-Control") {
			continue
		}
		w.Header()[k] = values
	}
	// Write alone can leave a small secret in net/http's response buffers until
	// the outermost handler returns, after our lease has ended. Flush while the
	// lease is active. Retain the server's existing deadlines; cancellation
	// interrupts both socket writes and HTTP/1's pre-header unread-body drain.
	controller := http.NewResponseController(w)
	interrupted := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		defer close(interrupted)
		now := time.Now()
		// Stop emission before unblocking a body drain that may resume Flush.
		controller.SetWriteDeadline(now)
		controller.SetReadDeadline(now)
	})
	defer func() {
		if !stop() {
			// Never let the callback use ResponseWriter after handler return.
			<-interrupted
		}
	}()
	w.WriteHeader(buffered.code)
	n, err := w.Write(buffered.body.Bytes())
	if err != nil || n != buffered.body.Len() {
		// Do not let handler-return finalization retry retained secret bytes.
		panic(http.ErrAbortHandler)
	}
	if err := controller.Flush(); err != nil || ctx.Err() != nil {
		panic(http.ErrAbortHandler)
	}
}

// Secret responses are not streamed: cancellation must be able to discard them
// atomically before delivery. Export/import remain disabled until T3.
type responseBuffer struct {
	header http.Header
	body   bytes.Buffer
	code   int
	wrote  bool
}

func (b *responseBuffer) Header() http.Header { return b.header }
func (b *responseBuffer) WriteHeader(code int) {
	if !b.wrote {
		b.code = code
		b.wrote = true
	}
}
func (b *responseBuffer) Write(p []byte) (int, error) { b.WriteHeader(200); return b.body.Write(p) }

func (p *Plane) authHTTP(w http.ResponseWriter, r *http.Request, x store.Session) {
	if r.URL.Path == "/api/v1/auth/status" && r.Method == "GET" {
		server.WriteJSON(w, 200, map[string]any{"authenticated": true, "unlocked": p.vault.Unlocked(), "csrf": csrfToken(readCookie(r, sessionCookie)), "credential_id": x.CredentialID})
		return
	}
	if r.Method != "POST" {
		fail(w, 404, "not_found")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 64<<10))
	defer clear(body)
	if err != nil {
		fail(w, 400, "invalid_json")
		return
	}
	switch r.URL.Path {
	case "/api/v1/auth/login/begin", "/api/v1/auth/login/finish":
		if !p.loginRate() {
			w.Header().Set("Retry-After", "1")
			fail(w, 429, "rate_limited")
			return
		}
		if strings.HasSuffix(r.URL.Path, "/begin") {
			if strict(body, &struct{}{}) != nil {
				fail(w, 400, "invalid_json")
				return
			}
			p.begin(w, r, "login", "")
		} else {
			p.finish(w, r, body, "login", "")
		}
	case "/api/v1/auth/fresh/begin":
		var b struct {
			Action     string `json:"action"`
			Credential string `json:"credential_id"`
		}
		if strict(body, &b) != nil || b.Action != "unlock" || b.Credential != x.CredentialID {
			fail(w, 403, "forbidden")
			return
		}
		p.begin(w, r, "unlock", x.Hash)
	case "/api/v1/auth/fresh/finish":
		p.finish(w, r, body, "unlock", x.Hash)
	case "/api/v1/auth/unlock":
		var b struct {
			Grant string `json:"grant"`
			DEK   string `json:"dek"`
		}
		if strict(body, &b) != nil {
			fail(w, 400, "invalid_json")
			return
		}
		p.mu.Lock()
		g, ok := p.grants[hash(b.Grant)]
		delete(p.grants, hash(b.Grant))
		p.mu.Unlock()
		if !ok || g.Session != x.Hash || g.Credential != x.CredentialID || g.Purpose != "unlock" || g.Target != p.install.Passkey.CredentialID || !p.now().Before(g.Expires) {
			fail(w, 403, "forbidden")
			return
		}
		key, err := crypto.Decode(b.DEK, 32)
		defer clear(key)
		if err != nil || p.install.KeyCheck.Verify(key, p.install.Passkey.VaultID) != nil {
			fail(w, 403, "forbidden")
			return
		}
		if !p.now().Before(g.Expires) {
			fail(w, 403, "forbidden")
			return
		}
		if err = p.vault.Unlock(key, g.Epoch); err != nil {
			fail(w, 423, "vault_locked")
			return
		}
		server.WriteJSON(w, 200, map[string]bool{"unlocked": true})
	case "/api/v1/auth/lock":
		if strict(body, &struct{}{}) != nil {
			fail(w, 400, "invalid_json")
			return
		}
		p.vault.Lock()
		server.WriteJSON(w, 200, map[string]bool{"unlocked": false})
	case "/api/v1/auth/logout":
		if strict(body, &struct{}{}) != nil {
			fail(w, 400, "invalid_json")
			return
		}
		if err = p.store.RevokeSession(r.Context(), x.Hash); err != nil {
			fail(w, 500, "storage")
			return
		}
		cookie(w, sessionCookie, "", -1)
		server.WriteJSON(w, 200, map[string]bool{"authenticated": false})
	default:
		fail(w, 404, "not_found")
	}
}
func (p *Plane) loginRate() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	elapsed := now.Sub(p.refill).Seconds()
	if elapsed > 0 {
		p.tokens = min(10, p.tokens+elapsed*5)
		p.refill = now
	}
	if p.tokens < 1 {
		return false
	}
	p.tokens--
	return true
}
func (p *Plane) prune() {
	now := p.now()
	for id, c := range p.challenges {
		if !now.Before(c.Expires) {
			delete(p.challenges, id)
		}
	}
	for id, g := range p.grants {
		if !now.Before(g.Expires) {
			delete(p.grants, id)
		}
	}
}
func (p *Plane) begin(w http.ResponseWriter, r *http.Request, purpose, session string) {
	contextID := session
	if purpose == "login" {
		raw := readCookie(r, loginCookie)
		if _, err := crypto.Decode(raw, 32); err != nil {
			raw, err = token()
			if err != nil {
				fail(w, 500, "internal")
				return
			}
			cookie(w, loginCookie, raw, 300)
		}
		contextID = hash(raw)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.prune()
	count := 0
	for _, c := range p.challenges {
		if c.Context == contextID {
			count++
		}
	}
	if count >= 8 || len(p.challenges) >= 128 {
		w.Header().Set("Retry-After", "1")
		fail(w, 429, "rate_limited")
		return
	}
	opts, data, err := p.verifier.BeginAssertion(p.install.Owner)
	if err != nil {
		fail(w, 500, "internal")
		return
	}
	id, err := token()
	if err != nil {
		fail(w, 500, "internal")
		return
	}
	expires := p.now().Add(5 * time.Minute)
	if data.Expires.Before(expires) {
		expires = data.Expires
	}
	target := p.install.Passkey.CredentialID
	p.challenges[hash(id)] = ceremony{*data, contextID, purpose, target, target, p.vault.Generation(), expires}
	result := map[string]any{"id": id, "options": opts, "credential_id": target}
	if purpose == "unlock" {
		result["prf_input"] = p.install.Passkey.PRFInput
	}
	server.WriteJSON(w, 200, result)
}
func (p *Plane) finish(w http.ResponseWriter, r *http.Request, body []byte, purpose, session string) {
	var b struct {
		ID         string          `json:"id"`
		Credential json.RawMessage `json:"credential"`
	}
	if strict(body, &b) != nil {
		fail(w, 400, "invalid_json")
		return
	}
	p.mu.Lock()
	c, ok := p.challenges[hash(b.ID)]
	delete(p.challenges, hash(b.ID))
	p.mu.Unlock()
	contextID := session
	if purpose == "login" {
		contextID = hash(readCookie(r, loginCookie))
	}
	if !ok || c.Context != contextID || c.Purpose != purpose || !p.now().Before(c.Expires) {
		fail(w, 403, "forbidden")
		return
	}
	p.mu.Lock()
	owner := p.install.Owner
	owner.Credentials = append([]webauthn.Credential(nil), owner.Credentials...)
	p.mu.Unlock()
	credential, err := p.verifier.FinishAssertion(owner, c.Session, b.Credential)
	if err != nil || credential == nil || crypto.Encode(credential.ID) != c.Credential || !p.now().Before(c.Expires) {
		fail(w, 403, "forbidden")
		return
	}
	// Keep the verifier's backup/counter semantics, including valid zero counters
	// for synced credentials. Serialize updates; never roll a counter backwards.
	p.mu.Lock()
	updated := p.install
	updated.Owner.Credentials = append([]webauthn.Credential(nil), p.install.Owner.Credentials...)
	next := *credential
	if next.Authenticator.SignCount < updated.Owner.Credentials[0].Authenticator.SignCount {
		next.Authenticator.SignCount = updated.Owner.Credentials[0].Authenticator.SignCount
	}
	updated.Owner.Credentials[0] = next
	rawIdentity, saveErr := json.Marshal(updated)
	if saveErr == nil {
		saveErr = p.store.UpdateInstallation(r.Context(), rawIdentity)
	}
	if saveErr == nil {
		p.install.Owner = updated.Owner
	}
	p.mu.Unlock()
	if saveErr != nil {
		fail(w, 500, "storage")
		return
	}
	if !p.now().Before(c.Expires) {
		fail(w, 403, "forbidden")
		return
	}
	if purpose == "login" {
		raw, err := token()
		if err != nil {
			fail(w, 500, "internal")
			return
		}
		csrf := csrfToken(raw)
		now := p.now().Unix()
		if err = p.store.PruneSessions(r.Context(), now); err != nil {
			fail(w, 500, "storage")
			return
		}
		if err = p.store.SaveSession(r.Context(), store.Session{Hash: hash(raw), CSRFHash: hash(csrf), CredentialID: c.Credential, Created: now, Seen: now}); err != nil {
			fail(w, 500, "storage")
			return
		}
		if old := readCookie(r, sessionCookie); old != "" {
			if err = p.store.RevokeSession(r.Context(), hash(old)); err != nil {
				p.store.RevokeSession(r.Context(), hash(raw))
				fail(w, 500, "storage")
				return
			}
		}
		cookie(w, sessionCookie, raw, 43200)
		cookie(w, loginCookie, "", -1)
		server.WriteJSON(w, 200, map[string]any{"authenticated": true, "unlocked": p.vault.Unlocked(), "csrf": csrf, "credential_id": c.Credential})
		return
	}
	// Recheck durable session AFTER verifier work: logout during an assertion
	// must not allow its late result to grant key access.
	x, active := p.session(r)
	if !active || x.Hash != session || c.Epoch != p.vault.Generation() {
		fail(w, 403, "forbidden")
		return
	}
	raw, err := token()
	if err != nil {
		fail(w, 500, "internal")
		return
	}
	p.mu.Lock()
	p.prune()
	if len(p.grants) >= 128 {
		p.mu.Unlock()
		fail(w, 429, "rate_limited")
		return
	}
	p.grants[hash(raw)] = grant{session, c.Credential, purpose, c.Target, c.Epoch, p.now().Add(60 * time.Second)}
	p.mu.Unlock()
	server.WriteJSON(w, 200, map[string]any{"grant": raw, "wrapper": p.install.Passkey})
}
