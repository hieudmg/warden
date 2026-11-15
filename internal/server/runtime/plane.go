// Package runtime owns the authenticated management and explicit client
// audiences. Setup is separate; client capabilities never alias management.
package runtime

import (
	"bytes"
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
	"warden/internal/server/audit"
	"warden/internal/server/auth"
	"warden/internal/server/profiles"
	"warden/internal/server/reports"
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
	mu             sync.Mutex
	cfg            config.Setup
	store          *store.Store
	install        setup.Installation
	vault          *crypto.Vault
	verifier       assertionVerifier
	managed        http.Handler
	clientManaged  http.Handler
	pairings       map[string]pairing
	pairTokens     float64
	pairRefill     time.Time
	now            func() time.Time
	challenges     map[string]ceremony
	grants         map[string]grant
	tokens         float64
	refill         time.Time
	requests       chan struct{}
	transfers      chan struct{}
	keyOperations  chan struct{}
	pending        map[string]enrollment
	recoveryNonces map[string]recoveryNonce
	recoveries     map[string]recoveryState
	recoveryRun    string
	recoveryTokens float64
	recoveryRefill time.Time
	rotations      map[string]recoveryRotation
	// Test-only scheduling hook; nil in production and cannot authorize a request.
	beforeVaultAcquire func(*http.Request)
}

func validateInstallation(raw []byte, cfg config.Setup) (setup.Installation, error) {
	var i setup.Installation
	invalid := errors.New("incompatible initialized storage or RP/origin: retain rollback artifacts; export using the old release and run warden-server init with fresh storage; changed RP/origin requires recovery/re-enrollment")
	if strict(raw, &i) != nil || i.Format != 1 || i.PublicOrigin != cfg.PublicOrigin || i.RPID != cfg.RPID || len(i.Owner.ID) != 32 || len(i.Owner.Credentials) < 1 || len(i.Owner.Credentials) > 32 || len(i.Passkeys) != len(i.Owner.Credentials) {
		return i, invalid
	}
	vault := i.KeyCheck.VaultID
	seen := make(map[string]bool)
	for _, c := range i.Owner.Credentials {
		id := crypto.Encode(c.ID)
		if seen[id] || len(c.ID) == 0 || len(c.ID) > 1024 || len(c.PublicKey) == 0 || len(c.PublicKey) > 4096 {
			return i, invalid
		}
		seen[id] = true
		w, ok := passkeyWrapper(i, id)
		if !ok || w.Validate("passkey", vault, id) != nil {
			return i, invalid
		}
	}
	wrappers := make(map[string]bool)
	for _, w := range i.Passkeys {
		if wrappers[w.CredentialID] || !seen[w.CredentialID] {
			return i, invalid
		}
		wrappers[w.CredentialID] = true
	}
	if i.Recovery.Validate("recovery", vault, "") != nil {
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
	raw, err := json.Marshal(i)
	if err != nil {
		return nil, err
	}
	i, err = validateInstallation(raw, cfg)
	if err != nil {
		return nil, err
	}
	clientMux := http.NewServeMux()
	profiles.New(s, audit.New(s)).RegisterClient(clientMux)
	reports.New(s, audit.New(s)).RegisterClient(clientMux)
	return &Plane{clientManaged: clientMux, pairings: make(map[string]pairing), pairTokens: 5, pairRefill: time.Now(), cfg: cfg, store: s, install: i, vault: v, verifier: verifier, managed: managed, now: time.Now, challenges: make(map[string]ceremony), grants: make(map[string]grant), tokens: 10, refill: time.Now(), requests: make(chan struct{}, 16), transfers: make(chan struct{}, 2), keyOperations: make(chan struct{}, 4), pending: make(map[string]enrollment), recoveryNonces: make(map[string]recoveryNonce), recoveries: make(map[string]recoveryState), recoveryTokens: 5, recoveryRefill: time.Now(), rotations: make(map[string]recoveryRotation)}, nil
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
	i, identityErr := p.current(r.Context())
	_, active := passkeyWrapper(i, x.CredentialID)
	if err != nil || identityErr != nil || !active || now >= x.Seen+1800 || now >= x.Created+43200 {
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
	if op := securityAuditOperation(r.Method, r.URL.Path); op != "" {
		event, request := auditedRequest(w, r)
		w, r = event, request
		defer func() {
			if v := recover(); v != nil {
				p.recordSecurityRequest(r, event, op, true)
				panic(v)
			}
			p.recordSecurityRequest(r, event, op, false)
		}()
	}
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
	p.expireRecovery()
	if strings.HasPrefix(r.URL.Path, "/api/v1/client/") {
		p.clientHTTP(w, r)
		return
	}
	// A bearer is never a management credential, even alongside a cookie.
	if r.Header.Get("Authorization") != "" {
		fail(w, 401, "unauthorized")
		return
	}
	x, authenticated := p.session(r)
	restricted, recovering := p.recoverySession(r)
	if recovering {
		x = restricted
		authenticated = true
	}
	if authenticated && !recovering {
		r = requestActor(r, audit.Actor{CredentialID: x.CredentialID})
	}
	publicRecovery := r.URL.Path == "/api/v1/auth/recovery/begin" || r.URL.Path == "/api/v1/auth/recovery/proof"
	publicLogin := r.URL.Path == "/api/v1/auth/login/begin" || r.URL.Path == "/api/v1/auth/login/finish" || publicRecovery
	if recovering && !recoveryRoute(r.URL.Path) {
		fail(w, 403, "recovery_restricted")
		return
	}
	if !authenticated && !publicLogin {
		fail(w, 401, "unauthorized")
		return
	}
	if p.recoveryBusy() && !recovering && !publicRecovery && r.URL.Path != "/api/v1/auth/status" && r.URL.Path != "/api/v1/auth/logout" && r.URL.Path != "/api/v1/auth/lock" {
		fail(w, 423, "recovery_in_progress")
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
	releaseExpensive, admitted := p.admitExpensive(w, r)
	if !admitted {
		return
	}
	defer releaseExpensive()
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
	if p.beforeVaultAcquire != nil {
		p.beforeVaultAcquire(r)
	}
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
	// Transport remains denied: T4 owns its separate client allowlist.
	if strings.HasPrefix(r.URL.Path, "/api/v1/transport/") {
		fail(w, 403, "fresh_action_required")
		return
	}
	p.deliver(w, r, ctx, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !p.validateVaultSession(w, r, x) {
			return
		}
		purpose := actionFor(r.Method, r.URL.Path)
		if purpose != "" {
			if !p.authorizeRequest(w, r, x.Hash, x.CredentialID, purpose) {
				return
			}
		} else if strings.HasPrefix(r.URL.Path, "/api/v1/data/") || strings.HasPrefix(r.URL.Path, "/api/v1/key-pairs") && !(r.Method == "GET" && (r.URL.Path == "/api/v1/key-pairs" || strings.HasSuffix(r.URL.Path, "/dependents"))) {
			fail(w, 403, "fresh_action_required")
			return
		}
		p.managed.ServeHTTP(w, r)
	}))
}

// Secret responses are not streamed: cancellation must be able to discard them
// atomically before delivery, including exports and runtime key delivery.
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
	if strings.HasPrefix(r.URL.Path, "/api/v1/auth/clients/") {
		p.clientsManagement(w, r, x)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/api/v1/auth/recovery/") {
		if strings.HasPrefix(r.URL.Path, "/api/v1/auth/recovery/rotation/") {
			if r.Method != "POST" {
				fail(w, 404, "not_found")
				return
			}
			p.withVault(w, r, x, func(w http.ResponseWriter, r *http.Request) { p.rotationHTTP(w, r, x) })
		} else {
			p.recoveryHTTP(w, r, x)
		}
		return
	}
	if strings.HasPrefix(r.URL.Path, "/api/v1/auth/passkeys/") {
		if r.Method == "GET" && r.URL.Path == "/api/v1/auth/passkeys/list" {
			p.mu.Lock()
			defer p.mu.Unlock()
			if p.validateOrdinarySession(w, r, x) {
				p.passkeyList(w, r)
			}
			return
		}
		if r.Method != "POST" {
			fail(w, 404, "not_found")
			return
		}
		defer p.finishRecovery(x.Hash)
		p.withVault(w, r, x, func(w http.ResponseWriter, r *http.Request) { p.passkeyHTTP(w, r, x) })
		return
	}
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
			Method     string `json:"method"`
			Path       string `json:"path"`
			Digest     string `json:"digest"`
		}
		if strict(body, &b) != nil || b.Credential != x.CredentialID {
			fail(w, 403, "forbidden")
			return
		}
		if b.Action == "unlock" {
			if b.Method != "" || b.Path != "" || b.Digest != "" {
				fail(w, 403, "forbidden")
				return
			}
			p.begin(w, r, "unlock", x.Hash)
		} else {
			if b.Action == "" || actionFor(b.Method, b.Path) != b.Action || (!p.vault.Unlocked() && b.Action != "client_approve" && b.Action != "client_revoke") {
				fail(w, 403, "forbidden")
				return
			}
			if _, err := crypto.Decode(b.Digest, 32); err != nil {
				fail(w, 403, "forbidden")
				return
			}
			p.begin(w, r, b.Action, x.Hash, requestTarget(b.Method, b.Path, b.Digest))
		}
	case "/api/v1/auth/fresh/finish":
		p.finish(w, r, body, "fresh", x.Hash)
	case "/api/v1/auth/unlock":
		var b struct {
			Grant string `json:"grant"`
			DEK   string `json:"dek"`
		}
		if strict(body, &b) != nil {
			fail(w, 400, "invalid_json")
			return
		}
		// Serialize revalidation and key publication with recovery reservation and
		// identity/session revocation. Never hold p.mu while draining vault leases.
		p.mu.Lock()
		defer p.mu.Unlock()
		if !p.validateOrdinarySession(w, r, x) {
			return
		}
		g, ok := p.grants[hash(b.Grant)]
		delete(p.grants, hash(b.Grant))
		if !ok || g.Session != x.Hash || g.Credential != x.CredentialID || g.Purpose != "unlock" || g.Target != x.CredentialID || !p.now().Before(g.Expires) {
			fail(w, 403, "forbidden")
			return
		}
		key, err := crypto.Decode(b.DEK, 32)
		defer clear(key)
		i, identityErr := p.current(r.Context())
		if err != nil || identityErr != nil || i.KeyCheck.Verify(key, i.KeyCheck.VaultID) != nil {
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
func (p *Plane) begin(w http.ResponseWriter, r *http.Request, purpose, session string, binding ...string) {
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
	if p.recoveryRun != "" {
		fail(w, 423, "recovery_in_progress")
		return
	}
	p.prune()
	p.pruneEnrollments()
	count := 0
	for _, e := range p.pending {
		if e.Context == contextID {
			count++
		}
	}
	for _, c := range p.challenges {
		if c.Context == contextID {
			count++
		}
	}
	if count >= 8 || len(p.challenges)+len(p.pending) >= 128 {
		w.Header().Set("Retry-After", "1")
		fail(w, 429, "rate_limited")
		return
	}
	i, err := p.current(r.Context())
	if err != nil {
		fail(w, 500, "storage")
		return
	}
	owner := i.Owner
	target := ""
	if purpose != "login" {
		x, active := p.session(r)
		if !active || x.Hash != session {
			fail(w, 403, "forbidden")
			return
		}
		target = x.CredentialID
		for _, c := range owner.Credentials {
			if crypto.Encode(c.ID) == target {
				owner.Credentials = []webauthn.Credential{c}
				break
			}
		}
	}
	opts, data, err := p.verifier.BeginAssertion(owner)
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
	bound := target
	if len(binding) > 0 {
		bound = binding[0]
	}
	p.challenges[hash(id)] = ceremony{*data, contextID, purpose, target, bound, p.vault.Generation(), expires}
	result := map[string]any{"id": id, "options": opts, "credential_id": target}
	if purpose == "unlock" {
		wrapper, _ := passkeyWrapper(i, target)
		result["prf_input"] = wrapper.PRFInput
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
	if !ok || c.Context != contextID || purpose == "login" && c.Purpose != "login" || purpose == "fresh" && c.Purpose == "login" || !p.now().Before(c.Expires) {
		fail(w, 403, "forbidden")
		return
	}
	i, identityErr := p.current(r.Context())
	if identityErr != nil {
		fail(w, 500, "storage")
		return
	}
	credential, err := p.verifier.FinishAssertion(i.Owner, c.Session, b.Credential)
	if err != nil || credential == nil || c.Credential != "" && crypto.Encode(credential.ID) != c.Credential || !p.now().Before(c.Expires) {
		fail(w, 403, "forbidden")
		return
	}
	c.Credential = crypto.Encode(credential.ID)
	// Merge counters into the CURRENT complete identity, never a stale snapshot.
	saveErr := p.updateIdentity(r.Context(), func(updated *setup.Installation) error {
		if updated.AuthorizationGeneration != i.AuthorizationGeneration {
			return store.ErrNotFound
		}
		for n, existing := range updated.Owner.Credentials {
			if crypto.Encode(existing.ID) == c.Credential {
				next := *credential
				if next.Authenticator.SignCount < existing.Authenticator.SignCount {
					next.Authenticator.SignCount = existing.Authenticator.SignCount
				}
				updated.Owner.Credentials[n] = next
				return nil
			}
		}
		return store.ErrNotFound
	}, "", false)
	if saveErr != nil {
		fail(w, 500, "storage")
		return
	}
	if !p.now().Before(c.Expires) {
		fail(w, 403, "forbidden")
		return
	}
	if purpose == "login" {
		// Serialize final credential recheck/session publication with revocation.
		p.mu.Lock()
		defer p.mu.Unlock()
		current, e := p.current(r.Context())
		_, active := passkeyWrapper(current, c.Credential)
		if p.recoveryRun != "" || e != nil || !active || current.AuthorizationGeneration != i.AuthorizationGeneration {
			fail(w, 403, "forbidden")
			return
		}
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
		requestActor(r, audit.Actor{CredentialID: c.Credential})
		cookie(w, sessionCookie, raw, 43200)
		cookie(w, loginCookie, "", -1)
		server.WriteJSON(w, 200, map[string]any{"authenticated": true, "unlocked": p.vault.Unlocked(), "csrf": csrf, "credential_id": c.Credential})
		return
	}
	// Publish a grant under the same mutex as recovery reservation/revocation.
	// Verifier work may have outlived the original session or audience check.
	p.mu.Lock()
	defer p.mu.Unlock()
	x, active := p.session(r)
	if p.recoveryRun != "" || !active || x.Hash != session || c.Epoch != p.vault.Generation() {
		fail(w, 403, "forbidden")
		return
	}
	raw, err := token()
	if err != nil {
		fail(w, 500, "internal")
		return
	}
	p.prune()
	if len(p.grants) >= 128 {
		fail(w, 429, "rate_limited")
		return
	}
	p.grants[hash(raw)] = grant{session, c.Credential, c.Purpose, c.Target, c.Epoch, p.now().Add(60 * time.Second)}
	result := map[string]any{"grant": raw}
	if c.Purpose == "unlock" {
		wrapper, _ := passkeyWrapper(i, c.Credential)
		result["wrapper"] = wrapper
	}
	server.WriteJSON(w, 200, result)
}
