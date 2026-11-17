package runtime

import (
	"crypto/sha256"
	"crypto/subtle"
	"io"
	"net/http"
	"time"
	"warden/internal/crypto"
	"warden/internal/server"
	"warden/internal/store"
)

const recoveryCookie = "__Host-warden-recovery"

type recoveryNonce struct {
	Expires    time.Time
	Verifier   string
	Generation uint64
}
type recoveryState struct {
	CSRFHash, Grant, Phase string
	Expires, GrantExpires  time.Time
	Epoch, Generation      uint64
	Completed              bool
}

func recoveryRoute(path string) bool {
	switch path {
	case "/api/v1/auth/account/reset", "/api/v1/auth/recovery/unlock", "/api/v1/auth/recovery/abort", "/api/v1/auth/passkeys/begin", "/api/v1/auth/passkeys/registration", "/api/v1/auth/passkeys/assertion", "/api/v1/auth/passkeys/key", "/api/v1/auth/passkeys/commit":
		return true
	}
	return false
}
func (p *Plane) recoverySession(r *http.Request) (store.Session, bool) {
	raw := readCookie(r, recoveryCookie)
	if _, err := crypto.Decode(raw, 32); err != nil {
		return store.Session{}, false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	s, ok := p.recoveries[hash(raw)]
	if !ok || s.Completed || p.recoveryRun != hash(raw) || !p.now().Before(s.Expires) {
		return store.Session{}, false
	}
	return store.Session{Hash: hash(raw), CSRFHash: s.CSRFHash, CredentialID: "recovery"}, true
}
func (p *Plane) recoveryBusy() bool { p.mu.Lock(); defer p.mu.Unlock(); return p.recoveryRun != "" }
func (p *Plane) expireRecovery() {
	p.mu.Lock()
	id := p.recoveryRun
	s, ok := p.recoveries[id]
	expired := id != "" && (!ok || !p.now().Before(s.Expires))
	p.mu.Unlock()
	if expired {
		p.endRecovery(id)
	}
}
func (p *Plane) endRecovery(id string) {
	// Keep normal management blocked until the global key is actually dropped.
	p.vault.Lock()
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.recoveryRun == id {
		p.recoveryRun = ""
		delete(p.recoveries, id)
	}
	for key, e := range p.pending {
		if e.Context == id {
			delete(p.pending, key)
		}
	}
}
func (p *Plane) finishRecovery(id string) {
	p.mu.Lock()
	s, ok := p.recoveries[id]
	completed := ok && s.Completed
	p.mu.Unlock()
	if completed {
		p.endRecovery(id)
	}
}
func (p *Plane) recoveryRate() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	elapsed := now.Sub(p.recoveryRefill).Seconds()
	if elapsed > 0 {
		p.recoveryTokens = min(5, p.recoveryTokens+elapsed/10)
		p.recoveryRefill = now
	}
	if p.recoveryTokens < 1 {
		return false
	}
	p.recoveryTokens--
	return true
}
func (p *Plane) recoveryHTTP(w http.ResponseWriter, r *http.Request, x store.Session) {
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
	case "/api/v1/auth/recovery/begin":
		if !p.loginRate() {
			fail(w, 429, "rate_limited")
			return
		}
		if strict(body, &struct{}{}) != nil {
			fail(w, 400, "invalid_json")
			return
		}
		i, err := p.current(r.Context())
		if err != nil {
			fail(w, 500, "storage")
			return
		}
		p.mu.Lock()
		defer p.mu.Unlock()
		for id, n := range p.recoveryNonces {
			if !p.now().Before(n.Expires) {
				delete(p.recoveryNonces, id)
			}
		}
		if len(p.recoveryNonces) >= 128 || p.recoveryRun != "" {
			fail(w, 429, "rate_limited")
			return
		}
		id, err := token()
		if err != nil {
			fail(w, 500, "internal")
			return
		}
		p.recoveryNonces[hash(id)] = recoveryNonce{p.now().Add(5 * time.Minute), i.RecoveryVerifier, i.AuthorizationGeneration}
		// Salt is public, ciphertext is not released until the proof succeeds.
		server.WriteJSON(w, 200, map[string]string{"id": id, "kdf_salt": i.Recovery.KDFSalt})
	case "/api/v1/auth/recovery/proof":
		if !p.recoveryRate() {
			w.Header().Set("Retry-After", "10")
			server.WriteError(w, 429, "rate_limited", "rate_limited")
			return
		}
		var b struct {
			ID    string `json:"id"`
			Proof string `json:"proof"`
		}
		if strict(body, &b) != nil {
			fail(w, 400, "invalid_json")
			return
		}
		p.mu.Lock()
		n, ok := p.recoveryNonces[hash(b.ID)]
		delete(p.recoveryNonces, hash(b.ID))
		p.mu.Unlock()
		proof, e := crypto.Decode(b.Proof, 32)
		defer clear(proof)
		digest := sha256.Sum256(proof)
		if !ok || e != nil || !p.now().Before(n.Expires) || subtle.ConstantTimeCompare([]byte(crypto.Encode(digest[:])), []byte(n.Verifier)) != 1 {
			fail(w, 403, "forbidden")
			return
		}
		raw, err := token()
		if err != nil {
			fail(w, 500, "internal")
			return
		}
		g, err := token()
		if err != nil {
			fail(w, 500, "internal")
			return
		}
		p.mu.Lock()
		i, err := p.current(r.Context())
		if err != nil || i.RecoveryVerifier != n.Verifier || i.AuthorizationGeneration != n.Generation || !p.now().Before(n.Expires) || r.Context().Err() != nil || p.recoveryRun != "" {
			p.mu.Unlock()
			fail(w, 403, "forbidden")
			return
		}
		id := hash(raw)
		p.recoveryRun = id
		p.recoveries[id] = recoveryState{CSRFHash: hash(csrfToken(raw)), Grant: hash(g), Phase: "activating", Expires: p.now().Add(5 * time.Minute), GrantExpires: p.now().Add(60 * time.Second), Generation: i.AuthorizationGeneration}
		// Reserve a complete expiring context BEFORE draining old secret work.
		p.mu.Unlock()
		p.vault.Lock()
		p.mu.Lock()
		s, active := p.recoveries[id]
		if !active || p.recoveryRun != id || !p.now().Before(s.Expires) || r.Context().Err() != nil {
			p.mu.Unlock()
			p.endRecovery(id)
			fail(w, 403, "forbidden")
			return
		}
		s.Phase = "proof"
		s.Epoch = p.vault.Generation()
		p.recoveries[id] = s
		p.mu.Unlock()
		cookie(w, sessionCookie, "", -1)
		cookie(w, recoveryCookie, raw, 300)
		server.WriteJSON(w, 200, map[string]any{"csrf": csrfToken(raw), "grant": g, "wrapper": i.Recovery})
	case "/api/v1/auth/recovery/unlock":
		if x.CredentialID != "recovery" {
			fail(w, 403, "forbidden")
			return
		}
		var b struct {
			Grant string `json:"grant"`
			DEK   string `json:"dek"`
		}
		if strict(body, &b) != nil {
			fail(w, 400, "invalid_json")
			return
		}
		p.mu.Lock()
		defer p.mu.Unlock()
		s, ok := p.recoveries[x.Hash]
		if !ok || p.recoveryRun != x.Hash || s.Phase != "proof" {
			fail(w, 403, "forbidden")
			return
		}
		valid := s.Grant == hash(b.Grant) && p.now().Before(s.GrantExpires) && p.now().Before(s.Expires)
		s.Grant = ""
		s.Phase = "consumed"
		p.recoveries[x.Hash] = s
		i, e := p.current(r.Context())
		key, de := crypto.Decode(b.DEK, 32)
		defer clear(key)
		if !valid || e != nil || de != nil || i.AuthorizationGeneration != s.Generation || i.KeyCheck.Verify(key, i.KeyCheck.VaultID) != nil || r.Context().Err() != nil {
			fail(w, 403, "forbidden")
			return
		}
		if err := p.vault.Unlock(key, s.Epoch); err != nil {
			fail(w, 423, "vault_locked")
			return
		}
		s.Phase = "unlocked"
		p.recoveries[x.Hash] = s
		server.WriteJSON(w, 200, map[string]bool{"unlocked": true})
	case "/api/v1/auth/recovery/abort":
		if strict(body, &struct{}{}) != nil || x.CredentialID != "recovery" {
			fail(w, 403, "forbidden")
			return
		}
		p.mu.Lock()
		s, ok := p.recoveries[x.Hash]
		if !ok || s.Completed {
			p.mu.Unlock()
			fail(w, 409, "recovery_completed")
			return
		}
		s.Phase = "aborting"
		p.recoveries[x.Hash] = s
		p.mu.Unlock()
		p.endRecovery(x.Hash)
		cookie(w, recoveryCookie, "", -1)
		server.WriteJSON(w, 200, map[string]bool{"aborted": true})
	default:
		fail(w, 404, "not_found")
	}
}

// Called with p.mu held during identity publication; recovery is never accepted
// by the ordinary session verifier or a management route.
func (p *Plane) activeRecovery(x store.Session) bool {
	s, ok := p.recoveries[x.Hash]
	return x.CredentialID == "recovery" && ok && !s.Completed && p.recoveryRun == x.Hash && s.Phase == "unlocked" && p.now().Before(s.Expires) && s.Epoch == p.vault.Generation()
}
