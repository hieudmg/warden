package runtime

import (
	"bytes"
	"io"
	"net/http"
	"time"

	"warden/internal/crypto"
	"warden/internal/server"
	"warden/internal/server/audit"
	"warden/internal/server/setup"
	"warden/internal/store"
)

func (p *Plane) accountHTTP(w http.ResponseWriter, r *http.Request, x store.Session) {
	login, unlock, fresh := r.URL.Path == "/api/v1/auth/account/login", r.URL.Path == "/api/v1/auth/account/unlock", r.URL.Path == "/api/v1/auth/account/fresh"
	if r.Method != "POST" || !login && !unlock && !fresh {
		fail(w, 404, "not_found")
		return
	}
	if !p.loginRate() {
		fail(w, 429, "rate_limited")
		return
	}
	body, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 8<<10))
	defer clear(body)
	if e != nil {
		fail(w, 400, "invalid_json")
		return
	}
	var b struct {
		Username string `json:"username,omitempty"`
		Password string `json:"password"`
		Action   string `json:"action,omitempty"`
		Method   string `json:"method,omitempty"`
		Path     string `json:"path,omitempty"`
		Digest   string `json:"digest,omitempty"`
	}
	if strict(body, &b) != nil || !crypto.ValidPassword([]byte(b.Password)) || login && !crypto.ValidUsername(b.Username) || !login && b.Username != "" || !fresh && (b.Action != "" || b.Method != "" || b.Path != "" || b.Digest != "") {
		fail(w, 403, "forbidden")
		return
	}
	if fresh {
		if b.Action == "" || actionFor(b.Method, b.Path) != b.Action {
			fail(w, 403, "forbidden")
			return
		}
		if _, e := crypto.Decode(b.Digest, 32); e != nil {
			fail(w, 403, "forbidden")
			return
		}
	}
	// Snapshot under the publication mutex, then release it during Argon2 work.
	p.mu.Lock()
	i, e := p.current(r.Context())
	epoch := p.vault.Generation()
	old, oldActive := p.session(r)
	if e != nil || i.Account == nil || p.recoveryRun != "" || !login && (!oldActive || old.Hash != x.Hash) {
		p.mu.Unlock()
		fail(w, 403, "forbidden")
		return
	}
	p.mu.Unlock()
	password := []byte(b.Password)
	b.Password = ""
	defer clear(password)
	key, e := i.Account.Envelope.Unwrap(password, i.KeyCheck.VaultID, i.Account.ID)
	defer clear(key)
	// Wrong usernames take the same derivation path; never disclose which half failed.
	if e != nil || login && b.Username != i.Account.Username || i.KeyCheck.Verify(key, i.KeyCheck.VaultID) != nil {
		fail(w, 403, "forbidden")
		return
	}
	if p.beforeAccountPublish != nil {
		p.beforeAccountPublish(r)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	current, e := p.current(r.Context())
	if e != nil || current.Account == nil || current.Account.ID != i.Account.ID || current.AuthorizationGeneration != i.AuthorizationGeneration || p.recoveryRun != "" || p.vault.Generation() != epoch || r.Context().Err() != nil {
		fail(w, 403, "forbidden")
		return
	}
	if !login || oldActive {
		live, active := p.session(r)
		if !active || live.Hash != old.Hash {
			fail(w, 403, "forbidden")
			return
		}
	}
	if fresh {
		if !p.vault.Unlocked() && b.Action != "client_approve" && b.Action != "client_revoke" {
			fail(w, 423, "vault_locked")
			return
		}
		p.prune()
		if len(p.grants) >= 128 {
			fail(w, 429, "rate_limited")
			return
		}
		raw, e := token()
		if e != nil {
			fail(w, 500, "internal")
			return
		}
		p.grants[hash(raw)] = grant{x.Hash, i.Account.ID, b.Action, requestTarget(b.Method, b.Path, b.Digest), epoch, p.now().Add(60 * time.Second)}
		server.WriteJSON(w, 200, map[string]string{"grant": raw})
		return
	}
	if !login {
		if e = p.vault.Unlock(key, epoch); e != nil {
			fail(w, 423, "vault_locked")
			return
		}
		server.WriteJSON(w, 200, map[string]bool{"unlocked": true})
		return
	}
	raw, e := token()
	if e != nil {
		fail(w, 500, "internal")
		return
	}
	csrf := csrfToken(raw)
	now := p.now().Unix()
	if e = p.store.PruneSessions(r.Context(), now); e != nil {
		fail(w, 500, "storage")
		return
	}
	if e = p.store.SaveSession(r.Context(), store.Session{Hash: hash(raw), CSRFHash: hash(csrf), CredentialID: i.Account.ID, Created: now, Seen: now}); e != nil {
		fail(w, 500, "storage")
		return
	}
	if oldRaw := readCookie(r, sessionCookie); oldRaw != "" {
		if e = p.store.RevokeSession(r.Context(), hash(oldRaw)); e != nil {
			p.store.RevokeSession(r.Context(), hash(raw))
			fail(w, 500, "storage")
			return
		}
	}
	if e = p.vault.Unlock(key, epoch); e != nil {
		p.store.RevokeSession(r.Context(), hash(raw))
		fail(w, 423, "vault_locked")
		return
	}
	requestActor(r, audit.Actor{CredentialID: i.Account.ID})
	cookie(w, sessionCookie, raw, 43200)
	server.WriteJSON(w, 200, map[string]any{"authenticated": true, "unlocked": p.vault.Unlocked(), "csrf": csrf, "credential_id": i.Account.ID})
}

func (p *Plane) resetAccount(w http.ResponseWriter, r *http.Request, x store.Session) {
	if r.Method != "POST" || x.CredentialID != "recovery" {
		fail(w, 403, "forbidden")
		return
	}
	body, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 8<<10))
	defer clear(body)
	if e != nil {
		fail(w, 400, "invalid_json")
		return
	}
	var b struct {
		Password     string `json:"password"`
		Confirmation string `json:"password_confirmation"`
	}
	if strict(body, &b) != nil || !crypto.ValidPassword([]byte(b.Password)) || b.Password != b.Confirmation {
		fail(w, 400, "invalid_password")
		return
	}
	i, e := p.current(r.Context())
	if e != nil || i.Account == nil {
		fail(w, 403, "forbidden")
		return
	}
	key, e := p.vault.KeyForLease(r.Context())
	defer clear(key)
	if e != nil {
		fail(w, 423, "vault_locked")
		return
	}
	id, e := token()
	if e != nil {
		fail(w, 500, "internal")
		return
	}
	password := []byte(b.Password)
	b.Password = ""
	b.Confirmation = ""
	defer clear(password)
	envelope, e := crypto.WrapPassword(password, key, i.KeyCheck.VaultID, id)
	if e != nil {
		fail(w, 500, "internal")
		return
	}
	round, e := envelope.Unwrap(password, i.KeyCheck.VaultID, id)
	defer clear(round)
	if e != nil || !bytes.Equal(round, key) || i.KeyCheck.Verify(round, i.KeyCheck.VaultID) != nil {
		fail(w, 403, "forbidden")
		return
	}
	if p.beforeAccountPublish != nil {
		p.beforeAccountPublish(r)
	}
	e = p.updateIdentity(r.Context(), func(current *setup.Installation) error {
		if !p.activeRecovery(x) || r.Context().Err() != nil || current.Account == nil || current.Account.ID != i.Account.ID || current.AuthorizationGeneration != i.AuthorizationGeneration {
			return store.ErrValidation
		}
		current.Account = &setup.AccountCredential{ID: id, Username: i.Account.Username, Envelope: envelope}
		return nil
	}, "", true)
	if e != nil {
		fail(w, 403, "forbidden")
		return
	}
	cookie(w, recoveryCookie, "", -1)
	cookie(w, sessionCookie, "", -1)
	server.WriteJSON(w, 200, map[string]bool{"replaced": true})
}
