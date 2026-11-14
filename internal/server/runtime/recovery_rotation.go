package runtime

import (
	"crypto/sha256"
	"crypto/subtle"
	"io"
	"net/http"
	"time"
	"warden/internal/crypto"
	"warden/internal/server"
	"warden/internal/server/setup"
	"warden/internal/store"
)

type recoveryRotation struct {
	Context, Credential, PreviousVerifier, Verifier string
	Epoch, Generation                               uint64
	Expires                                         time.Time
	Wrapper                                         *crypto.Wrapper
}

func (p *Plane) rotationHTTP(w http.ResponseWriter, r *http.Request, x store.Session) {
	if r.URL.Path == "/api/v1/auth/recovery/rotation/key" {
		p.mu.Lock()
		g := p.grants[hash(r.Header.Get("X-Warden-Action"))]
		p.mu.Unlock()
		if !p.authorizeRequest(w, r, x.Hash, x.CredentialID, "recovery_rotate") {
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 64<<10))
		defer clear(body)
		if err != nil || strict(body, &struct{}{}) != nil {
			fail(w, 400, "invalid_json")
			return
		}
		i, err := p.current(r.Context())
		if err != nil {
			fail(w, 500, "storage")
			return
		}
		key, err := p.vault.KeyForLease(r.Context())
		defer clear(key)
		if err != nil || !p.now().Before(g.Expires) {
			fail(w, 403, "forbidden")
			return
		}
		id, err := token()
		if err != nil {
			fail(w, 500, "internal")
			return
		}
		p.mu.Lock()
		defer p.mu.Unlock()
		count := 0
		for id, e := range p.rotations {
			if !p.now().Before(e.Expires) {
				delete(p.rotations, id)
			} else if e.Context == x.Hash {
				count++
			}
		}
		if count >= 8 || len(p.rotations) >= 128 {
			fail(w, 429, "rate_limited")
			return
		}
		p.rotations[hash(id)] = recoveryRotation{Context: x.Hash, Credential: x.CredentialID, PreviousVerifier: i.RecoveryVerifier, Epoch: g.Epoch, Generation: i.AuthorizationGeneration, Expires: g.Expires}
		server.WriteJSON(w, 200, map[string]string{"id": id, "dek": crypto.Encode(key), "vault_id": i.KeyCheck.VaultID})
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 64<<10))
	defer clear(body)
	if err != nil {
		fail(w, 400, "invalid_json")
		return
	}
	var b struct {
		ID       string          `json:"id"`
		Wrapper  *crypto.Wrapper `json:"wrapper,omitempty"`
		Verifier string          `json:"verifier,omitempty"`
		Proof    string          `json:"proof,omitempty"`
		DEK      string          `json:"dek,omitempty"`
	}
	if strict(body, &b) != nil {
		fail(w, 400, "invalid_json")
		return
	}
	p.mu.Lock()
	pending, ok := p.rotations[hash(b.ID)]
	delete(p.rotations, hash(b.ID))
	p.mu.Unlock()
	i, e := p.current(r.Context())
	if !ok || e != nil || pending.Context != x.Hash || pending.Credential != x.CredentialID || pending.Epoch != p.vault.Generation() || pending.Generation != i.AuthorizationGeneration || pending.PreviousVerifier != i.RecoveryVerifier || !p.now().Before(pending.Expires) {
		fail(w, 403, "forbidden")
		return
	}
	switch r.URL.Path {
	case "/api/v1/auth/recovery/rotation/prepare":
		if pending.Wrapper != nil || b.Wrapper == nil || b.Wrapper.Validate("recovery", i.KeyCheck.VaultID, "") != nil || b.DEK != "" || b.Proof != "" {
			fail(w, 403, "forbidden")
			return
		}
		if _, e := crypto.Decode(b.Verifier, 32); e != nil {
			fail(w, 403, "forbidden")
			return
		}
		pending.Wrapper = b.Wrapper
		pending.Verifier = b.Verifier
		p.mu.Lock()
		p.rotations[hash(b.ID)] = pending
		p.mu.Unlock()
		server.WriteJSON(w, 200, map[string]bool{"prepared": true})
	case "/api/v1/auth/recovery/rotation/commit":
		proof, e := crypto.Decode(b.Proof, 32)
		defer clear(proof)
		digest := sha256.Sum256(proof)
		key, de := crypto.Decode(b.DEK, 32)
		defer clear(key)
		if e != nil || de != nil || pending.Wrapper == nil || b.Wrapper != nil || b.Verifier != "" || subtle.ConstantTimeCompare([]byte(crypto.Encode(digest[:])), []byte(pending.Verifier)) != 1 || i.KeyCheck.Verify(key, i.KeyCheck.VaultID) != nil {
			fail(w, 403, "forbidden")
			return
		}
		err = p.updateIdentity(r.Context(), func(current *setup.Installation) error {
			if !p.activeSession(r, x) || pending.Generation != current.AuthorizationGeneration || pending.PreviousVerifier != current.RecoveryVerifier || !p.now().Before(pending.Expires) || pending.Epoch != p.vault.Generation() || r.Context().Err() != nil {
				return store.ErrValidation
			}
			current.Recovery = *pending.Wrapper
			current.RecoveryVerifier = pending.Verifier
			return nil
		}, "", false)
		if err != nil {
			fail(w, 403, "forbidden")
			return
		}
		server.WriteJSON(w, 200, map[string]bool{"rotated": true})
	default:
		fail(w, 404, "not_found")
	}
}
