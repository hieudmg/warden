package runtime

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"warden/internal/crypto"
	"warden/internal/server"
	"warden/internal/server/auth"
	"warden/internal/server/setup"
	"warden/internal/store"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

type registrationVerifier interface {
	BeginRegistration(auth.Owner) (*protocol.CredentialCreation, *webauthn.SessionData, error)
	FinishRegistration(auth.Owner, webauthn.SessionData, []byte) (*webauthn.Credential, error)
}
type enrollment struct {
	Context                        string
	Session                        webauthn.SessionData
	Credential                     *webauthn.Credential
	PRFInput, Phase                string
	Epoch, AuthorizationGeneration uint64
	Expires                        time.Time
	Recovery                       bool
}

func (p *Plane) passkeyList(w http.ResponseWriter, r *http.Request) {
	i, err := p.current(r.Context())
	if err != nil {
		fail(w, 500, "storage")
		return
	}
	ids := make([]string, 0, len(i.Passkeys))
	for _, wrapper := range i.Passkeys {
		ids = append(ids, wrapper.CredentialID)
	}
	server.WriteJSON(w, 200, map[string]any{"credentials": ids})
}
func (p *Plane) passkeyHTTP(w http.ResponseWriter, r *http.Request, x store.Session) {
	recovering := x.CredentialID == "recovery"
	if recovering {
		p.mu.Lock()
		active := p.activeRecovery(x)
		p.mu.Unlock()
		if !active {
			fail(w, 403, "forbidden")
			return
		}
	}
	purpose := actionFor(r.Method, r.URL.Path)
	var authorized grant
	if purpose != "" && !recovering {
		p.mu.Lock()
		authorized = p.grants[hash(r.Header.Get("X-Warden-Action"))]
		p.mu.Unlock()
		if !p.authorizeRequest(w, r, x.Hash, x.CredentialID, purpose) {
			return
		}
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 64<<10))
	defer clear(body)
	if err != nil {
		fail(w, 400, "invalid_json")
		return
	}
	i, err := p.current(r.Context())
	if err != nil {
		fail(w, 500, "storage")
		return
	}
	verifier, ok := p.verifier.(registrationVerifier)
	if !ok {
		fail(w, 500, "internal")
		return
	}
	switch r.URL.Path {
	case "/api/v1/auth/passkeys/begin":
		if strict(body, &struct{}{}) != nil {
			fail(w, 400, "invalid_json")
			return
		}
		p.mu.Lock()
		defer p.mu.Unlock()
		p.prune()
		p.pruneEnrollments()
		count := 0
		for _, c := range p.challenges {
			if c.Context == x.Hash {
				count++
			}
		}
		for _, e := range p.pending {
			if e.Context == x.Hash {
				count++
			}
		}
		if len(i.Passkeys) >= 32 && !recovering {
			fail(w, 409, "passkey_limit")
			return
		}
		if count >= 8 || len(p.pending)+len(p.challenges) >= 128 {
			fail(w, 429, "rate_limited")
			return
		}
		options, session, err := verifier.BeginRegistration(i.Owner)
		if err != nil {
			fail(w, 500, "internal")
			return
		}
		id, err := token()
		if err != nil {
			fail(w, 500, "internal")
			return
		}
		p.pending[hash(id)] = enrollment{Context: x.Hash, Session: *session, Epoch: p.vault.Generation(), AuthorizationGeneration: i.AuthorizationGeneration, Expires: minTime(p.now().Add(5*time.Minute), session.Expires), Phase: "registration", Recovery: recovering}
		server.WriteJSON(w, 200, map[string]any{"id": id, "options": options})
	case "/api/v1/auth/passkeys/remove":
		var b struct {
			Credential string `json:"credential_id"`
		}
		if strict(body, &b) != nil {
			fail(w, 400, "invalid_json")
			return
		}
		last := false
		err = p.updateIdentity(r.Context(), func(current *setup.Installation) error {
			if !p.activeSession(r, x) || r.Context().Err() != nil || !p.now().Before(authorized.Expires) {
				return store.ErrNotFound
			}
			if len(current.Passkeys) <= 1 {
				last = true
				return errors.New("last passkey")
			}
			found := false
			credentials := make([]webauthn.Credential, 0, len(current.Passkeys)-1)
			for _, c := range current.Owner.Credentials {
				if crypto.Encode(c.ID) == b.Credential {
					found = true
				} else {
					credentials = append(credentials, c)
				}
			}
			if !found {
				return store.ErrNotFound
			}
			wrappers := make([]crypto.Wrapper, 0, len(credentials))
			for _, w := range current.Passkeys {
				if w.CredentialID != b.Credential {
					wrappers = append(wrappers, w)
				}
			}
			current.Owner.Credentials = credentials
			current.Passkeys = wrappers
			return nil
		}, b.Credential, false)
		if last {
			fail(w, 409, "last_passkey")
			return
		}
		if err != nil {
			fail(w, 403, "forbidden")
			return
		}
		server.WriteJSON(w, 200, map[string]bool{"removed": true})
	default:
		var b struct {
			ID         string          `json:"id"`
			Credential json.RawMessage `json:"credential,omitempty"`
			Wrapper    *crypto.Wrapper `json:"wrapper,omitempty"`
			DEK        string          `json:"dek,omitempty"`
		}
		if strict(body, &b) != nil {
			fail(w, 400, "invalid_json")
			return
		}
		p.mu.Lock()
		pending, ok := p.pending[hash(b.ID)]
		delete(p.pending, hash(b.ID))
		p.mu.Unlock()
		if !ok || pending.Context != x.Hash || pending.Recovery != recovering || pending.Epoch != p.vault.Generation() || pending.AuthorizationGeneration != i.AuthorizationGeneration || !p.now().Before(pending.Expires) {
			fail(w, 403, "forbidden")
			return
		}
		switch r.URL.Path {
		case "/api/v1/auth/passkeys/registration":
			if pending.Phase != "registration" || b.Wrapper != nil || b.DEK != "" {
				fail(w, 403, "forbidden")
				return
			}
			credential, err := verifier.FinishRegistration(i.Owner, pending.Session, b.Credential)
			if err != nil || credential == nil || !p.now().Before(pending.Expires) {
				fail(w, 403, "forbidden")
				return
			}
			options, session, err := p.verifier.BeginAssertion(auth.Owner{ID: i.Owner.ID, Credentials: []webauthn.Credential{*credential}})
			if err != nil {
				fail(w, 500, "internal")
				return
			}
			input, err := token()
			if err != nil {
				fail(w, 500, "internal")
				return
			}
			pending.Credential = credential
			pending.PRFInput = input
			pending.Session = *session
			pending.Phase = "assertion"
			pending.Expires = minTime(pending.Expires, session.Expires)
			p.putEnrollment(b.ID, pending)
			server.WriteJSON(w, 200, map[string]any{"options": options, "credential_id": crypto.Encode(credential.ID), "prf_input": input, "vault_id": i.KeyCheck.VaultID})
		case "/api/v1/auth/passkeys/assertion":
			if pending.Phase != "assertion" || b.Wrapper != nil || b.DEK != "" {
				fail(w, 403, "forbidden")
				return
			}
			credential, err := p.verifier.FinishAssertion(auth.Owner{ID: i.Owner.ID, Credentials: []webauthn.Credential{*pending.Credential}}, pending.Session, b.Credential)
			if err != nil || credential == nil || crypto.Encode(credential.ID) != crypto.Encode(pending.Credential.ID) || !p.now().Before(pending.Expires) {
				fail(w, 403, "forbidden")
				return
			}
			pending.Credential = credential
			pending.Phase = "verified"
			if recovering {
				pending.Expires = minTime(pending.Expires, p.now().Add(60*time.Second))
			}
			p.putEnrollment(b.ID, pending)
			server.WriteJSON(w, 200, map[string]bool{"verified": true})
		case "/api/v1/auth/passkeys/key":
			if pending.Phase != "verified" || b.Wrapper != nil || b.DEK != "" || len(b.Credential) > 0 {
				fail(w, 403, "forbidden")
				return
			}
			key, err := p.vault.KeyForLease(r.Context())
			defer clear(key)
			if recovering {
				authorized.Expires = pending.Expires
			}
			if err != nil || !p.now().Before(authorized.Expires) {
				fail(w, 403, "forbidden")
				return
			}
			pending.Phase = "commit"
			pending.Expires = minTime(pending.Expires, authorized.Expires)
			p.putEnrollment(b.ID, pending)
			server.WriteJSON(w, 200, map[string]any{"dek": crypto.Encode(key), "prf_input": pending.PRFInput, "vault_id": i.KeyCheck.VaultID})
		case "/api/v1/auth/passkeys/commit":
			key, e := crypto.Decode(b.DEK, 32)
			defer clear(key)
			if pending.Phase != "commit" || len(b.Credential) > 0 || b.Wrapper == nil || e != nil || i.KeyCheck.Verify(key, i.KeyCheck.VaultID) != nil || b.Wrapper.Validate("passkey", i.KeyCheck.VaultID, crypto.Encode(pending.Credential.ID)) != nil || b.Wrapper.PRFInput != pending.PRFInput {
				fail(w, 403, "forbidden")
				return
			}
			err = p.updateIdentity(r.Context(), func(current *setup.Installation) error {
				if !p.activeSession(r, x) || pending.AuthorizationGeneration != current.AuthorizationGeneration || !p.now().Before(pending.Expires) || r.Context().Err() != nil || len(current.Passkeys) >= 32 && !recovering {
					return store.ErrValidation
				}
				for _, c := range current.Owner.Credentials {
					if crypto.Encode(c.ID) == crypto.Encode(pending.Credential.ID) {
						return store.ErrValidation
					}
				}
				if recovering {
					current.Owner.Credentials = []webauthn.Credential{*pending.Credential}
					current.Passkeys = []crypto.Wrapper{*b.Wrapper}
				} else {
					current.Owner.Credentials = append(current.Owner.Credentials, *pending.Credential)
					current.Passkeys = append(current.Passkeys, *b.Wrapper)
				}
				return nil
			}, "", recovering)
			if err != nil {
				fail(w, 403, "forbidden")
				return
			}
			if recovering {
				cookie(w, recoveryCookie, "", -1)
				cookie(w, sessionCookie, "", -1)
			}
			server.WriteJSON(w, 200, map[string]bool{"added": true})
		default:
			fail(w, 404, "not_found")
		}
	}
}
func (p *Plane) activeSession(r *http.Request, x store.Session) bool {
	if x.CredentialID == "recovery" {
		return p.activeRecovery(x)
	}
	current, err := p.store.Session(r.Context(), x.Hash)
	now := p.now().Unix()
	return err == nil && current.CredentialID == x.CredentialID && now < current.Seen+1800 && now < current.Created+43200
}
func minTime(a, b time.Time) time.Time {
	if b.Before(a) {
		return b
	}
	return a
}
func (p *Plane) putEnrollment(id string, e enrollment) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.now().Before(e.Expires) {
		p.pending[hash(id)] = e
	}
}
func (p *Plane) pruneEnrollments() {
	for id, e := range p.pending {
		if !p.now().Before(e.Expires) {
			delete(p.pending, id)
		}
	}
}
