package runtime

import (
	"crypto/subtle"
	"io"
	"mime"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"
	"unicode"

	"warden/internal/crypto"
	"warden/internal/server"
	"warden/internal/server/audit"
	"warden/internal/store"
)

type pairing struct {
	ID         string    `json:"id"`
	Commitment string    `json:"fingerprint"`
	Label      string    `json:"label"`
	Status     string    `json:"status"`
	Expires    time.Time `json:"expires"`
	PollHash   string    `json:"-"`
	Generation uint64    `json:"-"`
	LastPoll   time.Time `json:"-"`
}

func (p *Plane) prunePairings() {
	for id, v := range p.pairings {
		if !p.now().Before(v.Expires) {
			delete(p.pairings, id)
		}
	}
}
func readClientJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 16<<10))
	defer clear(b)
	if err != nil || strict(b, v) != nil {
		fail(w, 400, "invalid_json")
		return false
	}
	return true
}
func validDeviceLabel(s string) bool {
	if len(s) < 1 || len(s) > 80 {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) || !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}
func (p *Plane) clientHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawPath != "" || path.Clean(r.URL.Path) != r.URL.Path || strings.HasSuffix(r.URL.Path, "/") {
		fail(w, 404, "not_found")
		return
	}
	if r.Method != "GET" && r.Method != "HEAD" {
		types := r.Header.Values("Content-Type")
		media := ""
		if len(types) == 1 {
			media, _, _ = mime.ParseMediaType(types[0])
		}
		if media != "application/json" {
			fail(w, 403, "forbidden")
			return
		}
	}
	select {
	case p.requests <- struct{}{}:
		defer func() { <-p.requests }()
	default:
		fail(w, 429, "rate_limited")
		return
	}
	if r.Method == "POST" && r.URL.Path == "/api/v1/client/pairing" {
		p.pairingBegin(w, r)
		return
	}
	if r.Method == "POST" && r.URL.Path == "/api/v1/client/poll" {
		p.pairingPoll(w, r)
		return
	}
	// No cookie, user-agent, pending request or polling proof authenticates data.
	auth := r.Header.Values("Authorization")
	bearer := ""
	if len(auth) == 1 && strings.HasPrefix(auth[0], "Bearer ") {
		bearer = strings.TrimPrefix(auth[0], "Bearer ")
	}
	if _, err := crypto.Decode(bearer, 32); err != nil {
		fail(w, 401, "unauthorized")
		return
	}
	verifier := hash(bearer)
	p.mu.Lock()
	c, ok := p.currentClient(r, verifier)
	p.mu.Unlock()
	if !ok {
		fail(w, 401, "unauthorized")
		return
	}
	r = requestActor(r, audit.Actor{ClientCredentialID: c.ID})
	if r.URL.Path == "/api/v1/client/logout" && r.Method == "POST" {
		if !readClientJSON(w, r, &struct{}{}) {
			return
		}
		if err := p.store.RevokeClient(r.Context(), c.ID); err != nil {
			fail(w, 500, "storage")
			return
		}
		server.WriteJSON(w, 200, map[string]bool{"authenticated": false})
		return
	}
	if r.URL.Path == "/api/v1/client/status" && r.Method == "GET" {
		server.WriteJSON(w, 200, map[string]any{"authenticated": true, "unlocked": p.vault.Unlocked()})
		return
	}
	releaseExpensive, admitted := p.admitExpensive(w, r)
	if !admitted {
		return
	}
	defer releaseExpensive()
	if p.beforeVaultAcquire != nil {
		p.beforeVaultAcquire(r)
	}
	ctx, release, err := p.vault.Acquire(r.Context())
	if err != nil {
		fail(w, 423, "vault_locked")
		return
	}
	defer release()
	p.deliver(w, r, ctx, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		// Recovery reservation and identity publication serialize with admission.
		_, ok := p.currentClient(r, verifier)
		recovering := p.recoveryRun != ""
		p.mu.Unlock()
		if !ok {
			fail(w, 401, "unauthorized")
			return
		}
		if recovering {
			fail(w, 423, "recovery_in_progress")
			return
		}
		p.clientManaged.ServeHTTP(w, r)
	}))
}

// Always read both durable verifier and current generation; no cached validity.
func (p *Plane) currentClient(r *http.Request, verifier string) (store.ClientCredential, bool) {
	c, err := p.store.ClientByVerifier(r.Context(), verifier)
	i, e := p.current(r.Context())
	return c, err == nil && e == nil && !c.Revoked && c.Generation == i.AuthorizationGeneration && subtle.ConstantTimeCompare([]byte(c.Verifier), []byte(verifier)) == 1
}
func (p *Plane) pairingBegin(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Commitment string `json:"commitment"`
		Label      string `json:"label"`
	}
	if !readClientJSON(w, r, &b) {
		return
	}
	if _, err := crypto.Decode(b.Commitment, 32); err != nil || !validDeviceLabel(b.Label) {
		fail(w, 400, "invalid_json")
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.prunePairings()
	now := p.now()
	elapsed := now.Sub(p.pairRefill).Seconds()
	if elapsed > 0 {
		p.pairTokens = min(5, p.pairTokens+elapsed)
		p.pairRefill = now
	}
	if p.pairTokens < 1 || len(p.pairings) >= 20 {
		fail(w, 429, "rate_limited")
		return
	}
	p.pairTokens--
	i, err := p.current(r.Context())
	if err != nil {
		fail(w, 500, "storage")
		return
	}
	id, err := token()
	if err != nil {
		fail(w, 500, "internal")
		return
	}
	poll, err := token()
	if err != nil {
		fail(w, 500, "internal")
		return
	}
	v := pairing{ID: id, Commitment: b.Commitment, Label: b.Label, Status: "pending", PollHash: hash(poll), Generation: i.AuthorizationGeneration, Expires: now.Add(5 * time.Minute)}
	p.pairings[id] = v
	server.WriteJSON(w, 200, map[string]any{"id": id, "poll_secret": poll, "fingerprint": v.Commitment, "approval_url": p.cfg.PublicOrigin + "/?device=" + url.QueryEscape(id), "expires": v.Expires})
}
func (p *Plane) pairingPoll(w http.ResponseWriter, r *http.Request) {
	var b struct {
		ID   string `json:"id"`
		Poll string `json:"poll_secret"`
	}
	if !readClientJSON(w, r, &b) {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.prunePairings()
	v, ok := p.pairings[b.ID]
	if !ok || subtle.ConstantTimeCompare([]byte(hash(b.Poll)), []byte(v.PollHash)) != 1 {
		fail(w, 403, "forbidden")
		return
	}
	if !v.LastPoll.IsZero() && p.now().Sub(v.LastPoll) < time.Second {
		fail(w, 429, "rate_limited")
		return
	}
	v.LastPoll = p.now()
	p.pairings[b.ID] = v
	i, err := p.current(r.Context())
	if err != nil || i.AuthorizationGeneration != v.Generation {
		fail(w, 403, "forbidden")
		return
	}
	server.WriteJSON(w, 200, map[string]string{"status": v.Status})
}
func (p *Plane) clientsManagement(w http.ResponseWriter, r *http.Request, x store.Session) {
	if r.URL.Path == "/api/v1/auth/clients/list" && r.Method == "GET" {
		p.mu.Lock()
		defer p.mu.Unlock()
		if !p.validateOrdinarySession(w, r, x) {
			return
		}
		p.prunePairings()
		pending := []pairing{}
		for _, v := range p.pairings {
			if v.Status == "pending" {
				pending = append(pending, v)
			}
		}
		clients, err := p.store.Clients(r.Context())
		if err != nil {
			fail(w, 500, "storage")
			return
		}
		i, err := p.current(r.Context())
		if err != nil {
			fail(w, 500, "storage")
			return
		}
		for n := range clients {
			clients[n].Revoked = clients[n].Revoked || clients[n].Generation != i.AuthorizationGeneration
		}
		server.WriteJSON(w, 200, map[string]any{"pending": pending, "clients": clients})
		return
	}
	purpose := actionFor(r.Method, r.URL.Path)
	if purpose != "client_approve" && purpose != "client_revoke" {
		fail(w, 404, "not_found")
		return
	}
	if !p.authorizeRequest(w, r, x.Hash, x.CredentialID, purpose) {
		return
	}
	defer r.Body.Close()
	var b struct {
		ID         string `json:"id"`
		Commitment string `json:"commitment,omitempty"`
		Deny       bool   `json:"deny,omitempty"`
	}
	if !readClientJSON(w, r, &b) {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.validateOrdinarySession(w, r, x) {
		return
	}
	p.prunePairings()
	if purpose == "client_revoke" {
		if b.ID == "" || b.Commitment != "" || b.Deny {
			fail(w, 403, "forbidden")
			return
		}
		if err := p.store.RevokeClient(r.Context(), b.ID); err != nil {
			fail(w, 500, "storage")
			return
		}
	} else {
		v, ok := p.pairings[b.ID]
		i, err := p.current(r.Context())
		if !ok || err != nil || v.Status != "pending" || v.Commitment != b.Commitment || v.Generation != i.AuthorizationGeneration {
			fail(w, 403, "forbidden")
			return
		}
		if b.Deny {
			v.Status = "denied"
		} else {
			identity, err := p.store.Installation(r.Context())
			if err != nil {
				fail(w, 500, "storage")
				return
			}
			// Same mutex as all identity writers plus the SQL identity CAS.
			err = p.store.ApproveClient(r.Context(), identity, store.ClientCredential{ID: v.ID, Verifier: v.Commitment, Label: v.Label, Generation: i.AuthorizationGeneration, Created: p.now().Unix()})
			if err != nil {
				fail(w, 409, "registration_failed")
				return
			}
			v.Status = "approved"
		}
		p.pairings[b.ID] = v
	}
	server.WriteJSON(w, 200, map[string]bool{"ok": true})
}
