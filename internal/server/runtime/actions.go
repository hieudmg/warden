package runtime

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"path"
	"strings"
	"time"

	"warden/internal/store"
)

// Deliberately no management transport action; T4 owns its client allowlist.
func actionFor(method, target string) string {
	if path.Clean(target) != target || strings.HasSuffix(target, "/") || strings.ContainsAny(target, "?#%\n\r") {
		return ""
	}
	if target == "/api/v1/data/export" && method == "GET" {
		return "export"
	}
	if target == "/api/v1/data/import" && method == "POST" {
		return "import"
	}
	if target == "/api/v1/key-pairs" && method == "POST" {
		return "key_mutation"
	}
	if strings.HasPrefix(target, "/api/v1/key-pairs/") {
		rest := strings.TrimPrefix(target, "/api/v1/key-pairs/")
		if rest != "" && !strings.Contains(rest, "/") {
			if method == "GET" {
				return "key_reveal"
			}
			if method == "PUT" || method == "DELETE" {
				return "key_mutation"
			}
		}
	}
	if method == "POST" {
		switch target {
		case "/api/v1/auth/clients/approve":
			return "client_approve"
		case "/api/v1/auth/clients/revoke":
			return "client_revoke"
		case "/api/v1/auth/passkeys/begin", "/api/v1/auth/passkeys/key":
			return "passkey_add"
		case "/api/v1/auth/passkeys/remove":
			return "passkey_remove"
		case "/api/v1/auth/recovery/rotation/key":
			return "recovery_rotate"
		}
	}
	return ""
}
func requestTarget(method, path, digest string) string { return method + "\n" + path + "\n" + digest }

// Consume before body reading; failed/oversize attempts cannot reuse a grant.
func (p *Plane) authorizeRequest(w http.ResponseWriter, r *http.Request, xHash, credential, purpose string) bool {
	p.mu.Lock()
	g, ok := p.grants[hash(r.Header.Get("X-Warden-Action"))]
	delete(p.grants, hash(r.Header.Get("X-Warden-Action")))
	p.mu.Unlock()
	if !ok || g.Session != xHash || g.Credential != credential || g.Purpose != purpose || g.Epoch != p.vault.Generation() || !p.now().Before(g.Expires) {
		fail(w, 403, "fresh_action_required")
		return false
	}
	limit := int64(1 << 20)
	if purpose == "import" {
		limit = 50 << 20
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
	if err != nil {
		clear(body)
		fail(w, 400, "invalid_json")
		return false
	}
	session, active := p.session(r)
	if !active || session.Hash != xHash || g.Target != requestTarget(r.Method, r.URL.RequestURI(), hash(string(body))) || !p.now().Before(g.Expires) || g.Epoch != p.vault.Generation() || r.Context().Err() != nil {
		clear(body)
		fail(w, 403, "fresh_action_required")
		return false
	}
	r.Body = &clearingBody{Reader: bytes.NewReader(body), body: body}
	return true
}

type clearingBody struct {
	*bytes.Reader
	body []byte
}

func (b *clearingBody) Close() error { clear(b.body); return nil }

// Called with p.mu held, which serializes recovery reservation and identity
// publication. The initial ingress session is only a hint until revalidated.
func (p *Plane) validateOrdinarySession(w http.ResponseWriter, r *http.Request, x store.Session) bool {
	if p.recoveryRun != "" {
		fail(w, 423, "recovery_in_progress")
		return false
	}
	current, active := p.session(r)
	if !active || current.Hash != x.Hash || current.CredentialID != x.CredentialID {
		fail(w, 401, "unauthorized")
		return false
	}
	return true
}

// The lease must already exist. Recovery either reserved first (reject here),
// or reserves later and must cancel/drain this lease before proof/unlock. Do not
// hold p.mu across handler execution or vault.Lock, which waits for lease release.
func (p *Plane) validateVaultSession(w http.ResponseWriter, r *http.Request, x store.Session) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if r.Context().Err() != nil {
		fail(w, 423, "vault_locked")
		return false
	}
	if x.CredentialID == "recovery" {
		if !p.activeRecovery(x) {
			fail(w, 403, "recovery_restricted")
			return false
		}
		return true
	}
	return p.validateOrdinarySession(w, r, x)
}

func (p *Plane) withVault(w http.ResponseWriter, r *http.Request, x store.Session, h http.HandlerFunc) {
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
		if p.validateVaultSession(w, r, x) {
			h(w, r)
		}
	}))
}

// Shared HTTP/1 response lease: buffer, checked Write+Flush, abort on failure.
// Install cancellation BEFORE handlers/body reads as well as delivery; lock must
// interrupt an authenticated slow upload, not wait for the 120s read budget.
func (p *Plane) deliver(w http.ResponseWriter, r *http.Request, ctx context.Context, h http.Handler) {
	controller := http.NewResponseController(w)
	interrupted := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		defer close(interrupted)
		now := time.Now()
		controller.SetWriteDeadline(now)
		controller.SetReadDeadline(now)
	})
	defer func() {
		if !stop() {
			<-interrupted
		}
	}()
	buffered := &responseBuffer{header: make(http.Header), code: 200}
	defer func() { clear(buffered.body.Bytes()) }()
	leased := r.WithContext(ctx)
	h.ServeHTTP(buffered, leased)
	if b, ok := leased.Body.(*clearingBody); ok {
		defer b.Close()
	}
	if ctx.Err() != nil {
		// No secret was sent: retain T2's stable canceled-operation response.
		fail(w, 423, "vault_locked")
		return
	}
	for k, values := range buffered.Header() {
		if !strings.EqualFold(k, "Cache-Control") {
			w.Header()[k] = values
		}
	}
	w.WriteHeader(buffered.code)
	if buffered.body.Len() != 0 {
		n, err := w.Write(buffered.body.Bytes())
		if err != nil || n != buffered.body.Len() {
			panic(http.ErrAbortHandler)
		}
	}
	if err := controller.Flush(); err != nil || ctx.Err() != nil {
		panic(http.ErrAbortHandler)
	}
}
