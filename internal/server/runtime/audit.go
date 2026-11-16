package runtime

import (
	"context"
	"net/http"
	"strings"

	"warden/internal/server/audit"
)

// Security operations are exact server-owned route names, never raw URLs,
// request targets, action-header values, tokens, device labels or proofs.
func securityAuditOperation(method, route string) string {
	if method == "GET" {
		switch route {
		case "/api/v1/auth/status", "/api/v1/auth/passkeys/list", "/api/v1/auth/clients/list", "/api/v1/client/status":
		default:
			return ""
		}
	} else if method == "POST" {
		switch route {
		case "/api/v1/auth/account/login", "/api/v1/auth/account/unlock", "/api/v1/auth/account/fresh", "/api/v1/auth/account/reset",
			"/api/v1/auth/login/begin", "/api/v1/auth/login/finish",
			"/api/v1/auth/fresh/begin", "/api/v1/auth/fresh/finish",
			"/api/v1/auth/unlock", "/api/v1/auth/lock", "/api/v1/auth/logout",
			"/api/v1/auth/passkeys/begin", "/api/v1/auth/passkeys/registration", "/api/v1/auth/passkeys/assertion", "/api/v1/auth/passkeys/key", "/api/v1/auth/passkeys/commit", "/api/v1/auth/passkeys/remove",
			"/api/v1/auth/recovery/begin", "/api/v1/auth/recovery/proof", "/api/v1/auth/recovery/unlock", "/api/v1/auth/recovery/abort",
			"/api/v1/auth/recovery/rotation/key", "/api/v1/auth/recovery/rotation/prepare", "/api/v1/auth/recovery/rotation/commit",
			"/api/v1/auth/clients/approve", "/api/v1/auth/clients/revoke",
			"/api/v1/client/pairing", "/api/v1/client/poll", "/api/v1/client/logout":
		default:
			return ""
		}
	} else {
		return ""
	}
	return strings.ReplaceAll(strings.TrimPrefix(route, "/api/v1/"), "/", ".")
}

type requestAuditKey struct{}
type requestAudit struct {
	http.ResponseWriter
	status int
	actor  audit.Actor
}

func (w *requestAudit) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *requestAudit) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
	w.ResponseWriter.WriteHeader(status)
}
func (w *requestAudit) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(200)
	}
	return w.ResponseWriter.Write(b)
}
func (w *requestAudit) FlushError() error {
	if w.status == 0 {
		w.WriteHeader(200)
	}
	return http.NewResponseController(w.ResponseWriter).Flush()
}
func requestActor(r *http.Request, actor audit.Actor) *http.Request {
	if event, ok := r.Context().Value(requestAuditKey{}).(*requestAudit); ok {
		event.actor = actor
	}
	return r.WithContext(audit.WithActor(r.Context(), actor))
}
func auditStatus(status int) error {
	switch {
	case status < 400:
		return nil
	case status == 400:
		return audit.InvalidJSON
	case status == 401 || status == 403:
		return audit.Unauthorized
	case status == 404:
		return audit.NotFound
	case status == 409:
		return audit.Conflict
	case status == 413:
		return audit.PayloadTooLarge
	case status == 423:
		return audit.Locked
	case status == 429:
		return audit.RateLimited
	default:
		return audit.Internal
	}
}
func (p *Plane) recordSecurityRequest(r *http.Request, event *requestAudit, op string, panicked bool) {
	status := event.status
	if status == 0 {
		status = 200
	}
	err := auditStatus(status)
	if panicked {
		err = audit.Internal
	}
	result := "success"
	if err != nil {
		result = "failure"
	}
	ctx := audit.WithActor(r.Context(), event.actor)
	if e := audit.New(p.store).RecordRequest(ctx, r, op, "auth", "", result, err, map[string]any{"status": status}); e != nil {
		audit.WarnFailure(op, "auth", "")
	}
}
func auditedRequest(w http.ResponseWriter, r *http.Request) (*requestAudit, *http.Request) {
	event := &requestAudit{ResponseWriter: w}
	return event, r.WithContext(context.WithValue(r.Context(), requestAuditKey{}, event))
}
