package runtime

import (
	"net/http"
	"strings"
)

// Transfers retain large plaintext request/response buffers through delivery.
// Two transfers and four key/verification operations may run independently;
// ordinary interactive CRUD, status, logout and lock do not queue behind them.
func (p *Plane) admitExpensive(w http.ResponseWriter, r *http.Request) (func(), bool) {
	var slots chan struct{}
	target := r.URL.Path
	switch {
	case target == "/api/v1/data/import" || target == "/api/v1/data/export":
		slots = p.transfers
	// Enrollment finish endpoints do not have a /finish suffix.
	case target == "/api/v1/auth/passkeys/registration" || target == "/api/v1/auth/passkeys/assertion",
		actionFor(r.Method, target) == "key_mutation" || actionFor(r.Method, target) == "key_reveal",
		strings.HasPrefix(target, "/api/v1/client/transport/"),
		strings.HasPrefix(target, "/api/v1/auth/") && (strings.HasSuffix(target, "/finish") || strings.HasSuffix(target, "/key") || strings.HasSuffix(target, "/prepare") || strings.HasSuffix(target, "/confirm") || strings.HasSuffix(target, "/unlock")):
		slots = p.keyOperations
	default:
		return func() {}, true
	}
	select {
	case slots <- struct{}{}:
		return func() { <-slots }, true
	default:
		fail(w, http.StatusTooManyRequests, "rate_limited")
		return nil, false
	}
}
