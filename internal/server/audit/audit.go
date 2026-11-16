// Package audit records classifications and explicitly allowed, bounded metadata.
package audit

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"warden/internal/crypto"
	"warden/internal/model"
	"warden/internal/store"
)

const (
	maxUserAgentBytes = 512
	maxMetadataBytes  = 4 << 10
)

// Classification is a fixed audit vocabulary, not an error-message container.
type Classification string

func (c Classification) Error() string { return string(c) }

const (
	Validation      Classification = "validation"
	InvalidJSON     Classification = "invalid_json"
	InvalidGraph    Classification = "invalid_graph"
	Unauthorized    Classification = "unauthorized"
	Locked          Classification = "locked"
	RateLimited     Classification = "rate_limited"
	Storage         Classification = "storage"
	Internal        Classification = "internal"
	NotFound        Classification = "not_found"
	Conflict        Classification = "conflict"
	PayloadTooLarge Classification = "payload_too_large"
	Cancelled       Classification = "cancelled"
	Timeout         Classification = "timeout"
)

// Classify never formats an error, including unknown errors and their causes.
func Classify(err error) string {
	if err == nil {
		return ""
	}
	for _, c := range []Classification{Validation, InvalidJSON, InvalidGraph, Unauthorized, Locked, RateLimited, Storage, Internal, NotFound, Conflict, PayloadTooLarge, Cancelled, Timeout} {
		if errors.Is(err, c) {
			return string(c)
		}
	}
	switch {
	case errors.Is(err, store.ErrValidation):
		return string(Validation)
	case errors.Is(err, store.ErrNotFound):
		return string(NotFound)
	case errors.Is(err, store.ErrDuplicate), errors.Is(err, store.ErrDestinationNotEmpty):
		return string(Conflict)
	case errors.Is(err, crypto.ErrVaultLocked):
		return string(Locked)
	case errors.Is(err, context.Canceled):
		return string(Cancelled)
	case errors.Is(err, context.DeadlineExceeded):
		return string(Timeout)
	default:
		return string(Internal)
	}
}

type actorKey struct{}

// Actor contains only validated, nonsecret credential identifiers. Session token
// hashes, client verifiers and request-supplied identity headers are not IDs.
type Actor struct{ CredentialID, ClientCredentialID string }

func WithActor(ctx context.Context, actor Actor) context.Context {
	return context.WithValue(ctx, actorKey{}, actor)
}

type Recorder struct{ store *store.Store }

func New(s *store.Store) *Recorder { return &Recorder{store: s} }

func (r *Recorder) RecordRequest(ctx context.Context, req *http.Request, op, resourceType, resourceID, result string, err error, metadata map[string]any) error {
	// Copy only the finite allowed keys. Never walk or marshal attacker structures.
	safe := safeMetadata(metadata)
	delete(safe, "credential_id")
	delete(safe, "client_credential_id")
	if actor, ok := ctx.Value(actorKey{}).(Actor); ok {
		if safeID(actor.CredentialID, 1366) {
			safe["credential_id"] = actor.CredentialID
		}
		if safeID(actor.ClientCredentialID, 128) {
			safe["client_credential_id"] = actor.ClientCredentialID
		}
	}
	delete(safe, "user_agent")
	if ua := boundedUserAgent(req.UserAgent()); ua != "" {
		safe["user_agent"] = ua
	}
	return r.Record(ctx, op, resourceType, resourceID, req.RemoteAddr, result, err, safe)
}

func (r *Recorder) Record(ctx context.Context, op, resourceType, resourceID, source, result string, err error, metadata map[string]any) error {
	e := model.AuditEvent{Operation: op, ResourceType: resourceType, ResourceID: numericResourceID(resourceID), Source: peerSource(source), Result: result, Error: Classify(err), Metadata: encodeMetadata(safeMetadata(metadata))}
	return r.store.AppendAudit(ctx, e)
}

// WarnFailure surfaces audit loss without formatting the persistence error,
// which can contain SQL, parameters or driver-provided request values.
func WarnFailure(op, resourceType, resourceID string) {
	slog.Warn("audit write failed", "op", op, "resource_type", resourceType, "resource_id", numericResourceID(resourceID), "error", string(Storage))
}

func numericResourceID(id string) string {
	if len(id) == 0 || len(id) > 19 {
		return ""
	}
	n, err := strconv.ParseInt(id, 10, 64)
	if err != nil || n < 1 || strconv.FormatInt(n, 10) != id {
		return ""
	}
	return id
}
func peerSource(source string) string {
	if len(source) > 64 {
		return ""
	}
	if a, err := netip.ParseAddrPort(source); err == nil && a.Addr().Zone() == "" {
		return a.String()
	}
	if a, err := netip.ParseAddr(source); err == nil && a.Zone() == "" {
		return a.String()
	}
	return ""
}
func safeID(id string, limit int) bool {
	if len(id) == 0 || len(id) > limit {
		return false
	}
	for _, c := range id {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}
func boundedUserAgent(ua string) string {
	if len(ua) > maxUserAgentBytes {
		ua = ua[:maxUserAgentBytes]
	}
	// Drop incomplete/invalid UTF-8 and controls inside the bounded prefix only.
	return strings.Map(func(r rune) rune {
		if r == utf8.RuneError || unicode.IsControl(r) {
			return -1
		}
		return r
	}, ua)
}
func safeMetadata(metadata map[string]any) map[string]any {
	safe := make(map[string]any)
	for _, key := range []string{"groups", "key_pairs", "ssh_connections", "db_connections", "projects", "reports", "connection_notes", "status"} {
		switch v := metadata[key].(type) {
		case int:
			if v >= 0 && (key != "status" || v >= 100 && v <= 599) {
				safe[key] = v
			}
		case int64:
			if v >= 0 && (key != "status" || v >= 100 && v <= 599) {
				safe[key] = v
			}
		}
	}
	if v, ok := metadata["archived"].(bool); ok {
		safe["archived"] = v
	}
	for _, key := range []string{"credential_id", "client_credential_id"} {
		limit := 1366
		if key == "client_credential_id" {
			limit = 128
		}
		if v, ok := metadata[key].(string); ok && safeID(v, limit) {
			safe[key] = v
		}
	}
	if v, ok := metadata["user_agent"].(string); ok {
		if v = boundedUserAgent(v); v != "" {
			safe["user_agent"] = v
		}
	}
	return safe
}
func encodeMetadata(safe map[string]any) string {
	// These values are already bounded built-in primitives. Apply the encoded
	// budget deterministically, omitting a field that would overflow (UA last).
	out := make(map[string]any)
	used := 2 // braces
	for _, key := range []string{"credential_id", "client_credential_id", "status", "archived", "groups", "key_pairs", "ssh_connections", "db_connections", "projects", "reports", "connection_notes", "user_agent"} {
		v, ok := safe[key]
		if !ok {
			continue
		}
		value, _ := json.Marshal(v)
		cost := len(key) + 3 + len(value) // quoted key + colon
		if len(out) > 0 {
			cost++
		}
		if used+cost > maxMetadataBytes {
			continue
		}
		out[key] = v
		used += cost
	}
	b, _ := json.Marshal(out)
	return string(b)
}
