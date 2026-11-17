package audit

import (
	"context"
	"encoding/json"
	"net/http"

	"warden/internal/model"
	"warden/internal/store"
)

// maxErrorBytes bounds the sanitized error text stored in an audit row.
const maxErrorBytes = 1000

// Recorder writes safe audit events. It never stores credentials, SQL text,
// or remote command text: callers pass only operation names, resource
// identifiers, source metadata, and sanitized error messages.
type Recorder struct {
	store *store.Store
}

func New(s *store.Store) *Recorder { return &Recorder{store: s} }

// RecordRequest records an event derived from an HTTP request, capturing the
// remote address as source and the user agent in metadata.
func (r *Recorder) RecordRequest(ctx context.Context, req *http.Request, op, resourceType, resourceID, result string, err error, metadata map[string]any) error {
	if metadata == nil {
		metadata = map[string]any{}
	}
	if ua := req.UserAgent(); ua != "" {
		metadata["user_agent"] = ua
	}
	return r.Record(ctx, op, resourceType, resourceID, req.RemoteAddr, result, err, metadata)
}

// Record appends an audit event. err is optional; when non-nil the event
// records a failure with a sanitized, truncated error message.
func (r *Recorder) Record(ctx context.Context, op, resourceType, resourceID, source, result string, err error, metadata map[string]any) error {
	e := model.AuditEvent{
		Operation:    op,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		Source:       source,
		Result:       result,
		Metadata:     "{}",
	}
	if err != nil {
		e.Error = sanitizeError(err)
	}
	if len(metadata) > 0 {
		if b, merr := json.Marshal(metadata); merr == nil {
			e.Metadata = string(b)
		}
	}
	return r.store.AppendAudit(ctx, e)
}

func sanitizeError(err error) string {
	msg := err.Error()
	if len(msg) > maxErrorBytes {
		msg = msg[:maxErrorBytes]
	}
	return msg
}
