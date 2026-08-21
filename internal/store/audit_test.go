package store

import (
	"context"
	"testing"
	"time"

	"warden/internal/model"
)

func TestAppendAuditPersists(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	before := time.Now().UTC()

	event := model.AuditEvent{
		Operation:    "profile.retrieve",
		ResourceType: "ssh_connection",
		ResourceID:   "web-prod",
		Source:       "10.0.0.7",
		Result:       "success",
		Error:        "",
		Metadata:     `{"endpoint":"/api/v1/transport/ssh/1"}`,
	}
	if err := s.AppendAudit(ctx, event); err != nil {
		t.Fatalf("AppendAudit: %v", err)
	}
	after := time.Now().UTC()

	var id int64
	var operation, resourceType, resourceID, source, result, errText, metadata, createdAt string
	row := s.db.QueryRowContext(ctx,
		"SELECT id, operation, resource_type, resource_id, source, result, error, metadata, created_at FROM audit_events")
	if err := row.Scan(&id, &operation, &resourceType, &resourceID, &source, &result, &errText, &metadata, &createdAt); err != nil {
		t.Fatalf("read audit row: %v", err)
	}
	if id == 0 {
		t.Error("audit id is zero")
	}
	if operation != "profile.retrieve" || resourceType != "ssh_connection" || resourceID != "web-prod" {
		t.Errorf("audit identity fields mismatch: %+v", event)
	}
	if source != "10.0.0.7" || result != "success" || errText != "" || metadata != event.Metadata {
		t.Errorf("audit metadata fields mismatch: source=%q result=%q err=%q metadata=%q", source, result, errText, metadata)
	}

	parsed, err := time.Parse(time.RFC3339Nano, createdAt)
	if err != nil {
		t.Fatalf("created_at %q not RFC3339: %v", createdAt, err)
	}
	if parsed.Before(before) || parsed.After(after) {
		t.Errorf("created_at %v outside [%v, %v]; must be server-generated", parsed, before, after)
	}
}

func TestAppendAuditFailureResult(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	event := model.AuditEvent{
		Operation:    "ssh_connection.delete",
		ResourceType: "ssh_connection",
		ResourceID:   "gone",
		Source:       "127.0.0.1",
		Result:       "failure",
		Error:        "not found",
		Metadata:     `{}`,
	}
	if err := s.AppendAudit(ctx, event); err != nil {
		t.Fatalf("AppendAudit: %v", err)
	}
	var result, errText string
	if err := s.db.QueryRowContext(ctx, "SELECT result, error FROM audit_events").Scan(&result, &errText); err != nil {
		t.Fatalf("read audit row: %v", err)
	}
	if result != "failure" || errText != "not found" {
		t.Errorf("result/error = %q/%q, want failure/not found", result, errText)
	}
}
