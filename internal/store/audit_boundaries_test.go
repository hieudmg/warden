package store

import (
	"context"
	"errors"
	"strings"
	"testing"

	"warden/internal/model"
)

func TestAppendAuditFailureIsGeneric(t *testing.T) {
	s := newTestStore(t)
	const secret = "synthetic-driver-body-SQL-secret"
	if _, err := s.db.Exec(`CREATE TRIGGER fail_audit BEFORE INSERT ON audit_events BEGIN SELECT RAISE(FAIL, '` + secret + `'); END`); err != nil {
		t.Fatal(err)
	}
	err := s.AppendAudit(context.Background(), model.AuditEvent{Operation: "data.import", Result: "failure"})
	if !errors.Is(err, ErrAuditWrite) || errors.Unwrap(err) != nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("audit error is not the generic sentinel")
	}
	var count int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM audit_events").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("failed audit inserted partial row")
	}
}
