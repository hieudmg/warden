package runtime

import (
	"bytes"
	"database/sql"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
)

func TestAuditPersistenceFailureLogsNoDriverValues(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.db")
	p, _, _, _, _ := runtimeFixture(t, path)
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	const secret = "synthetic-auth-audit-driver-body-secret"
	if _, err := db.Exec(`CREATE TRIGGER fail_audit BEFORE INSERT ON audit_events BEGIN SELECT RAISE(FAIL, '` + secret + `'); END`); err != nil {
		t.Fatal(err)
	}
	cookie, csrf := sessionFor(t, p)
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	w := call(p, "POST", "/api/v1/auth/lock", struct{}{}, cookie, csrf)
	if w.Code != 200 {
		t.Fatalf("lock status=%d", w.Code)
	}
	if !strings.Contains(logs.String(), "audit write failed") {
		t.Fatal("audit loss became silent")
	}
	if strings.Contains(logs.String()+w.Body.String(), secret) {
		t.Fatal("auth audit persistence failure leaked driver data")
	}
}
