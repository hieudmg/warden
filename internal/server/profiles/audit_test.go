package profiles_test

import (
	"bytes"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestAuditNeverPersistsRawValidationValues(t *testing.T) {
	// No Parallel: this test owns slog.Default for its entire lifetime.
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	const secret = "synthetic-T8-secret"
	for _, tc := range []struct {
		name, method, target, body, classification string
		status                                     int
	}{
		{"transfer format", "POST", "/api/v1/data/import", `{"format":"` + secret + `","version":1}`, "validation", 400},
		{"name", "POST", "/api/v1/ssh-connections", `{"name":"` + secret + `!","host":"h","port":22,"username":"u","jump_connection_ids":"[]"}`, "validation", 400},
		{"database selector", "GET", "/api/v1/transport/db/1?database=" + url.QueryEscape(secret), "", "validation", 422},
		{"graph", "GET", "/api/v1/transport/ssh/1", "", "invalid_graph", 422},
		{"invalid json", "POST", "/api/v1/ssh-connections", `{"` + secret + `":1}`, "invalid_json", 400},
		{"success", "POST", "/api/v1/ssh-connections", `{"name":"valid","host":"h","port":22,"username":"u","password":"` + secret + `","jump_connection_ids":"[]"}`, "", 201},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mux, s, path := newTestAPI(t)
			if tc.name == "database selector" {
				createDB(t, s, "db", 0)
			}
			if tc.name == "graph" {
				p := createSSH(t, s, "ssh", "[]")
				if _, err := rawDB(t, path).Exec("UPDATE ssh_connections SET jump_connection_ids=? WHERE id=?", `["`+secret+`"]`, p.ID); err != nil {
					t.Fatal(err)
				}
			}
			rec := doRequest(t, mux, tc.method, tc.target, tc.body)
			if rec.Code != tc.status {
				t.Fatalf("status=%d want=%d", rec.Code, tc.status)
			}
			event := lastAuditEvent(t, path)
			encoded := fmt.Sprintf("%+v", event)
			if strings.Contains(encoded, secret) {
				t.Errorf("raw validation value persisted in audit row (%s)", tc.name)
			}
			if event.Error != tc.classification {
				t.Errorf("classification=%q want=%q", event.Error, tc.classification)
			}
			if strings.Contains(logs.String(), secret) {
				t.Error("raw validation value in slog")
			}
			if event.Operation == "" || event.Result == "" {
				t.Error("audit action/result lost")
			}
		})
	}
}

func TestAuditPersistenceFailureLogsNoDriverValues(t *testing.T) {
	mux, _, path := newTestAPI(t)
	const secret = "synthetic-audit-SQL-parameter-secret"
	db := rawDB(t, path)
	if _, err := db.Exec(`CREATE TRIGGER fail_audit BEFORE INSERT ON audit_events BEGIN SELECT RAISE(FAIL, '` + secret + `'); END`); err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	rec := doRequest(t, mux, http.MethodGet, "/api/v1/ssh-connections", "")
	if rec.Code != 200 {
		t.Fatalf("status=%d", rec.Code)
	}
	if !strings.Contains(logs.String(), "audit write failed") {
		t.Fatal("audit failure became silent")
	}
	if strings.Contains(logs.String(), secret) || strings.Contains(rec.Body.String(), secret) {
		t.Fatal("audit persistence failure leaked driver data")
	}
}
