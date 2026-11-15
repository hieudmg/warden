package reports_test

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func TestAuditNeverPersistsRawValidationValues(t *testing.T) {
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	const secret = "synthetic-T8-report-secret"
	for _, tc := range []struct {
		name, target, body string
		status             int
		classification     string
	}{
		{"invalid name", "/api/v1/projects", `{"name":"` + secret + `!"}`, 400, "validation"},
		{"successful name", "/api/v1/projects", `{"name":"` + secret + `"}`, 201, ""},
		{"report contents", "/api/v1/reports", `{"project":"` + secret + `","title":"` + secret + `","summary":"` + secret + `","agent_model":"` + secret + `"}`, 201, ""},
		{"list reports", "/api/v1/projects/" + secret + "/reports", "", 200, ""},
		{"missing reports", "/api/v1/projects/" + secret + "/reports", "", 404, "not_found"},
		{"unknown storage error", "/api/v1/reports", `{"project":"demo","title":"title","summary":"summary","agent_model":"model"}`, 500, "internal"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mux, path := newTestAPI(t)
			db := rawDB(t, path)
			if tc.name == "unknown storage error" {
				if _, err := db.Exec(`CREATE TRIGGER fail_report BEFORE INSERT ON reports BEGIN SELECT RAISE(FAIL, '` + secret + `'); END`); err != nil {
					t.Fatal(err)
				}
			}
			method := "POST"
			if tc.name == "list reports" {
				created := doRequest(t, mux, "POST", "/api/v1/projects", `{"name":"`+secret+`"}`)
				if created.Code != 201 {
					t.Fatalf("create project fixture status=%d", created.Code)
				}
			}
			if strings.HasSuffix(tc.target, "/reports") && tc.target != "/api/v1/reports" {
				method = "GET"
			}
			rec := doRequest(t, mux, method, tc.target, tc.body)
			if rec.Code != tc.status {
				t.Fatalf("status=%d want=%d", rec.Code, tc.status)
			}
			var resourceID, metadata, classification string
			if err := db.QueryRow("SELECT resource_id,metadata,error FROM audit_events ORDER BY id DESC LIMIT 1").Scan(&resourceID, &metadata, &classification); err != nil {
				t.Fatal(err)
			}
			if strings.Contains(resourceID+metadata+classification+logs.String(), secret) {
				t.Error("raw supplied value or unknown error reached audit/slog")
			}
			if classification != tc.classification {
				t.Errorf("classification=%q want=%q", classification, tc.classification)
			}
		})
	}
}

func TestAuditPersistenceFailureLogsNoDriverValues(t *testing.T) {
	mux, path := newTestAPI(t)
	const secret = "synthetic-report-audit-driver-secret"
	if _, err := rawDB(t, path).Exec(`CREATE TRIGGER fail_audit BEFORE INSERT ON audit_events BEGIN SELECT RAISE(FAIL, '` + secret + `'); END`); err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	rec := doRequest(t, mux, "GET", "/api/v1/projects", "")
	if rec.Code != 200 {
		t.Fatalf("status=%d", rec.Code)
	}
	if !strings.Contains(logs.String(), "audit write failed") {
		t.Fatal("audit failure silent")
	}
	if strings.Contains(logs.String()+rec.Body.String(), secret) {
		t.Fatal("driver value leaked")
	}
}
