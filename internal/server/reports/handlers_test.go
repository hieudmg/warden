package reports_test

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"warden/internal/model"
	"warden/internal/server/audit"
	"warden/internal/server/reports"
	"warden/internal/store"

	_ "modernc.org/sqlite"
)

// newTestAPI builds a store, audit recorder, and report handler mounted on a
// fresh mux. It returns the handler and the SQLite file path (for tests that
// read audit rows directly).
func newTestAPI(t *testing.T) (http.Handler, string) {
	t.Helper()
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatalf("generate key: %v", err)
	}
	path := filepath.Join(t.TempDir(), "warden.db")
	s, err := store.Open(context.Background(), path, key)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	rec := audit.New(s)
	h := reports.New(s, rec)
	mux := http.NewServeMux()
	h.Register(mux)
	return mux, path
}

// rawDB opens a second connection to the same SQLite file so tests can
// inspect audit rows directly.
func rawDB(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatalf("open raw db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func doRequest(t *testing.T, h http.Handler, method, target, body string) *httptest.ResponseRecorder {
	t.Helper()
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, target, reader)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func decodeReport(t *testing.T, rec *httptest.ResponseRecorder) model.Report {
	t.Helper()
	var r model.Report
	if err := json.Unmarshal(rec.Body.Bytes(), &r); err != nil {
		t.Fatalf("decode report response %q: %v", rec.Body.String(), err)
	}
	return r
}

func decodeProject(t *testing.T, rec *httptest.ResponseRecorder) model.Project {
	t.Helper()
	var p model.Project
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
		t.Fatalf("decode project response %q: %v", rec.Body.String(), err)
	}
	return p
}

func decodeProjects(t *testing.T, rec *httptest.ResponseRecorder) []model.Project {
	t.Helper()
	var out []model.Project
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode projects response %q: %v", rec.Body.String(), err)
	}
	return out
}

func decodeReports(t *testing.T, rec *httptest.ResponseRecorder) []model.Report {
	t.Helper()
	var out []model.Report
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode reports response %q: %v", rec.Body.String(), err)
	}
	return out
}

func TestCreateProjectAndIdempotent(t *testing.T) {
	mux, _ := newTestAPI(t)

	body := `{"name":"demo"}`
	first := doRequest(t, mux, "POST", "/api/v1/projects", body)
	if first.Code != http.StatusOK && first.Code != http.StatusCreated {
		t.Fatalf("first status = %d, body=%s", first.Code, first.Body.String())
	}
	p1 := decodeProject(t, first)
	if p1.Name != "demo" || p1.ID == 0 {
		t.Errorf("project = %+v, want id>0 name=demo", p1)
	}

	second := doRequest(t, mux, "POST", "/api/v1/projects", body)
	if second.Code != http.StatusOK && second.Code != http.StatusCreated {
		t.Fatalf("second status = %d, body=%s", second.Code, second.Body.String())
	}
	p2 := decodeProject(t, second)
	if p2.ID != p1.ID {
		t.Errorf("idempotent re-POST id = %d, want %d", p2.ID, p1.ID)
	}
}

func TestListProjects(t *testing.T) {
	mux, _ := newTestAPI(t)

	for _, name := range []string{"alpha", "beta"} {
		rec := doRequest(t, mux, "POST", "/api/v1/projects", `{"name":"`+name+`"}`)
		if rec.Code != http.StatusOK && rec.Code != http.StatusCreated {
			t.Fatalf("create %s status = %d, body=%s", name, rec.Code, rec.Body.String())
		}
	}

	rec := doRequest(t, mux, "GET", "/api/v1/projects", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	projects := decodeProjects(t, rec)
	if len(projects) != 2 {
		t.Fatalf("got %d projects, want 2", len(projects))
	}
	if projects[0].Name != "alpha" || projects[1].Name != "beta" {
		t.Errorf("projects = %+v, want alpha, beta ordered", projects)
	}
}

func TestCreateReport(t *testing.T) {
	mux, _ := newTestAPI(t)

	body := `{"project":"team-app","title":"v2.0.0","summary":"Rolled out the new dashboard.","agent_model":"gpt-5.4-ultra"}`
	rec := doRequest(t, mux, "POST", "/api/v1/reports", body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	r := decodeReport(t, rec)
	if r.ID == 0 {
		t.Error("report id = 0, want nonzero")
	}
	if r.Project != "team-app" {
		t.Errorf("report project = %q, want team-app", r.Project)
	}
	if r.Title != "v2.0.0" {
		t.Errorf("report title = %q, want v2.0.0", r.Title)
	}
	if r.Summary != "Rolled out the new dashboard." {
		t.Errorf("report summary = %q, want original", r.Summary)
	}
	if r.AgentModel != "gpt-5.4-ultra" {
		t.Errorf("agent_model = %q, want gpt-5.4-ultra", r.AgentModel)
	}
	if r.CreatedAt.IsZero() {
		t.Error("created_at is zero; server must set UTC timestamp")
	}
}

func TestCreateReportRejectsInvalidFields(t *testing.T) {
	mux, _ := newTestAPI(t)

	cases := []struct {
		name string
		body string
	}{
		{"missing project", `{"title":"t","summary":"s","agent_model":"a"}`},
		{"missing title", `{"project":"p","summary":"s","agent_model":"a"}`},
		{"empty title", `{"project":"p","title":"","summary":"s","agent_model":"a"}`},
		{"oversize title", `{"project":"p","title":"` + strings.Repeat("t", 201) + `","summary":"s","agent_model":"a"}`},
		{"oversize summary", `{"project":"p","title":"t","summary":"` + strings.Repeat("s", 16385) + `","agent_model":"a"}`},
		{"empty agent model", `{"project":"p","title":"t","summary":"s","agent_model":""}`},
		{"oversize agent model", `{"project":"p","title":"t","summary":"s","agent_model":"` + strings.Repeat("a", 201) + `"}`},
		{"invalid project name", `{"project":"bad name!","title":"t","summary":"s","agent_model":"a"}`},
		{"empty project", `{"project":"","title":"t","summary":"s","agent_model":"a"}`},
		{"unknown field", `{"project":"p","title":"t","summary":"s","agent_model":"a","extra":1}`},
		{"malformed json", `{"project":"p",`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := doRequest(t, mux, "POST", "/api/v1/reports", tc.body)
			if rec.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestListReportsChronologicalAndUnknownProject(t *testing.T) {
	mux, _ := newTestAPI(t)

	for i := 0; i < 3; i++ {
		rec := doRequest(t, mux, "POST", "/api/v1/reports",
			`{"project":"demo","title":"r`+strconv.Itoa(i)+`","summary":"s","agent_model":"a"}`)
		if rec.Code != http.StatusCreated {
			t.Fatalf("create status = %d, body=%s", rec.Code, rec.Body.String())
		}
	}

	rec := doRequest(t, mux, "GET", "/api/v1/projects/demo/reports", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	got := decodeReports(t, rec)
	if len(got) != 3 {
		t.Fatalf("got %d reports, want 3", len(got))
	}
	if got[0].Title != "r0" || got[1].Title != "r1" || got[2].Title != "r2" {
		t.Errorf("chronological order broken: %+v", got)
	}
	if got[0].Project != "demo" {
		t.Errorf("reports project = %q, want demo", got[0].Project)
	}

	missing := doRequest(t, mux, "GET", "/api/v1/projects/nope/reports", "")
	if missing.Code != http.StatusNotFound {
		t.Errorf("unknown project status = %d, want 404", missing.Code)
	}
}

// TestReportAppendOnly pins the immutable contract at the API layer: no
// update/delete handlers exist for reports, and no report-mutating
// repository methods exist on the store.
func TestReportAppendOnly(t *testing.T) {
	handlerType := reflect.TypeOf(&reports.Handler{})
	for _, method := range []string{"UpdateReport", "DeleteReport"} {
		if _, ok := handlerType.MethodByName(method); ok {
			t.Errorf("reports.Handler must not expose %s; reports are append-only", method)
		}
	}
	storeType := reflect.TypeOf(&store.Store{})
	for _, method := range []string{"UpdateReport", "DeleteReport"} {
		if _, ok := storeType.MethodByName(method); ok {
			t.Errorf("Store must not expose %s; reports are append-only", method)
		}
	}

	mux, _ := newTestAPI(t)
	for _, target := range []string{
		"PUT /api/v1/reports/1",
		"DELETE /api/v1/reports/1",
		"PUT /api/v1/projects/demo/reports/1",
	} {
		parts := strings.Fields(target)
		rec := doRequest(t, mux, parts[0], parts[1], "")
		if rec.Code != http.StatusNotFound && rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s %s status = %d, want 404/405", parts[0], parts[1], rec.Code)
		}
	}
}

// TestReportAuditOmitsContents verifies audit metadata carries project and
// agent_model but never the report title or summary.
func TestReportAuditOmitsContents(t *testing.T) {
	mux, path := newTestAPI(t)

	rec := doRequest(t, mux, "POST", "/api/v1/reports",
		`{"project":"audited","title":"secret-title-value","summary":"secret-summary-value","agent_model":"m1"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}

	db := rawDB(t, path)
	rows, err := db.Query("SELECT operation, resource_id, metadata, error FROM audit_events")
	if err != nil {
		t.Fatalf("query audit_events: %v", err)
	}
	defer rows.Close()
	found := false
	for rows.Next() {
		var op, resourceID, metadata, errText string
		if err := rows.Scan(&op, &resourceID, &metadata, &errText); err != nil {
			t.Fatal(err)
		}
		if op == "report.create" {
			found = true
			if resourceID == "" {
				t.Error("report.create audit missing resource_id")
			}
			if strings.Contains(metadata, "secret-title-value") || strings.Contains(metadata, "secret-summary-value") {
				t.Errorf("audit metadata leaks report contents: %s", metadata)
			}
			if !strings.Contains(metadata, `"project":"audited"`) {
				t.Errorf("audit metadata missing project: %s", metadata)
			}
			if !strings.Contains(metadata, `"agent_model":"m1"`) {
				t.Errorf("audit metadata missing agent_model: %s", metadata)
			}
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatal("no report.create audit event recorded")
	}
}
