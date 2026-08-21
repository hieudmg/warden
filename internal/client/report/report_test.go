package report

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"warden/internal/client/api"
	"warden/internal/model"
)

const projectJSON = `{"id":3,"name":"demo"}`

const reportJSON = `{
	"id": 11,
	"project": "demo",
	"title": "v2.0.0 shipped",
	"summary": "Rolled out the dashboard.",
	"agent_model": "gpt-5.4",
	"created_at": "2026-08-21T10:00:00Z"
}`

func TestListProjectsPathAndDecode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/v1/projects" {
			t.Errorf("got %s %s, want GET /api/v1/projects", r.Method, r.URL.Path)
		}
		w.Write([]byte(`[{"id":1,"name":"alpha"},{"id":2,"name":"beta"}]`))
	}))
	defer srv.Close()

	cl := New(api.New(srv.URL, nil))
	projects, err := cl.ListProjects(context.Background())
	if err != nil {
		t.Fatalf("ListProjects: %v", err)
	}
	if len(projects) != 2 || projects[0].Name != "alpha" || projects[1].Name != "beta" {
		t.Errorf("projects = %+v", projects)
	}
}

func TestCreateProjectSendsName(t *testing.T) {
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/projects" {
			t.Errorf("got %s %s, want POST /api/v1/projects", r.Method, r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Fatalf("decode request body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(projectJSON))
	}))
	defer srv.Close()

	cl := New(api.New(srv.URL, nil))
	p, err := cl.CreateProject(context.Background(), "demo")
	if err != nil {
		t.Fatalf("CreateProject: %v", err)
	}
	if p.ID != 3 || p.Name != "demo" {
		t.Errorf("project = %+v, want id=3 name=demo", p)
	}
	if gotBody["name"] != "demo" {
		t.Errorf("request body name = %v, want demo", gotBody["name"])
	}
}

func TestCreateReportPathAndDecode(t *testing.T) {
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/reports" {
			t.Errorf("got %s %s, want POST /api/v1/reports", r.Method, r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Fatalf("decode request body: %v", err)
		}
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(reportJSON))
	}))
	defer srv.Close()

	cl := New(api.New(srv.URL, nil))
	r, err := cl.CreateReport(context.Background(), model.ReportRequest{
		Project:    "demo-app",
		Title:      "v2.0.0 shipped",
		Summary:    "Rolled out the dashboard.",
		AgentModel: "gpt-5.4",
	})
	if err != nil {
		t.Fatalf("CreateReport: %v", err)
	}
	if r.ID != 11 || r.Project != "demo" || r.Title != "v2.0.0 shipped" {
		t.Errorf("report = %+v", r)
	}
	wantCreated, _ := time.Parse(time.RFC3339, "2026-08-21T10:00:00Z")
	if !r.CreatedAt.Equal(wantCreated) {
		t.Errorf("created_at = %v, want %v", r.CreatedAt, wantCreated)
	}
	if gotBody["project"] != "demo-app" || gotBody["agent_model"] != "gpt-5.4" {
		t.Errorf("request body = %v", gotBody)
	}
}

func TestListReportsPathAndDecode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/v1/projects/demo/reports" {
			t.Errorf("got %s %s, want GET /api/v1/projects/demo/reports", r.Method, r.URL.Path)
		}
		w.Write([]byte(`[` + reportJSON + `]`))
	}))
	defer srv.Close()

	cl := New(api.New(srv.URL, nil))
	reports, err := cl.ListReports(context.Background(), "demo")
	if err != nil {
		t.Fatalf("ListReports: %v", err)
	}
	if len(reports) != 1 || reports[0].Title != "v2.0.0 shipped" {
		t.Errorf("reports = %+v", reports)
	}
}

func TestJSONErrorSurfacesAPIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"code":"validation_error","message":"title must be 1-200 bytes"}`))
	}))
	defer srv.Close()

	cl := New(api.New(srv.URL, nil))
	_, err := cl.CreateReport(context.Background(), model.ReportRequest{
		Project: "p", Title: "", Summary: "s", AgentModel: "a",
	})
	if err == nil {
		t.Fatal("CreateReport succeeded, want APIError")
	}
var apiErr *api.APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("err = %T, want *api.APIError", err)
	}
	if apiErr.Code != "validation_error" || !strings.Contains(err.Error(), "title must be 1-200 bytes") {
		t.Errorf("apiErr = %+v", apiErr)
	}
}

func TestStrictDecodingRejectsUnknownFields(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"id":1,"name":"a","unexpected":true}`))
	}))
	defer srv.Close()

	cl := New(api.New(srv.URL, nil))
	if _, err := cl.ListProjects(context.Background()); err == nil {
		t.Fatal("ListProjects accepted unknown response field")
	}
}
