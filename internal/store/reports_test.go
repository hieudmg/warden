package store

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestCreateProjectIdempotent(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	first, err := s.CreateProject(ctx, "demo")
	if err != nil {
		t.Fatalf("CreateProject: %v", err)
	}
	second, err := s.CreateProject(ctx, "demo")
	if err != nil {
		t.Fatalf("CreateProject second: %v", err)
	}
	if first.ID == 0 || first.ID != second.ID {
		t.Errorf("CreateProject ids = %d and %d, want same nonzero id", first.ID, second.ID)
	}
}

func TestGetProjectByNameAndList(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	if _, err := s.CreateProject(ctx, "alpha"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateProject(ctx, "beta"); err != nil {
		t.Fatal(err)
	}

	got, err := s.GetProjectByName(ctx, "alpha")
	if err != nil {
		t.Fatalf("GetProjectByName: %v", err)
	}
	if got.Name != "alpha" {
		t.Errorf("project name = %q, want alpha", got.Name)
	}

	if _, err := s.GetProjectByName(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("GetProjectByName missing error = %v, want ErrNotFound", err)
	}

	all, err := s.ListProjects(ctx)
	if err != nil {
		t.Fatalf("ListProjects: %v", err)
	}
	if len(all) != 2 {
		t.Errorf("ListProjects returned %d projects, want 2", len(all))
	}
}

func TestCreateReportServerTimestamp(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	before := time.Now().UTC()

	r, err := s.CreateReport(ctx, "demo", "v1.0 released", "shipped feature X", "gpt-5.4")
	if err != nil {
		t.Fatalf("CreateReport: %v", err)
	}
	after := time.Now().UTC()

	if r.ID == 0 {
		t.Error("CreateReport returned zero id")
	}
	if r.CreatedAt.Before(before) || r.CreatedAt.After(after) {
		t.Errorf("CreatedAt %v outside [%v, %v]; must be server-generated UTC now", r.CreatedAt, before, after)
	}
	if loc := r.CreatedAt.Location(); loc != time.UTC {
		t.Errorf("CreatedAt location = %v, want UTC", loc)
	}
	if r.Project != "demo" || r.Title != "v1.0 released" || r.Summary != "shipped feature X" || r.AgentModel != "gpt-5.4" {
		t.Errorf("report fields mismatch: %+v", r)
	}
}

func TestCreateReportAutoCreatesProject(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if _, err := s.CreateReport(ctx, "brand-new", "title", "summary", "agent"); err != nil {
		t.Fatalf("CreateReport with unknown project: %v", err)
	}
	if _, err := s.GetProjectByName(ctx, "brand-new"); err != nil {
		t.Errorf("project not auto-created: %v", err)
	}
}

func TestCreateReportRejectsInvalidFields(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	cases := []struct {
		name       string
		project    string
		title      string
		summary    string
		agentModel string
	}{
		{"empty title", "demo", "", "summary", "agent"},
		{"empty summary", "demo", "title", "", "agent"},
		{"empty agent model", "demo", "title", "summary", ""},
		{"bad project name", "bad name!", "title", "summary", "agent"},
		{"empty project", "", "title", "summary", "agent"},
		{"overlong title", "demo", strings.Repeat("t", 201), "summary", "agent"},
		{"overlong agent model", "demo", "title", "summary", strings.Repeat("a", 201)},
	}
	for _, tc := range cases {
		if _, err := s.CreateReport(ctx, tc.project, tc.title, tc.summary, tc.agentModel); err == nil {
			t.Errorf("%s: CreateReport accepted invalid input", tc.name)
		}
	}
}

func TestListReportsChronological(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	want := []string{"first", "second", "third"}
	for _, title := range want {
		if _, err := s.CreateReport(ctx, "demo", title, "summary", "agent"); err != nil {
			t.Fatalf("CreateReport %s: %v", title, err)
		}
	}

	reports, err := s.ListReports(ctx, "demo")
	if err != nil {
		t.Fatalf("ListReports: %v", err)
	}
	if len(reports) != 3 {
		t.Fatalf("ListReports returned %d reports, want 3", len(reports))
	}
	for i, title := range want {
		if reports[i].Title != title {
			t.Errorf("reports[%d].Title = %q, want %q (chronological)", i, reports[i].Title, title)
		}
		if reports[i].Project != "demo" {
			t.Errorf("reports[%d].Project = %q, want demo", i, reports[i].Project)
		}
	}
}

func TestListReportsUnknownProject(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if _, err := s.ListReports(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("ListReports missing project error = %v, want ErrNotFound", err)
	}
}

// TestReportAppendOnly pins the immutable, append-only contract: no update or
// delete repository methods exist for reports.
func TestReportAppendOnly(t *testing.T) {
	typ := reflect.TypeOf(&Store{})
	for _, method := range []string{"UpdateReport", "DeleteReport"} {
		if _, ok := typ.MethodByName(method); ok {
			t.Errorf("Store must not expose %s; reports are append-only", method)
		}
	}
	for _, method := range []string{"CreateReport", "ListReports"} {
		if _, ok := typ.MethodByName(method); !ok {
			t.Errorf("Store must expose %s", method)
		}
	}
}
