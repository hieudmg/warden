package profiles_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"warden/internal/model"
	"warden/internal/store"
)

func createGroup(t *testing.T, s *store.Store, name string) model.Group {
	t.Helper()
	g, err := s.CreateGroup(context.Background(), model.Group{Name: name})
	if err != nil {
		t.Fatalf("CreateGroup(%s): %v", name, err)
	}
	return g
}

func TestGroupCRUD(t *testing.T) {
	mux, s, _ := newTestAPI(t)
	ctx := context.Background()

	// Empty list marshals as [] rather than null.
	rec := doRequest(t, mux, "GET", "/api/v1/groups", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("list status = %d, body=%s", rec.Code, rec.Body.String())
	}
	if body := strings.TrimSpace(rec.Body.String()); body != "[]" {
		t.Errorf("empty list body = %q, want []", body)
	}

	// Create.
	rec = doRequest(t, mux, "POST", "/api/v1/groups", `{"name":"prod"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var created model.Group
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	if created.ID == 0 || created.Name != "prod" {
		t.Errorf("create response incomplete: %+v", created)
	}
	if created.SSHConnectionCount != 0 || created.DBConnectionCount != 0 {
		t.Errorf("create response counts = %d/%d, want 0/0", created.SSHConnectionCount, created.DBConnectionCount)
	}

	// List.
	rec = doRequest(t, mux, "GET", "/api/v1/groups", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("list status = %d, body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "prod") {
		t.Errorf("list response missing prod: %s", rec.Body.String())
	}

	// Get.
	rec = doRequest(t, mux, "GET", fmt.Sprintf("/api/v1/groups/%d", created.ID), "")
	if rec.Code != http.StatusOK {
		t.Fatalf("get status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var got model.Group
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode get response: %v", err)
	}
	if got.ID != created.ID || got.Name != "prod" {
		t.Errorf("get response = %+v, want id=%d name=prod", got, created.ID)
	}

	// Rename.
	rec = doRequest(t, mux, "PUT", fmt.Sprintf("/api/v1/groups/%d", created.ID), `{"name":"production"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("rename status = %d, body=%s", rec.Code, rec.Body.String())
	}
	renamed, err := s.GetGroup(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetGroup after rename: %v", err)
	}
	if renamed.Name != "production" {
		t.Errorf("renamed name = %q, want production", renamed.Name)
	}

	// Delete.
	rec = doRequest(t, mux, "DELETE", fmt.Sprintf("/api/v1/groups/%d", created.ID), "")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete status = %d, body=%s", rec.Code, rec.Body.String())
	}
	if _, err := s.GetGroup(ctx, created.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("GetGroup after delete error = %v, want ErrNotFound", err)
	}
}

func TestGroupCreateRejectsInvalidName(t *testing.T) {
	mux, _, _ := newTestAPI(t)
	rec := doRequest(t, mux, "POST", "/api/v1/groups", `{"name":"bad name!"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body=%s", rec.Code, rec.Body.String())
	}
	var e struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &e); err != nil {
		t.Fatalf("decode error body: %v", err)
	}
	if e.Code != "validation_error" {
		t.Errorf("error code = %q, want validation_error", e.Code)
	}
}

func TestGroupCreateDuplicateNameConflict(t *testing.T) {
	mux, _, _ := newTestAPI(t)
	rec := doRequest(t, mux, "POST", "/api/v1/groups", `{"name":"prod"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("first create status = %d, body=%s", rec.Code, rec.Body.String())
	}
	rec = doRequest(t, mux, "POST", "/api/v1/groups", `{"name":"prod"}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("duplicate status = %d, want 409, body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "a resource with that name already exists") {
		t.Errorf("duplicate message = %s, want resource-neutral wording", rec.Body.String())
	}
}

func TestGroupGetNotFound(t *testing.T) {
	mux, _, _ := newTestAPI(t)
	rec := doRequest(t, mux, "GET", "/api/v1/groups/999999", "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404, body=%s", rec.Code, rec.Body.String())
	}
	var e struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &e); err != nil {
		t.Fatalf("decode error body: %v", err)
	}
	if e.Code != "not_found" {
		t.Errorf("error code = %q, want not_found", e.Code)
	}
}

func TestGroupDependentsNotFound(t *testing.T) {
	mux, _, _ := newTestAPI(t)
	rec := doRequest(t, mux, "GET", "/api/v1/groups/999999/dependents", "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404, body=%s", rec.Code, rec.Body.String())
	}
}

func TestGroupDeleteNotFound(t *testing.T) {
	mux, _, _ := newTestAPI(t)
	rec := doRequest(t, mux, "DELETE", "/api/v1/groups/999999", "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404, body=%s", rec.Code, rec.Body.String())
	}
}

func TestGroupDependents(t *testing.T) {
	mux, s, _ := newTestAPI(t)
	ctx := context.Background()
	g := createGroup(t, s, "prod")

	if _, err := s.CreateSSH(ctx, model.SSHProfile{
		Name: "web", Host: "h.invalid", Port: 22, Username: "u",
		JumpConnectionIDs: "[]", GroupID: g.ID,
	}); err != nil {
		t.Fatalf("CreateSSH: %v", err)
	}
	if _, err := s.CreateDB(ctx, model.DBProfile{
		Name: "app", Host: "db.invalid", Port: 3306, Username: "u",
		Database: "appdb", GroupID: g.ID,
	}); err != nil {
		t.Fatalf("CreateDB: %v", err)
	}

	rec := doRequest(t, mux, "GET", fmt.Sprintf("/api/v1/groups/%d/dependents", g.ID), "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "web") {
		t.Errorf("dependents response missing ssh dependent: %s", body)
	}
	if !strings.Contains(body, "app") {
		t.Errorf("dependents response missing db dependent: %s", body)
	}
}

func TestGroupDeleteClearsAssignments(t *testing.T) {
	mux, s, _ := newTestAPI(t)
	ctx := context.Background()
	g := createGroup(t, s, "prod")

	ssh, err := s.CreateSSH(ctx, model.SSHProfile{
		Name: "web", Host: "h.invalid", Port: 22, Username: "u",
		JumpConnectionIDs: "[]", GroupID: g.ID,
	})
	if err != nil {
		t.Fatalf("CreateSSH: %v", err)
	}
	db, err := s.CreateDB(ctx, model.DBProfile{
		Name: "app", Host: "db.invalid", Port: 3306, Username: "u",
		Database: "appdb", GroupID: g.ID,
	})
	if err != nil {
		t.Fatalf("CreateDB: %v", err)
	}

	rec := doRequest(t, mux, "DELETE", fmt.Sprintf("/api/v1/groups/%d", g.ID), "")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete status = %d, want 204, body=%s", rec.Code, rec.Body.String())
	}

	gotSSH, err := s.GetSSH(ctx, ssh.ID)
	if err != nil {
		t.Fatalf("GetSSH: %v", err)
	}
	if gotSSH.GroupID != 0 {
		t.Errorf("ssh group_id after group delete = %d, want 0", gotSSH.GroupID)
	}
	gotDB, err := s.GetDB(ctx, db.ID)
	if err != nil {
		t.Fatalf("GetDB: %v", err)
	}
	if gotDB.GroupID != 0 {
		t.Errorf("db group_id after group delete = %d, want 0", gotDB.GroupID)
	}
}

func TestGroupAudit(t *testing.T) {
	mux, _, path := newTestAPI(t)
	req := newRequestWithSource("POST", "/api/v1/groups", `{"name":"audited"}`, "10.0.0.9:2222", "curl/8")
	rec := httptestRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}

	e := lastAuditEvent(t, path)
	if e.Operation != "group.create" {
		t.Errorf("operation = %q, want group.create", e.Operation)
	}
	if e.ResourceType != "group" {
		t.Errorf("resource_type = %q, want group", e.ResourceType)
	}
	if e.Result != "success" {
		t.Errorf("result = %q, want success", e.Result)
	}
}
