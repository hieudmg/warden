package profiles_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"warden/internal/model"
)

func TestListSSHRedactsSecrets(t *testing.T) {
	mux, s, _ := newTestAPI(t)
	if _, err := s.CreateSSH(context.Background(), model.SSHProfile{
		Name: "secret-host", Host: "h.invalid", Port: 22, Username: "u",
		Password: []byte("s3cret-value"), PrivateKey: []byte("PRIVATE-KEY-MATERIAL"),
		JumpConnectionIDs: "[]",
	}); err != nil {
		t.Fatalf("CreateSSH: %v", err)
	}

	rec := doRequest(t, mux, "GET", "/api/v1/ssh-connections", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if strings.Contains(body, "s3cret-value") || strings.Contains(body, "PRIVATE-KEY-MATERIAL") {
		t.Errorf("list response leaks secrets: %s", body)
	}
	if !strings.Contains(body, `"has_password":true`) {
		t.Errorf("list response missing has_password marker: %s", body)
	}
	if !strings.Contains(body, `"has_private_key":true`) {
		t.Errorf("list response missing has_private_key marker: %s", body)
	}
}

func TestGetSSHRedactsSecrets(t *testing.T) {
	mux, s, _ := newTestAPI(t)
	created, err := s.CreateSSH(context.Background(), model.SSHProfile{
		Name: "one", Host: "h.invalid", Port: 22, Username: "u",
		Password: []byte("pw-value"), ProxyPassword: []byte("proxy-value"),
		JumpConnectionIDs: "[]",
	})
	if err != nil {
		t.Fatalf("CreateSSH: %v", err)
	}

	rec := doRequest(t, mux, "GET", fmt.Sprintf("/api/v1/ssh-connections/%d", created.ID), "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if strings.Contains(body, "pw-value") || strings.Contains(body, "proxy-value") {
		t.Errorf("get response leaks secrets: %s", body)
	}
	if !strings.Contains(body, `"has_password":true`) || !strings.Contains(body, `"has_proxy_password":true`) {
		t.Errorf("get response missing has_* markers: %s", body)
	}
}

func TestCreateSSH(t *testing.T) {
	mux, _, _ := newTestAPI(t)
	body := `{"name":"new","host":"h.invalid","port":22,"username":"u","password":"pw-value","jump_connection_ids":"[]"}`
	rec := doRequest(t, mux, "POST", "/api/v1/ssh-connections", body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "pw-value") {
		t.Errorf("create response leaks password: %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"has_password":true`) {
		t.Errorf("create response missing has_password: %s", rec.Body.String())
	}
}

func TestCreateSSHRejectsUnknownField(t *testing.T) {
	mux, _, _ := newTestAPI(t)
	body := `{"name":"x","host":"h","port":22,"username":"u","jump_connection_ids":"[]","bogus":1}`
	rec := doRequest(t, mux, "POST", "/api/v1/ssh-connections", body)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body=%s", rec.Code, rec.Body.String())
	}
	var e struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &e); err != nil {
		t.Fatalf("decode error body: %v", err)
	}
	if e.Code != "invalid_request" {
		t.Errorf("error code = %q, want invalid_request", e.Code)
	}
}

func TestCreateSSHRejectsMalformedJumpJSON(t *testing.T) {
	mux, _, _ := newTestAPI(t)
	body := `{"name":"x","host":"h","port":22,"username":"u","jump_connection_ids":"[1,2"}`
	rec := doRequest(t, mux, "POST", "/api/v1/ssh-connections", body)
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

func TestCreateSSHRejectsOversizedBody(t *testing.T) {
	mux, _, _ := newTestAPI(t)
	big := strings.Repeat("a", 2<<20)
	body := `{"name":"` + big + `","host":"h","port":22,"username":"u","jump_connection_ids":"[]"}`
	rec := doRequest(t, mux, "POST", "/api/v1/ssh-connections", body)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413, body=%s", rec.Code, rec.Body.String())
	}
	var e struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &e); err != nil {
		t.Fatalf("decode error body: %v", err)
	}
	if e.Code != "payload_too_large" {
		t.Errorf("error code = %q, want payload_too_large", e.Code)
	}
}

func TestUpdateSSH(t *testing.T) {
	mux, s, _ := newTestAPI(t)
	created := createSSH(t, s, "upd", "[]")

	body := `{"name":"upd","host":"new.invalid","port":2200,"username":"root","jump_connection_ids":"[]"}`
	rec := doRequest(t, mux, "PUT", fmt.Sprintf("/api/v1/ssh-connections/%d", created.ID), body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}

	got, err := s.GetSSH(context.Background(), created.ID)
	if err != nil {
		t.Fatalf("GetSSH: %v", err)
	}
	if got.Host != "new.invalid" || got.Port != 2200 || got.Username != "root" {
		t.Errorf("updated metadata mismatch: %+v", got)
	}
	if string(got.Password) != "pw-upd" {
		t.Errorf("password = %q, want preserved pw-upd (nil secret keeps stored value)", got.Password)
	}
}

func TestDeleteSSHWithDependents(t *testing.T) {
	mux, s, _ := newTestAPI(t)
	target := createSSH(t, s, "target", "[]")
	jumper := createSSH(t, s, "jumper", fmt.Sprintf("[%d]", target.ID))

	// Dependents endpoint lists the jumper before deletion.
	rec := doRequest(t, mux, "GET", fmt.Sprintf("/api/v1/ssh-connections/%d/dependents", target.ID), "")
	if rec.Code != http.StatusOK {
		t.Fatalf("dependents status = %d, body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "jumper") {
		t.Errorf("dependents response missing jumper: %s", rec.Body.String())
	}

	// Deletion proceeds despite the dependent.
	rec = doRequest(t, mux, "DELETE", fmt.Sprintf("/api/v1/ssh-connections/%d", target.ID), "")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete status = %d, want 204, body=%s", rec.Code, rec.Body.String())
	}

	// Stored dependent JSON is not rewritten.
	got, err := s.GetSSH(context.Background(), jumper.ID)
	if err != nil {
		t.Fatalf("GetSSH jumper after deletion: %v", err)
	}
	if got.JumpConnectionIDs != fmt.Sprintf("[%d]", target.ID) {
		t.Errorf("jumper jump ids rewritten to %q after target deletion", got.JumpConnectionIDs)
	}
}

func TestSSHDependents(t *testing.T) {
	mux, s, _ := newTestAPI(t)
	target := createSSH(t, s, "target", "[]")
	jumper := createSSH(t, s, "jumper", fmt.Sprintf("[%d]", target.ID))
	createDB(t, s, "tunneled", target.ID)

	rec := doRequest(t, mux, "GET", fmt.Sprintf("/api/v1/ssh-connections/%d/dependents", target.ID), "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "jumper") {
		t.Errorf("dependents response missing ssh dependent: %s", body)
	}
	if !strings.Contains(body, "tunneled") {
		t.Errorf("dependents response missing db dependent: %s", body)
	}
	if jumper.ID == target.ID {
		t.Fatal("test invariant broken")
	}
}

func TestTransportSSHNoStoreAndPlaintext(t *testing.T) {
	mux, s, _ := newTestAPI(t)
	created, err := s.CreateSSH(context.Background(), model.SSHProfile{
		Name: "t", Host: "h.invalid", Port: 22, Username: "u",
		Password: []byte("topsecret"), JumpConnectionIDs: "[]",
	})
	if err != nil {
		t.Fatalf("CreateSSH: %v", err)
	}

	rec := doRequest(t, mux, "GET", fmt.Sprintf("/api/v1/transport/ssh/%d", created.ID), "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
	var bundle model.SSHBundle
	if err := json.Unmarshal(rec.Body.Bytes(), &bundle); err != nil {
		t.Fatalf("decode transport response: %v", err)
	}
	if string(bundle.Target.Password) != "topsecret" {
		t.Errorf("transport password = %q, want decrypted topsecret", bundle.Target.Password)
	}
}

func TestTransportSSHGraphError(t *testing.T) {
	mux, s, _ := newTestAPI(t)
	target := createSSH(t, s, "broken", "[999999]")

	rec := doRequest(t, mux, "GET", fmt.Sprintf("/api/v1/transport/ssh/%d", target.ID), "")
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422, body=%s", rec.Code, rec.Body.String())
	}
	var e struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &e); err != nil {
		t.Fatalf("decode error body: %v", err)
	}
	if e.Code != "invalid_graph" {
		t.Errorf("error code = %q, want invalid_graph", e.Code)
	}
}

func TestTransportSSHNotFound(t *testing.T) {
	mux, _, _ := newTestAPI(t)
	rec := doRequest(t, mux, "GET", "/api/v1/transport/ssh/999999", "")
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

func TestTransportDBOverSSH(t *testing.T) {
	mux, s, _ := newTestAPI(t)
	target := createSSH(t, s, "jump", "[]")
	dbp := createDB(t, s, "app", target.ID)

	rec := doRequest(t, mux, "GET", fmt.Sprintf("/api/v1/transport/db/%d", dbp.ID), "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
	var bundle model.DBBundle
	if err := json.Unmarshal(rec.Body.Bytes(), &bundle); err != nil {
		t.Fatalf("decode transport response: %v", err)
	}
	if string(bundle.Password) != "dbpw-app" {
		t.Errorf("db password = %q, want decrypted dbpw-app", bundle.Password)
	}
	if bundle.SSH == nil {
		t.Fatal("transport db response missing ssh graph")
	}
	if string(bundle.SSH.Target.Password) != "pw-jump" {
		t.Errorf("ssh target password = %q, want decrypted pw-jump", bundle.SSH.Target.Password)
	}
}

func TestDBCRUD(t *testing.T) {
	mux, s, _ := newTestAPI(t)

	// Create.
	body := `{"name":"app","host":"db.invalid","port":3306,"username":"app","password":"dbpw","database":"appdb","ssh_connection_id":0}`
	rec := doRequest(t, mux, "POST", "/api/v1/db-connections", body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status = %d, body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "dbpw") {
		t.Errorf("create response leaks password: %s", rec.Body.String())
	}
	var created model.DBConnection
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	if created.ID == 0 || !created.HasPassword {
		t.Errorf("create response incomplete: %+v", created)
	}

	// Get (redacted).
	rec = doRequest(t, mux, "GET", fmt.Sprintf("/api/v1/db-connections/%d", created.ID), "")
	if rec.Code != http.StatusOK {
		t.Fatalf("get status = %d, body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "dbpw") {
		t.Errorf("get response leaks password: %s", rec.Body.String())
	}

	// List.
	rec = doRequest(t, mux, "GET", "/api/v1/db-connections", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("list status = %d, body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "dbpw") {
		t.Errorf("list response leaks password: %s", rec.Body.String())
	}

	// Update.
	body = `{"name":"app","host":"db2.invalid","port":3307,"username":"app","database":"appdb","ssh_connection_id":0}`
	rec = doRequest(t, mux, "PUT", fmt.Sprintf("/api/v1/db-connections/%d", created.ID), body)
	if rec.Code != http.StatusOK {
		t.Fatalf("update status = %d, body=%s", rec.Code, rec.Body.String())
	}
	got, err := s.GetDB(context.Background(), created.ID)
	if err != nil {
		t.Fatalf("GetDB: %v", err)
	}
	if got.Host != "db2.invalid" || got.Port != 3307 {
		t.Errorf("updated db mismatch: %+v", got)
	}
	if string(got.Password) != "dbpw" {
		t.Errorf("password = %q, want preserved dbpw", got.Password)
	}

	// Delete.
	rec = doRequest(t, mux, "DELETE", fmt.Sprintf("/api/v1/db-connections/%d", created.ID), "")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete status = %d, want 204, body=%s", rec.Code, rec.Body.String())
	}
}

func TestDBDependentsAlwaysEmpty(t *testing.T) {
	mux, s, _ := newTestAPI(t)
	dbp := createDB(t, s, "app", 0)

	rec := doRequest(t, mux, "GET", fmt.Sprintf("/api/v1/db-connections/%d/dependents", dbp.ID), "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"ssh":[]`) || !strings.Contains(body, `"db":[]`) {
		t.Errorf("db dependents response = %s, want empty ssh and db arrays", body)
	}
}

func TestAuditRecordsSourceMetadata(t *testing.T) {
	mux, _, path := newTestAPI(t)
	body := `{"name":"audited","host":"h.invalid","port":22,"username":"u","jump_connection_ids":"[]"}`
	req := newRequestWithSource("POST", "/api/v1/ssh-connections", body, "10.0.0.5:4321", "warden-cli/0.1")
	rec := httptestRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}

	e := lastAuditEvent(t, path)
	if e.Operation != "ssh_connection.create" {
		t.Errorf("operation = %q, want ssh_connection.create", e.Operation)
	}
	if e.Result != "success" {
		t.Errorf("result = %q, want success", e.Result)
	}
	if !strings.Contains(e.Source, "10.0.0.5:4321") {
		t.Errorf("source = %q, want remote addr", e.Source)
	}
	if !strings.Contains(e.Metadata, "warden-cli/0.1") {
		t.Errorf("metadata = %q, want user agent", e.Metadata)
	}
	if e.Error != "" {
		t.Errorf("error = %q, want empty on success", e.Error)
	}
}

func TestAuditRecordsFailure(t *testing.T) {
	mux, _, path := newTestAPI(t)
	// Invalid name triggers validation; the request also carries a password
	// that must never appear in the audit error.
	body := `{"name":"bad name!","host":"h.invalid","port":22,"username":"u","password":"supersecret","jump_connection_ids":"[]"}`
	req := newRequestWithSource("POST", "/api/v1/ssh-connections", body, "10.0.0.9:1111", "curl/8")
	rec := httptestRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body=%s", rec.Code, rec.Body.String())
	}

	e := lastAuditEvent(t, path)
	if e.Result != "failure" {
		t.Errorf("result = %q, want failure", e.Result)
	}
	if e.Error == "" {
		t.Error("error empty on failure")
	}
	if strings.Contains(e.Error, "supersecret") {
		t.Errorf("audit error leaks password: %q", e.Error)
	}
}

func TestMethodNotAllowed(t *testing.T) {
	mux, _, _ := newTestAPI(t)
	rec := doRequest(t, mux, "POST", "/api/v1/ssh-connections/1", `{}`)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405, body=%s", rec.Code, rec.Body.String())
	}
}
