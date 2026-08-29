package profiles_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"warden/internal/model"
)

func TestListSSHRedactsSecrets(t *testing.T) {
	mux, s, _ := newTestAPI(t)
	ctx := context.Background()
	pair, err := s.CreateKeyPair(ctx, model.KeyPair{
		Name: "pair", PrivateKey: []byte("PRIVATE-KEY-MATERIAL"),
		PrivateKeyPassphrase: []byte("PHRASE-MATERIAL"),
	})
	if err != nil {
		t.Fatalf("CreateKeyPair: %v", err)
	}
	for _, p := range []model.SSHProfile{
		{
			Name: "password-secret", Host: "h.invalid", Port: 22, Username: "u",
			Password: []byte("s3cret-value"), JumpConnectionIDs: "[]",
		},
		{
			Name: "key-secret", Host: "h.invalid", Port: 22, Username: "u",
			KeyPairID: pair.ID, JumpConnectionIDs: "[]",
		},
	} {
		if _, err := s.CreateSSH(ctx, p); err != nil {
			t.Fatalf("CreateSSH: %v", err)
		}
	}

	rec := doRequest(t, mux, "GET", "/api/v1/ssh-connections", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if strings.Contains(body, "s3cret-value") ||
		strings.Contains(body, "PRIVATE-KEY-MATERIAL") ||
		strings.Contains(body, "PHRASE-MATERIAL") {
		t.Errorf("list response leaks secrets: %s", body)
	}
	if !strings.Contains(body, `"has_password":true`) {
		t.Errorf("list response missing has_password marker: %s", body)
	}
	if !strings.Contains(body, `"key_pair_id":`+strconv.FormatInt(pair.ID, 10)) {
		t.Errorf("list response missing key_pair_id marker: %s", body)
	}
	if !strings.Contains(body, `"key_pair_name":"pair"`) {
		t.Errorf("list response missing key_pair_name: %s", body)
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

func TestKeyPairListRedactsVaultMaterial(t *testing.T) {
	mux, s, _ := newTestAPI(t)
	ctx := context.Background()
	for _, name := range []string{"alpha", "beta"} {
		if _, err := s.CreateKeyPair(ctx, model.KeyPair{
			Name:                 name,
			PublicKey:            []byte("PUBLIC-KEY-MATERIAL-" + name),
			PrivateKey:           []byte("PRIVATE-KEY-MATERIAL-" + name),
			PrivateKeyPassphrase: []byte("PHRASE-MATERIAL-" + name),
		}); err != nil {
			t.Fatalf("CreateKeyPair(%s): %v", name, err)
		}
	}

	rec := doRequest(t, mux, "GET", "/api/v1/key-pairs", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, secret := range []string{"PUBLIC-KEY-MATERIAL", "PRIVATE-KEY-MATERIAL", "PHRASE-MATERIAL"} {
		if strings.Contains(body, secret) {
			t.Errorf("list response leaks %s: %s", secret, body)
		}
	}
	if strings.Contains(body, `"public_key":"`) || strings.Contains(body, `"private_key":"`) {
		t.Errorf("list response carries a raw key field: %s", body)
	}
	if !strings.Contains(body, `"name":"alpha"`) ||
		!strings.Contains(body, `"has_public_key":true`) ||
		!strings.Contains(body, `"has_private_key":true`) ||
		!strings.Contains(body, `"has_private_key_passphrase":true`) {
		t.Errorf("list response missing presence metadata: %s", body)
	}
}

func TestGetKeyPairReturnsVaultMaterial(t *testing.T) {
	mux, s, _ := newTestAPI(t)
	ctx := context.Background()
	created, err := s.CreateKeyPair(ctx, model.KeyPair{
		Name: "vault", PublicKey: []byte("PUBLIC-KEY-EXACT"),
		PrivateKey: []byte("PRIVATE-KEY-EXACT"), PrivateKeyPassphrase: []byte("PHRASE-EXACT"),
	})
	if err != nil {
		t.Fatalf("CreateKeyPair: %v", err)
	}

	rec := doRequest(t, mux, "GET", fmt.Sprintf("/api/v1/key-pairs/%d", created.ID), "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{
		`"public_key":"PUBLIC-KEY-EXACT"`,
		`"private_key":"PRIVATE-KEY-EXACT"`,
		`"private_key_passphrase":"PHRASE-EXACT"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("vault GET missing %s: %s", want, body)
		}
	}

	// A missing pair maps to the standard store error envelope.
	rec = doRequest(t, mux, "GET", "/api/v1/key-pairs/999999", "")
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

func TestKeyPairCreateUpdateAndClear(t *testing.T) {
	mux, s, path := newTestAPI(t)
	ctx := context.Background()

	// Unknown JSON field is rejected with 400 invalid_request.
	body := `{"name":"pair-a","private_key":"PRIVATE-KEY-MATERIAL","bogus":1}`
	rec := doRequest(t, mux, "POST", "/api/v1/key-pairs", body)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown field status = %d, want 400, body=%s", rec.Code, rec.Body.String())
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

	// Create stores all three values but the response is metadata-only.
	body = `{"name":"pair-a","public_key":"PUBLIC-KEY-A","private_key":"PRIVATE-KEY-A","private_key_passphrase":"PHRASE-A"}`
	rec = doRequest(t, mux, "POST", "/api/v1/key-pairs", body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status = %d, body=%s", rec.Code, rec.Body.String())
	}
	respBody := rec.Body.String()
	if strings.Contains(respBody, "PRIVATE-KEY-A") || strings.Contains(respBody, "PHRASE-A") {
		t.Errorf("create response leaks key material: %s", respBody)
	}
	var created model.KeyPairSummary
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	if created.ID == 0 || !created.HasPublicKey || !created.HasPrivateKey || !created.HasPrivateKeyPassphrase {
		t.Errorf("create response missing presence metadata: %+v", created)
	}

	// Audit records only resource identifiers, never raw request values.
	auditEv := lastAuditEvent(t, path)
	if auditEv.Operation != "key_pair.create" || auditEv.ResourceType != "key_pair" ||
		auditEv.ResourceID != strconv.FormatInt(created.ID, 10) {
		t.Errorf("audit = %q/%q/%q, want key_pair.create/key_pair/%d", auditEv.Operation, auditEv.ResourceType, auditEv.ResourceID, created.ID)
	}
	if strings.Contains(auditEv.Error, "PRIVATE-KEY-A") || strings.Contains(auditEv.Metadata, "PRIVATE-KEY-A") {
		t.Errorf("audit carries raw request value: %+v", auditEv)
	}

	// Duplicate name maps to 409 conflict.
	body = `{"name":"pair-a","public_key":"pub-a","private_key":"PRIVATE-KEY-A","private_key_passphrase":"PHRASE-A"}`
	rec = doRequest(t, mux, "POST", "/api/v1/key-pairs", body)
	if rec.Code != http.StatusConflict {
		t.Fatalf("duplicate status = %d, want 409, body=%s", rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &e); err != nil {
		t.Fatalf("decode error body: %v", err)
	}
	if e.Code != "conflict" {
		t.Errorf("error code = %q, want conflict", e.Code)
	}

	// Update: omitted secrets retain stored values, an explicit empty
	// string clears. The response stays metadata-only.
	body = fmt.Sprintf(`{"name":"pair-a-renamed","private_key_passphrase":""}`)
	rec = doRequest(t, mux, "PUT", fmt.Sprintf("/api/v1/key-pairs/%d", created.ID), body)
	if rec.Code != http.StatusOK {
		t.Fatalf("update status = %d, body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "PRIVATE-KEY-A") {
		t.Errorf("update response leaks key material: %s", rec.Body.String())
	}
	got, err := s.GetKeyPair(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetKeyPair after update: %v", err)
	}
	if got.Name != "pair-a-renamed" {
		t.Errorf("name = %q, want pair-a-renamed", got.Name)
	}
	if string(got.PublicKey) != "PUBLIC-KEY-A" || string(got.PrivateKey) != "PRIVATE-KEY-A" {
		t.Errorf("omitted secrets were not retained: public=%q private=%q", got.PublicKey, got.PrivateKey)
	}
	if len(got.PrivateKeyPassphrase) != 0 {
		t.Errorf("passphrase = %q, want cleared by empty string", got.PrivateKeyPassphrase)
	}
}

func TestKeyPairDeleteWarnsButLeavesSSHReference(t *testing.T) {
	mux, s, path := newTestAPI(t)
	ctx := context.Background()
	pair, err := s.CreateKeyPair(ctx, model.KeyPair{Name: "doomed", PrivateKey: []byte("key-material")})
	if err != nil {
		t.Fatalf("CreateKeyPair: %v", err)
	}
	sshConn, err := s.CreateSSH(ctx, model.SSHProfile{
		Name: "ref", Host: "h.invalid", Port: 22, Username: "u",
		KeyPairID: pair.ID, JumpConnectionIDs: "[]",
	})
	if err != nil {
		t.Fatalf("CreateSSH: %v", err)
	}

	// Dependents warn about the SSH reference before deletion.
	rec := doRequest(t, mux, "GET", fmt.Sprintf("/api/v1/key-pairs/%d/dependents", pair.ID), "")
	if rec.Code != http.StatusOK {
		t.Fatalf("dependents status = %d, body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"ssh":[{"id":`+strconv.FormatInt(sshConn.ID, 10)) {
		t.Errorf("dependents response missing ssh reference: %s", body)
	}
	if !strings.Contains(body, `"db":[]`) {
		t.Errorf("dependents response missing empty db array: %s", body)
	}
	if strings.Contains(body, "key-material") {
		t.Errorf("dependents response leaks key material: %s", body)
	}

	// Deletion proceeds and leaves the SSH reference dangling.
	rec = doRequest(t, mux, "DELETE", fmt.Sprintf("/api/v1/key-pairs/%d", pair.ID), "")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete status = %d, want 204, body=%s", rec.Code, rec.Body.String())
	}
	auditEv := lastAuditEvent(t, path)
	if auditEv.Operation != "key_pair.delete" || auditEv.ResourceID != strconv.FormatInt(pair.ID, 10) {
		t.Errorf("audit = %q/%q, want key_pair.delete/%d", auditEv.Operation, auditEv.ResourceID, pair.ID)
	}

	got, err := s.GetSSH(ctx, sshConn.ID)
	if err != nil {
		t.Fatalf("GetSSH after pair deletion: %v", err)
	}
	if got.KeyPairID != pair.ID {
		t.Errorf("SSH key_pair_id = %d after pair deletion, want dangling %d", got.KeyPairID, pair.ID)
	}

	// Deleting the already-deleted pair maps to 404.
	rec = doRequest(t, mux, "DELETE", fmt.Sprintf("/api/v1/key-pairs/%d", pair.ID), "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("second delete status = %d, want 404, body=%s", rec.Code, rec.Body.String())
	}
}

func TestSSHHandlersAcceptKeyPairAndRejectPasswordConflict(t *testing.T) {
	mux, s, path := newTestAPI(t)
	ctx := context.Background()
	full, err := s.CreateKeyPair(ctx, model.KeyPair{Name: "full", PrivateKey: []byte("key-material")})
	if err != nil {
		t.Fatalf("CreateKeyPair full: %v", err)
	}
	publicOnly, err := s.CreateKeyPair(ctx, model.KeyPair{Name: "public-only", PublicKey: []byte("pub")})
	if err != nil {
		t.Fatalf("CreateKeyPair public-only: %v", err)
	}

	// Create with a stored key pair succeeds and never returns material.
	body := fmt.Sprintf(`{"name":"keyed","host":"h.invalid","port":22,"username":"u","key_pair_id":%d,"jump_connection_ids":"[]"}`, full.ID)
	rec := doRequest(t, mux, "POST", "/api/v1/ssh-connections", body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status = %d, body=%s", rec.Code, rec.Body.String())
	}
	respBody := rec.Body.String()
	if strings.Contains(respBody, "key-material") {
		t.Errorf("create response leaks key material: %s", respBody)
	}
	if !strings.Contains(respBody, `"key_pair_id":`+strconv.FormatInt(full.ID, 10)) ||
		!strings.Contains(respBody, `"key_pair_name":"full"`) {
		t.Errorf("create response missing key-pair reference: %s", respBody)
	}
	if strings.Contains(respBody, `"has_password":true`) {
		t.Errorf("create response reports a password for a key-pair connection: %s", respBody)
	}
	var created model.SSHConnection
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	event := lastAuditEvent(t, path)
	if event.Operation != "ssh_connection.create" || event.ResourceID != strconv.FormatInt(created.ID, 10) {
		t.Errorf("audit = %q/%q, want ssh_connection.create/%d", event.Operation, event.ResourceID, created.ID)
	}

	// Password and key_pair_id together are rejected as validation_error.
	body = fmt.Sprintf(`{"name":"both","host":"h.invalid","port":22,"username":"u","password":"pw","key_pair_id":%d,"jump_connection_ids":"[]"}`, full.ID)
	rec = doRequest(t, mux, "POST", "/api/v1/ssh-connections", body)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("conflict status = %d, want 400, body=%s", rec.Code, rec.Body.String())
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
	auditErr := lastAuditEvent(t, path)
	if auditErr.Operation != "ssh_connection.create" || auditErr.Result != "failure" {
		t.Errorf("audit = %q/%q, want ssh_connection.create/failure", auditErr.Operation, auditErr.Result)
	}
	if strings.Contains(auditErr.Error, "key-material") || strings.Contains(auditErr.Error, "\"pw\"") {
		t.Errorf("audit error leaks request values: %q", auditErr.Error)
	}

	// A public-only pair cannot be selected for authentication.
	body = fmt.Sprintf(`{"name":"nokey","host":"h.invalid","port":22,"username":"u","key_pair_id":%d,"jump_connection_ids":"[]"}`, publicOnly.ID)
	rec = doRequest(t, mux, "POST", "/api/v1/ssh-connections", body)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("public-only status = %d, want 400, body=%s", rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &e); err != nil {
		t.Fatalf("decode error body: %v", err)
	}
	if e.Code != "validation_error" {
		t.Errorf("error code = %q, want validation_error", e.Code)
	}

	// Update also accepts a stored pair and clears the stored password.
	upd := createSSH(t, s, "update-me", "[]")
	body = fmt.Sprintf(`{"name":"update-me","host":"h.invalid","port":22,"username":"u","key_pair_id":%d,"jump_connection_ids":"[]"}`, full.ID)
	rec = doRequest(t, mux, "PUT", fmt.Sprintf("/api/v1/ssh-connections/%d", upd.ID), body)
	if rec.Code != http.StatusOK {
		t.Fatalf("update status = %d, body=%s", rec.Code, rec.Body.String())
	}
	respBody = rec.Body.String()
	if strings.Contains(respBody, `"has_password":true`) {
		t.Errorf("update response still reports password after pair selection: %s", respBody)
	}
	if !strings.Contains(respBody, `"key_pair_name":"full"`) {
		t.Errorf("update response missing pair name: %s", respBody)
	}
	got, err := s.GetSSH(ctx, upd.ID)
	if err != nil {
		t.Fatalf("GetSSH after update: %v", err)
	}
	if got.KeyPairID != full.ID || len(got.Password) != 0 {
		t.Errorf("after update: key_pair_id=%d password=%q, want %d with no password", got.KeyPairID, got.Password, full.ID)
	}
}

func TestSSHUpdateExplicitZeroKeyPairClearsSelection(t *testing.T) {
	mux, s, _ := newTestAPI(t)
	ctx := context.Background()
	pair, err := s.CreateKeyPair(ctx, model.KeyPair{Name: "pair", PrivateKey: []byte("key-material")})
	if err != nil {
		t.Fatalf("CreateKeyPair: %v", err)
	}
	conn, err := s.CreateSSH(ctx, model.SSHProfile{
		Name: "keyed", Host: "h.invalid", Port: 22, Username: "u",
		KeyPairID: pair.ID, JumpConnectionIDs: "[]",
	})
	if err != nil {
		t.Fatalf("CreateSSH: %v", err)
	}

	// Switch to password mode with a blank password: an explicit
	// key_pair_id: 0 must clear the stored selection even though password
	// is null (nil password alone means "keep the stored value").
	body := `{"name":"keyed","host":"h.invalid","port":22,"username":"u","password":null,"key_pair_id":0,"jump_connection_ids":"[]"}`
	rec := doRequest(t, mux, "PUT", fmt.Sprintf("/api/v1/ssh-connections/%d", conn.ID), body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), `"key_pair_id":`+strconv.FormatInt(pair.ID, 10)) {
		t.Errorf("update response still reports the cleared pair: %s", rec.Body.String())
	}
	got, err := s.GetSSH(ctx, conn.ID)
	if err != nil {
		t.Fatalf("GetSSH: %v", err)
	}
	if got.KeyPairID != 0 {
		t.Errorf("key_pair_id = %d, want cleared 0", got.KeyPairID)
	}
	if got.Password != nil {
		t.Errorf("password = %q, want retained nil", got.Password)
	}
}

func TestCreateSSHRejectsNonObjectBody(t *testing.T) {
	mux, _, _ := newTestAPI(t)
	for _, body := range []string{"null", "[]", `"str"`, "42", "true"} {
		rec := doRequest(t, mux, "POST", "/api/v1/ssh-connections", body)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("body %q status = %d, want 400, body=%s", body, rec.Code, rec.Body.String())
			continue
		}
		var e struct {
			Code string `json:"code"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &e); err != nil {
			t.Fatalf("decode error body for %q: %v", body, err)
		}
		if e.Code != "invalid_request" {
			t.Errorf("body %q error code = %q, want invalid_request", body, e.Code)
		}
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

func TestCreateDBAcceptsDatabasesAndReturnsLegacyDefaultAlias(t *testing.T) {
	mux, s, _ := newTestAPI(t)
	body := `{"name":"multi","host":"db.invalid","port":3306,"username":"u","databases":[{"name":"main","is_default":true},{"name":"audit","is_default":false}]}`
	rec := doRequest(t, mux, "POST", "/api/v1/db-connections", body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var got model.DBConnection
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got.Database != "main" {
		t.Errorf("database alias = %q, want main", got.Database)
	}
	want := []model.DatabaseInfo{{Name: "main", IsDefault: true}, {Name: "audit", IsDefault: false}}
	if !reflect.DeepEqual(got.Databases, want) {
		t.Errorf("databases = %+v, want %+v", got.Databases, want)
	}
	stored, err := s.GetDB(context.Background(), got.ID)
	if err != nil {
		t.Fatalf("GetDB: %v", err)
	}
	if !reflect.DeepEqual(stored.Databases, want) {
		t.Errorf("stored databases = %+v, want %+v", stored.Databases, want)
	}
}

func TestCreateDBAcceptsLegacyDatabaseAndUpgradesStoredValue(t *testing.T) {
	mux, s, path := newTestAPI(t)
	body := `{"name":"legacy","host":"db.invalid","port":3306,"username":"u","database":"main"}`
	rec := doRequest(t, mux, "POST", "/api/v1/db-connections", body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var got model.DBConnection
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got.Database != "main" || !reflect.DeepEqual(got.Databases, []model.DatabaseInfo{{Name: "main", IsDefault: true}}) {
		t.Errorf("response = %+v, want legacy alias and one default", got)
	}
	var raw string
	if err := rawDB(t, path).QueryRow("SELECT database FROM db_connections WHERE id=?", got.ID).Scan(&raw); err != nil {
		t.Fatalf("read stored database: %v", err)
	}
	if raw != `[{"name":"main","is_default":true}]` {
		t.Errorf("stored database = %q, want canonical JSON", raw)
	}
}

func TestCreateDBRejectsConflictingDatabaseFields(t *testing.T) {
	mux, _, _ := newTestAPI(t)
	body := `{"name":"conflict","host":"db.invalid","port":3306,"username":"u","database":"main","databases":[{"name":"audit","is_default":true}]}`
	rec := doRequest(t, mux, "POST", "/api/v1/db-connections", body)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body=%s", rec.Code, rec.Body.String())
	}
	var errBody struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &errBody); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	if errBody.Code != "validation_error" {
		t.Errorf("error code = %q, want validation_error", errBody.Code)
	}
}

func TestGetDBReturnsDatabasesAndDefaultAlias(t *testing.T) {
	mux, s, _ := newTestAPI(t)
	created, err := s.CreateDB(context.Background(), model.DBProfile{
		Name: "multi", Host: "db.invalid", Port: 3306, Username: "u",
		Databases: []model.DatabaseInfo{{Name: "main", IsDefault: true}, {Name: "audit"}},
	})
	if err != nil {
		t.Fatalf("CreateDB: %v", err)
	}
	rec := doRequest(t, mux, "GET", fmt.Sprintf("/api/v1/db-connections/%d", created.ID), "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var got model.DBConnection
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got.Database != "main" || len(got.Databases) != 2 || got.Databases[0].Name != "main" || !got.Databases[0].IsDefault {
		t.Errorf("response = %+v, want default alias and database list", got)
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

func TestAuditFailureIsLogged(t *testing.T) {
	mux, s, _ := newTestAPI(t)

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	prev := slog.Default()
	slog.SetDefault(logger)
	t.Cleanup(func() { slog.SetDefault(prev) })

	// Close the store so the list operation fails; the resulting audit
	// write also fails and must be surfaced as a server warning, not
	// silently dropped.
	if err := s.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}

	rec := doRequest(t, mux, http.MethodGet, "/api/v1/ssh-connections", "")
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 (body=%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(buf.String(), "audit write failed") {
		t.Errorf("audit write failure not logged as a warning; output=%q", buf.String())
	}
}

func TestMethodNotAllowed(t *testing.T) {
	mux, _, _ := newTestAPI(t)
	rec := doRequest(t, mux, "POST", "/api/v1/ssh-connections/1", `{}`)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405, body=%s", rec.Code, rec.Body.String())
	}
}

func TestCreateSSHWithGroupID(t *testing.T) {
	mux, s, _ := newTestAPI(t)
	ctx := context.Background()
	g, err := s.CreateGroup(ctx, model.Group{Name: "prod"})
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}

	body := fmt.Sprintf(`{"name":"grouped","host":"h.invalid","port":22,"username":"u","jump_connection_ids":"[]","group_id":%d}`, g.ID)
	rec := doRequest(t, mux, "POST", "/api/v1/ssh-connections", body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var created model.SSHConnection
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	if created.GroupID != g.ID {
		t.Errorf("create response group_id = %d, want %d", created.GroupID, g.ID)
	}
	if created.GroupName != "prod" {
		t.Errorf("create response group_name = %q, want prod", created.GroupName)
	}

	// GET returns the joined group name.
	rec = doRequest(t, mux, "GET", fmt.Sprintf("/api/v1/ssh-connections/%d", created.ID), "")
	if rec.Code != http.StatusOK {
		t.Fatalf("get status = %d, body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"group_name":"prod"`) {
		t.Errorf("get response missing joined group_name: %s", rec.Body.String())
	}

	got, err := s.GetSSH(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetSSH: %v", err)
	}
	if got.GroupID != g.ID || got.GroupName != "prod" {
		t.Errorf("stored group = %d/%q, want %d/prod", got.GroupID, got.GroupName, g.ID)
	}
}

func TestCreateDBWithGroupID(t *testing.T) {
	mux, s, _ := newTestAPI(t)
	ctx := context.Background()
	g, err := s.CreateGroup(ctx, model.Group{Name: "prod"})
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}

	body := fmt.Sprintf(`{"name":"grouped","host":"db.invalid","port":3306,"username":"u","database":"appdb","group_id":%d}`, g.ID)
	rec := doRequest(t, mux, "POST", "/api/v1/db-connections", body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var created model.DBConnection
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	if created.GroupID != g.ID {
		t.Errorf("create response group_id = %d, want %d", created.GroupID, g.ID)
	}
	if created.GroupName != "prod" {
		t.Errorf("create response group_name = %q, want prod", created.GroupName)
	}

	got, err := s.GetDB(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetDB: %v", err)
	}
	if got.GroupID != g.ID || got.GroupName != "prod" {
		t.Errorf("stored group = %d/%q, want %d/prod", got.GroupID, got.GroupName, g.ID)
	}
}

func TestUpdateSSHClearsGroupID(t *testing.T) {
	mux, s, _ := newTestAPI(t)
	ctx := context.Background()
	g, err := s.CreateGroup(ctx, model.Group{Name: "prod"})
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	created, err := s.CreateSSH(ctx, model.SSHProfile{
		Name: "grp", Host: "h.invalid", Port: 22, Username: "u",
		JumpConnectionIDs: "[]", GroupID: g.ID,
	})
	if err != nil {
		t.Fatalf("CreateSSH: %v", err)
	}

	body := `{"name":"grp","host":"h.invalid","port":22,"username":"u","jump_connection_ids":"[]","group_id":0}`
	rec := doRequest(t, mux, "PUT", fmt.Sprintf("/api/v1/ssh-connections/%d", created.ID), body)
	if rec.Code != http.StatusOK {
		t.Fatalf("update status = %d, body=%s", rec.Code, rec.Body.String())
	}
	got, err := s.GetSSH(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetSSH: %v", err)
	}
	if got.GroupID != 0 || got.GroupName != "" {
		t.Errorf("group after clear = %d/%q, want 0/empty", got.GroupID, got.GroupName)
	}
}

func TestCreateSSHRejectsMissingGroup(t *testing.T) {
	mux, _, _ := newTestAPI(t)
	body := `{"name":"x","host":"h","port":22,"username":"u","jump_connection_ids":"[]","group_id":999999}`
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

func TestCreateDBRejectsMissingGroup(t *testing.T) {
	mux, _, _ := newTestAPI(t)
	body := `{"name":"x","host":"h","port":3306,"username":"u","database":"d","group_id":999999}`
	rec := doRequest(t, mux, "POST", "/api/v1/db-connections", body)
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
