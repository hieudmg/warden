package profiles_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"warden/internal/model"
	"warden/internal/store"
)

// Distinctive secret markers let tests prove an exported bundle carries real
// plaintext values while audit rows, error bodies, and other non-bundle
// surfaces never do.
const (
	sshPasswordMarker     = "SSH-PASSWORD-MATERIAL"
	proxyPasswordMarker   = "PROXY-PASSWORD-MATERIAL"
	dbPasswordMarker      = "DB-PASSWORD-MATERIAL"
	publicKeyMarker       = "PUBLIC-KEY-MATERIAL"
	privateKeyMarker      = "PRIVATE-KEY-MATERIAL"
	passphraseMarker      = "PASSPHRASE-MATERIAL"
	transferBodySizeBound = 50 << 20 // mirrors the handler's documented 50 MiB limit
)

func secretMarkers() []string {
	return []string{
		sshPasswordMarker,
		proxyPasswordMarker,
		dbPasswordMarker,
		publicKeyMarker,
		privateKeyMarker,
		passphraseMarker,
	}
}

func transferTimestamp(t *testing.T) time.Time {
	t.Helper()
	return time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)
}

// seedTransferSource writes one record of every managed kind into s so an
// export has something to carry.
func seedTransferSource(t *testing.T, s *store.Store) {
	t.Helper()
	ctx := context.Background()

	group := createGroup(t, s, "prod")
	pair, err := s.CreateKeyPair(ctx, model.KeyPair{
		Name:                 "deploy",
		PublicKey:            []byte(publicKeyMarker),
		PrivateKey:           []byte(privateKeyMarker),
		PrivateKeyPassphrase: []byte(passphraseMarker),
	})
	if err != nil {
		t.Fatalf("CreateKeyPair: %v", err)
	}
	if _, err := s.CreateSSH(ctx, model.SSHProfile{
		Name: "ssh-password", Note: "ssh note", Host: "ssh.invalid", Port: 22,
		Username: "deploy", Password: []byte(sshPasswordMarker),
		ProxyHost: "proxy.invalid", ProxyPort: 1080, ProxyUsername: "proxy-user",
		ProxyPassword: []byte(proxyPasswordMarker), JumpConnectionIDs: "[999999]",
		DefaultDir: "/srv/app", GroupID: group.ID,
	}); err != nil {
		t.Fatalf("CreateSSH password profile: %v", err)
	}
	if _, err := s.CreateSSH(ctx, model.SSHProfile{
		Name: "ssh-pair", Host: "pair.invalid", Port: 22, Username: "deploy",
		KeyPairID: pair.ID, JumpConnectionIDs: "[]", GroupID: group.ID,
	}); err != nil {
		t.Fatalf("CreateSSH key-pair profile: %v", err)
	}
	if _, err := s.CreateDB(ctx, model.DBProfile{
		Name: "db-one", Note: "db note", Host: "db.invalid", Port: 3306,
		Username: "app", Password: []byte(dbPasswordMarker),
		Databases: []model.DatabaseInfo{{Name: "appdb", IsDefault: true}, {Name: "otherdb"}},
		GroupID:   group.ID,
	}); err != nil {
		t.Fatalf("CreateDB: %v", err)
	}
	if _, err := s.CreateReport(ctx, "proj", "title", "summary", "model-x"); err != nil {
		t.Fatalf("CreateReport: %v", err)
	}
}

// sampleBundle builds a complete, valid bundle with dangling soft references
// (jump id, DB tunnel id, DB group id) so import preservation is asserted
// against data the store APIs cannot create on their own.
func sampleBundle(t *testing.T) model.DataBundle {
	t.Helper()
	ts := transferTimestamp(t)
	return model.DataBundle{
		Format:     model.DataBundleFormat,
		Version:    model.DataBundleVersion,
		ExportedAt: ts,
		Groups: []model.TransferGroup{
			{ID: 1, Name: "prod", CreatedAt: ts, UpdatedAt: ts},
		},
		KeyPairs: []model.TransferKeyPair{
			{
				ID: 1, Name: "deploy", PublicKey: publicKeyMarker,
				PrivateKey: privateKeyMarker, PrivateKeyPassphrase: passphraseMarker,
				CreatedAt: ts, UpdatedAt: ts,
			},
		},
		SSHConnections: []model.TransferSSHConnection{
			{
				ID: 1, Name: "ssh-password", Host: "ssh.invalid",
				Port: 22, Username: "deploy", Password: sshPasswordMarker,
				ProxyHost: "proxy.invalid", ProxyPort: 1080, ProxyUsername: "proxy-user",
				ProxyPassword: proxyPasswordMarker, JumpConnectionIDs: "[999999]",
				DefaultDir: "/srv/app", GroupID: 1, CreatedAt: ts, UpdatedAt: ts,
			},
			{
				ID: 2, Name: "ssh-pair", Host: "pair.invalid", Port: 22,
				Username: "deploy", JumpConnectionIDs: "[]", KeyPairID: 1,
				CreatedAt: ts, UpdatedAt: ts,
			},
		},
		DBConnections: []model.TransferDBConnection{
			{
				ID: 1, Name: "db-one", Host: "db.invalid", Port: 3306,
				Username: "app", Password: dbPasswordMarker,
				Databases:       []model.DatabaseInfo{{Name: "appdb", IsDefault: true}, {Name: "otherdb"}},
				SSHConnectionID: 999999, GroupID: 999999,
				CreatedAt: ts, UpdatedAt: ts,
			},
		},
		ConnectionNotes: []model.TransferConnectionNote{
			{ConnectionType: "ssh", ConnectionID: 1, Note: "ssh note"},
			{ConnectionType: "db", ConnectionID: 1, Note: "db note"},
		},
		Projects: []model.TransferProject{{ID: 1, Name: "proj"}},
		Reports: []model.TransferReport{
			{
				ID: 1, ProjectID: 1, Title: "title", Summary: "summary",
				AgentModel: "model-x", CreatedAt: ts,
			},
		},
	}
}

func marshalBundle(t *testing.T, bundle model.DataBundle) string {
	t.Helper()
	raw, err := json.Marshal(bundle)
	if err != nil {
		t.Fatalf("marshal bundle: %v", err)
	}
	return string(raw)
}

// managedRowCount counts every row the import is allowed to write, so tests
// can prove a rejected import left the destination untouched.
func managedRowCount(t *testing.T, path string) int {
	t.Helper()
	db := rawDB(t, path)
	total := 0
	for _, table := range []string{
		"groups", "key_pairs", "ssh_connections", "db_connections",
		"projects", "reports", "connection_notes",
	} {
		var n int
		if err := db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&n); err != nil {
			t.Fatalf("count %s: %v", table, err)
		}
		total += n
	}
	return total
}

func decodeErrorCode(t *testing.T, body string) string {
	t.Helper()
	var e struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal([]byte(body), &e); err != nil {
		t.Fatalf("decode error envelope %q: %v", body, err)
	}
	return e.Code
}

func TestDataExportReturnsAttachmentWithPlaintextSecrets(t *testing.T) {
	mux, s, path := newTestAPI(t)
	seedTransferSource(t, s)

	rec := doRequest(t, mux, http.MethodGet, "/api/v1/data/export", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	if cd := rec.Header().Get("Content-Disposition"); cd != `attachment; filename="warden-data.json"` {
		t.Errorf("Content-Disposition = %q, want attachment filename warden-data.json", cd)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}

	var bundle model.DataBundle
	if err := json.Unmarshal(rec.Body.Bytes(), &bundle); err != nil {
		t.Fatalf("decode exported bundle: %v", err)
	}
	if bundle.Format != model.DataBundleFormat || bundle.Version != model.DataBundleVersion {
		t.Errorf("bundle identity = %q/%d, want %q/%d",
			bundle.Format, bundle.Version, model.DataBundleFormat, model.DataBundleVersion)
	}
	if bundle.ExportedAt.IsZero() {
		t.Error("exported_at is zero")
	}
	if len(bundle.Groups) != 1 || len(bundle.KeyPairs) != 1 ||
		len(bundle.SSHConnections) != 2 || len(bundle.DBConnections) != 1 ||
		len(bundle.Projects) != 1 || len(bundle.Reports) != 1 {
		t.Errorf("bundle counts = groups:%d pairs:%d ssh:%d db:%d projects:%d reports:%d, want 1/1/2/1/1/1",
			len(bundle.Groups), len(bundle.KeyPairs), len(bundle.SSHConnections),
			len(bundle.DBConnections), len(bundle.Projects), len(bundle.Reports))
	}

	body := rec.Body.String()
	for _, marker := range secretMarkers() {
		if !strings.Contains(body, marker) {
			t.Errorf("export body missing plaintext secret %q", marker)
		}
	}
	if !strings.Contains(body, "ssh note") || !strings.Contains(body, "/srv/app") {
		t.Errorf("export body missing stored metadata: %s", body)
	}

	// The export audit row reports the operation without carrying bundle
	// contents or secrets.
	e := lastAuditEvent(t, path)
	if e.Operation != "data.export" || e.Result != "success" {
		t.Errorf("audit = %q/%q, want data.export/success", e.Operation, e.Result)
	}
	for _, marker := range secretMarkers() {
		if strings.Contains(e.Error, marker) || strings.Contains(e.Metadata, marker) {
			t.Errorf("export audit leaked secret %q: error=%q metadata=%q", marker, e.Error, e.Metadata)
		}
	}
}

func TestDataExportImportMigratesBetweenServers(t *testing.T) {
	sourceMux, sourceStore, _ := newTestAPI(t)
	seedTransferSource(t, sourceStore)

	exported := doRequest(t, sourceMux, http.MethodGet, "/api/v1/data/export", "")
	if exported.Code != http.StatusOK {
		t.Fatalf("export status = %d, body=%s", exported.Code, exported.Body.String())
	}

	// The destination is a different server with its own master key.
	destMux, destStore, destPath := newTestAPI(t)
	rec := doRequest(t, destMux, http.MethodPost, "/api/v1/data/import", exported.Body.String())
	if rec.Code != http.StatusNoContent {
		t.Fatalf("import status = %d, want 204, body=%s", rec.Code, rec.Body.String())
	}
	if rec.Body.Len() != 0 {
		t.Errorf("import body = %q, want empty", rec.Body.String())
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("import Cache-Control = %q, want no-store", cc)
	}

	ctx := context.Background()
	ssh, err := destStore.GetSSH(ctx, 1)
	if err != nil {
		t.Fatalf("GetSSH after import: %v", err)
	}
	if string(ssh.Password) != sshPasswordMarker {
		t.Errorf("migrated ssh password = %q, want decrypted under the destination key", ssh.Password)
	}
	if string(ssh.ProxyPassword) != proxyPasswordMarker {
		t.Errorf("migrated proxy password = %q, want decrypted under the destination key", ssh.ProxyPassword)
	}
	if ssh.Note != "ssh note" || ssh.DefaultDir != "/srv/app" {
		t.Errorf("migrated ssh metadata = note %q dir %q", ssh.Note, ssh.DefaultDir)
	}

	pair, err := destStore.GetKeyPair(ctx, 1)
	if err != nil {
		t.Fatalf("GetKeyPair after import: %v", err)
	}
	if string(pair.PrivateKey) != privateKeyMarker || string(pair.PrivateKeyPassphrase) != passphraseMarker {
		t.Errorf("migrated key pair material = %q/%q", pair.PrivateKey, pair.PrivateKeyPassphrase)
	}

	dbConn, err := destStore.GetDB(ctx, 1)
	if err != nil {
		t.Fatalf("GetDB after import: %v", err)
	}
	if string(dbConn.Password) != dbPasswordMarker {
		t.Errorf("migrated db password = %q, want decrypted under the destination key", dbConn.Password)
	}
	if dbConn.Note != "db note" || len(dbConn.Databases) != 2 {
		t.Errorf("migrated db metadata = note %q databases %#v", dbConn.Note, dbConn.Databases)
	}

	reports, err := destStore.ListReports(ctx, "proj")
	if err != nil {
		t.Fatalf("ListReports after import: %v", err)
	}
	if len(reports) != 1 || reports[0].Title != "title" || reports[0].Summary != "summary" {
		t.Errorf("migrated reports = %#v", reports)
	}

	groups, err := destStore.ListGroups(ctx)
	if err != nil {
		t.Fatalf("ListGroups after import: %v", err)
	}
	if len(groups) != 1 || groups[0].Name != "prod" {
		t.Errorf("migrated groups = %#v", groups)
	}

	e := lastAuditEvent(t, destPath)
	if e.Operation != "data.import" || e.Result != "success" {
		t.Errorf("audit = %q/%q, want data.import/success", e.Operation, e.Result)
	}
	if !strings.Contains(e.Metadata, `"ssh_connections":2`) {
		t.Errorf("import audit metadata = %q, want safe record counts", e.Metadata)
	}
	for _, marker := range secretMarkers() {
		if strings.Contains(e.Error, marker) || strings.Contains(e.Metadata, marker) {
			t.Errorf("import audit leaked secret %q: error=%q metadata=%q", marker, e.Error, e.Metadata)
		}
	}
}

func TestDataImportPreservesIDsTimestampsAndDanglingReferences(t *testing.T) {
	mux, s, _ := newTestAPI(t)
	ts := transferTimestamp(t)
	rec := doRequest(t, mux, http.MethodPost, "/api/v1/data/import", marshalBundle(t, sampleBundle(t)))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204, body=%s", rec.Code, rec.Body.String())
	}

	ctx := context.Background()
	ssh, err := s.GetSSH(ctx, 1)
	if err != nil {
		t.Fatalf("GetSSH(1): %v", err)
	}
	if ssh.JumpConnectionIDs != "[999999]" {
		t.Errorf("jump ids = %q, want dangling reference preserved", ssh.JumpConnectionIDs)
	}
	if ssh.GroupID != 1 {
		t.Errorf("ssh group_id = %d, want 1", ssh.GroupID)
	}
	if !ssh.CreatedAt.Equal(ts) || !ssh.UpdatedAt.Equal(ts) {
		t.Errorf("ssh timestamps = %s/%s, want %s", ssh.CreatedAt, ssh.UpdatedAt, ts)
	}

	paired, err := s.GetSSH(ctx, 2)
	if err != nil {
		t.Fatalf("GetSSH(2): %v", err)
	}
	if paired.KeyPairID != 1 || len(paired.Password) != 0 {
		t.Errorf("key-pair profile = pair %d password %q, want key pair 1 and no password",
			paired.KeyPairID, paired.Password)
	}

	dbConn, err := s.GetDB(ctx, 1)
	if err != nil {
		t.Fatalf("GetDB(1): %v", err)
	}
	if dbConn.SSHConnectionID != 999999 || dbConn.GroupID != 999999 {
		t.Errorf("db soft refs = ssh %d group %d, want dangling 999999/999999",
			dbConn.SSHConnectionID, dbConn.GroupID)
	}
	if len(dbConn.Databases) != 2 || !dbConn.Databases[0].IsDefault || dbConn.Databases[0].Name != "appdb" {
		t.Errorf("db databases = %#v, want appdb default plus otherdb", dbConn.Databases)
	}

	reports, err := s.ListReports(ctx, "proj")
	if err != nil {
		t.Fatalf("ListReports: %v", err)
	}
	if len(reports) != 1 {
		t.Fatalf("reports = %#v, want one report", reports)
	}
	if reports[0].ID != 1 || !reports[0].CreatedAt.Equal(ts) {
		t.Errorf("report id/created_at = %d/%s, want 1/%s", reports[0].ID, reports[0].CreatedAt, ts)
	}
}

func TestDataImportRejectsInvalidBundles(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*model.DataBundle)
	}{
		{"unsupported format", func(b *model.DataBundle) { b.Format = "other-data" }},
		{"unsupported version", func(b *model.DataBundle) { b.Version = 99 }},
		{"missing exported_at", func(b *model.DataBundle) { b.ExportedAt = time.Time{} }},
		{"ssh password with key pair", func(b *model.DataBundle) { b.SSHConnections[0].KeyPairID = 1 }},
		{"duplicate group id", func(b *model.DataBundle) {
			b.Groups = append(b.Groups, model.TransferGroup{ID: 1, Name: "other", CreatedAt: b.ExportedAt, UpdatedAt: b.ExportedAt})
		}},
		{"duplicate ssh name", func(b *model.DataBundle) { b.SSHConnections[1].Name = "ssh-password" }},
		{"invalid ssh name", func(b *model.DataBundle) { b.SSHConnections[0].Name = "bad name!" }},
		{"malformed jump json", func(b *model.DataBundle) { b.SSHConnections[0].JumpConnectionIDs = "not-json" }},
		{"missing ssh timestamp", func(b *model.DataBundle) { b.SSHConnections[0].CreatedAt = time.Time{} }},
		{"negative ssh group reference", func(b *model.DataBundle) { b.SSHConnections[0].GroupID = -1 }},
		{"invalid db port", func(b *model.DataBundle) { b.DBConnections[0].Port = 0 }},
		{"report without project", func(b *model.DataBundle) { b.Reports[0].ProjectID = 4242 }},
		{"report without title", func(b *model.DataBundle) { b.Reports[0].Title = "" }},
		{"non-positive record id", func(b *model.DataBundle) { b.Groups[0].ID = 0 }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mux, _, path := newTestAPI(t)
			bundle := sampleBundle(t)
			tc.mutate(&bundle)

			rec := doRequest(t, mux, http.MethodPost, "/api/v1/data/import", marshalBundle(t, bundle))
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400, body=%s", rec.Code, rec.Body.String())
			}
			if code := decodeErrorCode(t, rec.Body.String()); code != "validation_error" {
				t.Errorf("error code = %q, want validation_error", code)
			}
			if n := managedRowCount(t, path); n != 0 {
				t.Errorf("managed rows after rejected import = %d, want 0", n)
			}
		})
	}
}

func TestDataImportRejectsMalformedBodies(t *testing.T) {
	cases := []struct {
		name     string
		body     string
		wantCode string
	}{
		{"array body", `[]`, "invalid_request"},
		{"scalar body", `"warden"`, "invalid_request"},
		{"unknown field", `{"format":"warden-data","version":1,"extra":true}`, "invalid_request"},
		{"truncated json", `{"format":"warden-data"`, "invalid_request"},
		{"two json values", `{"format":"warden-data","version":1}{}`, "invalid_request"},
		{"empty body", ``, "invalid_request"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mux, _, path := newTestAPI(t)
			rec := doRequest(t, mux, http.MethodPost, "/api/v1/data/import", tc.body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400, body=%s", rec.Code, rec.Body.String())
			}
			if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
				t.Errorf("import Cache-Control = %q, want no-store on rejected bodies", cc)
			}
			if code := decodeErrorCode(t, rec.Body.String()); code != tc.wantCode {
				t.Errorf("error code = %q, want %q", code, tc.wantCode)
			}
			if n := managedRowCount(t, path); n != 0 {
				t.Errorf("managed rows after rejected import = %d, want 0", n)
			}
		})
	}
}

func TestDataImportRejectsNonEmptyDestination(t *testing.T) {
	mux, s, path := newTestAPI(t)
	createSSH(t, s, "existing", "[]")
	before := managedRowCount(t, path)

	rec := doRequest(t, mux, http.MethodPost, "/api/v1/data/import", marshalBundle(t, sampleBundle(t)))
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409, body=%s", rec.Code, rec.Body.String())
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("import Cache-Control = %q, want no-store", cc)
	}
	if code := decodeErrorCode(t, rec.Body.String()); code != "conflict" {
		t.Errorf("error code = %q, want conflict", code)
	}
	if after := managedRowCount(t, path); after != before {
		t.Errorf("managed rows after conflict = %d, want unchanged %d", after, before)
	}
	groups, err := s.ListGroups(context.Background())
	if err != nil {
		t.Fatalf("ListGroups: %v", err)
	}
	if len(groups) != 0 {
		t.Errorf("groups after conflict = %#v, want none", groups)
	}
}

// Audit history is operational metadata: it must not block a migration.
func TestDataImportAllowsAuditOnlyDestination(t *testing.T) {
	mux, s, _ := newTestAPI(t)
	doRequest(t, mux, http.MethodGet, "/api/v1/ssh-connections", "")

	rec := doRequest(t, mux, http.MethodPost, "/api/v1/data/import", marshalBundle(t, sampleBundle(t)))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204, body=%s", rec.Code, rec.Body.String())
	}
	ssh, err := s.GetSSH(context.Background(), 1)
	if err != nil {
		t.Fatalf("GetSSH after import: %v", err)
	}
	if string(ssh.Password) != sshPasswordMarker {
		t.Errorf("imported password = %q, want %q", ssh.Password, sshPasswordMarker)
	}
}

func TestDataImportFailureLeavesDestinationImportable(t *testing.T) {
	mux, s, path := newTestAPI(t)

	invalid := sampleBundle(t)
	invalid.Format = "other-data"
	rec := doRequest(t, mux, http.MethodPost, "/api/v1/data/import", marshalBundle(t, invalid))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body=%s", rec.Code, rec.Body.String())
	}
	if n := managedRowCount(t, path); n != 0 {
		t.Fatalf("managed rows after failed import = %d, want 0", n)
	}

	rec = doRequest(t, mux, http.MethodPost, "/api/v1/data/import", marshalBundle(t, sampleBundle(t)))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("retry status = %d, want 204, body=%s", rec.Code, rec.Body.String())
	}
	if _, err := s.GetSSH(context.Background(), 1); err != nil {
		t.Fatalf("GetSSH after retry: %v", err)
	}
}

func TestDataImportFailureAuditOmitsSecrets(t *testing.T) {
	mux, _, path := newTestAPI(t)

	bundle := sampleBundle(t)
	bundle.SSHConnections[1].Name = "ssh-password" // duplicate name: valid secrets, invalid record
	rec := doRequest(t, mux, http.MethodPost, "/api/v1/data/import", marshalBundle(t, bundle))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body=%s", rec.Code, rec.Body.String())
	}

	e := lastAuditEvent(t, path)
	if e.Operation != "data.import" || e.Result != "failure" {
		t.Errorf("audit = %q/%q, want data.import/failure", e.Operation, e.Result)
	}
	if e.Error == "" {
		t.Error("audit error empty on failure")
	}
	for _, marker := range secretMarkers() {
		if strings.Contains(e.Error, marker) || strings.Contains(e.Metadata, marker) {
			t.Errorf("import audit leaked secret %q: error=%q metadata=%q", marker, e.Error, e.Metadata)
		}
		if strings.Contains(rec.Body.String(), marker) {
			t.Errorf("error response leaked secret %q: %s", marker, rec.Body.String())
		}
	}
}

func TestDataImportRejectsOversizedBundle(t *testing.T) {
	mux, _, path := newTestAPI(t)

	// A syntactically valid object whose filler pushes the body one byte past
	// the documented limit. The filler streams instead of allocating 50 MiB.
	body := io.MultiReader(
		strings.NewReader(`{"format":"warden-data","version":1,"pad":"`),
		&repeatByteReader{remaining: transferBodySizeBound, value: 'a'},
		strings.NewReader(`"}`),
	)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/data/import", body)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413, body=%s", rec.Code, rec.Body.String())
	}
	if code := decodeErrorCode(t, rec.Body.String()); code != "payload_too_large" {
		t.Errorf("error code = %q, want payload_too_large", code)
	}
	if n := managedRowCount(t, path); n != 0 {
		t.Errorf("managed rows after oversized import = %d, want 0", n)
	}
}

func TestDataImportTrailingWhitespaceOverflowIsPayloadTooLarge(t *testing.T) {
	mux, _, path := newTestAPI(t)

	// A complete, valid JSON object followed by enough trailing whitespace to
	// cross the body limit while the handler checks for trailing content. The
	// overflow must be reported as an oversized payload, not malformed JSON.
	body := io.MultiReader(
		strings.NewReader(`{"format":"warden-data","version":1}`),
		&repeatByteReader{remaining: transferBodySizeBound, value: ' '},
	)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/data/import", body)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413, body=%s", rec.Code, rec.Body.String())
	}
	if code := decodeErrorCode(t, rec.Body.String()); code != "payload_too_large" {
		t.Errorf("error code = %q, want payload_too_large", code)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
	if n := managedRowCount(t, path); n != 0 {
		t.Errorf("managed rows after oversized import = %d, want 0", n)
	}
}

// repeatByteReader yields a fixed number of identical bytes so an oversized
// body can be streamed instead of built in memory.
type repeatByteReader struct {
	remaining int64
	value     byte
}

func (r *repeatByteReader) Read(p []byte) (int, error) {
	if r.remaining <= 0 {
		return 0, io.EOF
	}
	n := int64(len(p))
	if n > r.remaining {
		n = r.remaining
	}
	for i := int64(0); i < n; i++ {
		p[i] = r.value
	}
	r.remaining -= n
	return int(n), nil
}
