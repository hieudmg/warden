package profiles_test

import (
	"context"
	"crypto/rand"
	"database/sql"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"warden/internal/model"
	"warden/internal/server/audit"
	"warden/internal/server/profiles"
	"warden/internal/store"

	_ "modernc.org/sqlite"
)

// newTestAPI builds a store, audit recorder, and profile handler mounted on
// a fresh mux. It returns the handler, the store, and the SQLite file path
// (the path is needed by tests that corrupt stored rows directly).
func newTestAPI(t *testing.T) (http.Handler, *store.Store, string) {
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
	h := profiles.New(s, rec)
	mux := http.NewServeMux()
	h.Register(mux)
	return mux, s, path
}

func createSSH(t *testing.T, s *store.Store, name, jumpIDs string) model.SSHProfile {
	t.Helper()
	p, err := s.CreateSSH(context.Background(), model.SSHProfile{
		Name: name, Host: name + ".invalid", Port: 22, Username: "deploy",
		Password: []byte("pw-" + name), JumpConnectionIDs: jumpIDs,
	})
	if err != nil {
		t.Fatalf("CreateSSH(%s): %v", name, err)
	}
	return p
}

func createDB(t *testing.T, s *store.Store, name string, sshID int64) model.DBProfile {
	t.Helper()
	p, err := s.CreateDB(context.Background(), model.DBProfile{
		Name: name, Host: name + ".invalid", Port: 3306, Username: "app",
		Password: []byte("dbpw-" + name), Databases: []model.DatabaseInfo{{Name: "appdb", IsDefault: true}}, SSHConnectionID: sshID,
	})
	if err != nil {
		t.Fatalf("CreateDB(%s): %v", name, err)
	}
	return p
}

// rawDB opens a second connection to the same SQLite file so tests can
// corrupt stored rows (blobs, jump JSON) to exercise resolver defenses.
func rawDB(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatalf("open raw db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func corruptJumpIDs(t *testing.T, path string, id int64) {
	t.Helper()
	db := rawDB(t, path)
	if _, err := db.Exec("UPDATE ssh_connections SET jump_connection_ids='not-json' WHERE id=?", id); err != nil {
		t.Fatalf("corrupt jump ids: %v", err)
	}
}

// corruptPassword overwrites the stored password blob with a structurally
// valid but wrong-ciphertext blob so GCM authentication fails on decrypt.
func corruptPassword(t *testing.T, path string, id int64) {
	t.Helper()
	db := rawDB(t, path)
	blob := make([]byte, 1+12+16+8)
	blob[0] = 1
	if _, err := db.Exec("UPDATE ssh_connections SET password=? WHERE id=?", blob, id); err != nil {
		t.Fatalf("corrupt password: %v", err)
	}
}

// swapPasswords exchanges two rows' password blobs, breaking the AAD binding
// (warden/ssh/<id>/password) for both rows.
func swapPasswords(t *testing.T, path string, idA, idB int64) {
	t.Helper()
	db := rawDB(t, path)
	var a, b []byte
	if err := db.QueryRow("SELECT password FROM ssh_connections WHERE id=?", idA).Scan(&a); err != nil {
		t.Fatalf("read password A: %v", err)
	}
	if err := db.QueryRow("SELECT password FROM ssh_connections WHERE id=?", idB).Scan(&b); err != nil {
		t.Fatalf("read password B: %v", err)
	}
	if _, err := db.Exec("UPDATE ssh_connections SET password=? WHERE id=?", b, idA); err != nil {
		t.Fatalf("swap A: %v", err)
	}
	if _, err := db.Exec("UPDATE ssh_connections SET password=? WHERE id=?", a, idB); err != nil {
		t.Fatalf("swap B: %v", err)
	}
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

// newRequestWithSource builds a request with a specific remote address and
// user agent so audit source metadata can be asserted.
func newRequestWithSource(method, target, body, remoteAddr, userAgent string) *http.Request {
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, target, reader)
	req.RemoteAddr = remoteAddr
	req.Header.Set("User-Agent", userAgent)
	return req
}

func httptestRecorder() *httptest.ResponseRecorder {
	return httptest.NewRecorder()
}

// lastAuditEvent reads the most recent audit_events row directly from the
// SQLite file (the store exposes no audit read API in this task).
func lastAuditEvent(t *testing.T, path string) model.AuditEvent {
	t.Helper()
	db := rawDB(t, path)
	var e model.AuditEvent
	var createdAt string
	err := db.QueryRow(`SELECT operation, resource_type, resource_id, source, result, error, metadata, created_at
		FROM audit_events ORDER BY id DESC LIMIT 1`).
		Scan(&e.Operation, &e.ResourceType, &e.ResourceID, &e.Source, &e.Result, &e.Error, &e.Metadata, &createdAt)
	if err != nil {
		t.Fatalf("query audit_events: %v", err)
	}
	return e
}
