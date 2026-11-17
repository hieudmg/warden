package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"warden/internal/model"
	"warden/migrations"
)

func TestHTTPMigrationPreservesExistingProfiles(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "legacy.db")
	db, err := sql.Open("sqlite", sqliteDSN(path))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, name := range []string{"001_initial.up.sql", "002_default_dir.up.sql", "003_groups.up.sql", "004_key_pairs.up.sql", "005_multiple_databases.up.sql", "006_connection_notes.up.sql", "007_archive_connections.up.sql"} {
		migration, err := migrations.FS.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(string(migration)); err != nil {
			t.Fatal(err)
		}
	}
	ts := time.Now().UTC().Format(timeLayout)
	for _, statement := range []string{"CREATE TABLE schema_migrations (version uint64,dirty bool)", "INSERT INTO schema_migrations VALUES (7,false)"} {
		if _, err := db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec("INSERT INTO ssh_connections (id,name,host,port,username,proxy_host,proxy_port,proxy_username,archived,created_at,updated_at) VALUES (1,'legacy','localhost',22,'user','',0,'',1,?,?)", ts, ts); err != nil {
		t.Fatal(err)
	}
	var key [32]byte
	s, err := Open(ctx, path, key)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	p, err := s.GetSSH(ctx, 1)
	if err != nil || p.Name != "legacy" || !p.Archived {
		t.Fatalf("existing profile changed: %+v %v", p, err)
	}
	rows, err := s.ListHTTP(ctx)
	if err != nil || len(rows) != 0 {
		t.Fatal(rows, err)
	}
	if _, err := s.CreateHTTP(ctx, model.HTTPProfile{Name: "new", Origin: "http://localhost", AuthType: "bearer"}); err != nil {
		t.Fatal(err)
	}
}

func TestHTTPSecretAADBindingAndImportRollback(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	a, err := s.CreateHTTP(ctx, model.HTTPProfile{Name: "first", Origin: "http://localhost", AuthType: "basic", Username: []byte("user"), Password: []byte("secret")})
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.CreateHTTP(ctx, model.HTTPProfile{Name: "second", Origin: "http://localhost", AuthType: "basic", Username: []byte("other"), Password: []byte("different")})
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := s.ExportData(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec("UPDATE http_connections SET password=(SELECT password FROM http_connections WHERE id=?) WHERE id=?", a.ID, b.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetHTTP(ctx, b.ID); err == nil {
		t.Fatal("row-swapped ciphertext authenticated")
	}
	if _, err := s.db.Exec("UPDATE http_connections SET username=password WHERE id=?", a.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetHTTP(ctx, a.ID); err == nil {
		t.Fatal("field-swapped ciphertext authenticated")
	}
	dst := newTestStore(t)
	if _, err := dst.db.Exec("CREATE TRIGGER reject_http BEFORE INSERT ON http_connections BEGIN SELECT RAISE(ABORT,'fixture rejection'); END"); err != nil {
		t.Fatal(err)
	}
	bundle.Groups = append(bundle.Groups, model.TransferGroup{ID: 42, Name: "inserted-first", CreatedAt: time.Now(), UpdatedAt: time.Now()})
	if err := dst.ImportData(ctx, bundle); err == nil {
		t.Fatal("fixture insert unexpectedly succeeded")
	}
	for _, table := range managedTransferTables {
		var n int
		if err := dst.db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Fatalf("partial import left %d rows in %s", n, table)
		}
	}
}

func TestHTTPProfileLifecycle(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	g, err := s.CreateGroup(ctx, model.Group{Name: "apis"})
	if err != nil {
		t.Fatal(err)
	}
	p, err := s.CreateHTTP(ctx, model.HTTPProfile{Name: "service", Origin: "http://127.0.0.1:1234", AuthType: "bearer", Credential: []byte("secret-token"), Note: "private api", GroupID: g.ID})
	if err != nil {
		t.Fatal(err)
	}
	var blob []byte
	if err := s.db.QueryRow("SELECT credential FROM http_connections WHERE id=?", p.ID).Scan(&blob); err != nil {
		t.Fatal(err)
	}
	if len(blob) == 0 || bytes.Contains(blob, []byte("secret-token")) {
		t.Fatalf("not encrypted: %q", blob)
	}
	p, err = s.GetHTTP(ctx, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if string(p.Credential) != "secret-token" || p.GroupName != "apis" || p.Note != "private api" {
		t.Fatalf("read: %+v", p)
	}
	p.Credential = nil
	p.Note = "edited"
	if err := s.UpdateHTTP(ctx, p); err != nil {
		t.Fatal(err)
	}
	p, _ = s.GetHTTP(ctx, p.ID)
	if string(p.Credential) != "secret-token" {
		t.Fatal("omission did not preserve")
	}
	p.Credential = []byte("rotated")
	if err := s.UpdateHTTP(ctx, p); err != nil {
		t.Fatal(err)
	}
	p, _ = s.GetHTTP(ctx, p.ID)
	if string(p.Credential) != "rotated" {
		t.Fatal("rotation failed")
	}
	p.AuthType = "basic"
	p.Credential = nil
	p.Username = []byte("user")
	p.Password = []byte("pass")
	if err := s.UpdateHTTP(ctx, p); err != nil {
		t.Fatal(err)
	}
	p, _ = s.GetHTTP(ctx, p.ID)
	if len(p.Credential) != 0 || string(p.Username) != "user" || string(p.Password) != "pass" {
		t.Fatal("mode switch retained incompatible credential")
	}
	p.Password = []byte{}
	if err := s.UpdateHTTP(ctx, p); err != nil {
		t.Fatal(err)
	}
	p, _ = s.GetHTTP(ctx, p.ID)
	if len(p.Password) != 0 {
		t.Fatal("explicit empty did not clear")
	}
	if err := s.SetHTTPArchived(ctx, p.ID, true); err != nil {
		t.Fatal(err)
	}
	p, _ = s.GetHTTP(ctx, p.ID)
	if !p.Archived {
		t.Fatal("archive")
	}
	deps, err := s.GroupDependents(ctx, g.ID)
	if err != nil || len(deps.HTTP) != 1 {
		t.Fatalf("deps=%+v err=%v", deps, err)
	}
	gotGroup, err := s.GetGroup(ctx, g.ID)
	if err != nil || gotGroup.HTTPConnectionCount != 1 {
		t.Fatalf("group=%+v err=%v", gotGroup, err)
	}
	if err := s.DeleteGroup(ctx, g.ID); err != nil {
		t.Fatal(err)
	}
	p, _ = s.GetHTTP(ctx, p.ID)
	if p.GroupID != 0 {
		t.Fatal("dangling deleted group")
	}
	if err := s.DeleteHTTP(ctx, p.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetHTTP(ctx, p.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	var notes int
	s.db.QueryRow("SELECT COUNT(*) FROM connection_notes WHERE connection_type='http'").Scan(&notes)
	if notes != 0 {
		t.Fatal("note leaked after delete")
	}
}

func TestHTTPProfileValidation(t *testing.T) {
	for _, origin := range []string{"http://127.0.0.1", "https://localhost", "https://example.test:443", "http://[::1]:8080", "http://[fe80::1%25eth0]:8080"} {
		if err := model.ValidateHTTPOrigin(origin); err != nil {
			t.Fatalf("valid origin %q: %v", origin, err)
		}
	}
	for _, origin := range []string{"https://user:pass@example.test", "https://example.test/", "https://example.test/api", "https://example.test?x=1", "https://example.test#", "ftp://example.test", "//example.test", "http://", "http://example.test:0", "http://example.test:65536", "http://example.test:", "http://example.test\\evil", "http://::1", "http://[not-an-ip]"} {
		t.Run(origin, func(t *testing.T) {
			s := newTestStore(t)
			_, err := s.CreateHTTP(context.Background(), model.HTTPProfile{Name: "test", Origin: origin, AuthType: "bearer"})
			if !errors.Is(err, ErrValidation) {
				t.Fatalf("origin %q accepted: %v", origin, err)
			}
		})
	}
	s := newTestStore(t)
	ctx := context.Background()
	p := model.HTTPProfile{Name: "test", Origin: "https://example.test", AuthType: "other"}
	if _, err := s.CreateHTTP(ctx, p); !errors.Is(err, ErrValidation) {
		t.Fatal(err)
	}
	p.AuthType = "bearer"
	p.Credential = []byte("bad\r\nheader")
	if _, err := s.CreateHTTP(ctx, p); !errors.Is(err, ErrValidation) {
		t.Fatal(err)
	}
	p.Credential = nil
	p.GroupID = 99
	if _, err := s.CreateHTTP(ctx, p); !errors.Is(err, ErrValidation) {
		t.Fatal(err)
	}
}

func TestHTTPTransferCompatibilityAndAtomicity(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	p, err := s.CreateHTTP(ctx, model.HTTPProfile{Name: "api", Origin: "https://example.test", AuthType: "x_api_key", Credential: []byte("transfer-secret"), Note: "note"})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetHTTPArchived(ctx, p.ID, true); err != nil {
		t.Fatal(err)
	}
	bundle, err := s.ExportData(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(bundle.HTTPConnections) != 1 || bundle.HTTPConnections[0].Credential != "transfer-secret" || !bundle.HTTPConnections[0].Archived {
		t.Fatalf("export=%+v", bundle.HTTPConnections)
	}
	dst := newTestStore(t)
	if err := dst.ImportData(ctx, bundle); err != nil {
		t.Fatal(err)
	}
	got, err := dst.GetHTTP(ctx, p.ID)
	if err != nil || string(got.Credential) != "transfer-secret" || got.Note != "note" || !got.Archived {
		t.Fatalf("import=%+v %v", got, err)
	}
	var a, b []byte
	s.db.QueryRow("SELECT credential FROM http_connections").Scan(&a)
	dst.db.QueryRow("SELECT credential FROM http_connections").Scan(&b)
	if bytes.Equal(a, b) {
		t.Fatal("not reencrypted")
	}
	if err := s.ImportData(ctx, bundle); !errors.Is(err, ErrDestinationNotEmpty) {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(bundle)
	var fields map[string]json.RawMessage
	json.Unmarshal(raw, &fields)
	delete(fields, "http_connections")
	fields["connection_notes"] = json.RawMessage(`[]`)
	raw, _ = json.Marshal(fields)
	var old model.DataBundle
	json.Unmarshal(raw, &old)
	if err := newTestStore(t).ImportData(ctx, old); err != nil {
		t.Fatalf("legacy: %v", err)
	}
	empty, _ := newTestStore(t).ExportData(ctx)
	httpOnly := newTestStore(t)
	if _, err := httpOnly.CreateHTTP(ctx, model.HTTPProfile{Name: "only-http", Origin: "http://localhost", AuthType: "bearer"}); err != nil {
		t.Fatal(err)
	}
	if err := httpOnly.ImportData(ctx, empty); !errors.Is(err, ErrDestinationNotEmpty) {
		t.Fatal("HTTP-only destination overwritten", err)
	}
	bundle.HTTPConnections = append(bundle.HTTPConnections, bundle.HTTPConnections[0])
	clean := newTestStore(t)
	if err := clean.ImportData(ctx, bundle); !errors.Is(err, ErrValidation) {
		t.Fatal(err)
	}
	rows, _ := clean.ListHTTP(ctx)
	if len(rows) != 0 {
		t.Fatal("partial import")
	}
}
