package store

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"warden/internal/crypto"
	"warden/migrations"
)

type refusalArtifact struct {
	data []byte
	mode os.FileMode
}

func refusalArtifacts(t *testing.T, dir string) map[string]refusalArtifact {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]refusalArtifact{}
	for _, entry := range entries {
		path := filepath.Join(dir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		out[entry.Name()] = refusalArtifact{data, info.Mode()}
	}
	return out
}
func assertRefusalArtifacts(t *testing.T, dir string, want map[string]refusalArtifact) {
	t.Helper()
	got := refusalArtifacts(t, dir)
	if len(got) != len(want) {
		t.Fatalf("directory entries changed %d -> %d", len(want), len(got))
	}
	for name, x := range want {
		y, ok := got[name]
		if !ok || x.mode != y.mode || !bytes.Equal(x.data, y.data) {
			t.Fatal("refusal mutated artifact", name)
		}
	}
}

// Passing-existing characterization. Known legacy schema is built from the
// actual unchanged 001..007 release migrations, with an encrypted SSH value in
// live WAL, not random bytes pretending to be SQLite. No old server is run.
func TestLegacyDBRefusalPreservesArtifacts(t *testing.T) {
	for _, kind := range []string{"absent", "uninitialized SQLite", "legacy encrypted WAL", "unknown schema", "corrupt", "partial schema", "partial identity", "unknown identity", "orphan WAL"} {
		t.Run(kind, func(t *testing.T) {
			ctx := context.Background()
			dir := t.TempDir()
			path := filepath.Join(dir, "old #%.db")
			open := func() *sql.DB {
				t.Helper()
				u, err := sqliteFileURL(path)
				if err != nil {
					t.Fatal(err)
				}
				db, err := sql.Open("sqlite", u.String())
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { db.Close() })
				return db
			}
			exec := func(db *sql.DB, query string, args ...any) {
				t.Helper()
				if _, err := db.Exec(query, args...); err != nil {
					t.Fatal(err)
				}
			}
			switch kind {
			case "uninitialized SQLite":
				exec(open(), `PRAGMA user_version=0`)
			case "legacy encrypted WAL":
				db := open()
				files, err := migrations.FS.ReadDir(".")
				if err != nil {
					t.Fatal(err)
				}
				for _, file := range files {
					if strings.HasSuffix(file.Name(), ".up.sql") && file.Name() < "008" {
						raw, err := migrations.FS.ReadFile(file.Name())
						if err != nil {
							t.Fatal(err)
						}
						exec(db, string(raw))
					}
				}
				exec(db, `PRAGMA journal_mode=WAL`)
				exec(db, `PRAGMA wal_autocheckpoint=0`)
				codec := crypto.Codec{Key: transferSourceKey}
				cipher, err := codec.Encrypt([]byte("synthetic old encrypted content"), []byte("warden/ssh/31/password"))
				if err != nil {
					t.Fatal(err)
				}
				exec(db, `INSERT INTO ssh_connections(id,name,host,port,username,password,created_at,updated_at) VALUES (31,'old','old.invalid',22,'user',?,'2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')`, cipher)
				var marker int
				if err = db.QueryRow(`SELECT count(*) FROM sqlite_schema WHERE name='installation'`).Scan(&marker); err != nil || marker != 0 {
					t.Fatal("legacy gained identity marker", err)
				}
				wal, err := os.ReadFile(path + "-wal")
				if err != nil || !bytes.Contains(wal, cipher) {
					t.Fatal("fixture not encrypted live WAL", err)
				}
			case "unknown schema":
				exec(open(), `CREATE TABLE unknown_data(secret BLOB); INSERT INTO unknown_data VALUES (x'1234')`)
			case "corrupt":
				if err := os.WriteFile(path, []byte("synthetic corrupt SQLite"), 0640); err != nil {
					t.Fatal(err)
				}
			case "partial schema":
				if err := CommitInstallation(ctx, path, []byte(`{"format":1,"complete":true}`)); err != nil {
					t.Fatal(err)
				}
				exec(open(), `CREATE TABLE projects(id INTEGER PRIMARY KEY,name TEXT)`)
			case "partial identity", "unknown identity":
				identity := []byte(`{"format":1}`)
				if kind == "unknown identity" {
					identity = []byte(`{"format":99,"complete":true}`)
				}
				if err := CommitInstallation(ctx, path, identity); err != nil {
					t.Fatal(err)
				}
			case "orphan WAL":
				if err := os.WriteFile(path+"-wal", []byte("synthetic orphan WAL"), 0640); err != nil {
					t.Fatal(err)
				}
			}
			// Rollback config and key are never opened, changed, or used as fallback.
			for name, data := range map[string][]byte{"old-server.json": []byte(`{"db_path":"old #%.db"}`), "master.key": bytes.Repeat([]byte{71}, 32), "old-binary": []byte("synthetic rollback binary")} {
				if err := os.WriteFile(filepath.Join(dir, name), data, 0640); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := os.Stat(path); err == nil {
				if err = os.Chmod(path, 0640); err != nil {
					t.Fatal(err)
				}
			}
			before := refusalArtifacts(t, dir)
			validate := func(raw []byte) error {
				if string(raw) != `{"format":1,"complete":true}` {
					return fmt.Errorf("incomplete/unknown identity")
				}
				return nil
			}
			if s, err := OpenInitialized(ctx, path, validate, crypto.NewVault()); err == nil {
				s.Close()
				t.Fatal("serve accepted incompatible storage")
			}
			assertRefusalArtifacts(t, dir, before)
			if kind != "absent" {
				if lock, err := ReserveInitialization(path); err == nil {
					lock.Close()
					t.Fatal("init accepted existing artifacts")
				}
				assertRefusalArtifacts(t, dir, before)
			}
		})
	}
}
