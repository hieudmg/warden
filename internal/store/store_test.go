package store

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"warden/migrations"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatalf("generate test key: %v", err)
	}
	path := filepath.Join(t.TempDir(), "warden.db")
	s, err := Open(context.Background(), path, key)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestOpenCreatesSchema(t *testing.T) {
	s := newTestStore(t)
	want := []string{
		"ssh_connections",
		"db_connections",
		"groups",
		"projects",
		"reports",
		"audit_events",
		"schema_migrations",
	}
	for _, table := range want {
		var name string
		err := s.db.QueryRowContext(context.Background(),
			"SELECT name FROM sqlite_master WHERE type='table' AND name=?", table).Scan(&name)
		if errors.Is(err, sql.ErrNoRows) {
			t.Errorf("table %q missing from schema", table)
		} else if err != nil {
			t.Fatalf("query sqlite_master for %q: %v", table, err)
		}
	}
}

func TestOpenRerunSafeMigration(t *testing.T) {
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "warden.db")
	first, err := Open(context.Background(), path, key)
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	second, err := Open(context.Background(), path, key)
	if err != nil {
		t.Fatalf("second Open (rerun): %v", err)
	}
	defer second.Close()
}

func TestOpenConfiguresPragmas(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	var journalMode string
	if err := s.db.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&journalMode); err != nil {
		t.Fatalf("read journal_mode: %v", err)
	}
	if journalMode != "wal" {
		t.Errorf("journal_mode = %q, want %q", journalMode, "wal")
	}

	var busyTimeout int
	if err := s.db.QueryRowContext(ctx, "PRAGMA busy_timeout").Scan(&busyTimeout); err != nil {
		t.Fatalf("read busy_timeout: %v", err)
	}
	if busyTimeout != 5000 {
		t.Errorf("busy_timeout = %d, want 5000", busyTimeout)
	}

	var foreignKeys int
	if err := s.db.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&foreignKeys); err != nil {
		t.Fatalf("read foreign_keys: %v", err)
	}
	if foreignKeys != 1 {
		t.Errorf("foreign_keys = %d, want 1", foreignKeys)
	}

	var synchronous int
	if err := s.db.QueryRowContext(ctx, "PRAGMA synchronous").Scan(&synchronous); err != nil {
		t.Fatalf("read synchronous: %v", err)
	}
	if synchronous != 2 {
		t.Errorf("synchronous = %d, want 2 (FULL)", synchronous)
	}
}

func TestOpenCreatesParentDirectory(t *testing.T) {
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "nested", "state")
	path := filepath.Join(dir, "warden.db")
	s, err := Open(context.Background(), path, key)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("db file not created: %v", err)
	}
}

func TestOpenDBFilePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission bits are Unix-only")
	}
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "warden.db")
	s, err := Open(context.Background(), path, key)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat db file: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("db file mode = %o, want 0600", perm)
	}
}

func TestSecretColumnsAreBLOB(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	wantBlob := map[string][]string{
		"ssh_connections": {"password", "proxy_password"},
		"db_connections":  {"password"},
		"key_pairs":       {"public_key", "private_key", "private_key_passphrase"},
	}
	for table, columns := range wantBlob {
		rows, err := s.db.QueryContext(ctx, "PRAGMA table_info("+table+")")
		if err != nil {
			t.Fatalf("PRAGMA table_info(%s): %v", table, err)
		}
		types := map[string]string{}
		for rows.Next() {
			var cid int
			var name, typ string
			var notNull, pk int
			var dflt sql.NullString
			if err := rows.Scan(&cid, &name, &typ, &notNull, &dflt, &pk); err != nil {
				t.Fatalf("scan table_info(%s): %v", table, err)
			}
			types[name] = typ
		}
		rows.Close()
		for _, col := range columns {
			if got := types[col]; got != "BLOB" {
				t.Errorf("%s.%s type = %q, want BLOB", table, col, got)
			}
		}
	}
}

func TestReportsForeignKeyEnforced(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	_, err := s.db.ExecContext(ctx,
		"INSERT INTO reports (project_id, title, summary, agent_model, created_at) VALUES (999, 't', 's', 'm', '2026-01-01T00:00:00Z')")
	if err == nil {
		t.Fatal("insert report with missing project_id succeeded; FK must be enforced")
	}
}

func TestProjectsDeleteRestrictedByReports(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	proj, err := s.CreateProject(ctx, "demo")
	if err != nil {
		t.Fatalf("CreateProject: %v", err)
	}
	if _, err := s.CreateReport(ctx, "demo", "title", "summary", "agent"); err != nil {
		t.Fatalf("CreateReport: %v", err)
	}
	_, err = s.db.ExecContext(ctx, "DELETE FROM projects WHERE id=?", proj.ID)
	if err == nil {
		t.Fatal("delete project with reports succeeded; ON DELETE RESTRICT must block it")
	}
}

func TestDBSSHReferenceHasNoForeignKey(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	ssh, err := s.CreateSSH(ctx, SSHProfileForTest("jump-host", "[]"))
	if err != nil {
		t.Fatalf("CreateSSH: %v", err)
	}
	dbProf, err := s.CreateDB(ctx, DBProfileForTest("app", ssh.ID))
	if err != nil {
		t.Fatalf("CreateDB: %v", err)
	}
	if err := s.DeleteSSH(ctx, ssh.ID); err != nil {
		t.Fatalf("DeleteSSH with DB dependent failed: %v", err)
	}
	got, err := s.GetDB(ctx, dbProf.ID)
	if err != nil {
		t.Fatalf("GetDB after SSH deletion: %v", err)
	}
	if got.SSHConnectionID != ssh.ID {
		t.Errorf("DB row SSHConnectionID = %d, want preserved %d", got.SSHConnectionID, ssh.ID)
	}
}

// TestOpenMigratesSSHKeysToKeyPairReferences proves migration 004 rebuilds
// ssh_connections: legacy per-connection private-key ciphertext columns are
// dropped (key material is intentionally destroyed), key_pair_id defaults to
// 0, and all other SSH data (password, proxy fields, jump ids, default dir,
// group) survives. The prior schema is seeded from the embedded migration
// files and schema_migrations is stamped at version 3 so Open applies only
// 004.
func TestOpenMigratesSSHKeysToKeyPairReferences(t *testing.T) {
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "warden.db")
	db, err := sql.Open("sqlite", sqliteDSN(path))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"001_initial.up.sql", "002_default_dir.up.sql", "003_groups.up.sql"} {
		statement, err := migrations.FS.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(string(statement)); err != nil {
			t.Fatalf("apply %s: %v", name, err)
		}
	}
	if _, err := db.Exec("CREATE TABLE schema_migrations (version uint64, dirty bool)"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO schema_migrations (version, dirty) VALUES (3, false)"); err != nil {
		t.Fatal(err)
	}

	ts := time.Now().UTC().Format(time.RFC3339Nano)
	oldPassword := []byte("encrypted-password-blob")
	legacyKey := []byte("encrypted-private-key-blob")
	legacyPassphrase := []byte("encrypted-passphrase-blob")
	oldGroupID := int64(7)
	if _, err := db.Exec(`INSERT INTO ssh_connections
		(name, host, port, username, password, private_key, private_key_passphrase,
		 proxy_host, proxy_port, proxy_username, proxy_password, jump_connection_ids,
		 default_dir, group_id, created_at, updated_at)
		VALUES ('ssh', 'h', 22, 'u', ?, ?, ?, 'proxy', 3128, 'pu', ?, '[1, 2]', '/srv/app', ?, ?, ?)`,
		oldPassword, legacyKey, legacyPassphrase, []byte("encrypted-proxy-blob"),
		oldGroupID, ts, ts); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	s, err := Open(context.Background(), path, key)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()

	var password []byte
	var keyPairID, groupID int64
	err = s.db.QueryRow(`SELECT password, key_pair_id, group_id FROM ssh_connections WHERE name='ssh'`).
		Scan(&password, &keyPairID, &groupID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(password, oldPassword) || keyPairID != 0 || groupID != oldGroupID {
		t.Fatalf("migrated ssh = password:%x keyPair:%d group:%d", password, keyPairID, groupID)
	}

	var proxyHost, jumpIDs, defaultDir string
	var proxyPort int
	if err := s.db.QueryRowContext(ctx, `SELECT proxy_host, proxy_port, jump_connection_ids, default_dir FROM ssh_connections WHERE name='ssh'`).
		Scan(&proxyHost, &proxyPort, &jumpIDs, &defaultDir); err != nil {
		t.Fatal(err)
	}
	if proxyHost != "proxy" || proxyPort != 3128 || jumpIDs != "[1, 2]" || defaultDir != "/srv/app" {
		t.Fatalf("migrated ssh metadata = proxy:%s:%d jump:%s dir:%s", proxyHost, proxyPort, jumpIDs, defaultDir)
	}

	// Legacy key columns are gone; key_pair_id is present.
	cols := map[string]bool{}
	rows, err := s.db.QueryContext(ctx, "PRAGMA table_info(ssh_connections)")
	if err != nil {
		t.Fatalf("PRAGMA table_info(ssh_connections): %v", err)
	}
	for rows.Next() {
		var cid int
		var name, typ string
		var notNull, pk int
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &typ, &notNull, &dflt, &pk); err != nil {
			t.Fatalf("scan table_info: %v", err)
		}
		cols[name] = true
	}
	rows.Close()
	if cols["private_key"] || cols["private_key_passphrase"] {
		t.Errorf("legacy key columns still present after migration 004: private_key=%v private_key_passphrase=%v",
			cols["private_key"], cols["private_key_passphrase"])
	}
	if !cols["key_pair_id"] {
		t.Error("ssh_connections.key_pair_id missing after migration 004")
	}

	var tableName string
	if err := s.db.QueryRowContext(ctx, "SELECT name FROM sqlite_master WHERE type='table' AND name='key_pairs'").Scan(&tableName); err != nil {
		t.Errorf("key_pairs table missing: %v", err)
	}
	for _, idx := range []string{"idx_ssh_connections_group_id", "idx_ssh_connections_key_pair_id"} {
		var idxName string
		if err := s.db.QueryRowContext(ctx, "SELECT name FROM sqlite_master WHERE type='index' AND name=?", idx).Scan(&idxName); err != nil {
			t.Errorf("index %q missing: %v", idx, err)
		}
	}

	// Legacy private ciphertext cannot be selected: the column no longer exists.
	if err := s.db.QueryRowContext(ctx, "SELECT private_key FROM ssh_connections WHERE name='ssh'").Scan(new([]byte)); err == nil {
		t.Error("select of dropped private_key column succeeded")
	}
}

// TestOpenMigratesExistingConnectionsToUngrouped proves migration 003
// upgrades a database created at the 001+002 schema: preexisting SSH and DB
// rows gain group_id = 0 (ungrouped) and the groups table starts empty. The
// prior schema is seeded from the embedded migration files and the
// schema_migrations table is marked at version 2 so Open applies only 003.
func TestOpenMigratesExistingConnectionsToUngrouped(t *testing.T) {
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "warden.db")
	db, err := sql.Open("sqlite", sqliteDSN(path))
	if err != nil {
		t.Fatal(err)
	}
	initial, err := migrations.FS.ReadFile("001_initial.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	defaultDir, err := migrations.FS.ReadFile("002_default_dir.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{string(initial), string(defaultDir),
		"CREATE TABLE schema_migrations (version uint64, dirty bool)",
		"INSERT INTO schema_migrations (version, dirty) VALUES (2, false)"} {
		if _, err := db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	ts := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := db.Exec(`INSERT INTO ssh_connections (name, host, port, username, jump_connection_ids, default_dir, created_at, updated_at) VALUES ('ssh', 'h', 22, 'u', '[]', '', ?, ?)`, ts, ts); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO db_connections (name, host, port, username, database, created_at, updated_at) VALUES ('db', 'h', 3306, 'u', 'd', ?, ?)`, ts, ts); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	s, err := Open(context.Background(), path, key)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var sshGroupID, dbGroupID, groupCount int
	if err := s.db.QueryRow("SELECT group_id FROM ssh_connections WHERE name='ssh'").Scan(&sshGroupID); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRow("SELECT group_id FROM db_connections WHERE name='db'").Scan(&dbGroupID); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRow("SELECT COUNT(*) FROM groups").Scan(&groupCount); err != nil {
		t.Fatal(err)
	}
	if sshGroupID != 0 || dbGroupID != 0 || groupCount != 0 {
		t.Fatalf("migration result = ssh:%d db:%d groups:%d; want 0, 0, 0", sshGroupID, dbGroupID, groupCount)
	}
}
