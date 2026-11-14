package store

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"sync"
	"warden/migrations"

	"warden/internal/crypto"
)

// OpenInitialized never invokes the legacy key-taking Open. The OS lease excludes
// init/serve writers. Before ANY original SQLite open/pragmas/migration it probes
// a private copy with its WAL using SQLite's ordinary reader, not immutable=1.
// This also prevents SQLite's read-only WAL shared-memory writes on refused DBs.
// Concurrent non-Warden writers are unsupported; never edit live storage externally.
func OpenInitialized(ctx context.Context, path string, validate func([]byte) error, vault *crypto.Vault) (s *Store, err error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return nil, ErrExistingInstallation
	}
	// First refuse incompatible storage without even creating a lock artifact.
	// A second probe under the lease establishes the authoritative coherent view.
	preliminary, err := probeInstallation(ctx, path)
	if err != nil {
		return nil, ErrExistingInstallation
	}
	if err = validate(preliminary); err != nil {
		return nil, err
	}
	lock, err := os.OpenFile(path+".init.lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = lockInitialization(lock); err != nil {
		lock.Close()
		return nil, err
	}
	defer func() {
		if s == nil {
			lock.Close()
		}
	}()
	raw, err := probeInstallation(ctx, path)
	if err != nil {
		return nil, ErrExistingInstallation
	}
	if err = validate(raw); err != nil {
		return nil, err
	}
	u, err := sqliteFileURL(path)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	q.Set("mode", "rw")
	q.Add("_pragma", "foreign_keys(1)")
	q.Add("_pragma", "journal_mode(WAL)")
	q.Add("_pragma", "busy_timeout(5000)")
	q.Add("_pragma", "synchronous(FULL)")
	u.RawQuery = q.Encode()
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, err
	}
	defer func() {
		if s == nil {
			db.Close()
		}
	}()
	if err = initializeManagedSchema(ctx, db, nil); err != nil {
		return nil, err
	}
	return &Store{db: db, codec: vault, runtimeLease: lock}, nil
}

func probeInstallation(ctx context.Context, path string) ([]byte, error) {
	dir, err := os.MkdirTemp("", "warden-probe-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	target := filepath.Join(dir, "vault.db")
	for _, suffix := range []string{"", "-wal", "-shm"} {
		in, err := os.Open(path + suffix)
		if os.IsNotExist(err) && suffix != "" {
			continue
		}
		if err != nil {
			return nil, err
		}
		info, e := in.Stat()
		if e != nil || !info.Mode().IsRegular() {
			in.Close()
			return nil, ErrExistingInstallation
		}
		out, e := os.OpenFile(target+suffix, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			in.Close()
			return nil, e
		}
		_, e = io.Copy(out, in)
		ce := out.Close()
		in.Close()
		if e != nil {
			return nil, e
		}
		if ce != nil {
			return nil, ce
		}
	}
	// A hot rollback journal needs recovery; do not guess whether it is safe.
	if _, err := os.Lstat(path + "-journal"); !os.IsNotExist(err) {
		return nil, ErrExistingInstallation
	}
	u, err := sqliteFileURL(target)
	if err != nil {
		return nil, err
	}
	u.RawQuery = "mode=ro"
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, err
	}
	defer db.Close()
	if err := validateRuntimeSchema(ctx, db); err != nil {
		return nil, err
	}
	return installation(ctx, db)
}

const sessionSchema = `CREATE TABLE IF NOT EXISTS web_sessions (
 token_hash TEXT PRIMARY KEY, csrf_hash TEXT NOT NULL, credential_id TEXT NOT NULL,
 created INTEGER NOT NULL, seen INTEGER NOT NULL)`
const installationSchema = `CREATE TABLE installation (singleton INTEGER PRIMARY KEY CHECK(singleton=1), format INTEGER NOT NULL CHECK(format=1), identity BLOB NOT NULL)`

var schemaOnce sync.Once
var expectedSchema map[string]string
var schemaError error

func schemaRows(ctx context.Context, db *sql.DB) (map[string]string, error) {
	rows, err := db.QueryContext(ctx, `SELECT type||':'||name,sql FROM sqlite_schema WHERE sql IS NOT NULL AND name NOT LIKE 'sqlite_%'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := map[string]string{}
	for rows.Next() {
		var name, sql string
		if err := rows.Scan(&name, &sql); err != nil {
			return nil, err
		}
		result[name] = sql
	}
	return result, rows.Err()
}
func validateRuntimeSchema(ctx context.Context, db *sql.DB) error {
	var integrity string
	if err := db.QueryRowContext(ctx, `PRAGMA integrity_check`).Scan(&integrity); err != nil || integrity != "ok" {
		return ErrExistingInstallation
	}
	got, err := schemaRows(ctx, db)
	if err != nil {
		return err
	}
	if len(got) == 1 && got["table:installation"] == installationSchema {
		return nil
	}
	expected, err := runtimeSchema()
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(got, expected) {
		return ErrExistingInstallation
	}
	var version int
	var dirty bool
	if err := db.QueryRowContext(ctx, `SELECT version,dirty FROM schema_migrations`).Scan(&version, &dirty); err != nil || version != 7 || dirty {
		return ErrExistingInstallation
	}
	return nil
}
func runtimeSchema() (map[string]string, error) {
	schemaOnce.Do(func() {
		dir, err := os.MkdirTemp("", "warden-schema-*")
		if err != nil {
			schemaError = err
			return
		}
		defer os.RemoveAll(dir)
		u, err := sqliteFileURL(filepath.Join(dir, "reference.db"))
		if err != nil {
			schemaError = err
			return
		}
		ref, err := sql.Open("sqlite", u.String())
		if err != nil {
			schemaError = err
			return
		}
		defer ref.Close()
		if err = migrateDB(ref); err == nil {
			_, err = ref.Exec(installationSchema)
		}
		if err == nil {
			_, err = ref.Exec(sessionSchema)
		}
		if err == nil {
			expectedSchema, err = schemaRows(context.Background(), ref)
		}
		schemaError = err
	})
	return expectedSchema, schemaError
}

// T1 identity-only storage gets ALL managed/auth tables in one transaction.
// A crash/cancel cannot leave a dirty migration marker or partial managed schema.
// Existing runtime schema was checked exactly on the private probe, not migrated.
func initializeManagedSchema(ctx context.Context, db *sql.DB, beforeCommit func()) error {
	schema, err := schemaRows(ctx, db)
	if err != nil {
		return err
	}
	if len(schema) != 1 || schema["table:installation"] != installationSchema {
		return nil
	}
	expected, err := runtimeSchema()
	if err != nil {
		return err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	files, err := migrations.FS.ReadDir(".")
	if err != nil {
		return err
	}
	for _, file := range files {
		if !strings.HasSuffix(file.Name(), ".up.sql") {
			continue
		}
		sql, err := migrations.FS.ReadFile(file.Name())
		if err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, string(sql)); err != nil {
			return err
		}
	}
	if _, err = tx.ExecContext(ctx, expected["table:schema_migrations"]); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, expected["index:version_unique"]); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO schema_migrations(version,dirty) VALUES (7,0)`); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, sessionSchema); err != nil {
		return err
	}
	if beforeCommit != nil {
		beforeCommit()
	}
	return tx.Commit()
}
func installation(ctx context.Context, db *sql.DB) ([]byte, error) {
	var raw []byte
	var format, count int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM installation`).Scan(&count); err != nil || count != 1 {
		return nil, ErrExistingInstallation
	}
	err := db.QueryRowContext(ctx, `SELECT format,identity FROM installation WHERE singleton=1`).Scan(&format, &raw)
	if err != nil || format != 1 || len(raw) > 1<<20 {
		return nil, ErrExistingInstallation
	}
	return raw, nil
}

// Installation reads committed live WAL state through the owned database. It is
// key-independent; unlike T1 ReadInstallation this is NOT an immutable snapshot.
func (s *Store) Installation(ctx context.Context) ([]byte, error) { return installation(ctx, s.db) }

// UpdateInstallation preserves the complete typed identity assembled by the
// auth owner; it never touches managed records or stores transient key material.
func (s *Store) UpdateInstallation(ctx context.Context, raw []byte) error {
	result, err := s.db.ExecContext(ctx, `UPDATE installation SET identity=? WHERE singleton=1 AND format=1`, raw)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrNotFound
	}
	return nil
}

type Session struct {
	Hash, CSRFHash, CredentialID string
	Created, Seen                int64
}

func (s *Store) SaveSession(ctx context.Context, x Session) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO web_sessions VALUES (?,?,?,?,?)`, x.Hash, x.CSRFHash, x.CredentialID, x.Created, x.Seen)
	return err
}
func (s *Store) Session(ctx context.Context, hash string) (Session, error) {
	var x Session
	x.Hash = hash
	err := s.db.QueryRowContext(ctx, `SELECT csrf_hash,credential_id,created,seen FROM web_sessions WHERE token_hash=?`, hash).Scan(&x.CSRFHash, &x.CredentialID, &x.Created, &x.Seen)
	if errors.Is(err, sql.ErrNoRows) {
		return x, ErrNotFound
	}
	return x, err
}
func (s *Store) TouchSession(ctx context.Context, hash string, now int64) error {
	_, err := s.db.ExecContext(ctx, `UPDATE web_sessions SET seen=max(seen,?) WHERE token_hash=?`, now, hash)
	return err
}
func (s *Store) RevokeSession(ctx context.Context, hash string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM web_sessions WHERE token_hash=?`, hash)
	return err
}
func (s *Store) PruneSessions(ctx context.Context, now int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM web_sessions WHERE seen<=? OR created<=?`, now-1800, now-43200)
	return err
}
