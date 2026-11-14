package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
)

var ErrExistingInstallation = errors.New("storage exists: retain it; export using the old release if legacy, then run warden-server init with a fresh storage path")

// ReserveInitialization excludes other initializers with an OS-owned lock.
// The lock inode intentionally remains: unlinking it permits two lock owners.
// Kernel ownership is released on close/crash. Existing storage is never opened.
func ReserveInitialization(path string) (*os.File, error) {
	if _, err := os.Lstat(path); err == nil {
		return nil, ErrExistingInstallation
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		if _, err := os.Lstat(path + suffix); !os.IsNotExist(err) {
			return nil, ErrExistingInstallation
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	lock, err := os.OpenFile(path+".init.lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = lockInitialization(lock); err != nil {
		lock.Close()
		return nil, fmt.Errorf("initialization already running or unavailable: %w", err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		lock.Close()
		return nil, ErrExistingInstallation
	}
	return lock, nil
}

// CommitInstallation publishes a complete, key-independent identity database.
// Call only while holding ReserveInitialization and after protocol validation.
// No unwrapped key material is accepted by this persistence interface.
func CommitInstallation(ctx context.Context, path string, record []byte) error {
	return publishInstallation(ctx, path, record)
}

func publishInstallation(ctx context.Context, path string, record []byte) error {
	name, err := stageInstallation(ctx, path, record)
	if err != nil {
		return err
	}
	defer os.Remove(name)
	if err := ctx.Err(); err != nil {
		return err
	}
	// Link is atomic and exclusive, unlike Rename which replaces an old vault.
	// A crash before this point leaves no target; after it leaves a locked identity.
	return os.Link(name, path)
}

// stageInstallation commits only a private sibling temporary database. The
// caller owns cleanup after success. A process crash here cannot expose an
// initialized marker at the target, and a later explicit init can safely retry.
func stageInstallation(ctx context.Context, path string, record []byte) (result string, err error) {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".warden-init-*.db")
	if err != nil {
		return "", err
	}
	name := tmp.Name()
	defer func() {
		if result == "" {
			os.Remove(name)
		}
	}()
	defer os.Remove(name + "-journal")
	if err = tmp.Close(); err != nil {
		return "", err
	}
	u, err := sqliteFileURL(name)
	if err != nil {
		return "", err
	}
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return "", err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `CREATE TABLE installation (singleton INTEGER PRIMARY KEY CHECK(singleton=1), format INTEGER NOT NULL CHECK(format=1), identity BLOB NOT NULL)`); err != nil {
		return "", err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO installation VALUES (1,1,?)`, record); err != nil {
		return "", err
	}
	if err = tx.Commit(); err != nil {
		return "", err
	}
	if err = db.Close(); err != nil {
		return "", err
	}
	f, err := os.OpenFile(name, os.O_RDWR, 0)
	if err != nil {
		return "", err
	}
	err = f.Sync()
	closeErr := f.Close()
	if err != nil {
		return "", err
	}
	if closeErr != nil {
		return "", closeErr
	}
	return name, nil
}

// sqliteFileURL keeps filenames out of URI authority/query/fragment fields.
// Absolute native drive paths need /X: after file://; SQLite's Windows VFS
// removes that leading slash. URL.Path percent-encodes filename delimiters.
func sqliteFileURL(path string) (*url.URL, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	uriPath := filepath.ToSlash(absolute)
	if uriPath[0] != '/' {
		uriPath = "/" + uriPath
	}
	return &url.URL{Scheme: "file", Path: uriPath}, nil
}

// ReadInstallation reads T1's immutable DELETE-journal identity format without
// codec, migrations, pragmas, WAL setup or chmod. Refuse journal sidecars rather
// than silently ignoring a possible newer state; T2 must supply its live reader.
func ReadInstallation(ctx context.Context, path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, ErrExistingInstallation
	}
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		if _, err := os.Lstat(path + suffix); !os.IsNotExist(err) {
			return nil, ErrExistingInstallation
		}
	}
	u, err := sqliteFileURL(path)
	if err != nil {
		return nil, err
	}
	u.RawQuery = "mode=ro&immutable=1"
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, err
	}
	defer db.Close()
	var record []byte
	err = db.QueryRowContext(ctx, `SELECT identity FROM installation WHERE singleton=1 AND format=1`).Scan(&record)
	return record, err
}
