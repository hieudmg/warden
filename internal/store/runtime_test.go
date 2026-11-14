package store

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"warden/internal/crypto"
)

func TestInitializedRuntimeLiveWALAndLockedRestart(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "vault #%.db")
	identity := []byte(`{"format":1,"complete":"identity"}`)
	if err := CommitInstallation(ctx, path, identity); err != nil {
		t.Fatal(err)
	}
	validate := func(b []byte) error {
		if !bytes.Equal(b, identity) {
			return errors.New("identity changed")
		}
		return nil
	}
	v := crypto.NewVault()
	s, err := OpenInitialized(ctx, path, validate, v)
	if err != nil {
		t.Fatal(err)
	}
	gotSchema, _ := schemaRows(ctx, s.db)
	expected, _ := runtimeSchema()
	for name, want := range expected {
		if gotSchema[name] != want {
			t.Errorf("schema %s got %q want %q", name, gotSchema[name], want)
		}
	}
	if _, err := OpenInitialized(ctx, path, validate, crypto.NewVault()); err == nil {
		t.Fatal("concurrent serve accepted")
	}
	if err := s.SaveSession(ctx, Session{Hash: "hash-only", CSRFHash: "csrf-hash", CredentialID: "credential", Created: 1, Seen: 1}); err != nil {
		t.Fatal(err)
	}
	// A separate key-independent reader must observe WAL frames, not stale main DB.
	b, err := s.Installation(ctx)
	if err != nil || !bytes.Equal(b, identity) {
		t.Fatal(err)
	}
	if _, err := s.Session(ctx, "hash-only"); err != nil {
		t.Fatal(err)
	}
	s.Close()
	v = crypto.NewVault()
	s, err = OpenInitialized(ctx, path, validate, v)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if v.Unlocked() {
		t.Fatal("restart resumed key")
	}
	if _, err := s.Session(ctx, "hash-only"); err != nil {
		t.Fatal("session lost", err)
	}
	b, err = s.Installation(ctx)
	if err != nil || !bytes.Equal(b, identity) {
		t.Fatal("identity lost", err)
	}
}

func TestInitializedRuntimeSchemaCreationAtomic(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	path := filepath.Join(t.TempDir(), "atomic.db")
	identity := []byte(`{"format":1}`)
	if err := CommitInstallation(ctx, path, identity); err != nil {
		t.Fatal(err)
	}
	u, _ := sqliteFileURL(path)
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		t.Fatal(err)
	}
	err = initializeManagedSchema(ctx, db, cancel)
	if err == nil {
		t.Fatal("cancelled schema commit accepted")
	}
	schema, err := schemaRows(context.Background(), db)
	if err != nil || len(schema) != 1 || schema["table:installation"] != installationSchema {
		t.Fatal("partial managed schema", schema, err)
	}
	raw, err := installation(context.Background(), db)
	if err != nil || !bytes.Equal(raw, identity) {
		t.Fatal("identity lost", err)
	}
	db.Close()
	s, err := OpenInitialized(context.Background(), path, func([]byte) error { return nil }, crypto.NewVault())
	if err != nil {
		t.Fatal("cannot retry", err)
	}
	s.Close()
}

func TestInitializedRuntimeUnknownSchemaRefusedBeforeMutation(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "unknown.db")
	if err := CommitInstallation(ctx, path, []byte(`{"format":1}`)); err != nil {
		t.Fatal(err)
	}
	u, _ := sqliteFileURL(path)
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`CREATE TABLE foreign_data (secret BLOB)`); err != nil {
		t.Fatal(err)
	}
	db.Close()
	before, _ := os.ReadFile(path)
	entriesBefore, _ := os.ReadDir(filepath.Dir(path))
	s, err := OpenInitialized(ctx, path, func([]byte) error { return nil }, crypto.NewVault())
	if err == nil {
		s.Close()
		t.Fatal("unknown schema accepted and migrated")
	}
	after, _ := os.ReadFile(path)
	entriesAfter, _ := os.ReadDir(filepath.Dir(path))
	if !bytes.Equal(before, after) || len(entriesBefore) != len(entriesAfter) {
		t.Fatal("unknown schema or directory mutated")
	}
}

func TestLiveInstallationReaderObservesCommittedWALWithoutOriginalMutation(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "wal.db")
	old := []byte(`{"format":1,"revision":0}`)
	latest := []byte(`{"format":1,"revision":1}`)
	if err := CommitInstallation(ctx, path, old); err != nil {
		t.Fatal(err)
	}
	s, err := OpenInitialized(ctx, path, func([]byte) error { return nil }, crypto.NewVault())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err = s.db.Exec(`PRAGMA wal_autocheckpoint=0`); err != nil {
		t.Fatal(err)
	}
	if err = s.UpdateInstallation(ctx, latest); err != nil {
		t.Fatal(err)
	}
	main, _ := os.ReadFile(path)
	if bytes.Contains(main, latest) {
		t.Fatal("fixture did not keep latest identity in WAL")
	}
	before := map[string][]byte{}
	for _, suffix := range []string{"", "-wal", "-shm"} {
		b, err := os.ReadFile(path + suffix)
		if err != nil {
			t.Fatal(err)
		}
		before[suffix] = b
	}
	raw, err := probeInstallation(ctx, path)
	if err != nil || !bytes.Equal(raw, latest) {
		t.Fatal("stale WAL probe", string(raw), err)
	}
	for suffix, b := range before {
		after, _ := os.ReadFile(path + suffix)
		if !bytes.Equal(b, after) {
			t.Fatal("probe mutated original", suffix)
		}
	}
	// The already-owned normal WAL connection may update SHM read marks.
	live, err := s.Installation(ctx)
	if err != nil || !bytes.Equal(live, latest) {
		t.Fatal("stale live reader", err)
	}
}
func TestInitializedRuntimeRefusesLegacyLiveWALWithoutArtifactMutation(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "legacy.db")
	old, err := Open(ctx, path, [32]byte{7})
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	if _, err = old.db.Exec(`INSERT INTO projects (name) VALUES ('synthetic')`); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	before := map[string][]byte{}
	modes := map[string]os.FileMode{}
	for _, entry := range entries {
		full := filepath.Join(filepath.Dir(path), entry.Name())
		before[full], _ = os.ReadFile(full)
		info, _ := os.Stat(full)
		modes[full] = info.Mode()
	}
	if s, err := OpenInitialized(ctx, path, func([]byte) error { return nil }, crypto.NewVault()); err == nil {
		s.Close()
		t.Fatal("legacy WAL accepted")
	}
	afterEntries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != len(afterEntries) {
		t.Fatal("directory changed")
	}
	for full, b := range before {
		after, _ := os.ReadFile(full)
		info, _ := os.Stat(full)
		if !bytes.Equal(b, after) || modes[full] != info.Mode() {
			t.Fatal("legacy artifact changed", filepath.Base(full))
		}
	}
}

func TestInitializedRuntimeRefusalDoesNotMutate(t *testing.T) {
	for _, data := range [][]byte{[]byte("not a database"), nil} {
		t.Run(string(data), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "old.db")
			if data == nil {
				if err := CommitInstallation(context.Background(), path, []byte(`{"format":99}`)); err != nil {
					t.Fatal(err)
				}
			} else {
				os.WriteFile(path, data, 0640)
			}
			before, _ := os.ReadFile(path)
			info, _ := os.Stat(path)
			_, err := OpenInitialized(context.Background(), path, func([]byte) error { return errors.New("invalid format/origin") }, crypto.NewVault())
			if err == nil {
				t.Fatal("accepted unknown")
			}
			after, _ := os.ReadFile(path)
			next, _ := os.Stat(path)
			if !bytes.Equal(before, after) || info.Mode() != next.Mode() {
				t.Fatal("mutated refused database")
			}
			for _, suffix := range []string{"-wal", "-shm", "-journal"} {
				if _, err := os.Stat(path + suffix); !os.IsNotExist(err) {
					t.Fatal("created sidecar", suffix)
				}
			}
		})
	}
}
