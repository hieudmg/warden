package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"
	"warden/internal/crypto"
)

func TestClientVerifierRevocationPersistsAndNeverTransfers(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "vault.db")
	identity := []byte(`{"format":1}`)
	if err := CommitInstallation(ctx, path, identity); err != nil {
		t.Fatal(err)
	}
	s, err := OpenInitialized(ctx, path, func([]byte) error { return nil }, crypto.NewVault())
	if err != nil {
		t.Fatal(err)
	}
	client := ClientCredential{ID: "fixture-device", Verifier: "synthetic-verifier-not-a-secret", Label: "fixture", Generation: 0}
	if err = s.ApproveClient(ctx, identity, client); err != nil {
		t.Fatal(err)
	}
	bundle, err := s.ExportData(ctx)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte(client.Verifier)) || bytes.Contains(encoded, []byte(client.ID)) {
		t.Fatal("client authorization exported")
	}
	if err = s.ImportData(ctx, bundle); err != nil {
		t.Fatal("auth rows defeated managed emptiness", err)
	}
	if err = s.RevokeClient(ctx, client.ID); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s, err = OpenInitialized(ctx, path, func([]byte) error { return nil }, crypto.NewVault())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	got, err := s.ClientByVerifier(ctx, client.Verifier)
	if err != nil || !got.Revoked {
		t.Fatal("durable revocation lost on restart", err)
	}
}

func TestRecoveryInvalidatedClientVerifiersCannotExhaustRegistration(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "vault.db")
	identity := []byte(`{"format":1,"authorization_generation":0}`)
	if err := CommitInstallation(ctx, path, identity); err != nil {
		t.Fatal(err)
	}
	s, err := OpenInitialized(ctx, path, func([]byte) error { return nil }, crypto.NewVault())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for n := 0; n < 128; n++ {
		if err = s.ApproveClient(ctx, identity, ClientCredential{ID: fmt.Sprint(n), Verifier: fmt.Sprint(n), Label: "fixture", Generation: 0}); err != nil {
			t.Fatal(err)
		}
	}
	after := []byte(`{"format":1,"authorization_generation":1}`)
	if err = s.UpdateInstallation(ctx, after); err != nil {
		t.Fatal(err)
	}
	if err = s.ApproveClient(ctx, after, ClientCredential{ID: "new", Verifier: "new", Label: "after recovery", Generation: 1}); err != nil {
		t.Fatal("recovery-invalidated verifiers exhausted registration", err)
	}
}

func TestClientVerifierSchemaUpgradePreservesIdentityAndSessions(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "vault.db")
	identity := []byte(`{"format":1,"complete":"fixture"}`)
	if err := CommitInstallation(ctx, path, identity); err != nil {
		t.Fatal(err)
	}
	s, err := OpenInitialized(ctx, path, func([]byte) error { return nil }, crypto.NewVault())
	if err != nil {
		t.Fatal(err)
	}
	if err = s.SaveSession(ctx, Session{Hash: "browser", CSRFHash: "csrf", CredentialID: "owner", Created: 1, Seen: 1}); err != nil {
		t.Fatal(err)
	}
	var n int
	if err = s.db.QueryRow(`SELECT count(*) FROM client_credentials`).Scan(&n); err != nil {
		t.Fatal("client verifier schema absent", err)
	}
	s.Close()
	// Manufacture the exact reviewed v7 runtime, not an arbitrary legacy schema.
	u, _ := sqliteFileURL(path)
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`DROP TABLE client_credentials; UPDATE schema_migrations SET version=7`); err != nil {
		t.Fatal(err)
	}
	db.Close()
	s, err = OpenInitialized(ctx, path, func([]byte) error { return nil }, crypto.NewVault())
	if err != nil {
		t.Fatal("supported checkpoint refused", err)
	}
	defer s.Close()
	got, _ := s.Installation(ctx)
	if !bytes.Equal(got, identity) {
		t.Fatal("identity changed")
	}
	if _, err = s.Session(ctx, "browser"); err != nil {
		t.Fatal("session lost", err)
	}
	if err = s.db.QueryRow(`SELECT count(*) FROM client_credentials`).Scan(&n); err != nil {
		t.Fatal("not upgraded", err)
	}
}
