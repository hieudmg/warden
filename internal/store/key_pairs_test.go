package store

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"warden/internal/model"
)

// KeyPairForTest builds a valid key pair with named plaintext material.
// Secrets are plaintext in the model; the store encrypts them at rest.
func KeyPairForTest(name string) model.KeyPair {
	return model.KeyPair{
		Name:                 name,
		PublicKey:            []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI" + name + " test@example.invalid"),
		PrivateKey:           []byte("-----BEGIN OPENSSH PRIVATE KEY-----\n" + name + "-secret\n-----END OPENSSH PRIVATE KEY-----"),
		PrivateKeyPassphrase: []byte(name + "-phrase"),
	}
}

func TestKeyPairCreateGetRoundTrip(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	created, err := s.CreateKeyPair(ctx, KeyPairForTest("roundtrip"))
	if err != nil {
		t.Fatalf("CreateKeyPair: %v", err)
	}
	if created.ID == 0 {
		t.Error("CreateKeyPair returned zero id")
	}
	if created.CreatedAt.IsZero() || created.UpdatedAt.IsZero() {
		t.Error("CreateKeyPair returned zero timestamps")
	}

	got, err := s.GetKeyPair(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetKeyPair: %v", err)
	}
	if got.Name != "roundtrip" {
		t.Errorf("name = %q, want roundtrip", got.Name)
	}
	if !bytes.Equal(got.PublicKey, created.PublicKey) {
		t.Errorf("public key round trip mismatch: %q", got.PublicKey)
	}
	if !bytes.Equal(got.PrivateKey, created.PrivateKey) {
		t.Errorf("private key round trip mismatch: %q", got.PrivateKey)
	}
	if !bytes.Equal(got.PrivateKeyPassphrase, created.PrivateKeyPassphrase) {
		t.Errorf("passphrase round trip mismatch: %q", got.PrivateKeyPassphrase)
	}
}

func TestKeyPairKeysAreEncryptedAtRest(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	created, err := s.CreateKeyPair(ctx, KeyPairForTest("at-rest"))
	if err != nil {
		t.Fatalf("CreateKeyPair: %v", err)
	}
	source := KeyPairForTest("at-rest")
	for _, tc := range []struct {
		column string
		plain  []byte
	}{
		{"public_key", source.PublicKey},
		{"private_key", source.PrivateKey},
		{"private_key_passphrase", source.PrivateKeyPassphrase},
	} {
		var stored []byte
		if err := s.db.QueryRowContext(ctx, "SELECT "+tc.column+" FROM key_pairs WHERE id=?",
			created.ID).Scan(&stored); err != nil {
			t.Fatalf("read stored %s: %v", tc.column, err)
		}
		if bytes.Contains(stored, tc.plain) {
			t.Errorf("%s stored with plaintext substring", tc.column)
		}
		if len(stored) < 1+12+16 {
			t.Errorf("%s blob too short for [version][nonce][ciphertext+tag]: %d bytes",
				tc.column, len(stored))
		}
		if stored[0] != 1 {
			t.Errorf("%s blob version byte = %d, want 1", tc.column, stored[0])
		}
	}
}

func TestKeyPairListReturnsOnlyPresenceMetadata(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	mk := func(name string, pub, priv, phrase bool) model.KeyPair {
		p := model.KeyPair{Name: name}
		if pub {
			p.PublicKey = []byte("pub-" + name)
		}
		if priv {
			p.PrivateKey = []byte("priv-" + name)
		}
		if phrase {
			p.PrivateKeyPassphrase = []byte("phrase-" + name)
		}
		return p
	}
	for _, p := range []model.KeyPair{
		mk("m-public", true, false, false),
		mk("a-full", true, true, true),
		mk("z-none", false, false, false),
	} {
		if _, err := s.CreateKeyPair(ctx, p); err != nil {
			t.Fatalf("CreateKeyPair %s: %v", p.Name, err)
		}
	}

	all, err := s.ListKeyPairs(ctx)
	if err != nil {
		t.Fatalf("ListKeyPairs: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("ListKeyPairs returned %d rows, want 3", len(all))
	}
	want := []model.KeyPairSummary{
		{Name: "a-full", HasPublicKey: true, HasPrivateKey: true, HasPrivateKeyPassphrase: true},
		{Name: "m-public", HasPublicKey: true, HasPrivateKey: false, HasPrivateKeyPassphrase: false},
		{Name: "z-none", HasPublicKey: false, HasPrivateKey: false, HasPrivateKeyPassphrase: false},
	}
	for i, w := range want {
		got := all[i]
		if got.Name != w.Name ||
			got.HasPublicKey != w.HasPublicKey ||
			got.HasPrivateKey != w.HasPrivateKey ||
			got.HasPrivateKeyPassphrase != w.HasPrivateKeyPassphrase {
			t.Errorf("summary[%d] = %+v, want %+v", i, got, w)
		}
		if got.CreatedAt.IsZero() || got.UpdatedAt.IsZero() {
			t.Errorf("summary[%d] has zero timestamps", i)
		}
	}
}

func TestKeyPairUpdateRetainsNilAndClearsEmptySecret(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	created, err := s.CreateKeyPair(ctx, model.KeyPair{
		Name:                 "retain-clear",
		PublicKey:            []byte("pub"),
		PrivateKey:           []byte("priv"),
		PrivateKeyPassphrase: []byte("phrase"),
	})
	if err != nil {
		t.Fatalf("CreateKeyPair: %v", err)
	}

	updated := created
	updated.PrivateKey = nil                // omit: retain stored value
	updated.PrivateKeyPassphrase = []byte{} // empty non-nil: explicit clear
	if err := s.UpdateKeyPair(ctx, updated); err != nil {
		t.Fatalf("UpdateKeyPair: %v", err)
	}

	got, err := s.GetKeyPair(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetKeyPair: %v", err)
	}
	if string(got.PrivateKey) != "priv" {
		t.Errorf("private key = %q, want retained priv", got.PrivateKey)
	}
	if got.PrivateKeyPassphrase != nil {
		t.Errorf("passphrase = %q, want cleared nil", got.PrivateKeyPassphrase)
	}
	if string(got.PublicKey) != "pub" {
		t.Errorf("public key = %q, want retained pub", got.PublicKey)
	}
}

func TestKeyPairDeleteLeavesSSHReferenceAndDependents(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	pair, err := s.CreateKeyPair(ctx, KeyPairForTest("dep"))
	if err != nil {
		t.Fatalf("CreateKeyPair: %v", err)
	}
	ssh, err := s.CreateSSH(ctx, SSHProfileForTest("pair-user", "[]"))
	if err != nil {
		t.Fatalf("CreateSSH: %v", err)
	}
	// Task 3 wires key_pair_id persistence in CreateSSH/UpdateSSH; until
	// then the reference is written directly.
	if _, err := s.db.ExecContext(ctx,
		"UPDATE ssh_connections SET key_pair_id=? WHERE id=?", pair.ID, ssh.ID); err != nil {
		t.Fatalf("set ssh key_pair_id: %v", err)
	}

	deps, err := s.KeyPairDependents(ctx, pair.ID)
	if err != nil {
		t.Fatalf("KeyPairDependents: %v", err)
	}
	if len(deps) != 1 || deps[0].ID != ssh.ID || deps[0].Name != "pair-user" {
		t.Errorf("dependents = %+v, want ssh %d (pair-user)", deps, ssh.ID)
	}

	// Deletion is allowed with dependents; the SSH reference stays dangling.
	if err := s.DeleteKeyPair(ctx, pair.ID); err != nil {
		t.Fatalf("DeleteKeyPair with dependent failed: %v", err)
	}
	var keyPairID int64
	if err := s.db.QueryRowContext(ctx, "SELECT key_pair_id FROM ssh_connections WHERE id=?",
		ssh.ID).Scan(&keyPairID); err != nil {
		t.Fatalf("read ssh key_pair_id after delete: %v", err)
	}
	if keyPairID != pair.ID {
		t.Errorf("ssh key_pair_id = %d, want preserved %d", keyPairID, pair.ID)
	}

	if err := s.DeleteKeyPair(ctx, pair.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("second DeleteKeyPair error = %v, want ErrNotFound", err)
	}
	if _, err := s.GetKeyPair(ctx, pair.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("GetKeyPair after delete error = %v, want ErrNotFound", err)
	}
	if _, err := s.KeyPairDependents(ctx, pair.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("KeyPairDependents after delete error = %v, want ErrNotFound", err)
	}
}

func TestKeyPairRejectsInvalidOrDuplicateName(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	if _, err := s.CreateKeyPair(ctx, KeyPairForTest("bad name!")); !errors.Is(err, ErrValidation) {
		t.Errorf("invalid name error = %v, want ErrValidation", err)
	}
	if _, err := s.CreateKeyPair(ctx, KeyPairForTest("dup")); err != nil {
		t.Fatalf("first CreateKeyPair: %v", err)
	}
	if _, err := s.CreateKeyPair(ctx, KeyPairForTest("dup")); !errors.Is(err, ErrDuplicate) {
		t.Errorf("duplicate CreateKeyPair error = %v, want ErrDuplicate", err)
	}
}

func TestKeyPairValidateIDClassification(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	publicOnly, err := s.CreateKeyPair(ctx, model.KeyPair{Name: "public-only", PublicKey: []byte("pub")})
	if err != nil {
		t.Fatalf("CreateKeyPair public-only: %v", err)
	}
	full, err := s.CreateKeyPair(ctx, KeyPairForTest("full-pair"))
	if err != nil {
		t.Fatalf("CreateKeyPair full: %v", err)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}
	defer tx.Rollback()

	if err := validateKeyPairID(ctx, tx, 0); err != nil {
		t.Errorf("validateKeyPairID(0) = %v, want nil", err)
	}
	if err := validateKeyPairID(ctx, tx, -1); !errors.Is(err, ErrValidation) {
		t.Errorf("validateKeyPairID(-1) error = %v, want ErrValidation", err)
	}
	if err := validateKeyPairID(ctx, tx, publicOnly.ID); !errors.Is(err, ErrValidation) {
		t.Errorf("validateKeyPairID(public-only) error = %v, want ErrValidation", err)
	}
	if err := validateKeyPairID(ctx, tx, full.ID); err != nil {
		t.Errorf("validateKeyPairID(full) = %v, want nil", err)
	}
	if err := validateKeyPairID(ctx, tx, 999999); !errors.Is(err, ErrValidation) {
		t.Errorf("validateKeyPairID(missing) error = %v, want ErrValidation", err)
	}
}
