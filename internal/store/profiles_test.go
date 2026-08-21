package store

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"testing"

	"warden/internal/model"
)

// SSHProfileForTest builds a valid SSH profile. Secrets are plaintext in the
// model; the store encrypts them at rest.
func SSHProfileForTest(name string, jumpIDs string) model.SSHProfile {
	return model.SSHProfile{
		Name:                 name,
		Host:                 "example.invalid",
		Port:                 22,
		Username:             "deploy",
		Password:             []byte("s3cret"),
		PrivateKey:           []byte("-----BEGIN OPENSSH PRIVATE KEY-----\ntest\n-----END OPENSSH PRIVATE KEY-----\n"),
		PrivateKeyPassphrase: []byte("passphrase"),
		ProxyHost:            "proxy.invalid",
		ProxyPort:            3128,
		ProxyUsername:        "proxyuser",
		ProxyPassword:        []byte("proxysecret"),
		JumpConnectionIDs:    jumpIDs,
	}
}

// DBProfileForTest builds a valid DB profile.
func DBProfileForTest(name string, sshConnectionID int64) model.DBProfile {
	return model.DBProfile{
		Name:            name,
		Host:            "db.invalid",
		Port:            3306,
		Username:        "app",
		Password:        []byte("dbsecret"),
		Database:        "appdb",
		SSHConnectionID: sshConnectionID,
	}
}

func TestSSHCreateGetRoundTrip(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	created, err := s.CreateSSH(ctx, SSHProfileForTest("web-prod", "[12, 4]"))
	if err != nil {
		t.Fatalf("CreateSSH: %v", err)
	}
	if created.ID == 0 {
		t.Error("CreateSSH returned zero id")
	}
	if created.CreatedAt.IsZero() || created.UpdatedAt.IsZero() {
		t.Error("CreateSSH returned zero timestamps")
	}

	got, err := s.GetSSH(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetSSH: %v", err)
	}
	if got.Name != "web-prod" || got.Host != "example.invalid" || got.Port != 22 || got.Username != "deploy" {
		t.Errorf("GetSSH metadata mismatch: %+v", got)
	}
	if string(got.Password) != "s3cret" {
		t.Errorf("GetSSH password = %q, want plaintext round trip", got.Password)
	}
	if string(got.PrivateKey) == "s3cret" {
		t.Error("private key round trip corrupted")
	}
	if string(got.ProxyPassword) != "proxysecret" {
		t.Errorf("proxy password mismatch: %q", got.ProxyPassword)
	}
	if got.JumpConnectionIDs != "[12, 4]" {
		t.Errorf("jump ids stored as %q, want original text preserved", got.JumpConnectionIDs)
	}
}

func TestSSHStoredSecretsAreEncrypted(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	created, err := s.CreateSSH(ctx, SSHProfileForTest("enc-check", "[]"))
	if err != nil {
		t.Fatalf("CreateSSH: %v", err)
	}
	var stored []byte
	if err := s.db.QueryRowContext(ctx, "SELECT password FROM ssh_connections WHERE id=?", created.ID).Scan(&stored); err != nil {
		t.Fatalf("read stored password: %v", err)
	}
	if string(stored) == "s3cret" {
		t.Fatal("password stored as plaintext")
	}
	if len(stored) < 1+12+16 {
		t.Errorf("stored blob too short for [version][nonce][ciphertext+tag]: %d bytes", len(stored))
	}
	if stored[0] != 1 {
		t.Errorf("blob version byte = %d, want 1", stored[0])
	}
}

func TestSSHAADBindingPreventsFieldSwap(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	first, err := s.CreateSSH(ctx, SSHProfileForTest("first", "[]"))
	if err != nil {
		t.Fatalf("CreateSSH first: %v", err)
	}
	second, err := s.CreateSSH(ctx, SSHProfileForTest("second", "[]"))
	if err != nil {
		t.Fatalf("CreateSSH second: %v", err)
	}

	var firstPwd, secondPwd []byte
	if err := s.db.QueryRowContext(ctx, "SELECT password FROM ssh_connections WHERE id=?", first.ID).Scan(&firstPwd); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRowContext(ctx, "SELECT password FROM ssh_connections WHERE id=?", second.ID).Scan(&secondPwd); err != nil {
		t.Fatal(err)
	}

	// Swap encrypted values; AAD binds password to warden/ssh/<id>/password.
	if _, err := s.db.ExecContext(ctx, "UPDATE ssh_connections SET password=? WHERE id=?", secondPwd, first.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx, "UPDATE ssh_connections SET password=? WHERE id=?", firstPwd, second.ID); err != nil {
		t.Fatal(err)
	}

	if _, err := s.GetSSH(ctx, first.ID); err == nil {
		t.Fatal("GetSSH after AAD-broken field swap succeeded; must fail decryption")
	}
	if _, err := s.GetSSH(ctx, second.ID); err == nil {
		t.Fatal("GetSSH after AAD-broken field swap succeeded; must fail decryption")
	}
}

func TestSSHDuplicateNameRejected(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if _, err := s.CreateSSH(ctx, SSHProfileForTest("dup", "[]")); err != nil {
		t.Fatalf("first CreateSSH: %v", err)
	}
	if _, err := s.CreateSSH(ctx, SSHProfileForTest("dup", "[]")); err == nil {
		t.Fatal("duplicate SSH name accepted")
	}
}

func TestSSHDuplicateNameReturnsErrDuplicate(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if _, err := s.CreateSSH(ctx, SSHProfileForTest("dup", "[]")); err != nil {
		t.Fatalf("first CreateSSH: %v", err)
	}
	if _, err := s.CreateSSH(ctx, SSHProfileForTest("dup", "[]")); !errors.Is(err, ErrDuplicate) {
		t.Errorf("duplicate CreateSSH error = %v, want ErrDuplicate", err)
	}
}

func TestSSHValidationReturnsErrValidation(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if _, err := s.CreateSSH(ctx, SSHProfileForTest("bad name!", "[]")); !errors.Is(err, ErrValidation) {
		t.Errorf("invalid name error = %v, want ErrValidation", err)
	}
}

func TestSSHJumpJSONAcceptance(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	for i, ids := range []string{"[]", "[12, 4]", "[1]", "[ 1 , 2 ]"} {
		created, err := s.CreateSSH(ctx, SSHProfileForTest(fmt.Sprintf("jump%d", i), ids))
		if err != nil {
			t.Errorf("CreateSSH with jump ids %q: %v", ids, err)
			continue
		}
		got, err := s.GetSSH(ctx, created.ID)
		if err != nil {
			t.Errorf("GetSSH after create with %q: %v", ids, err)
			continue
		}
		if got.JumpConnectionIDs != ids {
			t.Errorf("jump ids = %q, want %q preserved", got.JumpConnectionIDs, ids)
		}
	}
}

func TestSSHJumpJSONRejection(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	for _, ids := range []string{
		"not json",
		"",
		"[1, 2",       // unterminated
		"[1, \"x\"]",  // non-integer
		"[1.5]",       // float
		"{\"a\":1}",   // object
		"null",        // not an array
		"[true]",      // bool
		"[1, 2]extra", // trailing garbage
	} {
		if _, err := s.CreateSSH(ctx, SSHProfileForTest("bad-"+ids, ids)); err == nil {
			t.Errorf("CreateSSH accepted malformed jump ids %q", ids)
		}
	}
}

func TestSSHUpdate(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	created, err := s.CreateSSH(ctx, SSHProfileForTest("upd", "[]"))
	if err != nil {
		t.Fatalf("CreateSSH: %v", err)
	}

	updated := created
	updated.Host = "new.invalid"
	updated.Port = 2200
	updated.Username = "root"
	updated.Password = []byte("newpass")
	updated.JumpConnectionIDs = "[2, 1]"
	if err := s.UpdateSSH(ctx, updated); err != nil {
		t.Fatalf("UpdateSSH: %v", err)
	}

	got, err := s.GetSSH(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetSSH: %v", err)
	}
	if got.Host != "new.invalid" || got.Port != 2200 || got.Username != "root" {
		t.Errorf("updated metadata mismatch: %+v", got)
	}
	if string(got.Password) != "newpass" {
		t.Errorf("updated password = %q, want newpass", got.Password)
	}
	if got.JumpConnectionIDs != "[2, 1]" {
		t.Errorf("updated jump ids = %q, want [2, 1]", got.JumpConnectionIDs)
	}
}

func TestSSHUpdateKeepsUnsetSecrets(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	created, err := s.CreateSSH(ctx, SSHProfileForTest("keep", "[]"))
	if err != nil {
		t.Fatalf("CreateSSH: %v", err)
	}
	// Update only the host; password fields stay nil meaning "leave unchanged".
	updated := created
	updated.Host = "kept.invalid"
	updated.Password = nil
	updated.PrivateKey = nil
	updated.PrivateKeyPassphrase = nil
	updated.ProxyPassword = nil
	if err := s.UpdateSSH(ctx, updated); err != nil {
		t.Fatalf("UpdateSSH: %v", err)
	}
	got, err := s.GetSSH(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetSSH: %v", err)
	}
	if string(got.Password) != "s3cret" {
		t.Errorf("password = %q, want preserved s3cret", got.Password)
	}
	if string(got.ProxyPassword) != "proxysecret" {
		t.Errorf("proxy password = %q, want preserved", got.ProxyPassword)
	}
}

func TestSSHList(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	for _, name := range []string{"b", "a", "c"} {
		if _, err := s.CreateSSH(ctx, SSHProfileForTest(name, "[]")); err != nil {
			t.Fatalf("CreateSSH %s: %v", name, err)
		}
	}
	all, err := s.ListSSH(ctx)
	if err != nil {
		t.Fatalf("ListSSH: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("ListSSH returned %d rows, want 3", len(all))
	}
}

func TestSSHDeleteAndNotFound(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	created, err := s.CreateSSH(ctx, SSHProfileForTest("gone", "[]"))
	if err != nil {
		t.Fatalf("CreateSSH: %v", err)
	}
	if err := s.DeleteSSH(ctx, created.ID); err != nil {
		t.Fatalf("DeleteSSH: %v", err)
	}
	if _, err := s.GetSSH(ctx, created.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("GetSSH after delete error = %v, want ErrNotFound", err)
	}
	if err := s.DeleteSSH(ctx, created.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("second DeleteSSH error = %v, want ErrNotFound", err)
	}
}

func TestSSHDependentsAndDeletionAllowed(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	target, err := s.CreateSSH(ctx, SSHProfileForTest("target", "[]"))
	if err != nil {
		t.Fatalf("CreateSSH target: %v", err)
	}
	jumper, err := s.CreateSSH(ctx, SSHProfileForTest("jumper", "["+strconv.FormatInt(target.ID, 10)+"]"))
	if err != nil {
		t.Fatalf("CreateSSH jumper: %v", err)
	}
	unrelated, err := s.CreateSSH(ctx, SSHProfileForTest("unrelated", "[]"))
	if err != nil {
		t.Fatalf("CreateSSH unrelated: %v", err)
	}
	dbProf, err := s.CreateDB(ctx, DBProfileForTest("tunneled", target.ID))
	if err != nil {
		t.Fatalf("CreateDB: %v", err)
	}
	directDB, err := s.CreateDB(ctx, DBProfileForTest("direct", 0))
	if err != nil {
		t.Fatalf("CreateDB direct: %v", err)
	}

	deps, err := s.SSHDependents(ctx, target.ID)
	if err != nil {
		t.Fatalf("SSHDependents: %v", err)
	}
	if len(deps.SSH) != 1 || deps.SSH[0].ID != jumper.ID {
		t.Errorf("deps.SSH = %+v, want jumper %d", deps.SSH, jumper.ID)
	}
	if len(deps.DB) != 1 || deps.DB[0].ID != dbProf.ID {
		t.Errorf("deps.DB = %+v, want tunneled DB %d", deps.DB, dbProf.ID)
	}
	if unrelated.ID == target.ID {
		t.Fatal("test invariant broken")
	}

	// Deletion is allowed with dependents; stored JSON is not rewritten.
	if err := s.DeleteSSH(ctx, target.ID); err != nil {
		t.Fatalf("DeleteSSH with dependents failed: %v", err)
	}
	jumperGot, err := s.GetSSH(ctx, jumper.ID)
	if err != nil {
		t.Fatalf("GetSSH jumper after deletion: %v", err)
	}
	if jumperGot.JumpConnectionIDs != "["+strconv.FormatInt(target.ID, 10)+"]" {
		t.Errorf("jumper jump ids rewritten to %q after target deletion", jumperGot.JumpConnectionIDs)
	}
	dbGot, err := s.GetDB(ctx, dbProf.ID)
	if err != nil {
		t.Fatalf("GetDB tunneled after deletion: %v", err)
	}
	if dbGot.SSHConnectionID != target.ID {
		t.Errorf("DB ssh_connection_id = %d, want preserved %d", dbGot.SSHConnectionID, target.ID)
	}
	directGot, err := s.GetDB(ctx, directDB.ID)
	if err != nil {
		t.Fatalf("GetDB direct: %v", err)
	}
	if directGot.SSHConnectionID != 0 {
		t.Errorf("direct DB ssh_connection_id = %d, want 0", directGot.SSHConnectionID)
	}
}

func TestDBCreateGetUpdateListDelete(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	created, err := s.CreateDB(ctx, DBProfileForTest("app-prod", 0))
	if err != nil {
		t.Fatalf("CreateDB: %v", err)
	}
	if created.ID == 0 || created.CreatedAt.IsZero() || created.UpdatedAt.IsZero() {
		t.Fatalf("CreateDB returned incomplete row: %+v", created)
	}

	got, err := s.GetDB(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetDB: %v", err)
	}
	if string(got.Password) != "dbsecret" || got.Database != "appdb" {
		t.Errorf("GetDB round trip mismatch: %+v", got)
	}

	var stored []byte
	if err := s.db.QueryRowContext(ctx, "SELECT password FROM db_connections WHERE id=?", created.ID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if string(stored) == "dbsecret" {
		t.Fatal("db password stored as plaintext")
	}

	updated := got
	updated.Host = "db2.invalid"
	updated.Password = []byte("changed")
	updated.SSHConnectionID = 7
	if err := s.UpdateDB(ctx, updated); err != nil {
		t.Fatalf("UpdateDB: %v", err)
	}
	got2, err := s.GetDB(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetDB after update: %v", err)
	}
	if got2.Host != "db2.invalid" || string(got2.Password) != "changed" || got2.SSHConnectionID != 7 {
		t.Errorf("updated DB mismatch: %+v", got2)
	}

	if _, err := s.CreateDB(ctx, DBProfileForTest("other", 0)); err != nil {
		t.Fatalf("CreateDB other: %v", err)
	}
	all, err := s.ListDB(ctx)
	if err != nil {
		t.Fatalf("ListDB: %v", err)
	}
	if len(all) != 2 {
		t.Errorf("ListDB returned %d rows, want 2", len(all))
	}

	if err := s.DeleteDB(ctx, created.ID); err != nil {
		t.Fatalf("DeleteDB: %v", err)
	}
	if _, err := s.GetDB(ctx, created.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("GetDB after delete error = %v, want ErrNotFound", err)
	}
}

func TestDBDuplicateNameRejected(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if _, err := s.CreateDB(ctx, DBProfileForTest("dup", 0)); err != nil {
		t.Fatalf("first CreateDB: %v", err)
	}
	if _, err := s.CreateDB(ctx, DBProfileForTest("dup", 0)); err == nil {
		t.Fatal("duplicate DB name accepted")
	}
}
