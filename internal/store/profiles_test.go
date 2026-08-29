package store

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"warden/internal/model"
)

// SSHProfileForTest builds a valid SSH profile. Secrets are plaintext in the
// model; the store encrypts them at rest.
func SSHProfileForTest(name string, jumpIDs string) model.SSHProfile {
	return model.SSHProfile{
		Name:              name,
		Host:              "example.invalid",
		Port:              22,
		Username:          "deploy",
		Password:          []byte("s3cret"),
		ProxyHost:         "proxy.invalid",
		ProxyPort:         3128,
		ProxyUsername:     "proxyuser",
		ProxyPassword:     []byte("proxysecret"),
		JumpConnectionIDs: jumpIDs,
	}
}

// DBProfileForTest builds a valid DB profile.
func DBProfileForTest(name string, sshConnectionID int64) model.DBProfile {
	return model.DBProfile{
		Name:     name,
		Host:     "db.invalid",
		Port:     3306,
		Username: "app",
		Password: []byte("dbsecret"),
		Databases: []model.DatabaseInfo{
			{Name: "appdb", IsDefault: true},
		},
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
	// Update only the host; secret fields stay nil meaning "leave unchanged".
	updated := created
	updated.Host = "kept.invalid"
	updated.Password = nil
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

func TestSSHCreateWithKeyPairRoundTrip(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	pair, err := s.CreateKeyPair(ctx, KeyPairForTest("roundtrip-pair"))
	if err != nil {
		t.Fatalf("CreateKeyPair: %v", err)
	}
	p := SSHProfileForTest("pair-user", "[]")
	p.Password = nil
	p.KeyPairID = pair.ID
	created, err := s.CreateSSH(ctx, p)
	if err != nil {
		t.Fatalf("CreateSSH: %v", err)
	}

	got, err := s.GetSSH(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetSSH: %v", err)
	}
	if got.KeyPairID != pair.ID || got.KeyPairName != "roundtrip-pair" {
		t.Errorf("key pair = %d/%q, want %d/roundtrip-pair", got.KeyPairID, got.KeyPairName, pair.ID)
	}
	if got.Password != nil {
		t.Errorf("password = %q, want nil", got.Password)
	}
}

func TestSSHCreateRejectsPasswordAndKeyPair(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	pair, err := s.CreateKeyPair(ctx, KeyPairForTest("both"))
	if err != nil {
		t.Fatalf("CreateKeyPair: %v", err)
	}
	p := SSHProfileForTest("both-auth", "[]")
	p.KeyPairID = pair.ID
	if _, err := s.CreateSSH(ctx, p); !errors.Is(err, ErrValidation) {
		t.Errorf("CreateSSH with password and key_pair_id error = %v, want ErrValidation", err)
	}
}

func TestSSHUpdateKeyPairClearsPassword(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	pair, err := s.CreateKeyPair(ctx, KeyPairForTest("pair"))
	if err != nil {
		t.Fatalf("CreateKeyPair: %v", err)
	}
	created, err := s.CreateSSH(ctx, SSHProfileForTest("switch-pair", "[]"))
	if err != nil {
		t.Fatalf("CreateSSH: %v", err)
	}

	updated := created
	updated.Password = nil
	updated.KeyPairID = pair.ID
	if err := s.UpdateSSH(ctx, updated); err != nil {
		t.Fatalf("UpdateSSH: %v", err)
	}

	got, err := s.GetSSH(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetSSH: %v", err)
	}
	if got.KeyPairID != pair.ID || got.KeyPairName != "pair" {
		t.Errorf("key pair = %d/%q, want %d/pair", got.KeyPairID, got.KeyPairName, pair.ID)
	}
	if got.Password != nil {
		t.Errorf("password = %q, want cleared nil", got.Password)
	}
}

func TestSSHUpdatePasswordClearsKeyPair(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	pair, err := s.CreateKeyPair(ctx, KeyPairForTest("pair"))
	if err != nil {
		t.Fatalf("CreateKeyPair: %v", err)
	}
	created, err := s.CreateSSH(ctx, SSHProfileForTest("switch-pw", "[]"))
	if err != nil {
		t.Fatalf("CreateSSH: %v", err)
	}

	// Select the pair first.
	updated := created
	updated.Password = nil
	updated.KeyPairID = pair.ID
	if err := s.UpdateSSH(ctx, updated); err != nil {
		t.Fatalf("UpdateSSH select pair: %v", err)
	}

	// Switch back to a password; the stored pair reference must be cleared.
	updated = created
	updated.Password = []byte("newpass")
	updated.KeyPairID = 0
	if err := s.UpdateSSH(ctx, updated); err != nil {
		t.Fatalf("UpdateSSH set password: %v", err)
	}

	got, err := s.GetSSH(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetSSH: %v", err)
	}
	if got.KeyPairID != 0 {
		t.Errorf("key_pair_id = %d, want cleared 0", got.KeyPairID)
	}
	if string(got.Password) != "newpass" {
		t.Errorf("password = %q, want newpass", got.Password)
	}
}

func TestSSHUpdateExplicitZeroClearsKeyPair(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	pair, err := s.CreateKeyPair(ctx, KeyPairForTest("pair"))
	if err != nil {
		t.Fatalf("CreateKeyPair: %v", err)
	}
	created, err := s.CreateSSH(ctx, SSHProfileForTest("clear-pair", "[]"))
	if err != nil {
		t.Fatalf("CreateSSH: %v", err)
	}

	// Select the pair first.
	updated := created
	updated.Password = nil
	updated.KeyPairID = pair.ID
	if err := s.UpdateSSH(ctx, updated); err != nil {
		t.Fatalf("UpdateSSH select pair: %v", err)
	}

	// Explicitly clear the selection with a blank password: the pair must
	// be deselected while the (nil) password is retained.
	updated = created
	updated.Password = nil
	updated.KeyPairID = 0
	updated.KeyPairIDSet = true
	if err := s.UpdateSSH(ctx, updated); err != nil {
		t.Fatalf("UpdateSSH clear pair: %v", err)
	}

	got, err := s.GetSSH(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetSSH: %v", err)
	}
	if got.KeyPairID != 0 {
		t.Errorf("key_pair_id = %d, want cleared 0", got.KeyPairID)
	}
	if got.Password != nil {
		t.Errorf("password = %q, want retained nil", got.Password)
	}
}

func TestSSHUpdateOmittedKeyPairRetainsSelection(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	pair, err := s.CreateKeyPair(ctx, KeyPairForTest("pair"))
	if err != nil {
		t.Fatalf("CreateKeyPair: %v", err)
	}
	created, err := s.CreateSSH(ctx, SSHProfileForTest("keep-pair", "[]"))
	if err != nil {
		t.Fatalf("CreateSSH: %v", err)
	}

	// Select the pair first.
	updated := created
	updated.Password = nil
	updated.KeyPairID = pair.ID
	if err := s.UpdateSSH(ctx, updated); err != nil {
		t.Fatalf("UpdateSSH select pair: %v", err)
	}

	// Update metadata with key_pair_id omitted (KeyPairIDSet false) and a
	// nil password: the stored selection must be preserved.
	updated = created
	updated.Host = "kept.invalid"
	updated.Password = nil
	updated.KeyPairID = 0
	if err := s.UpdateSSH(ctx, updated); err != nil {
		t.Fatalf("UpdateSSH omit pair: %v", err)
	}

	got, err := s.GetSSH(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetSSH: %v", err)
	}
	if got.KeyPairID != pair.ID {
		t.Errorf("key_pair_id = %d, want retained %d", got.KeyPairID, pair.ID)
	}
	if got.Password != nil {
		t.Errorf("password = %q, want retained nil", got.Password)
	}
}

func TestSSHRejectsMissingOrPublicOnlyKeyPair(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	publicOnly, err := s.CreateKeyPair(ctx, model.KeyPair{Name: "public-only", PublicKey: []byte("pub")})
	if err != nil {
		t.Fatalf("CreateKeyPair public-only: %v", err)
	}
	for _, tc := range []struct {
		name   string
		pairID int64
	}{
		{"missing", 999999},
		{"public-only", publicOnly.ID},
	} {
		p := SSHProfileForTest("kp-"+tc.name, "[]")
		p.Password = nil
		p.KeyPairID = tc.pairID
		if _, err := s.CreateSSH(ctx, p); !errors.Is(err, ErrValidation) {
			t.Errorf("CreateSSH(key_pair_id=%d) error = %v, want ErrValidation", tc.pairID, err)
		}
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

func TestDecodeDatabasesReadsLegacyJSONScalars(t *testing.T) {
	for _, raw := range []string{"123", "true", "null"} {
		databases, err := decodeDatabases(raw)
		if err != nil {
			t.Fatalf("decodeDatabases(%q): %v", raw, err)
		}
		want := []model.DatabaseInfo{{Name: raw, IsDefault: true}}
		if !reflect.DeepEqual(databases, want) {
			t.Errorf("decodeDatabases(%q) = %#v, want %#v", raw, databases, want)
		}
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
	if string(got.Password) != "dbsecret" || !reflect.DeepEqual(got.Databases, []model.DatabaseInfo{{Name: "appdb", IsDefault: true}}) {
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
	updated.Databases = []model.DatabaseInfo{
		{Name: "appdb", IsDefault: false}, {Name: "analytics", IsDefault: true},
	}
	updated.SSHConnectionID = 7
	if err := s.UpdateDB(ctx, updated); err != nil {
		t.Fatalf("UpdateDB: %v", err)
	}
	got2, err := s.GetDB(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetDB after update: %v", err)
	}
	wantDatabases := []model.DatabaseInfo{
		{Name: "appdb", IsDefault: false}, {Name: "analytics", IsDefault: true},
	}
	if got2.Host != "db2.invalid" || string(got2.Password) != "changed" || got2.SSHConnectionID != 7 || !reflect.DeepEqual(got2.Databases, wantDatabases) {
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

func TestSSHDefaultDirRoundTrip(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	p := SSHProfileForTest("dir-host", "[]")
	p.DefaultDir = "/srv/app"
	created, err := s.CreateSSH(ctx, p)
	if err != nil {
		t.Fatalf("CreateSSH: %v", err)
	}
	got, err := s.GetSSH(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetSSH: %v", err)
	}
	if got.DefaultDir != "/srv/app" {
		t.Errorf("GetSSH default_dir = %q, want %q", got.DefaultDir, "/srv/app")
	}

	got.DefaultDir = "/srv/other"
	if err := s.UpdateSSH(ctx, got); err != nil {
		t.Fatalf("UpdateSSH: %v", err)
	}
	got2, err := s.GetSSH(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetSSH after update: %v", err)
	}
	if got2.DefaultDir != "/srv/other" {
		t.Errorf("GetSSH default_dir after update = %q, want %q", got2.DefaultDir, "/srv/other")
	}
}

func TestSSHDefaultDirValidation(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	for _, bad := range []string{
		"relative/path",
		"/path/with/../escape",
		"/path/\x00null",
		"/path/\nnewline",
		strings.Repeat("a", 5000),
	} {
		p := SSHProfileForTest("bad-"+bad, "[]")
		p.DefaultDir = bad
		if _, err := s.CreateSSH(ctx, p); err == nil {
			t.Errorf("CreateSSH with default_dir=%q succeeded; want validation error", bad)
		}
	}
}

func TestSSHEmptyDefaultDirAllowed(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	p := SSHProfileForTest("no-dir", "[]")
	p.DefaultDir = ""
	if _, err := s.CreateSSH(ctx, p); err != nil {
		t.Fatalf("CreateSSH with empty default_dir: %v", err)
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

func TestSSHGroupRoundTripAndClear(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	group, err := s.CreateGroup(ctx, model.Group{Name: "prod"})
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	input := SSHProfileForTest("web", "[]")
	input.GroupID = group.ID
	created, err := s.CreateSSH(ctx, input)
	if err != nil {
		t.Fatalf("CreateSSH: %v", err)
	}
	got, err := s.GetSSH(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetSSH: %v", err)
	}
	if got.GroupID != group.ID || got.GroupName != "prod" {
		t.Fatalf("group = %d/%q, want %d/%q", got.GroupID, got.GroupName, group.ID, "prod")
	}
	got.GroupID = 0
	if err := s.UpdateSSH(ctx, got); err != nil {
		t.Fatalf("UpdateSSH: %v", err)
	}
	got, err = s.GetSSH(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetSSH after clear: %v", err)
	}
	if got.GroupID != 0 || got.GroupName != "" {
		t.Fatalf("group = %d/%q, want 0/\"\"", got.GroupID, got.GroupName)
	}
}

func TestDBGroupRoundTripAndClear(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	group, err := s.CreateGroup(ctx, model.Group{Name: "prod"})
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	input := DBProfileForTest("appdb", 0)
	input.GroupID = group.ID
	created, err := s.CreateDB(ctx, input)
	if err != nil {
		t.Fatalf("CreateDB: %v", err)
	}
	got, err := s.GetDB(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetDB: %v", err)
	}
	if got.GroupID != group.ID || got.GroupName != "prod" {
		t.Fatalf("group = %d/%q, want %d/%q", got.GroupID, got.GroupName, group.ID, "prod")
	}
	got.GroupID = 0
	if err := s.UpdateDB(ctx, got); err != nil {
		t.Fatalf("UpdateDB: %v", err)
	}
	got, err = s.GetDB(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetDB after clear: %v", err)
	}
	if got.GroupID != 0 || got.GroupName != "" {
		t.Fatalf("group = %d/%q, want 0/\"\"", got.GroupID, got.GroupName)
	}
}

func TestSSHGroupAssignmentValidation(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	for _, tc := range []struct {
		name    string
		groupID int64
	}{
		{"negative", -1},
		{"nonexistent", 999999},
	} {
		p := SSHProfileForTest("gv-"+tc.name, "[]")
		p.GroupID = tc.groupID
		if _, err := s.CreateSSH(ctx, p); !errors.Is(err, ErrValidation) {
			t.Errorf("CreateSSH(group_id=%d) error = %v, want ErrValidation", tc.groupID, err)
		}
	}
}

func TestDBGroupAssignmentValidation(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	for _, tc := range []struct {
		name    string
		groupID int64
	}{
		{"negative", -1},
		{"nonexistent", 999999},
	} {
		p := DBProfileForTest("gv-"+tc.name, 0)
		p.GroupID = tc.groupID
		if _, err := s.CreateDB(ctx, p); !errors.Is(err, ErrValidation) {
			t.Errorf("CreateDB(group_id=%d) error = %v, want ErrValidation", tc.groupID, err)
		}
	}
}

func TestSSHGroupOrphanedReferenceTolerated(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	created, err := s.CreateSSH(ctx, SSHProfileForTest("orphan", "[]"))
	if err != nil {
		t.Fatalf("CreateSSH: %v", err)
	}
	if _, err := s.db.ExecContext(ctx,
		"UPDATE ssh_connections SET group_id=999999 WHERE id=?", created.ID); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetSSH(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetSSH with orphaned group: %v", err)
	}
	if got.GroupID != 999999 || got.GroupName != "" {
		t.Errorf("group = %d/%q, want 999999/\"\"", got.GroupID, got.GroupName)
	}
}

func TestDBGroupOrphanedReferenceTolerated(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	created, err := s.CreateDB(ctx, DBProfileForTest("orphan-db", 0))
	if err != nil {
		t.Fatalf("CreateDB: %v", err)
	}
	if _, err := s.db.ExecContext(ctx,
		"UPDATE db_connections SET group_id=999999 WHERE id=?", created.ID); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetDB(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetDB with orphaned group: %v", err)
	}
	if got.GroupID != 999999 || got.GroupName != "" {
		t.Errorf("group = %d/%q, want 999999/\"\"", got.GroupID, got.GroupName)
	}
}

func TestCreateDBStoresCanonicalDatabaseList(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	p, err := s.CreateDB(ctx, model.DBProfile{
		Name: "multi", Host: "db.invalid", Port: 3306, Username: "app",
		Databases: []model.DatabaseInfo{
			{Name: "app", IsDefault: true}, {Name: "audit"},
		},
	})
	if err != nil {
		t.Fatalf("CreateDB: %v", err)
	}
	var raw string
	if err := s.db.QueryRowContext(ctx, "SELECT database FROM db_connections WHERE id=?", p.ID).Scan(&raw); err != nil {
		t.Fatalf("read stored databases: %v", err)
	}
	if raw != `[{"name":"app","is_default":true},{"name":"audit","is_default":false}]` {
		t.Fatalf("stored database = %q", raw)
	}
}

func TestGetDBReadsLegacyScalarAsDefault(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	ts := nowUTC()
	result, err := s.db.ExecContext(ctx, `
		INSERT INTO db_connections
			(name, host, port, username, database, ssh_connection_id, group_id, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"legacy", "db.invalid", 3306, "app", "legacy", 0, 0, ts, ts)
	if err != nil {
		t.Fatalf("insert legacy DB: %v", err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("legacy DB id: %v", err)
	}

	got, err := s.GetDB(ctx, id)
	if err != nil {
		t.Fatalf("GetDB: %v", err)
	}
	want := []model.DatabaseInfo{{Name: "legacy", IsDefault: true}}
	if !reflect.DeepEqual(got.Databases, want) {
		t.Errorf("Databases = %+v, want %+v", got.Databases, want)
	}
}

func TestGetDBRejectsMalformedDatabaseJSON(t *testing.T) {
	for i, raw := range []string{`[{"name":"legacy"}`, `{"name":"legacy"}`, "legacy\n"} {
		t.Run(fmt.Sprintf("malformed-%d", i), func(t *testing.T) {
			s := newTestStore(t)
			ctx := context.Background()
			ts := nowUTC()
			result, err := s.db.ExecContext(ctx, `
				INSERT INTO db_connections
					(name, host, port, username, database, ssh_connection_id, group_id, created_at, updated_at)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				fmt.Sprintf("malformed-%d", i), "db.invalid", 3306, "app", raw, 0, 0, ts, ts)
			if err != nil {
				t.Fatalf("insert malformed DB: %v", err)
			}
			id, err := result.LastInsertId()
			if err != nil {
				t.Fatalf("malformed DB id: %v", err)
			}
			if _, err := s.GetDB(ctx, id); err == nil {
				t.Fatalf("GetDB accepted malformed database JSON %q", raw)
			}
		})
	}
}

func TestCreateDBRejectsInvalidDatabaseList(t *testing.T) {
	cases := []struct {
		name      string
		databases []model.DatabaseInfo
	}{
		{"empty", nil},
		{"no-default", []model.DatabaseInfo{{Name: "app"}}},
		{"two-defaults", []model.DatabaseInfo{{Name: "app", IsDefault: true}, {Name: "audit", IsDefault: true}}},
		{"duplicate", []model.DatabaseInfo{{Name: "app", IsDefault: true}, {Name: "app"}}},
		{"slash", []model.DatabaseInfo{{Name: "app/db", IsDefault: true}}},
		{"control", []model.DatabaseInfo{{Name: "app\n", IsDefault: true}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestStore(t)
			_, err := s.CreateDB(context.Background(), model.DBProfile{
				Name: tc.name, Host: "db.invalid", Port: 3306, Username: "app", Databases: tc.databases,
			})
			if !errors.Is(err, ErrValidation) {
				t.Fatalf("CreateDB error = %v, want ErrValidation", err)
			}
		})
	}
}
