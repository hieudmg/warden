package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"warden/internal/crypto"
	"warden/internal/model"
)

func historicalBundle(t *testing.T) model.DataBundle {
	t.Helper()
	raw, err := os.ReadFile("testdata/warden-data-v1-c104353.json")
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprintf("%x", sha256.Sum256(raw)) != "732de3caaac4993b39baffcec6ea7c3328b3c620d91837e763ab9eefc8933337" {
		t.Fatal("historical fixture checksum changed; reverify with actual c104353 exporter")
	}
	var b model.DataBundle
	if err = json.Unmarshal(raw, &b); err != nil {
		t.Fatal(err)
	}
	return b
}

func initializedTransferStore(t *testing.T) *Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fresh.db")
	identity := []byte(`{"format":1,"owner":"destination-only","wrappers":"not transferred","authorization_generation":9}`)
	if err := CommitInstallation(context.Background(), path, identity); err != nil {
		t.Fatal(err)
	}
	v := crypto.NewVault()
	s, err := OpenInitialized(context.Background(), path, func(raw []byte) error {
		if !bytes.Equal(raw, identity) {
			return errors.New("identity changed")
		}
		return nil
	}, v)
	if err != nil {
		t.Fatal(err)
	}
	if err = v.Unlock(transferDestKey[:], v.Generation()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { v.Lock(); s.Close() })
	if err = s.SaveSession(context.Background(), Session{Hash: "session-hash", CSRFHash: "csrf-hash", CredentialID: "destination-passkey", Created: 1, Seen: 2}); err != nil {
		t.Fatal(err)
	}
	if err = s.ApproveClient(context.Background(), identity, ClientCredential{ID: "destination-client", Verifier: "destination-verifier", Label: "synthetic", Generation: 9, Created: 3}); err != nil {
		t.Fatal(err)
	}
	if err = s.AppendAudit(context.Background(), model.AuditEvent{Operation: "synthetic.before", ResourceType: "test", Source: "test", Result: "success"}); err != nil {
		t.Fatal(err)
	}
	return s
}

// Preserve exact auth rows (including complete wrapper/owner/generation blob),
// not just row counts. Import itself may not touch audit/session/client state.
func transferAuthSnapshot(t *testing.T, s *Store) []byte {
	t.Helper()
	var state []any
	for _, table := range []string{"installation", "web_sessions", "client_credentials", "audit_events"} {
		rows, err := s.db.Query("SELECT * FROM " + table + " ORDER BY 1")
		if err != nil {
			t.Fatal(err)
		}
		cols, err := rows.Columns()
		if err != nil {
			t.Fatal(err)
		}
		var records [][]any
		for rows.Next() {
			values := make([]any, len(cols))
			dest := make([]any, len(cols))
			for i := range values {
				dest[i] = &values[i]
			}
			if err = rows.Scan(dest...); err != nil {
				t.Fatal(err)
			}
			records = append(records, values)
		}
		if err = rows.Err(); err != nil {
			t.Fatal(err)
		}
		rows.Close()
		state = append(state, records)
	}
	raw, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func assertHistoricalManagedData(t *testing.T, s *Store, want model.DataBundle) {
	t.Helper()
	got, err := s.ExportData(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got.ExportedAt = want.ExportedAt
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("managed data differs from historical producer\ngot %#v\nwant %#v", got, want)
	}
	counts := []int{2, 2, 3, 2, 2, 2, 7}
	for i, table := range managedTransferTables {
		var n int
		if err = s.db.QueryRow("SELECT count(*) FROM " + table).Scan(&n); err != nil || n != counts[i] {
			t.Fatalf("%s count=%d want=%d err=%v", table, n, counts[i], err)
		}
	}
}

// Passing-existing characterization, not a new TDD RED/GREEN claim. The frozen
// input was emitted by c104353's real ExportData + JSON serializer, not today's
// ImportData or a manually constructed DataBundle (see testdata/README.md).
func TestVersion1ExportFixtureIntoInitializedEmptyVault(t *testing.T) {
	s := initializedTransferStore(t)
	before := transferAuthSnapshot(t, s)
	b := historicalBundle(t)
	if err := s.ImportData(context.Background(), b); err != nil {
		t.Fatal(err)
	}
	assertHistoricalManagedData(t, s, b)
	if !bytes.Equal(before, transferAuthSnapshot(t, s)) {
		t.Fatal("import changed destination identity/auth/audit")
	}
	// Check actual destination getters as well as full plaintext re-export.
	ssh, err := s.GetSSH(context.Background(), 31)
	if err != nil || string(ssh.Password) != b.SSHConnections[0].Password || string(ssh.ProxyPassword) != b.SSHConnections[0].ProxyPassword {
		t.Fatal("SSH secrets", err)
	}
	kp, err := s.GetKeyPair(context.Background(), 23)
	if err != nil || string(kp.PrivateKey) != b.KeyPairs[0].PrivateKey {
		t.Fatal("key pair secret", err)
	}
	db, err := s.GetDB(context.Background(), 43)
	if err != nil || string(db.Password) != b.DBConnections[0].Password || !reflect.DeepEqual(db.Databases, b.DBConnections[0].Databases) {
		t.Fatal("DB secret/settings", err)
	}
	if err = s.ImportData(context.Background(), b); !errors.Is(err, ErrDestinationNotEmpty) {
		t.Fatal("nonempty refusal", err)
	}
	assertHistoricalManagedData(t, s, b)
	if !bytes.Equal(before, transferAuthSnapshot(t, s)) {
		t.Fatal("rejected import changed auth")
	}
}

func TestVersion1ImportedSecretsUseDestinationKeyAndExactAAD(t *testing.T) {
	s := initializedTransferStore(t)
	b := historicalBundle(t)
	if err := s.ImportData(context.Background(), b); err != nil {
		t.Fatal(err)
	}
	var source []struct {
		Table      string
		ID         int64
		Field, AAD string
		Ciphertext []byte
	}
	raw, err := os.ReadFile("testdata/ciphertexts-c104353.json")
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprintf("%x", sha256.Sum256(raw)) != "1d0376d350660cee5b8dfdd14164dad65e682a875ceea1b2d8aa719d2b2d7cf9" {
		t.Fatal("historical ciphertext artifact checksum changed")
	}
	if err = json.Unmarshal(raw, &source); err != nil {
		t.Fatal(err)
	}
	oldCodec := crypto.Codec{Key: transferSourceKey}
	destCodec := crypto.Codec{Key: transferDestKey}
	for _, x := range source {
		t.Run(fmt.Sprintf("%s/%d/%s", x.Table, x.ID, x.Field), func(t *testing.T) {
			oldPlain, e := oldCodec.Decrypt(x.Ciphertext, []byte(x.AAD))
			if e != nil {
				t.Fatal("old fixture AAD/key", e)
			}
			var stored []byte
			if e = s.db.QueryRow("SELECT "+x.Field+" FROM "+x.Table+" WHERE id=?", x.ID).Scan(&stored); e != nil {
				t.Fatal(e)
			}
			if bytes.Equal(stored, x.Ciphertext) || bytes.Contains(stored, oldPlain) {
				t.Fatal("copied ciphertext/plaintext")
			}
			plain, e := destCodec.Decrypt(stored, []byte(x.AAD))
			if e != nil || !bytes.Equal(plain, oldPlain) {
				t.Fatal("destination secret/AAD", e)
			}
			tampered := append([]byte(nil), stored...)
			tampered[len(tampered)-1] ^= 1
			for name, neg := range map[string]struct {
				codec           crypto.Codec
				ciphertext, aad []byte
			}{
				"source DEK":     {oldCodec, stored, []byte(x.AAD)},
				"wrong row":      {destCodec, stored, []byte(strings.Replace(x.AAD, fmt.Sprintf("/%d/", x.ID), "/9876/", 1))},
				"wrong field":    {destCodec, stored, []byte(x.AAD + "-other")},
				"wrong resource": {destCodec, stored, []byte(strings.Replace(x.AAD, "warden/", "warden/other/", 1))},
				"tamper":         {destCodec, tampered, []byte(x.AAD)},
			} {
				if p, e := neg.codec.Decrypt(neg.ciphertext, neg.aad); e == nil || len(p) != 0 {
					t.Fatalf("%s accepted or leaked plaintext", name)
				}
			}
		})
	}
}

type transferFaultCodec struct {
	fieldCodec
	onEncrypt func() error
}

func (c transferFaultCodec) Encrypt(p, aad []byte) ([]byte, error) {
	if err := c.onEncrypt(); err != nil {
		return nil, err
	}
	return c.fieldCodec.Encrypt(p, aad)
}

// All injections are disposable fixture state, never production hooks. Deferred
// foreign keys make inserts succeed and COMMIT fail on modernc SQLite v1.57.0.
func TestImportFailurePreservesIdentityAndManagedData(t *testing.T) {
	for _, fault := range []string{"encryption", "SQL", "commit", "cancellation", "hard report reference"} {
		t.Run(fault, func(t *testing.T) {
			s := initializedTransferStore(t)
			before := transferAuthSnapshot(t, s)
			b := historicalBundle(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			codec := s.codec
			cleanup := func() {}
			switch fault {
			case "encryption", "cancellation":
				n := 0
				s.codec = transferFaultCodec{codec, func() error {
					n++
					if n == 2 {
						if fault == "encryption" {
							return errors.New("synthetic encryption failure")
						}
						cancel()
					}
					return nil
				}}
			case "SQL":
				if _, err := s.db.Exec(`CREATE TRIGGER fail_transfer BEFORE INSERT ON reports BEGIN SELECT RAISE(ABORT,'synthetic SQL failure'); END`); err != nil {
					t.Fatal(err)
				}
				cleanup = func() {
					if _, err := s.db.Exec(`DROP TRIGGER fail_transfer`); err != nil {
						t.Fatal(err)
					}
				}
			case "commit":
				if _, err := s.db.Exec(`CREATE TABLE transfer_parent(id INTEGER PRIMARY KEY);
CREATE TABLE transfer_child(id INTEGER REFERENCES transfer_parent(id) DEFERRABLE INITIALLY DEFERRED);
CREATE TRIGGER fail_transfer AFTER INSERT ON connection_notes BEGIN INSERT INTO transfer_child VALUES (123); END;`); err != nil {
					t.Fatal(err)
				}
				cleanup = func() {
					if _, err := s.db.Exec(`DROP TRIGGER fail_transfer; DROP TABLE transfer_child; DROP TABLE transfer_parent`); err != nil {
						t.Fatal(err)
					}
				}
			case "hard report reference":
				b.Reports[0].ProjectID = 999
			}
			err := s.ImportData(ctx, b)
			if err == nil {
				t.Fatal("faulted import succeeded")
			}
			if fault == "commit" && !strings.Contains(err.Error(), "commit import:") {
				t.Fatal("did not reach commit", err)
			}
			if countManagedRecords(t, s) != 0 || !bytes.Equal(before, transferAuthSnapshot(t, s)) {
				t.Fatal("failure changed data/auth")
			}
			s.codec = codec
			cleanup()
			if err = s.ImportData(context.Background(), historicalBundle(t)); err != nil {
				t.Fatal("retry failed", err)
			}
			assertHistoricalManagedData(t, s, historicalBundle(t))
			if !bytes.Equal(before, transferAuthSnapshot(t, s)) {
				t.Fatal("retry changed auth")
			}
		})
	}
}

func TestConcurrentInitializedImportsSingleWinner(t *testing.T) {
	s := initializedTransferStore(t)
	before := transferAuthSnapshot(t, s)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	codec := s.codec
	s.codec = transferFaultCodec{codec, func() error { once.Do(func() { close(entered); <-release }); return nil }}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	bundle := historicalBundle(t)
	first := make(chan error, 1)
	go func() { first <- s.ImportData(ctx, bundle) }()
	select {
	case <-entered: // First import inserted groups and owns the SQLite writer lock.
	case err := <-first:
		t.Fatal("first import did not reach encryption barrier", err)
	case <-ctx.Done():
		close(release)
		<-first
		t.Fatal("first import did not reach encryption barrier", ctx.Err())
	}
	second := historicalBundle(t)
	second.Groups[0].Name = "losing-import"
	// A separate connection sees no committed rows, but cannot upgrade its read
	// snapshot to a competing writer. No sleeps or scheduler-dependent winner.
	err := s.ImportData(ctx, second)
	close(release)
	if err == nil {
		t.Error("competing import succeeded")
	}
	if err = <-first; err != nil {
		t.Fatal("reserved winner failed", err)
	}
	s.codec = codec
	assertHistoricalManagedData(t, s, historicalBundle(t))
	if !bytes.Equal(before, transferAuthSnapshot(t, s)) {
		t.Fatal("concurrent import changed auth")
	}
}
