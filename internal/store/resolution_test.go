package store

import (
	"context"
	"database/sql"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"warden/internal/model"
)

type resolutionSpyCodec struct {
	fieldCodec
	decrypts     []string
	afterDecrypt func(string)
}

func (c *resolutionSpyCodec) Decrypt(p, aad []byte) ([]byte, error) {
	c.decrypts = append(c.decrypts, string(aad))
	plain, err := c.fieldCodec.Decrypt(p, aad)
	if c.afterDecrypt != nil {
		c.afterDecrypt(string(aad))
	}
	return plain, err
}

func TestResolutionSnapshotMetadataAndSecrets(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	ssh, err := s.CreateSSH(ctx, SSHProfileForTest("ssh", "[]"))
	if err != nil {
		t.Fatal(err)
	}
	db, err := s.CreateDB(ctx, DBProfileForTest("db", ssh.ID))
	if err != nil {
		t.Fatal(err)
	}
	pair, err := s.CreateKeyPair(ctx, model.KeyPair{Name: "pair", PrivateKey: []byte("key"), PrivateKeyPassphrase: []byte("phrase")})
	if err != nil {
		t.Fatal(err)
	}
	spy := &resolutionSpyCodec{fieldCodec: s.codec}
	s.codec = spy
	snap, err := s.BeginResolution(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer snap.Close()
	sm, err := snap.GetSSHMetadata(ctx, ssh.ID)
	if err != nil {
		t.Fatal(err)
	}
	dm, err := snap.GetDBMetadata(ctx, db.ID)
	if err != nil {
		t.Fatal(err)
	}
	has, err := snap.HasPrivateKey(ctx, pair.ID)
	if err != nil || !has {
		t.Fatalf("key presence=%v %v", has, err)
	}
	if len(spy.decrypts) != 0 || sm.Password != nil || sm.ProxyPassword != nil || dm.Password != nil {
		t.Fatalf("metadata decrypted: %v", spy.decrypts)
	}
	// WAL writers commit while the reader retains its first-read snapshot. The
	// subsequent secret reads must use those same rows, not live store getters.
	if err = s.SetSSHArchived(ctx, ssh.ID, true); err != nil {
		t.Fatal(err)
	}
	ssh.JumpConnectionIDs = "[999999]"
	ssh.Password = []byte("changed")
	if err = s.UpdateSSH(ctx, ssh); err != nil {
		t.Fatal(err)
	}
	db.SSHConnectionID = 999999
	db.Password = []byte("changed")
	if err = s.UpdateDB(ctx, db); err != nil {
		t.Fatal(err)
	}
	if err = s.DeleteKeyPair(ctx, pair.ID); err != nil {
		t.Fatal(err)
	}
	loaded, err := snap.GetSSH(ctx, ssh.ID)
	if err != nil {
		t.Fatal(err)
	}
	loadedDB, err := snap.GetDB(ctx, db.ID)
	if err != nil {
		t.Fatal(err)
	}
	loadedPair, err := snap.GetKeyPair(ctx, pair.ID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Archived || loaded.JumpConnectionIDs != "[]" || string(loaded.Password) != "s3cret" || loadedDB.SSHConnectionID != ssh.ID || string(loadedDB.Password) != "dbsecret" || string(loadedPair.PrivateKey) != "key" {
		t.Fatal("snapshot changed across phases")
	}
	if strings.Join(spy.decrypts, ",") != "warden/ssh/1/password,warden/ssh/1/proxy_password,warden/db/1/password,warden/key-pair/1/private_key,warden/key-pair/1/private_key_passphrase" {
		t.Fatalf("decrypt callbacks=%v", spy.decrypts)
	}
	fresh, err := s.GetSSH(ctx, ssh.ID)
	if err != nil || !fresh.Archived || fresh.JumpConnectionIDs != "[999999]" {
		t.Fatalf("writer not committed: %v", err)
	}
}

// These are passing characterizations of synchronous field decryption and
// cancelled snapshot disposal, not a claim that codec calls are interruptible.
// The resolver's no-partial/no-later-load contract is covered in profiles tests.
func TestResolutionSnapshotSecretCancellationCleanup(t *testing.T) {
	for _, field := range []string{"ssh-password", "ssh-proxy-password", "db-password", "private-key", "passphrase"} {
		t.Run(field, func(t *testing.T) {
			s := newTestStore(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			ssh, err := s.CreateSSH(ctx, SSHProfileForTest("ssh", "[]"))
			if err != nil {
				t.Fatal(err)
			}
			db, err := s.CreateDB(ctx, DBProfileForTest("db", ssh.ID))
			if err != nil {
				t.Fatal(err)
			}
			pair, err := s.CreateKeyPair(ctx, model.KeyPair{Name: "pair", PrivateKey: []byte("key"), PrivateKeyPassphrase: []byte("phrase")})
			if err != nil {
				t.Fatal(err)
			}
			// A leaked transaction cannot hide behind a second pool connection.
			s.db.SetMaxOpenConns(1)
			spy := &resolutionSpyCodec{fieldCodec: s.codec}
			s.codec = spy
			snap, err := s.BeginResolution(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer snap.Close()
			if _, err = snap.GetSSHMetadata(ctx, ssh.ID); err != nil {
				t.Fatal(err)
			}
			if _, err = snap.GetDBMetadata(ctx, db.ID); err != nil {
				t.Fatal(err)
			}
			if _, err = snap.HasPrivateKey(ctx, pair.ID); err != nil {
				t.Fatal(err)
			}
			if len(spy.decrypts) != 0 {
				t.Fatal("metadata decrypted")
			}

			var cancelAAD string
			var want []string
			switch field {
			case "ssh-password", "ssh-proxy-password":
				want = []string{string(sshAAD(ssh.ID, "password")), string(sshAAD(ssh.ID, "proxy_password"))}
				cancelAAD = want[0]
				if field == "ssh-proxy-password" {
					cancelAAD = want[1]
				}
			case "db-password":
				want = []string{string(dbAAD(db.ID, "password"))}
				cancelAAD = want[0]
			default:
				want = []string{string(keyPairAAD(pair.ID, "private_key")), string(keyPairAAD(pair.ID, "private_key_passphrase"))}
				cancelAAD = want[0]
				if field == "passphrase" {
					cancelAAD = want[1]
				}
			}
			spy.afterDecrypt = func(aad string) {
				if aad == cancelAAD {
					cancel()
				}
			}
			switch field {
			case "ssh-password", "ssh-proxy-password":
				_, err = snap.GetSSH(ctx, ssh.ID)
			case "db-password":
				_, err = snap.GetDB(ctx, db.ID)
			default:
				_, err = snap.GetKeyPair(ctx, pair.ID)
			}
			// SQL Scan finished before the codec callback cancels: the current
			// row can finish synchronously, including any remaining fields.
			if err != nil || !errors.Is(ctx.Err(), context.Canceled) || !reflect.DeepEqual(spy.decrypts, want) {
				t.Fatalf("in-progress row: err=%v context=%v callbacks=%v", err, ctx.Err(), spy.decrypts)
			}
			if _, err = snap.GetSSH(ctx, ssh.ID); !errors.Is(err, context.Canceled) {
				t.Fatalf("later SSH load: %v", err)
			}
			if _, err = snap.GetDB(ctx, db.ID); !errors.Is(err, context.Canceled) {
				t.Fatalf("later DB load: %v", err)
			}
			if _, err = snap.GetKeyPair(ctx, pair.ID); !errors.Is(err, context.Canceled) {
				t.Fatalf("later pair load: %v", err)
			}
			if !reflect.DeepEqual(spy.decrypts, want) {
				t.Fatal("later cancelled load invoked codec")
			}
			snap.Close()
			var one int
			if err = snap.tx.QueryRowContext(context.Background(), "SELECT 1").Scan(&one); !errors.Is(err, sql.ErrTxDone) {
				t.Fatalf("snapshot transaction still usable: %v", err)
			}
			// Cancellation may already have rolled back the transaction. This
			// checks eventual disposal/pool-slot release, not which Close won.
			probeCtx, stop := context.WithTimeout(context.Background(), 5*time.Second)
			defer stop()
			conn, err := s.db.Conn(probeCtx)
			if err != nil {
				t.Fatalf("single connection not released: %v", err)
			}
			defer conn.Close()
			if err = conn.QueryRowContext(probeCtx, "SELECT 1").Scan(&one); err != nil || one != 1 {
				t.Fatalf("pool reuse: value=%d err=%v", one, err)
			}
			if err = conn.Close(); err != nil {
				t.Fatal(err)
			}
			if inUse := s.db.Stats().InUse; inUse != 0 {
				t.Fatalf("pool connections still in use=%d", inUse)
			}
			t.Logf("cancelled at %s: completed decrypt callbacks=%d; transaction done; pool in-use=0", cancelAAD, len(spy.decrypts))
		})
	}
}

func TestResolutionSnapshotCancellationAndClose(t *testing.T) {
	s := newTestStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if snap, err := s.BeginResolution(ctx); !errors.Is(err, context.Canceled) {
		if snap != nil {
			snap.Close()
		}
		t.Fatalf("canceled begin=%v", err)
	}
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	snap, err := s.BeginResolution(ctx)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	if _, err = snap.GetSSHMetadata(ctx, 1); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled lookup=%v", err)
	}
	snap.Close()
}
