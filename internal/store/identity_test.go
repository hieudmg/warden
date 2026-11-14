package store

import (
	"bytes"
	"context"
	"path/filepath"
	"sync"
	"testing"
	"warden/internal/crypto"
)

func TestIdentityReplacementAndSessionRevocationAtomic(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "identity.db")
	before := []byte(`{"format":1,"authorization_generation":0}`)
	after := []byte(`{"format":1,"authorization_generation":1}`)
	if err := CommitInstallation(ctx, path, before); err != nil {
		t.Fatal(err)
	}
	s, err := OpenInitialized(ctx, path, func([]byte) error { return nil }, crypto.NewVault())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err = s.SaveSession(ctx, Session{Hash: "session", CSRFHash: "csrf", CredentialID: "old"}); err != nil {
		t.Fatal(err)
	}
	// A real SQL failure AFTER identity update must roll back identity and sessions.
	if _, err = s.db.Exec(`CREATE TRIGGER refuse_revocation BEFORE DELETE ON web_sessions BEGIN SELECT RAISE(ABORT,'synthetic failure'); END`); err != nil {
		t.Fatal(err)
	}
	if err = s.CompareAndSwapInstallation(ctx, before, after, "", true); err == nil {
		t.Fatal("failed revocation committed")
	}
	current, _ := s.Installation(ctx)
	if !bytes.Equal(current, before) {
		t.Fatal("half replacement")
	}
	if _, err = s.Session(ctx, "session"); err != nil {
		t.Fatal("session lost on rollback")
	}
	if _, err = s.db.Exec(`DROP TRIGGER refuse_revocation`); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for range 2 {
		wg.Add(1)
		go func() { defer wg.Done(); results <- s.CompareAndSwapInstallation(ctx, before, after, "", true) }()
	}
	wg.Wait()
	close(results)
	winners := 0
	for err := range results {
		if err == nil {
			winners++
		}
	}
	if winners != 1 {
		t.Fatal("CAS winners", winners)
	}
	current, _ = s.Installation(ctx)
	if !bytes.Equal(current, after) {
		t.Fatal("replacement missing")
	}
	if _, err = s.Session(ctx, "session"); err == nil {
		t.Fatal("session not revoked")
	}
}
