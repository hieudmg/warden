package runtime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"sync"
	"testing"
	"warden/internal/crypto"
	"warden/internal/server/setup"
)

func TestIdentityCounterWrapperAndRecoveryChangesMergeCurrentState(t *testing.T) {
	p, _, original, key, _ := runtimeFixture(t)
	root := bytes.Repeat([]byte{25}, 32)
	wrapper, err := crypto.Wrap(root, key, "recovery", original.KeyCheck.VaultID, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	salt, _ := crypto.Decode(wrapper.KDFSalt, 32)
	proof, _ := crypto.Derive(root, salt, "warden/v1/recovery-auth")
	verifier := sha256.Sum256(proof)
	var wg sync.WaitGroup
	errors := make(chan error, 32)
	for n := range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errors <- p.updateIdentity(context.Background(), func(i *setup.Installation) error {
				if n%2 == 0 {
					i.Owner.Credentials[0].Authenticator.SignCount++
				} else {
					i.Recovery = wrapper
					i.RecoveryVerifier = crypto.Encode(verifier[:])
				}
				return nil
			}, "", false)
		}()
	}
	wg.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
	current, err := p.current(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if current.Owner.Credentials[0].Authenticator.SignCount != 16 || current.Recovery != wrapper || current.Passkeys[0] != original.Passkey || current.KeyCheck != original.KeyCheck {
		t.Fatal("stale metadata overwrote independent updates")
	}
}
