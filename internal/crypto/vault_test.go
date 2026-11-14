package crypto

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestGlobalLockDrainsSecretOperations(t *testing.T) {
	v := NewVault()
	if _, _, err := v.Acquire(context.Background()); !errors.Is(err, ErrVaultLocked) {
		t.Fatalf("locked: %v", err)
	}
	epoch := v.Generation()
	if err := v.Unlock(make([]byte, 32), epoch); err != nil {
		t.Fatal(err)
	}
	ctx, release, err := v.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	locked := make(chan struct{})
	go func() { v.Lock(); close(locked) }()
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("lock did not cancel")
	}
	select {
	case <-locked:
		t.Fatal("ack before drain")
	default:
	}
	if _, _, err := v.Acquire(context.Background()); !errors.Is(err, ErrVaultLocked) {
		t.Fatal("new work accepted")
	}
	release()
	select {
	case <-locked:
	case <-time.After(time.Second):
		t.Fatal("lock did not drain")
	}
	if err := v.Unlock(make([]byte, 32), epoch); err == nil {
		t.Fatal("late key delivery reenabled vault")
	}
	if _, err := v.Decrypt([]byte("ciphertext"), nil); !errors.Is(err, ErrVaultLocked) {
		t.Fatalf("codec retained key: %v", err)
	}
}

func TestRuntimeVaultCodecRevocable(t *testing.T) {
	v := NewVault()
	key := make([]byte, 32)
	key[0] = 7
	if err := v.Unlock(key, v.Generation()); err != nil {
		t.Fatal(err)
	}
	ct, err := v.Encrypt([]byte("synthetic secret"), []byte("row/field"))
	if err != nil {
		t.Fatal(err)
	}
	p, err := v.Decrypt(ct, []byte("row/field"))
	if err != nil || string(p) != "synthetic secret" {
		t.Fatal(err)
	}
	v.Lock()
	if _, err = v.Decrypt(ct, []byte("row/field")); !errors.Is(err, ErrVaultLocked) {
		t.Fatal(err)
	}
}
