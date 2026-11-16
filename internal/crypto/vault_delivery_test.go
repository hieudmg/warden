package crypto

import (
	"bytes"
	"context"
	"testing"
)

func TestVaultKeyDeliveryRequiresLiveLease(t *testing.T) {
	v := NewVault()
	key := bytes.Repeat([]byte{7}, 32)
	v.Unlock(key, v.Generation())
	if _, err := v.KeyForLease(context.Background()); err == nil {
		t.Fatal("unleased key delivery")
	}
	ctx, release, err := v.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got, err := v.KeyForLease(ctx)
	if err != nil || !bytes.Equal(got, key) {
		t.Fatal("leased delivery", err)
	}
	clear(got)
	release()
	if _, err = v.KeyForLease(ctx); err == nil {
		t.Fatal("released lease delivers key")
	}
	v.Lock()
	if _, err = v.KeyForLease(ctx); err == nil {
		t.Fatal("locked delivery")
	}
}
