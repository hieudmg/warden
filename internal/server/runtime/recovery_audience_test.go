package runtime

import (
	"testing"
	"warden/internal/crypto"
)

func TestOrdinarySessionCannotEnterRecoveryUnlockOrAllocateState(t *testing.T) {
	p, _, _, key, _ := runtimeFixture(t)
	browser, csrf := sessionFor(t, p)
	result := call(p, "POST", "/api/v1/auth/recovery/unlock", map[string]string{"grant": "not-recovery", "dek": crypto.Encode(key)}, browser, csrf)
	if result.Code != 403 {
		t.Fatal("ordinary session recovery unlock", result.Code)
	}
	p.mu.Lock()
	count := len(p.recoveries)
	p.mu.Unlock()
	if count != 0 {
		t.Fatalf("ordinary session allocated %d restricted contexts", count)
	}
}
