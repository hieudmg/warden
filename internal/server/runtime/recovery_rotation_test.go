package runtime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"testing"
	"time"
	"warden/internal/crypto"
)

func TestRecoveryRotationSavedRoundTripAndOldKeyInvalidAgainstCurrentState(t *testing.T) {
	p, _, _, key, signer := runtimeFixture(t)
	_, oldProof := recoveryFixture(t, p, key)
	browser, csrf := sessionFor(t, p)
	p.vault.Unlock(key, p.vault.Generation())
	// A nonce issued before rotation must not authenticate against newer metadata.
	nonce := call(p, "POST", "/api/v1/auth/recovery/begin", struct{}{}, nil, "")
	var old struct {
		ID string `json:"id"`
	}
	json.Unmarshal(nonce.Body.Bytes(), &old)
	g := requestGrant(t, p, signer, browser, csrf, "recovery_rotate", "POST", "/api/v1/auth/recovery/rotation/key", "{}")
	result := callGranted(p, "POST", "/api/v1/auth/recovery/rotation/key", "{}", browser, csrf, g)
	var b struct {
		ID    string `json:"id"`
		Vault string `json:"vault_id"`
	}
	json.Unmarshal(result.Body.Bytes(), &b)
	root := bytes.Repeat([]byte{22}, 32)
	w, err := crypto.Wrap(root, key, "recovery", b.Vault, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	salt, _ := crypto.Decode(w.KDFSalt, 32)
	proof, _ := crypto.Derive(root, salt, "warden/v1/recovery-auth")
	verifier := sha256.Sum256(proof)
	prepared := call(p, "POST", "/api/v1/auth/recovery/rotation/prepare", map[string]any{"id": b.ID, "wrapper": w, "verifier": crypto.Encode(verifier[:])}, browser, csrf)
	if prepared.Code != 200 {
		t.Fatal(prepared.Code, prepared.Body)
	}
	// Local saved-root re-entry would recover this DEK; synthetic test material only.
	recovered, err := w.Unwrap(root, "recovery", b.Vault, "")
	if err != nil || !bytes.Equal(recovered, key) {
		t.Fatal(err)
	}
	defer clear(recovered)
	committed := call(p, "POST", "/api/v1/auth/recovery/rotation/commit", map[string]string{"id": b.ID, "proof": crypto.Encode(proof), "dek": crypto.Encode(recovered)}, browser, csrf)
	if committed.Code != 200 {
		t.Fatal(committed.Code, committed.Body)
	}
	i, _ := p.current(context.Background())
	if i.Recovery != w || i.RecoveryVerifier != crypto.Encode(verifier[:]) {
		t.Fatal("rotation not published")
	}
	stale := call(p, "POST", "/api/v1/auth/recovery/proof", map[string]string{"id": old.ID, "proof": crypto.Encode(oldProof)}, nil, "")
	if stale.Code != 403 {
		t.Fatal("stale proof context", stale.Code)
	}
	begin := call(p, "POST", "/api/v1/auth/recovery/begin", struct{}{}, nil, "")
	json.Unmarshal(begin.Body.Bytes(), &old)
	wrong := call(p, "POST", "/api/v1/auth/recovery/proof", map[string]string{"id": old.ID, "proof": crypto.Encode(oldProof)}, nil, "")
	if wrong.Code != 403 {
		t.Fatal("old proof accepted", wrong.Code)
	}
	startRecovery(t, p, proof)
}
func TestRecoveryProofGlobalRateAndBoundedNonceState(t *testing.T) {
	p, _, _, _, _ := runtimeFixture(t)
	for range 5 {
		if result := call(p, "POST", "/api/v1/auth/recovery/proof", map[string]string{"id": "missing", "proof": crypto.Encode(bytes.Repeat([]byte{1}, 32))}, nil, ""); result.Code != 403 {
			t.Fatal(result.Code)
		}
	}
	result := call(p, "POST", "/api/v1/auth/recovery/proof", map[string]string{"id": "missing", "proof": crypto.Encode(bytes.Repeat([]byte{1}, 32))}, nil, "")
	if result.Code != 429 || result.Header().Get("Retry-After") != "10" {
		t.Fatal(result.Code, result.Header())
	}
	now := p.now()
	p.now = func() time.Time { return now.Add(10 * time.Second) }
	if result := call(p, "POST", "/api/v1/auth/recovery/proof", map[string]string{"id": "missing", "proof": crypto.Encode(bytes.Repeat([]byte{1}, 32))}, nil, ""); result.Code != 403 {
		t.Fatal("rate not refilled", result.Code)
	}
	p.mu.Lock()
	for n := 0; n < 128; n++ {
		p.recoveryNonces[string(rune(n))] = recoveryNonce{Expires: p.now().Add(time.Minute)}
	}
	p.mu.Unlock()
	if result := call(p, "POST", "/api/v1/auth/recovery/begin", struct{}{}, nil, ""); result.Code != 429 {
		t.Fatal("unbounded nonce state", result.Code)
	}
}
