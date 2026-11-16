package runtime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"testing"
	"time"
	"warden/internal/crypto"
	"warden/internal/server/setup"
)

func recoveryFixture(t *testing.T, p *Plane, key []byte) ([]byte, []byte) {
	t.Helper()
	root := bytes.Repeat([]byte{21}, 32)
	w, err := crypto.Wrap(root, key, "recovery", p.install.KeyCheck.VaultID, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	salt, _ := crypto.Decode(w.KDFSalt, 32)
	proof, _ := crypto.Derive(root, salt, "warden/v1/recovery-auth")
	verifier := sha256.Sum256(proof)
	if err = p.updateIdentity(context.Background(), func(i *setup.Installation) error {
		i.Recovery = w
		i.RecoveryVerifier = crypto.Encode(verifier[:])
		return nil
	}, "", false); err != nil {
		t.Fatal(err)
	}
	return root, proof
}
func startRecovery(t *testing.T, p *Plane, proof []byte) (*http.Cookie, string, string) {
	t.Helper()
	begin := call(p, "POST", "/api/v1/auth/recovery/begin", struct{}{}, nil, "")
	if begin.Code != 200 {
		t.Fatalf("recovery begin: %d %s", begin.Code, begin.Body)
	}
	var b struct {
		ID string `json:"id"`
	}
	json.Unmarshal(begin.Body.Bytes(), &b)
	finish := call(p, "POST", "/api/v1/auth/recovery/proof", map[string]string{"id": b.ID, "proof": crypto.Encode(proof)}, nil, "")
	if finish.Code != 200 {
		t.Fatalf("proof: %d %s", finish.Code, finish.Body)
	}
	var result struct {
		CSRF    string         `json:"csrf"`
		Grant   string         `json:"grant"`
		Wrapper crypto.Wrapper `json:"wrapper"`
	}
	json.Unmarshal(finish.Body.Bytes(), &result)
	cookies := finish.Result().Cookies()
	if len(cookies) < 1 || result.Grant == "" || result.Wrapper.Kind != "recovery" {
		t.Fatal("missing restricted session", finish.Body)
	}
	for _, c := range cookies {
		if c.Name == "__Host-warden-recovery" {
			return c, result.CSRF, result.Grant
		}
	}
	t.Fatal("no restricted cookie")
	return nil, "", ""
}
func TestRecoveryRequiresProofBeforeWrapperOrKeyDelivery(t *testing.T) {
	for _, variant := range []string{"wrong", "expired", "replay", "correct"} {
		t.Run(variant, func(t *testing.T) {
			p, _, _, key, _ := runtimeFixture(t)
			_, proof := recoveryFixture(t, p, key)
			b := call(p, "POST", "/api/v1/auth/recovery/begin", struct{}{}, nil, "")
			if b.Code != 200 {
				t.Fatalf("begin: %d", b.Code)
			}
			if bytes.Contains(b.Body.Bytes(), []byte("ciphertext")) {
				t.Fatal("wrapper before proof")
			}
			var start struct {
				ID string `json:"id"`
			}
			json.Unmarshal(b.Body.Bytes(), &start)
			if variant == "wrong" {
				proof = bytes.Repeat([]byte{1}, 32)
			}
			if variant == "expired" {
				now := p.now()
				p.now = func() time.Time { return now.Add(5 * time.Minute) }
			}
			body := map[string]string{"id": start.ID, "proof": crypto.Encode(proof)}
			result := call(p, "POST", "/api/v1/auth/recovery/proof", body, nil, "")
			if variant == "correct" || variant == "replay" {
				if result.Code != 200 {
					t.Fatal(result.Code, result.Body)
				}
			} else if result.Code != 403 || bytes.Contains(result.Body.Bytes(), []byte("ciphertext")) {
				t.Fatal("bad proof accepted", result.Code, result.Body)
			}
			if variant == "replay" {
				if w := call(p, "POST", "/api/v1/auth/recovery/proof", body, nil, ""); w.Code != 403 {
					t.Fatal("replayed proof", w.Code)
				}
			}
			if w := call(p, "POST", "/api/v1/auth/recovery/unlock", map[string]string{"dek": crypto.Encode(key)}, nil, ""); w.Code != 401 {
				t.Fatal("correct key authenticated", w.Code)
			}
		})
	}
}
func TestRecoveryCannotReadManagementDataAndReplacementRemovesAllOldPasskeys(t *testing.T) {
	p, _, original, key, signer := runtimeFixture(t)
	owner, ownerCSRF := sessionFor(t, p)
	p.vault.Unlock(key, p.vault.Generation())
	clientSecret, _, _ := pairedFixture(t, p, func(id, commitment string) {
		body := `{"id":"` + id + `","commitment":"` + commitment + `"}`
		g := requestGrant(t, p, signer, owner, ownerCSRF, "client_approve", "POST", "/api/v1/auth/clients/approve", body)
		if w := callGranted(p, "POST", "/api/v1/auth/clients/approve", body, owner, ownerCSRF, g); w.Code != 200 {
			t.Fatal(w.Code, w.Body)
		}
	}, 90)
	additional, additionalID, additionalSigner := prepareEnrollmentSigned(t, p, owner, ownerCSRF, signer, false)
	commitEnrollment(t, p, owner, ownerCSRF, additional, additionalID, key, signer, false)
	additionalBrowser, additionalCSRF := loginSigner(t, p, additionalSigner, additionalID)
	_, proof := recoveryFixture(t, p, key)
	oldRecovery := pRecovery(t, p)
	old, oldCSRF := sessionFor(t, p)
	recovery, csrf, g := startRecovery(t, p, proof)
	if w := call(p, "POST", "/api/v1/auth/recovery/unlock", map[string]string{"grant": g, "dek": crypto.Encode(key)}, recovery, csrf); w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	if w := clientCall(p, "GET", "/api/v1/client/ssh-connections", "", clientSecret); w.Code != 423 {
		t.Fatal("valid API credential entered restricted recovery", w.Code)
	}
	for _, route := range []string{"/api/v1/ssh-connections", "/api/v1/key-pairs", "/api/v1/data/export", "/api/v1/auth/passkeys/list", "/api/v1/auth/fresh/begin"} {
		if w := call(p, "GET", route, nil, recovery, csrf); w.Code == 200 {
			t.Fatal("recovery management", route)
		}
	}
	if w := call(p, "GET", "/api/v1/ssh-connections", nil, old, oldCSRF); w.Code == 200 {
		t.Fatal("management during recovery")
	}
	id, credential := prepareEnrollment(t, p, recovery, csrf, nil, true)
	d := call(p, "POST", "/api/v1/auth/passkeys/key", map[string]string{"id": id}, recovery, csrf)
	if d.Code != 200 {
		t.Fatal(d.Code, d.Body)
	}
	var delivery struct {
		DEK   string `json:"dek"`
		PRF   string `json:"prf_input"`
		Vault string `json:"vault_id"`
	}
	json.Unmarshal(d.Body.Bytes(), &delivery)
	w, _ := crypto.Wrap(bytes.Repeat([]byte{10}, 32), key, "passkey", delivery.Vault, crypto.Encode(credential), nil)
	w.PRFInput = delivery.PRF
	// Simulate browser's local unwrap round-trip, not a claim of genuine PRF.
	round, err := w.Unwrap(bytes.Repeat([]byte{10}, 32), "passkey", delivery.Vault, crypto.Encode(credential))
	if err != nil || !bytes.Equal(round, key) {
		t.Fatal(err)
	}
	clear(round)
	result := call(p, "POST", "/api/v1/auth/passkeys/commit", map[string]any{"id": id, "wrapper": w, "dek": delivery.DEK}, recovery, csrf)
	if result.Code != 200 {
		t.Fatal(result.Code, result.Body)
	}
	i, err := p.current(context.Background())
	if err != nil || len(i.Passkeys) != 1 || i.Passkeys[0].CredentialID == original.Passkey.CredentialID || i.AuthorizationGeneration != 1 {
		t.Fatal("old identity retained", err)
	}
	if w := clientCall(p, "GET", "/api/v1/client/status", "", clientSecret); w.Code != 401 {
		t.Fatal("actual recovery replacement retained client authorization", w.Code)
	}
	if i.KeyCheck != original.KeyCheck || i.Recovery != oldRecovery {
		t.Fatal("DEK/recovery changed")
	}
	if p.vault.Unlocked() {
		t.Fatal("recovery did not return locked")
	}
	if w := call(p, "GET", "/api/v1/auth/status", nil, additionalBrowser, additionalCSRF); w.Code != 401 {
		t.Fatal("second old session survived", w.Code)
	}
	for _, w := range i.Passkeys {
		if w.CredentialID == crypto.Encode(additionalID) {
			t.Fatal("second old passkey retained")
		}
	}
	if w := call(p, "GET", "/api/v1/auth/status", nil, old, oldCSRF); w.Code != 401 {
		t.Fatal("old session", w.Code)
	}
	if w := call(p, "GET", "/api/v1/auth/status", nil, recovery, csrf); w.Code != 401 {
		t.Fatal("recovery became normal", w.Code)
	}
}
func pRecovery(t *testing.T, p *Plane) crypto.Wrapper {
	t.Helper()
	i, e := p.current(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	return i.Recovery
}
func TestRecoveryAbortCommitsNothing(t *testing.T) {
	p, _, _, key, _ := runtimeFixture(t)
	_, proof := recoveryFixture(t, p, key)
	before, _ := p.store.Installation(context.Background())
	recovery, csrf, g := startRecovery(t, p, proof)
	call(p, "POST", "/api/v1/auth/recovery/unlock", map[string]string{"grant": g, "dek": crypto.Encode(key)}, recovery, csrf)
	prepareEnrollment(t, p, recovery, csrf, nil, true)
	result := call(p, "POST", "/api/v1/auth/recovery/abort", struct{}{}, recovery, csrf)
	if result.Code != 200 {
		t.Fatal(result.Code, result.Body)
	}
	after, _ := p.store.Installation(context.Background())
	if !bytes.Equal(before, after) || p.vault.Unlocked() {
		t.Fatal("aborted recovery committed identity/key state")
	}
}
func TestRecoveryRotationRequiresSavedConfirmation(t *testing.T) {
	p, _, _, key, signer := runtimeFixture(t)
	_, oldProof := recoveryFixture(t, p, key)
	browser, csrf := sessionFor(t, p)
	p.vault.Unlock(key, p.vault.Generation())
	g := requestGrant(t, p, signer, browser, csrf, "recovery_rotate", "POST", "/api/v1/auth/recovery/rotation/key", "{}")
	start := callGranted(p, "POST", "/api/v1/auth/recovery/rotation/key", "{}", browser, csrf, g)
	if start.Code != 200 {
		t.Fatal(start.Code, start.Body)
	}
	var pending struct {
		ID    string `json:"id"`
		Vault string `json:"vault_id"`
	}
	json.Unmarshal(start.Body.Bytes(), &pending)
	root := bytes.Repeat([]byte{31}, 32)
	wrapper, _ := crypto.Wrap(root, key, "recovery", pending.Vault, "", nil)
	salt, _ := crypto.Decode(wrapper.KDFSalt, 32)
	proof, _ := crypto.Derive(root, salt, "warden/v1/recovery-auth")
	v := sha256.Sum256(proof)
	prepare := call(p, "POST", "/api/v1/auth/recovery/rotation/prepare", map[string]any{"id": pending.ID, "wrapper": wrapper, "verifier": crypto.Encode(v[:])}, browser, csrf)
	if prepare.Code != 200 {
		t.Fatal(prepare.Code, prepare.Body)
	}
	before, _ := p.store.Installation(context.Background())
	bad := call(p, "POST", "/api/v1/auth/recovery/rotation/commit", map[string]string{"id": pending.ID, "proof": crypto.Encode(oldProof), "dek": crypto.Encode(key)}, browser, csrf)
	after, _ := p.store.Installation(context.Background())
	if bad.Code != 403 || !bytes.Equal(before, after) {
		t.Fatal("saved confirmation bypass", bad.Code, bad.Body)
	}
}
