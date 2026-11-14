package runtime

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"net/http"
	"testing"

	"warden/internal/crypto"
	"warden/internal/server/setup"
)

func secondRegistration(t *testing.T, challenge, origin, rp string, identity ...byte) ([]byte, *ecdsa.PrivateKey, []byte) {
	body, key, id := fixtureRegistration(t, challenge, origin, rp, true)
	var c map[string]any
	json.Unmarshal(body, &c)
	value := byte(9)
	if len(identity) > 0 {
		value = identity[0]
	}
	next := bytes.Repeat([]byte{value}, len(id))
	response := c["response"].(map[string]any)
	att, _ := crypto.Decode(response["attestationObject"].(string), -1)
	response["attestationObject"] = crypto.Encode(bytes.Replace(att, id, next, 1))
	c["id"] = crypto.Encode(next)
	c["rawId"] = crypto.Encode(next)
	body, _ = json.Marshal(c)
	return body, key, next
}
func prepareEnrollment(t *testing.T, p *Plane, browser *http.Cookie, csrf string, signer *ecdsa.PrivateKey, recovery bool) (string, []byte) {
	id, credential, _ := prepareEnrollmentSigned(t, p, browser, csrf, signer, recovery)
	return id, credential
}
func prepareEnrollmentSigned(t *testing.T, p *Plane, browser *http.Cookie, csrf string, signer *ecdsa.PrivateKey, recovery bool) (string, []byte, *ecdsa.PrivateKey) {
	t.Helper()
	g := ""
	if !recovery {
		g = requestGrant(t, p, signer, browser, csrf, "passkey_add", "POST", "/api/v1/auth/passkeys/begin", "{}")
	}
	begin := callGranted(p, "POST", "/api/v1/auth/passkeys/begin", "{}", browser, csrf, g)
	if begin.Code != 200 {
		t.Fatalf("enrollment begin %d %s", begin.Code, begin.Body)
	}
	var b struct {
		ID      string `json:"id"`
		Options struct {
			PublicKey struct {
				Challenge string `json:"challenge"`
			} `json:"publicKey"`
		} `json:"options"`
	}
	json.Unmarshal(begin.Body.Bytes(), &b)
	current, err := p.current(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	reg, key, id := secondRegistration(t, b.Options.PublicKey.Challenge, p.cfg.PublicOrigin, p.cfg.RPID, byte(8+len(current.Owner.Credentials)))
	finish := call(p, "POST", "/api/v1/auth/passkeys/registration", map[string]any{"id": b.ID, "credential": json.RawMessage(reg)}, browser, csrf)
	if finish.Code != 200 {
		t.Fatal(finish.Code, finish.Body)
	}
	var a struct {
		Options struct {
			PublicKey struct {
				Challenge string `json:"challenge"`
			} `json:"publicKey"`
		} `json:"options"`
	}
	json.Unmarshal(finish.Body.Bytes(), &a)
	signed := fixtureAssertion(t, key, id, p.install.Owner.ID, a.Options.PublicKey.Challenge, p.cfg.PublicOrigin, p.cfg.RPID, true)
	result := call(p, "POST", "/api/v1/auth/passkeys/assertion", map[string]any{"id": b.ID, "credential": json.RawMessage(signed)}, browser, csrf)
	if result.Code != 200 {
		t.Fatal(result.Code, result.Body)
	}
	return b.ID, id, key
}
func TestAddPasskeyRequiresUnlockedOwnerAndFreshBoundGrant(t *testing.T) {
	p, _, _, key, signer := runtimeFixture(t)
	browser, csrf := sessionFor(t, p)
	if w := call(p, "POST", "/api/v1/auth/passkeys/begin", struct{}{}, browser, csrf); w.Code != 423 {
		t.Fatal("locked enrollment", w.Code)
	}
	p.vault.Unlock(key, p.vault.Generation())
	if w := call(p, "POST", "/api/v1/auth/passkeys/begin", struct{}{}, browser, csrf); w.Code != 403 {
		t.Fatal("no fresh grant", w.Code)
	}
	id, credential := prepareEnrollment(t, p, browser, csrf, signer, false)
	body, _ := json.Marshal(map[string]string{"id": id})
	// New credential has a verified registration+UV assertion, but cannot get the
	// old owner's DEK until an old-owner assertion is bound to THIS pending ID.
	if w := callGranted(p, "POST", "/api/v1/auth/passkeys/key", string(body), browser, csrf, ""); w.Code != 403 {
		t.Fatal("key without old-owner grant", w.Code)
	}
	g := requestGrant(t, p, signer, browser, csrf, "passkey_add", "POST", "/api/v1/auth/passkeys/key", string(body))
	delivery := callGranted(p, "POST", "/api/v1/auth/passkeys/key", string(body), browser, csrf, g)
	if delivery.Code != 200 {
		t.Fatal(delivery.Code, delivery.Body)
	}
	var d struct {
		DEK   string `json:"dek"`
		PRF   string `json:"prf_input"`
		Vault string `json:"vault_id"`
	}
	json.Unmarshal(delivery.Body.Bytes(), &d)
	if d.DEK != crypto.Encode(key) {
		t.Fatal("not same vault key")
	}
	wrapper, _ := crypto.Wrap(bytes.Repeat([]byte{11}, 32), key, "passkey", d.Vault, crypto.Encode(credential), nil)
	wrapper.PRFInput = d.PRF
	// Wrong recovered DEK must not corrupt initialized data or commit a wrapper.
	bad := call(p, "POST", "/api/v1/auth/passkeys/commit", map[string]any{"id": id, "wrapper": wrapper, "dek": crypto.Encode(bytes.Repeat([]byte{8}, 32))}, browser, csrf)
	if bad.Code != 403 {
		t.Fatal("wrong key commit", bad.Code)
	}
	// Re-authorization is required after failed completion (pending consumed).
	if i, _ := p.current(context.Background()); len(i.Passkeys) != 1 {
		t.Fatal("partial credential publication")
	}
}
func TestRevokedAndLastPasskeyRules(t *testing.T) {
	p, _, _, key, signer := runtimeFixture(t)
	browser, csrf := sessionFor(t, p)
	p.vault.Unlock(key, p.vault.Generation())
	body, _ := json.Marshal(map[string]string{"credential_id": p.install.Passkey.CredentialID})
	g := requestGrant(t, p, signer, browser, csrf, "passkey_remove", "POST", "/api/v1/auth/passkeys/remove", string(body))
	result := callGranted(p, "POST", "/api/v1/auth/passkeys/remove", string(body), browser, csrf, g)
	if result.Code != 409 {
		t.Fatal("last passkey removed", result.Code, result.Body)
	}
}
func TestCredentialWrapperCommitRollsBack(t *testing.T) {
	p, _, _, _, _ := runtimeFixture(t)
	before, _ := p.store.Installation(context.Background())
	err := p.updateIdentity(context.Background(), func(i *setup.Installation) error { i.Passkeys = nil; return nil }, "", false)
	if err == nil {
		t.Fatal("invalid partial publication")
	}
	after, _ := p.store.Installation(context.Background())
	if !bytes.Equal(before, after) {
		t.Fatal("failed update lost identity")
	}
}
