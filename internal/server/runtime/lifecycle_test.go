package runtime

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"
	"warden/internal/crypto"
	"warden/internal/store"
)

func loginSigner(t *testing.T, p *Plane, signer *ecdsa.PrivateKey, id []byte) (*http.Cookie, string) {
	t.Helper()
	begin := call(p, "POST", "/api/v1/auth/login/begin", struct{}{}, nil, "")
	if begin.Code != 200 {
		t.Fatal(begin.Code, begin.Body)
	}
	var b struct {
		ID string `json:"id"`
	}
	json.Unmarshal(begin.Body.Bytes(), &b)
	var login *http.Cookie
	for _, c := range begin.Result().Cookies() {
		if c.Name == loginCookie {
			login = c
		}
	}
	challenge := p.challenges[hash(b.ID)]
	signed := fixtureAssertion(t, signer, id, p.install.Owner.ID, challenge.Session.Challenge, p.cfg.PublicOrigin, p.cfg.RPID, true)
	finish := call(p, "POST", "/api/v1/auth/login/finish", map[string]any{"id": b.ID, "credential": json.RawMessage(signed)}, login, "")
	if finish.Code != 200 {
		t.Fatal(finish.Code, finish.Body)
	}
	var status struct {
		CSRF string `json:"csrf"`
	}
	json.Unmarshal(finish.Body.Bytes(), &status)
	for _, c := range finish.Result().Cookies() {
		if c.Name == sessionCookie {
			return c, status.CSRF
		}
	}
	t.Fatal("missing session")
	return nil, ""
}
func commitEnrollment(t *testing.T, p *Plane, browser *http.Cookie, csrf, id string, credential, key []byte, signer *ecdsa.PrivateKey, recovery bool) {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"id": id})
	g := ""
	if !recovery {
		g = requestGrant(t, p, signer, browser, csrf, "passkey_add", "POST", "/api/v1/auth/passkeys/key", string(body))
	}
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
	material := bytes.Repeat([]byte{12}, 32)
	wrapper, _ := crypto.Wrap(material, key, "passkey", d.Vault, crypto.Encode(credential), nil)
	wrapper.PRFInput = d.PRF
	round, e := wrapper.Unwrap(material, "passkey", d.Vault, crypto.Encode(credential))
	if e != nil || !bytes.Equal(round, key) {
		t.Fatal(e)
	}
	defer clear(round)
	commit := call(p, "POST", "/api/v1/auth/passkeys/commit", map[string]any{"id": id, "wrapper": wrapper, "dek": crypto.Encode(round)}, browser, csrf)
	if commit.Code != 200 {
		t.Fatal(commit.Code, commit.Body)
	}
}
func TestTwoPasskeysSeparateLoginsUnlockAndRevocation(t *testing.T) {
	p, _, original, key, signer := runtimeFixture(t)
	browser, csrf := sessionFor(t, p)
	p.vault.Unlock(key, p.vault.Generation())
	id, credential, newSigner := prepareEnrollmentSigned(t, p, browser, csrf, signer, false)
	commitEnrollment(t, p, browser, csrf, id, credential, key, signer, false)
	oldBrowser, oldCSRF := loginSigner(t, p, signer, original.Owner.Credentials[0].ID)
	newBrowser, newCSRF := loginSigner(t, p, newSigner, credential)
	p.vault.Lock()
	begin := call(p, "POST", "/api/v1/auth/fresh/begin", map[string]string{"action": "unlock", "credential_id": crypto.Encode(credential)}, newBrowser, newCSRF)
	var b struct {
		ID string `json:"id"`
	}
	json.Unmarshal(begin.Body.Bytes(), &b)
	c := p.challenges[hash(b.ID)]
	signed := fixtureAssertion(t, newSigner, credential, original.Owner.ID, c.Session.Challenge, p.cfg.PublicOrigin, p.cfg.RPID, true)
	finish := call(p, "POST", "/api/v1/auth/fresh/finish", map[string]any{"id": b.ID, "credential": json.RawMessage(signed)}, newBrowser, newCSRF)
	var f struct {
		Grant   string         `json:"grant"`
		Wrapper crypto.Wrapper `json:"wrapper"`
	}
	json.Unmarshal(finish.Body.Bytes(), &f)
	if finish.Code != 200 || f.Wrapper.CredentialID != crypto.Encode(credential) || f.Wrapper == original.Passkey {
		t.Fatal("wrong wrapper", finish.Code, finish.Body)
	}
	if _, err := original.Passkey.Unwrap(bytes.Repeat([]byte{12}, 32), "passkey", original.Passkey.VaultID, original.Passkey.CredentialID); err == nil {
		t.Fatal("new PRF used old wrapper")
	}
	unlock := call(p, "POST", "/api/v1/auth/unlock", map[string]string{"grant": f.Grant, "dek": crypto.Encode(key)}, newBrowser, newCSRF)
	if unlock.Code != 200 {
		t.Fatal(unlock.Code, unlock.Body)
	}
	body, _ := json.Marshal(map[string]string{"credential_id": crypto.Encode(credential)})
	g := requestGrant(t, p, signer, oldBrowser, oldCSRF, "passkey_remove", "POST", "/api/v1/auth/passkeys/remove", string(body))
	if result := callGranted(p, "POST", "/api/v1/auth/passkeys/remove", string(body), oldBrowser, oldCSRF, g); result.Code != 200 {
		t.Fatal(result.Code, result.Body)
	}
	if got := call(p, "GET", "/api/v1/auth/status", nil, newBrowser, newCSRF); got.Code != 401 {
		t.Fatal("revoked credential session", got.Code)
	}
	i, _ := p.current(context.Background())
	if len(i.Passkeys) != 1 || i.Passkeys[0] != original.Passkey {
		t.Fatal("lost old passkey")
	}
}
func TestRecoveryReplacementSurvivesRestartAndRevokesOldAccess(t *testing.T) {
	p, _, original, key, _ := runtimeFixture(t)
	_, proof := recoveryFixture(t, p, key)
	originalRecovery := pRecovery(t, p)
	browser, csrf, g := startRecovery(t, p, proof)
	if result := call(p, "POST", "/api/v1/auth/recovery/unlock", map[string]string{"grant": g, "dek": crypto.Encode(key)}, browser, csrf); result.Code != 200 {
		t.Fatal(result.Code, result.Body)
	}
	id, credential, signer := prepareEnrollmentSigned(t, p, browser, csrf, nil, true)
	commitEnrollment(t, p, browser, csrf, id, credential, key, nil, true)
	raw, _ := p.store.Installation(context.Background())
	path := filepath.Join(t.TempDir(), "restart.db")
	if err := store.CommitInstallation(context.Background(), path, raw); err != nil {
		t.Fatal(err)
	}
	vault := crypto.NewVault()
	s, err := store.OpenInitialized(context.Background(), path, func(raw []byte) error { _, e := validateInstallation(raw, p.cfg); return e }, vault)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	defer vault.Lock()
	i, err := validateInstallation(raw, p.cfg)
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := newPlane(p.cfg, s, i, vault, p.verifier, p.managed)
	if err != nil {
		t.Fatal(err)
	}
	if vault.Unlocked() || len(i.Passkeys) != 1 || i.Passkeys[0].CredentialID == original.Passkey.CredentialID || i.Recovery != originalRecovery {
		t.Fatal("restart lost replacement/recovery or unlocked")
	}
	loginSigner(t, restarted, signer, credential)
	if i.KeyCheck.Verify(key, i.KeyCheck.VaultID) != nil {
		t.Fatal("same DEK not preserved")
	}
}
