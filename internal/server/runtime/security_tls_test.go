package runtime

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"warden/internal/config"
	"warden/internal/crypto"
)

// One composed disposable journey using production init/serve/CLI binaries and
// the real signature verifier. Synthetic PRF and graph/clock substitutions are
// explicit; this is NOT genuine authenticator or native Windows acceptance.
// Extends the former TestHTTPSRuntimeT3SecurityLifecycle rather than duplicating
// its signed enrollment/recovery/rotation producer-consumer contracts.
func TestSecurityLifecycleHTTPS(t *testing.T) {
	binaries := securityBinaries(t)
	ambientDB := filepath.Join(t.TempDir(), "must-not-use.db")
	t.Setenv("WARDEN_SERVER_DB_PATH", ambientDB)
	t.Setenv("WARDEN_CLIENT_API_BASE_URL", "https://ambient.invalid")
	active := securityInitialize(t, binaries)
	initial, dek, firstSigner := active.initial, active.dek, active.signer
	root, initialProof := active.root, active.proof
	cfg := config.Setup{PublicOrigin: initial.PublicOrigin, RPID: initial.RPID}
	client := active.client
	var stop func()
	start := func() { stop = securityServe(t, binaries, active) }
	halt := func() {
		if stop != nil {
			stop()
			stop = nil
		}
	}
	defer halt()
	start()
	csrf := ""
	request := func(method, path, body, grant string) (int, []byte) {
		t.Helper()
		req, e := http.NewRequest(method, cfg.PublicOrigin+path, bytes.NewBufferString(body))
		if e != nil {
			t.Fatal(e)
		}
		req.Header.Set("Origin", cfg.PublicOrigin)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-CSRF-Token", csrf)
		if grant != "" {
			req.Header.Set("X-Warden-Action", grant)
		}
		res, e := client.Do(req)
		if e != nil {
			t.Fatal(e)
		}
		defer res.Body.Close()
		data, e := io.ReadAll(res.Body)
		if e != nil {
			t.Fatal(e)
		}
		if res.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("cache policy", path)
		}
		return res.StatusCode, data
	}
	post := func(path string, body any, grant string) []byte {
		t.Helper()
		raw, _ := json.Marshal(body)
		status, data := request("POST", "/api/v1/auth/"+path, string(raw), grant)
		if status != 200 {
			t.Fatalf("%s status %d: %s", path, status, data)
		}
		return data
	}
	assertionOptions := func(raw []byte) (string, string) {
		t.Helper()
		var b struct {
			ID      string `json:"id"`
			Options struct {
				PublicKey struct {
					Challenge string `json:"challenge"`
				} `json:"publicKey"`
			} `json:"options"`
		}
		if json.Unmarshal(raw, &b) != nil || b.Options.PublicKey.Challenge == "" {
			t.Fatalf("no challenge: %s", raw)
		}
		return b.ID, b.Options.PublicKey.Challenge
	}
	login := func(signer *ecdsa.PrivateKey, id []byte) {
		t.Helper()
		b := post("login/begin", struct{}{}, "")
		nonce, challenge := assertionOptions(b)
		signed := fixtureAssertion(t, signer, id, initial.Owner.ID, challenge, cfg.PublicOrigin, cfg.RPID, true)
		result := post("login/finish", map[string]any{"id": nonce, "credential": json.RawMessage(signed)}, "")
		var state struct {
			CSRF string `json:"csrf"`
		}
		json.Unmarshal(result, &state)
		csrf = state.CSRF
	}
	grantFor := func(signer *ecdsa.PrivateKey, id []byte, action, method, path, body string) string {
		t.Helper()
		b := post("fresh/begin", map[string]string{"action": action, "credential_id": crypto.Encode(id), "method": method, "path": path, "digest": hash(body)}, "")
		nonce, challenge := assertionOptions(b)
		signed := fixtureAssertion(t, signer, id, initial.Owner.ID, challenge, cfg.PublicOrigin, cfg.RPID, true)
		result := post("fresh/finish", map[string]any{"id": nonce, "credential": json.RawMessage(signed)}, "")
		var grant struct {
			Grant string `json:"grant"`
		}
		json.Unmarshal(result, &grant)
		return grant.Grant
	}
	unlock := func(signer *ecdsa.PrivateKey, id []byte) {
		t.Helper()
		b := post("fresh/begin", map[string]string{"action": "unlock", "credential_id": crypto.Encode(id)}, "")
		nonce, challenge := assertionOptions(b)
		signed := fixtureAssertion(t, signer, id, initial.Owner.ID, challenge, cfg.PublicOrigin, cfg.RPID, true)
		result := post("fresh/finish", map[string]any{"id": nonce, "credential": json.RawMessage(signed)}, "")
		var g struct {
			Grant   string         `json:"grant"`
			Wrapper crypto.Wrapper `json:"wrapper"`
		}
		if err := json.Unmarshal(result, &g); err != nil {
			t.Fatal(err)
		}
		// Explicit synthetic PRF result, never a raw-key alternative to the
		// independent signed assertion or wrapper/key-check contract.
		material := bytes.Repeat([]byte{15}, 32)
		if bytes.Equal(id, initial.Owner.Credentials[0].ID) {
			material = bytes.Repeat([]byte{13}, 32)
		}
		round, err := g.Wrapper.Unwrap(material, "passkey", g.Wrapper.VaultID, crypto.Encode(id))
		if err != nil || !bytes.Equal(round, dek) {
			t.Fatal("verified passkey wrapper did not preserve DEK", err)
		}
		defer clear(round)
		post("unlock", map[string]string{"grant": g.Grant, "dek": crypto.Encode(round)}, "")
	}
	enroll := func(ownerSigner *ecdsa.PrivateKey, ownerID []byte, recovery bool, newID byte) (*ecdsa.PrivateKey, []byte) {
		t.Helper()
		g := ""
		if !recovery {
			g = grantFor(ownerSigner, ownerID, "passkey_add", "POST", "/api/v1/auth/passkeys/begin", "{}")
		}
		nonce, challenge := assertionOptions(post("passkeys/begin", struct{}{}, g))
		registration, signer, id := secondRegistration(t, challenge, cfg.PublicOrigin, cfg.RPID, newID)
		result := post("passkeys/registration", map[string]any{"id": nonce, "credential": json.RawMessage(registration)}, "")
		_, challenge = assertionOptions(result)
		var metadata struct {
			PRF   string `json:"prf_input"`
			Vault string `json:"vault_id"`
		}
		json.Unmarshal(result, &metadata)
		signed := fixtureAssertion(t, signer, id, initial.Owner.ID, challenge, cfg.PublicOrigin, cfg.RPID, true)
		post("passkeys/assertion", map[string]any{"id": nonce, "credential": json.RawMessage(signed)}, "")
		body, _ := json.Marshal(map[string]string{"id": nonce})
		if !recovery {
			g = grantFor(ownerSigner, ownerID, "passkey_add", "POST", "/api/v1/auth/passkeys/key", string(body))
		}
		delivery := post("passkeys/key", map[string]string{"id": nonce}, g)
		var key struct {
			DEK string `json:"dek"`
		}
		json.Unmarshal(delivery, &key)
		if key.DEK != crypto.Encode(dek) {
			t.Fatal("not same DEK")
		}
		material := bytes.Repeat([]byte{15}, 32)
		wrapper, e := crypto.Wrap(material, dek, "passkey", metadata.Vault, crypto.Encode(id), nil)
		if e != nil {
			t.Fatal(e)
		}
		wrapper.PRFInput = metadata.PRF
		round, e := wrapper.Unwrap(material, "passkey", metadata.Vault, crypto.Encode(id))
		if e != nil || !bytes.Equal(round, dek) {
			t.Fatal(e)
		}
		defer clear(round)
		post("passkeys/commit", map[string]any{"id": nonce, "wrapper": wrapper, "dek": crypto.Encode(round)}, "")
		return signer, id
	}
	firstID := initial.Owner.Credentials[0].ID
	login(firstSigner, firstID)
	if status, _ := request("GET", "/api/v1/key-pairs", "", ""); status != 423 {
		t.Fatal("restart not locked", status)
	}
	unlock(firstSigner, firstID)
	secondSigner, secondID := enroll(firstSigner, firstID, false, 9)
	login(secondSigner, secondID) // separate signed ordinary login, no implicit unlock
	keyBody := `{"name":"tls-key","private_key":"synthetic-tls-key"}`
	g := grantFor(secondSigner, secondID, "key_mutation", "POST", "/api/v1/key-pairs", keyBody)
	if status, data := request("POST", "/api/v1/key-pairs", keyBody, g); status != 201 {
		t.Fatal(status, string(data))
	}
	g = grantFor(secondSigner, secondID, "export", "GET", "/api/v1/data/export", "")
	if status, data := request("GET", "/api/v1/data/export", "", g); status != 200 || !bytes.Contains(data, []byte("synthetic-tls-key")) {
		t.Fatal("export", status)
	}
	post("logout", struct{}{}, "")
	login(secondSigner, secondID)
	if status, _ := request("GET", "/api/v1/key-pairs", "", ""); status != 200 {
		t.Fatal("logout implicitly locked vault", status)
	}
	post("lock", struct{}{}, "")
	if status, _ := request("GET", "/api/v1/auth/status", "", ""); status != 200 {
		t.Fatal("lock logged out browser", status)
	}
	if status, _ := request("GET", "/api/v1/key-pairs", "", ""); status != 423 {
		t.Fatal("global lock did not deny management", status)
	}
	halt()
	start()
	if status, _ := request("GET", "/api/v1/key-pairs", "", ""); status != 423 {
		t.Fatal("server restart resumed DEK", status)
	}
	unlock(secondSigner, secondID)
	nonceRaw := post("recovery/begin", struct{}{}, "")
	var nonce struct {
		ID string `json:"id"`
	}
	json.Unmarshal(nonceRaw, &nonce)
	verified := post("recovery/proof", map[string]string{"id": nonce.ID, "proof": crypto.Encode(initialProof)}, "")
	var recovered struct {
		CSRF    string         `json:"csrf"`
		Grant   string         `json:"grant"`
		Wrapper crypto.Wrapper `json:"wrapper"`
	}
	json.Unmarshal(verified, &recovered)
	csrf = recovered.CSRF
	round, e := recovered.Wrapper.Unwrap(root, "recovery", recovered.Wrapper.VaultID, "")
	if e != nil || !bytes.Equal(round, dek) {
		t.Fatal(e)
	}
	post("recovery/unlock", map[string]string{"grant": recovered.Grant, "dek": crypto.Encode(round)}, "")
	clear(round)
	if status, _ := request("GET", "/api/v1/data/export", "", ""); status != 403 {
		t.Fatal("recovery export", status)
	}
	replacementSigner, replacementID := enroll(nil, nil, true, 10)
	halt()
	start()
	csrf = ""
	for _, old := range []struct {
		signer *ecdsa.PrivateKey
		id     []byte
	}{{firstSigner, firstID}, {secondSigner, secondID}} {
		nonce, challenge := assertionOptions(post("login/begin", struct{}{}, ""))
		signed := fixtureAssertion(t, old.signer, old.id, initial.Owner.ID, challenge, cfg.PublicOrigin, cfg.RPID, true)
		body, _ := json.Marshal(map[string]any{"id": nonce, "credential": json.RawMessage(signed)})
		if status, _ := request("POST", "/api/v1/auth/login/finish", string(body), ""); status != 403 {
			t.Fatal("old passkey authenticated after recovery", status)
		}
	}
	login(replacementSigner, replacementID)
	if status, _ := request("GET", "/api/v1/key-pairs", "", ""); status != 423 {
		t.Fatal("replacement restart unlocked", status)
	}
	unlock(replacementSigner, replacementID)
	g = grantFor(replacementSigner, replacementID, "key_reveal", "GET", "/api/v1/key-pairs/1", "")
	if status, data := request("GET", "/api/v1/key-pairs/1", "", g); status != 200 || !bytes.Contains(data, []byte("synthetic-tls-key")) {
		t.Fatal("replacement lost secrets", status)
	}
	securityClientLifecycle(t, binaries, active, post, func(action, method, path, body string) string {
		return grantFor(replacementSigner, replacementID, action, method, path, body)
	}, func() { halt(); start() })
	unlock(replacementSigner, replacementID)
	g = grantFor(replacementSigner, replacementID, "recovery_rotate", "POST", "/api/v1/auth/recovery/rotation/key", "{}")
	delivery := post("recovery/rotation/key", struct{}{}, g)
	var rotation struct {
		ID    string `json:"id"`
		Vault string `json:"vault_id"`
	}
	json.Unmarshal(delivery, &rotation)
	newRoot := bytes.Repeat([]byte{24}, 32)
	wrapper, e := crypto.Wrap(newRoot, dek, "recovery", rotation.Vault, "", nil)
	if e != nil {
		t.Fatal(e)
	}
	salt, _ := crypto.Decode(wrapper.KDFSalt, 32)
	proof, _ := crypto.Derive(newRoot, salt, "warden/v1/recovery-auth")
	verifier := sha256.Sum256(proof)
	post("recovery/rotation/prepare", map[string]any{"id": rotation.ID, "wrapper": wrapper, "verifier": crypto.Encode(verifier[:])}, "")
	post("recovery/rotation/commit", map[string]string{"id": rotation.ID, "proof": crypto.Encode(proof), "dek": crypto.Encode(dek)}, "")
	// The OLD root with the NEW salt cannot authenticate current recovery state.
	begin := post("recovery/begin", struct{}{}, "")
	json.Unmarshal(begin, &nonce)
	oldProof, _ := crypto.Derive(root, salt, "warden/v1/recovery-auth")
	body, _ := json.Marshal(map[string]string{"id": nonce.ID, "proof": crypto.Encode(oldProof)})
	if status, _ := request("POST", "/api/v1/auth/recovery/proof", string(body), ""); status != 403 {
		t.Fatal("old recovery root still authenticated", status)
	}
	g = grantFor(replacementSigner, replacementID, "export", "GET", "/api/v1/data/export", "")
	status, exported := request("GET", "/api/v1/data/export", "", g)
	if status != 200 {
		t.Fatal("source export", status)
	}
	halt()
	active = securityInitialize(t, binaries)
	initial, dek, client = active.initial, active.dek, active.client
	cfg = config.Setup{PublicOrigin: initial.PublicOrigin, RPID: initial.RPID}
	start()
	firstID = initial.Owner.Credentials[0].ID
	login(active.signer, firstID)
	unlock(active.signer, firstID)
	g = grantFor(active.signer, firstID, "import", "POST", "/api/v1/data/import", string(exported))
	if status, _ = request("POST", "/api/v1/data/import", string(exported), g); status != 204 {
		t.Fatal("fresh destination import", status)
	}
	g = grantFor(active.signer, firstID, "export", "GET", "/api/v1/data/export", "")
	status, imported := request("GET", "/api/v1/data/export", "", g)
	if status != 200 {
		t.Fatal("destination export", status)
	}
	var source, destination map[string]any
	if json.Unmarshal(exported, &source) != nil || json.Unmarshal(imported, &destination) != nil {
		t.Fatal("invalid v1 roundtrip")
	}
	delete(source, "exported_at")
	delete(destination, "exported_at")
	a, _ := json.Marshal(source)
	b, _ := json.Marshal(destination)
	if !bytes.Equal(a, b) {
		t.Fatal("v1 roundtrip changed managed data")
	}
	if _, err := os.Stat(ambientDB); !os.IsNotExist(err) {
		t.Fatal("fixture used ambient server database instead of disposable config")
	}
}
