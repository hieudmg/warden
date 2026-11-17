package runtime

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"warden/internal/crypto"
)

// Real init/serve binaries and a pinned disposable CA. No seeded session,
// WebAuthn, PRF substitute, system trust mutation, or plaintext disk-key fallback.
func TestAccountSecurityLifecycleHTTPS(t *testing.T) {
	binaries := securityBinaries(t)
	s := securityInitialize(t, binaries, "account")
	if s.initial.AuthMethod != "account" || s.initial.Account == nil {
		t.Fatal("not account installation")
	}
	var stop func()
	start := func() { stop = securityServe(t, binaries, s) }
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
		req, e := http.NewRequest(method, s.origin+path, bytes.NewBufferString(body))
		if e != nil {
			t.Fatal(e)
		}
		req.Header.Set("Origin", s.origin)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-CSRF-Token", csrf)
		req.Header.Set("X-Warden-Action", grant)
		res, e := s.client.Do(req)
		if e != nil {
			t.Fatal(e)
		}
		defer res.Body.Close()
		b, e := io.ReadAll(res.Body)
		if e != nil {
			t.Fatal(e)
		}
		if res.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("cache policy")
		}
		return res.StatusCode, b
	}
	post := func(path string, body any, grant string) []byte {
		t.Helper()
		b, _ := json.Marshal(body)
		status, result := request("POST", "/api/v1/auth/"+path, string(b), grant)
		if status != 200 {
			t.Fatalf("%s: %d", path, status)
		}
		return result
	}
	password := accountPassword
	login := func() {
		t.Helper()
		raw := post("account/login", map[string]string{"username": "owner", "password": password}, "")
		var b struct {
			CSRF     string `json:"csrf"`
			Unlocked bool   `json:"unlocked"`
		}
		json.Unmarshal(raw, &b)
		if b.CSRF == "" || !b.Unlocked {
			t.Fatal("login did not unlock")
		}
		csrf = b.CSRF
	}
	grantFor := func(action, method, path, body string) string {
		t.Helper()
		raw := post("account/fresh", map[string]string{"password": password, "action": action, "method": method, "path": path, "digest": hash(body)}, "")
		var b struct {
			Grant string `json:"grant"`
		}
		json.Unmarshal(raw, &b)
		if b.Grant == "" {
			t.Fatal("missing grant")
		}
		return b.Grant
	}
	if status, _ := request("GET", "/api/v1/auth/status", "", ""); status != 401 {
		t.Fatal("anonymous status", status)
	}
	login()
	raw := `{"name":"account-secret","private_key":"private account lifecycle key"}`
	g := grantFor("key_mutation", "POST", "/api/v1/key-pairs", raw)
	if status, _ := request("POST", "/api/v1/key-pairs", raw, g); status != 201 {
		t.Fatal("create key", status)
	}
	g = grantFor("export", "GET", "/api/v1/data/export", "")
	status, exported := request("GET", "/api/v1/data/export", "", g)
	if status != 200 || !bytes.Contains(exported, []byte("private account lifecycle key")) {
		t.Fatal("export", status)
	}
	if status, _ := request("GET", "/api/v1/data/export", "", g); status != 403 {
		t.Fatal("reused grant", status)
	}
	post("lock", struct{}{}, "")
	if status, _ := request("GET", "/api/v1/key-pairs", "", ""); status != 423 {
		t.Fatal("lock", status)
	}
	post("account/unlock", map[string]string{"password": password}, "")
	post("logout", struct{}{}, "")
	if status, _ := request("GET", "/api/v1/auth/status", "", ""); status != 401 {
		t.Fatal("logout", status)
	}
	login()
	halt()
	start()
	if status, b := request("GET", "/api/v1/auth/status", "", ""); status != 200 || !bytes.Contains(b, []byte(`"unlocked":false`)) {
		t.Fatal("restart not locked", status)
	}
	post("account/unlock", map[string]string{"password": password}, "")
	// Exercise actual CLI pairing, persistent verifier, restart and revocation.
	securityClientLifecycle(t, binaries, s, post, grantFor, func() { halt(); start() })
	var nonce struct {
		ID string `json:"id"`
	}
	json.Unmarshal(post("recovery/begin", struct{}{}, ""), &nonce)
	var recovery struct {
		CSRF    string         `json:"csrf"`
		Grant   string         `json:"grant"`
		Wrapper crypto.Wrapper `json:"wrapper"`
	}
	json.Unmarshal(post("recovery/proof", map[string]string{"id": nonce.ID, "proof": crypto.Encode(s.proof)}, ""), &recovery)
	csrf = recovery.CSRF
	round, e := recovery.Wrapper.Unwrap(s.root, "recovery", s.initial.KeyCheck.VaultID, "")
	if e != nil || !bytes.Equal(round, s.dek) {
		t.Fatal("same recovery DEK", e)
	}
	defer clear(round)
	post("recovery/unlock", map[string]string{"grant": recovery.Grant, "dek": crypto.Encode(round)}, "")
	if status, _ := request("GET", "/api/v1/data/export", "", ""); status != 403 {
		t.Fatal("restricted recovery", status)
	}
	password = " replacement account password "
	post("account/reset", map[string]string{"password": password, "password_confirmation": password}, "")
	if status, _ := request("POST", "/api/v1/auth/account/login", `{"username":"owner","password":" a correct password "}`, ""); status != 403 {
		t.Fatal("old password", status)
	}
	login()
	g = grantFor("export", "GET", "/api/v1/data/export", "")
	status, after := request("GET", "/api/v1/data/export", "", g)
	if status != 200 || !bytes.Contains(after, []byte("private account lifecycle key")) {
		t.Fatal("same data after recovery", status)
	}
	t.Log("production init/account login+unlock/export/lock/logout/restart/CLI pairing+revocation/password recovery PASS")
}
