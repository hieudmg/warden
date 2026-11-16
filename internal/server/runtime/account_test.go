package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"
	"warden/internal/config"
	"warden/internal/crypto"
	"warden/internal/server/auth"
	"warden/internal/server/setup"
	"warden/internal/store"
)

const accountPassword = " a correct password "

func accountFixture(t *testing.T) (*Plane, []byte) {
	t.Helper()
	key := bytes.Repeat([]byte{3}, 32)
	vault := crypto.Encode(bytes.Repeat([]byte{2}, 16))
	id := crypto.Encode(bytes.Repeat([]byte{4}, 32))
	envelope, e := crypto.WrapPassword([]byte(accountPassword), key, vault, id)
	if e != nil {
		t.Fatal(e)
	}
	recovery, _ := crypto.Wrap(bytes.Repeat([]byte{5}, 32), key, "recovery", vault, "", nil)
	check, _ := crypto.NewKeyCheck(key, vault)
	i := setup.Installation{AuthMethod: "account", Account: &setup.AccountCredential{ID: id, Username: "owner", Envelope: envelope}, Format: 1, PublicOrigin: "https://warden.example", RPID: "warden.example", Owner: auth.Owner{ID: bytes.Repeat([]byte{8}, 32)}, Recovery: recovery, RecoveryVerifier: crypto.Encode(bytes.Repeat([]byte{6}, 32)), KeyCheck: check}
	raw, _ := json.Marshal(i)
	db := filepath.Join(t.TempDir(), "vault.db")
	if e = store.CommitInstallation(context.Background(), db, raw); e != nil {
		t.Fatal(e)
	}
	v := crypto.NewVault()
	s, e := store.OpenInitialized(context.Background(), db, func([]byte) error { return nil }, v)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { v.Lock(); s.Close() })
	p, e := newPlane(config.Setup{AuthMethod: "account", PublicOrigin: i.PublicOrigin, RPID: i.RPID, Mode: "proxy", BackendAuthority: "127.0.0.1:8080"}, s, i, v, nil, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("secret")) }))
	if e != nil {
		t.Fatal(e)
	}
	return p, key
}
func accountLogin(t *testing.T, p *Plane, password string) (*http.Cookie, string) {
	t.Helper()
	w := call(p, "POST", "/api/v1/auth/account/login", map[string]string{"username": "owner", "password": password}, nil, "")
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	var b struct {
		CSRF     string `json:"csrf"`
		Unlocked bool   `json:"unlocked"`
	}
	json.Unmarshal(w.Body.Bytes(), &b)
	if !b.Unlocked || b.CSRF == "" {
		t.Fatal("not authenticated+unlocked", w.Body)
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == sessionCookie {
			return c, b.CSRF
		}
	}
	t.Fatal("no session")
	return nil, ""
}
func accountGrant(t *testing.T, p *Plane, c *http.Cookie, csrf, method, path, body string) string {
	t.Helper()
	w := call(p, "POST", "/api/v1/auth/account/fresh", map[string]string{"password": accountPassword, "action": actionFor(method, path), "method": method, "path": path, "digest": hash(body)}, c, csrf)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	var b struct {
		Grant string `json:"grant"`
	}
	json.Unmarshal(w.Body.Bytes(), &b)
	return b.Grant
}
func TestAccountRuntimeLifecycle(t *testing.T) {
	p, key := accountFixture(t)
	if w := call(p, "GET", "/api/v1/auth/method", nil, nil, ""); w.Code != 200 || !bytes.Contains(w.Body.Bytes(), []byte(`"account"`)) {
		t.Fatal(w.Code, w.Body)
	}
	if w := call(p, "GET", "/api/v1/auth/status", nil, nil, ""); w.Code != 401 {
		t.Fatal("status contract", w.Code)
	}
	for _, b := range []map[string]string{{"username": "owner", "password": "wrong password"}, {"username": "other", "password": accountPassword}} {
		if w := call(p, "POST", "/api/v1/auth/account/login", b, nil, ""); w.Code != 403 || p.vault.Unlocked() {
			t.Fatal("bad login", w.Code)
		}
	}
	if w := call(p, "POST", "/api/v1/auth/login/begin", struct{}{}, nil, ""); w.Code != 403 {
		t.Fatal("passkey in account", w.Code)
	}
	c, csrf := accountLogin(t, p, accountPassword)
	g := accountGrant(t, p, c, csrf, "GET", "/api/v1/data/export", "")
	if w := callGranted(p, "GET", "/api/v1/data/export", "", c, csrf, g); w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	if w := callGranted(p, "GET", "/api/v1/data/export", "", c, csrf, g); w.Code != 403 {
		t.Fatal("replayed", w.Code)
	}
	if w := call(p, "POST", "/api/v1/auth/lock", struct{}{}, c, csrf); w.Code != 200 || p.vault.Unlocked() {
		t.Fatal("lock", w.Code)
	}
	if w := call(p, "POST", "/api/v1/auth/account/unlock", map[string]string{"password": "wrong password"}, c, csrf); w.Code != 403 || p.vault.Unlocked() {
		t.Fatal("wrong unlock", w.Code)
	}
	if w := call(p, "POST", "/api/v1/auth/account/unlock", map[string]string{"password": accountPassword}, c, csrf); w.Code != 200 || !p.vault.Unlocked() {
		t.Fatal("unlock", w.Code, w.Body)
	}
	if w := call(p, "POST", "/api/v1/auth/logout", struct{}{}, c, csrf); w.Code != 200 || !p.vault.Unlocked() {
		t.Fatal("logout locks global vault", w.Code)
	}
	if w := call(p, "POST", "/api/v1/auth/account/unlock", map[string]string{"password": accountPassword}, c, csrf); w.Code != 401 {
		t.Fatal("revoked session", w.Code)
	}
	// A new Plane/Vault simulates locked restart against the same durable identity.
	v := crypto.NewVault()
	q, e := newPlane(p.cfg, p.store, p.install, v, nil, p.managed)
	if e != nil {
		t.Fatal(e)
	}
	defer v.Lock()
	if v.Unlocked() {
		t.Fatal("restart unlocked")
	}
	accountLogin(t, q, accountPassword)
	ctx, release, e := v.Acquire(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	round, e := v.KeyForLease(ctx)
	release()
	if e != nil || !bytes.Equal(round, key) {
		t.Fatal("changed DEK")
	}
	clear(round)
}
func TestAccountRecoveryReplacesPasswordSameDEK(t *testing.T) {
	p, key := accountFixture(t)
	c, csrf := accountLogin(t, p, accountPassword)
	secret, _, _ := pairedFixture(t, p, func(id, commitment string) {
		body := `{"id":"` + id + `","commitment":"` + commitment + `"}`
		g := accountGrant(t, p, c, csrf, "POST", "/api/v1/auth/clients/approve", body)
		if w := callGranted(p, "POST", "/api/v1/auth/clients/approve", body, c, csrf, g); w.Code != 200 {
			t.Fatal(w.Code, w.Body)
		}
	}, 90)
	_, proof := recoveryFixture(t, p, key)
	old, _ := p.current(context.Background())
	recovery, rcsrf, g := startRecovery(t, p, proof)
	if w := call(p, "POST", "/api/v1/auth/recovery/unlock", map[string]string{"grant": g, "dek": crypto.Encode(key)}, recovery, rcsrf); w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	if w := call(p, "GET", "/api/v1/data/export", nil, recovery, rcsrf); w.Code != 403 {
		t.Fatal("recovery management", w.Code)
	}
	b := map[string]string{"password": " replacement password ", "password_confirmation": "mismatch"}
	if w := call(p, "POST", "/api/v1/auth/account/reset", b, recovery, rcsrf); w.Code != 400 {
		t.Fatal("mismatch", w.Code, w.Body)
	}
	current, _ := p.current(context.Background())
	if current.Account.ID != old.Account.ID {
		t.Fatal("failed reset changed identity")
	}
	b["password_confirmation"] = b["password"]
	if w := call(p, "POST", "/api/v1/auth/account/reset", b, recovery, rcsrf); w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	current, e := p.current(context.Background())
	if e != nil || current.Account.ID == old.Account.ID || current.KeyCheck != old.KeyCheck || current.Recovery != old.Recovery || current.AuthorizationGeneration != old.AuthorizationGeneration+1 || p.vault.Unlocked() {
		t.Fatal("replacement contract", e)
	}
	if w := call(p, "GET", "/api/v1/auth/status", nil, c, csrf); w.Code != 401 {
		t.Fatal("old session", w.Code)
	}
	if w := clientCall(p, "GET", "/api/v1/client/status", "", secret); w.Code != 401 {
		t.Fatal("old client", w.Code)
	}
	if w := call(p, "POST", "/api/v1/auth/account/login", map[string]string{"username": "owner", "password": accountPassword}, nil, ""); w.Code != 403 {
		t.Fatal("old password", w.Code)
	}
	accountLogin(t, p, b["password"])
}
