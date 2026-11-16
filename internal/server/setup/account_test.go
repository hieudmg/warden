package setup

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"warden/internal/crypto"
)

func TestAccountSetupConfirmation(t *testing.T) {
	p, _ := plane(t)
	p.cfg.AuthMethod = "account"
	var committed []byte
	p.commit = func(_ context.Context, b []byte) error { committed = append([]byte(nil), b...); return nil }
	cookie, csrf := authorize(t, p)
	if w := request(p, "/api/v1/setup/registration/begin", struct{}{}, cookie, csrf); w.Code != 403 {
		t.Fatal("wrong mode", w.Code)
	}
	w := request(p, "/api/v1/setup/account/begin", struct{}{}, cookie, csrf)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	var begin struct {
		Vault string `json:"vault_id"`
	}
	json.Unmarshal(w.Body.Bytes(), &begin)
	dek, root := bytes.Repeat([]byte{7}, 32), bytes.Repeat([]byte{8}, 32)
	rw, e := crypto.Wrap(root, dek, "recovery", begin.Vault, "", nil)
	if e != nil {
		t.Fatal(e)
	}
	salt, _ := crypto.Decode(rw.KDFSalt, 32)
	proof, _ := crypto.Derive(root, salt, "warden/v1/recovery-auth")
	b := map[string]any{"username": "owner", "password": " correct password ", "password_confirmation": "wrong", "recovery_wrapper": rw, "recovery_verifier": hashToken(proof), "dek": crypto.Encode(dek)}
	if w = request(p, "/api/v1/setup/account/prepare", b, cookie, csrf); w.Code != 400 || committed != nil {
		t.Fatal("bad confirmation", w.Code)
	}
	b["password_confirmation"] = b["password"]
	if w = request(p, "/api/v1/setup/account/prepare", b, cookie, csrf); w.Code != 200 || committed != nil {
		t.Fatal("prepare", w.Code, w.Body)
	}
	if w = request(p, "/api/v1/setup/finalize", Confirmation{RecoveryAuth: crypto.Encode(make([]byte, 32)), DEK: crypto.Encode(dek)}, cookie, csrf); w.Code != 400 || committed != nil {
		t.Fatal("bad recovery confirmed", w.Code)
	}
	if w = request(p, "/api/v1/setup/finalize", Confirmation{RecoveryAuth: crypto.Encode(proof), DEK: crypto.Encode(dek)}, cookie, csrf); w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	var i Installation
	if e = json.Unmarshal(committed, &i); e != nil {
		t.Fatal(e)
	}
	if i.AuthMethod != "account" || i.Account == nil || len(i.Owner.Credentials) != 0 || len(i.Passkeys) != 0 {
		t.Fatal("mixed identity")
	}
	key, e := i.Account.Envelope.Unwrap([]byte(" correct password "), begin.Vault, i.Account.ID)
	if e != nil || !bytes.Equal(key, dek) {
		t.Fatal("producer consumer", e)
	}
	clear(key)
	if bytes.Contains(committed, []byte("correct password")) {
		t.Fatal("plaintext password")
	}
}
