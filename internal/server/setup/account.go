package setup

import (
	"bytes"
	"net/http"
	"warden/internal/crypto"
)

func (i Installation) AuthenticationMethod() string {
	if i.AuthMethod == "" {
		return "passkey"
	}
	return i.AuthMethod
}

// Called with mu held, but password KDF work must not block shutdown or other
// requests. Reserving the phase prevents concurrent prepares from publishing.
func (p *Plane) prepareAccount(w http.ResponseWriter, r *http.Request, body []byte) {
	if p.phase != "authorized" {
		reject(w, 409)
		return
	}
	var b struct {
		Username     string         `json:"username"`
		Password     string         `json:"password"`
		Confirmation string         `json:"password_confirmation"`
		Recovery     crypto.Wrapper `json:"recovery_wrapper"`
		Verifier     string         `json:"recovery_verifier"`
		DEK          string         `json:"dek"`
	}
	if strict(body, &b) != nil || !crypto.ValidUsername(b.Username) || !crypto.ValidPassword([]byte(b.Password)) || b.Password != b.Confirmation || b.Recovery.Validate("recovery", p.vaultID, "") != nil {
		reject(w, 400)
		return
	}
	if _, e := crypto.Decode(b.Verifier, 32); e != nil {
		reject(w, 400)
		return
	}
	dek, e := crypto.Decode(b.DEK, 32)
	if e != nil {
		reject(w, 400)
		return
	}
	defer clear(dek)
	id, e := randomToken(32)
	if e != nil {
		reject(w, 500)
		return
	}
	password := []byte(b.Password)
	b.Password = ""
	b.Confirmation = ""
	defer clear(password)
	p.phase = "account-working"
	p.mu.Unlock()
	envelope, e := crypto.WrapPassword(password, dek, p.vaultID, id)
	var round []byte
	if e == nil {
		round, e = envelope.Unwrap(password, p.vaultID, id)
	}
	check, checkErr := crypto.NewKeyCheck(dek, p.vaultID)
	p.mu.Lock()
	defer clear(round)
	if p.closed() || !p.now().Before(p.deadline) {
		p.stop()
		reject(w, 410)
		return
	}
	if r.Context().Err() != nil || !p.authorized(r) || p.phase != "account-working" {
		reject(w, 403)
		return
	}
	p.phase = "authorized"
	if e != nil || checkErr != nil || !bytes.Equal(round, dek) {
		reject(w, 500)
		return
	}
	p.pending = &Installation{AuthMethod: "account", Account: &AccountCredential{ID: id, Username: b.Username, Envelope: envelope}, Format: 1, PublicOrigin: p.cfg.PublicOrigin, RPID: p.cfg.RPID, Owner: p.owner, Recovery: b.Recovery, RecoveryVerifier: b.Verifier, KeyCheck: check}
	p.phase = "prepared"
	respond(w, 200, map[string]bool{"prepared": true})
}
