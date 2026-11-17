package crypto

import (
	"crypto/rand"
	"encoding/json"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

// AccountEnvelope is exclusively a password-protected DEK, not a reusable
// password verifier. Version 1 fixes the KDF costs before any allocation.
// Argon2id uses RFC 9106's second recommendation (64 MiB, 3 passes, 4 lanes).
type AccountEnvelope struct {
	Version      int    `json:"version"`
	Kind         string `json:"kind"`
	VaultID      string `json:"vault_id"`
	CredentialID string `json:"credential_id"`
	Time         uint32 `json:"time"`
	Memory       uint32 `json:"memory"`
	Threads      uint8  `json:"threads"`
	KDFSalt      string `json:"kdf_salt"`
	IV           string `json:"iv"`
	Ciphertext   string `json:"ciphertext"`
}

func ValidUsername(s string) bool {
	return len(s) > 0 && len(s) <= 64 && utf8.ValidString(s) && strings.TrimSpace(s) == s && !strings.ContainsFunc(s, unicode.IsControl)
}

// Passwords are exact UTF-8 bytes: no trimming or normalization. The upper bound
// also applies to login, before KDF work. There are no composition rules.
func ValidPassword(p []byte) bool { return len(p) >= 12 && len(p) <= 1024 && utf8.Valid(p) }
func (w AccountEnvelope) aad() []byte {
	b, _ := json.Marshal([]any{"warden", 1, "account-password-dek", w.VaultID, w.CredentialID, w.Time, w.Memory, w.Threads, w.KDFSalt})
	return b
}
func (w AccountEnvelope) Validate(vault, id string) error {
	if w.Version != 1 || w.Kind != "account" || w.Time != 3 || w.Memory != 64*1024 || w.Threads != 4 || w.VaultID != vault || w.CredentialID != id {
		return errEnvelope
	}
	for _, v := range []struct {
		s string
		n int
	}{{vault, 16}, {id, 32}, {w.KDFSalt, 32}, {w.IV, 12}, {w.Ciphertext, 48}} {
		if _, e := Decode(v.s, v.n); e != nil {
			return e
		}
	}
	return nil
}
func WrapPassword(password, dek []byte, vault, id string) (AccountEnvelope, error) {
	if !ValidPassword(password) || len(dek) != 32 {
		return AccountEnvelope{}, errEnvelope
	}
	salt, iv := make([]byte, 32), make([]byte, 12)
	if _, e := io.ReadFull(rand.Reader, salt); e != nil {
		return AccountEnvelope{}, e
	}
	if _, e := io.ReadFull(rand.Reader, iv); e != nil {
		return AccountEnvelope{}, e
	}
	w := AccountEnvelope{Version: 1, Kind: "account", VaultID: vault, CredentialID: id, Time: 3, Memory: 64 * 1024, Threads: 4, KDFSalt: Encode(salt), IV: Encode(iv), Ciphertext: Encode(make([]byte, 48))}
	if e := w.Validate(vault, id); e != nil {
		return AccountEnvelope{}, e
	}
	key := argon2.IDKey(password, salt, w.Time, w.Memory, w.Threads, 32)
	defer clear(key)
	g, e := newGCM(key)
	if e != nil {
		return AccountEnvelope{}, e
	}
	w.Ciphertext = Encode(g.Seal(nil, iv, dek, w.aad()))
	return w, nil
}
func (w AccountEnvelope) Unwrap(password []byte, vault, id string) ([]byte, error) {
	if !ValidPassword(password) {
		return nil, errEnvelope
	}
	if e := w.Validate(vault, id); e != nil {
		return nil, e
	}
	salt, _ := Decode(w.KDFSalt, 32)
	iv, _ := Decode(w.IV, 12)
	ct, _ := Decode(w.Ciphertext, 48)
	key := argon2.IDKey(password, salt, w.Time, w.Memory, w.Threads, 32)
	defer clear(key)
	g, e := newGCM(key)
	if e != nil {
		return nil, e
	}
	plain, e := g.Open(nil, iv, ct, w.aad())
	if e != nil || len(plain) != 32 {
		clear(plain)
		return nil, errEnvelope
	}
	return plain, nil
}
