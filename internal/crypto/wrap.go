package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
)

var errEnvelope = errors.New("invalid vault envelope")

type Wrapper struct {
	Version      int    `json:"version"`
	Kind         string `json:"kind"`
	VaultID      string `json:"vault_id"`
	CredentialID string `json:"credential_id"`
	KDFSalt      string `json:"kdf_salt"`
	IV           string `json:"iv"`
	Ciphertext   string `json:"ciphertext"`
	PRFInput     string `json:"prf_input,omitempty"`
}

func Encode(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
func Decode(s string, n int) ([]byte, error) {
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil || Encode(b) != s || (n >= 0 && len(b) != n) {
		return nil, errEnvelope
	}
	return b, nil
}
func Derive(material, salt []byte, info string) ([]byte, error) {
	if len(material) != 32 || len(salt) != 32 {
		return nil, errEnvelope
	}
	return hkdf.Key(sha256.New, material, salt, info, 32)
}
func (w Wrapper) AAD() ([]byte, error) {
	if w.Version != 1 || (w.Kind != "passkey" && w.Kind != "recovery") {
		return nil, errEnvelope
	}
	if _, err := Decode(w.VaultID, 16); err != nil {
		return nil, err
	}
	if w.Kind == "recovery" {
		if w.CredentialID != "" || w.PRFInput != "" {
			return nil, errEnvelope
		}
	} else {
		id, err := Decode(w.CredentialID, -1)
		if err != nil || len(id) == 0 || len(id) > 1024 {
			return nil, errEnvelope
		}
		if _, err := Decode(w.PRFInput, 32); err != nil {
			return nil, err
		}
	}
	return json.Marshal([]any{"warden", 1, w.Kind, w.VaultID, w.CredentialID})
}
func (w Wrapper) Validate(kind, vault, id string) error {
	if w.Kind != kind || w.VaultID != vault || w.CredentialID != id {
		return errEnvelope
	}
	if _, err := w.AAD(); err != nil {
		return err
	}
	for _, v := range []struct {
		s string
		n int
	}{{w.KDFSalt, 32}, {w.IV, 12}, {w.Ciphertext, 48}} {
		if _, err := Decode(v.s, v.n); err != nil {
			return err
		}
	}
	return nil
}
func Wrap(material, dek []byte, kind, vault, id string, rng io.Reader) (Wrapper, error) {
	if len(material) != 32 || len(dek) != 32 {
		return Wrapper{}, errEnvelope
	}
	if rng == nil {
		rng = rand.Reader
	}
	w := Wrapper{Version: 1, Kind: kind, VaultID: vault, CredentialID: id}
	salt := make([]byte, 32)
	iv := make([]byte, 12)
	if _, err := io.ReadFull(rng, salt); err != nil {
		return Wrapper{}, err
	}
	if _, err := io.ReadFull(rng, iv); err != nil {
		return Wrapper{}, err
	}
	w.KDFSalt = Encode(salt)
	w.IV = Encode(iv)
	if kind == "passkey" {
		input := make([]byte, 32)
		if _, err := io.ReadFull(rng, input); err != nil {
			return Wrapper{}, err
		}
		w.PRFInput = Encode(input)
	}
	aad, err := w.AAD()
	if err != nil {
		return Wrapper{}, err
	}
	kek, err := Derive(material, salt, "warden/v1/"+kind+"-wrap")
	if err != nil {
		return Wrapper{}, err
	}
	defer clear(kek)
	gcm, err := newGCM(kek)
	if err != nil {
		return Wrapper{}, err
	}
	w.Ciphertext = Encode(gcm.Seal(nil, iv, dek, aad))
	return w, nil
}
func (w Wrapper) Unwrap(material []byte, kind, vault, id string) ([]byte, error) {
	if err := w.Validate(kind, vault, id); err != nil {
		return nil, err
	}
	salt, _ := Decode(w.KDFSalt, 32)
	iv, _ := Decode(w.IV, 12)
	ct, _ := Decode(w.Ciphertext, 48)
	aad, _ := w.AAD()
	kek, err := Derive(material, salt, "warden/v1/"+kind+"-wrap")
	if err != nil {
		return nil, err
	}
	defer clear(kek)
	gcm, err := newGCM(kek)
	if err != nil {
		return nil, err
	}
	plain, err := gcm.Open(nil, iv, ct, aad)
	if err != nil || len(plain) != 32 {
		clear(plain)
		return nil, errEnvelope
	}
	return plain, nil
}
func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// KeyCheck authenticates an installation's DEK, never derives or recovers it.
// The separate purpose in AAD prevents using a wrapper as a key check.
type KeyCheck struct {
	Version    int    `json:"version"`
	VaultID    string `json:"vault_id"`
	IV         string `json:"iv"`
	Ciphertext string `json:"ciphertext"`
}

func checkAAD(vault string) []byte {
	b, _ := json.Marshal([]any{"warden", 1, "key-check", vault, ""})
	return b
}

var checkPlain = []byte("warden/v1/vault-key-check")

func NewKeyCheck(key []byte, vault string) (KeyCheck, error) {
	if len(key) != 32 {
		return KeyCheck{}, errEnvelope
	}
	if _, err := Decode(vault, 16); err != nil {
		return KeyCheck{}, err
	}
	iv := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return KeyCheck{}, err
	}
	gcm, err := newGCM(key)
	if err != nil {
		return KeyCheck{}, err
	}
	return KeyCheck{1, vault, Encode(iv), Encode(gcm.Seal(nil, iv, checkPlain, checkAAD(vault)))}, nil
}
func (c KeyCheck) Verify(key []byte, vault string) error {
	if c.Version != 1 || c.VaultID != vault || len(key) != 32 {
		return errEnvelope
	}
	if _, err := Decode(vault, 16); err != nil {
		return err
	}
	iv, err := Decode(c.IV, 12)
	if err != nil {
		return err
	}
	ct, err := Decode(c.Ciphertext, len(checkPlain)+16)
	if err != nil {
		return err
	}
	gcm, err := newGCM(key)
	if err != nil {
		return err
	}
	p, err := gcm.Open(nil, iv, ct, checkAAD(vault))
	defer clear(p)
	if err != nil || !bytes.Equal(p, checkPlain) {
		return errEnvelope
	}
	return nil
}
