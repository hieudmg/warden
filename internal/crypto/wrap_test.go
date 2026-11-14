package crypto

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestWrapContractAndRecoverySavedRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 32)
	dek := bytes.Repeat([]byte{2}, 32)
	vault := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{3}, 16))
	credential := base64.RawURLEncoding.EncodeToString([]byte("credential"))
	for _, kind := range []string{"passkey", "recovery"} {
		id := credential
		if kind == "recovery" {
			id = ""
		}
		w, err := Wrap(key, dek, kind, vault, id, bytes.NewReader(bytes.Repeat([]byte{4}, 128)))
		if err != nil {
			t.Fatal(err)
		}
		aad, _ := w.AAD()
		want := `["warden",1,"` + kind + `","` + vault + `","` + id + `"]`
		if string(aad) != want {
			t.Fatalf("AAD %s want %s", aad, want)
		}
		got, err := w.Unwrap(key, kind, vault, id)
		if err != nil || !bytes.Equal(got, dek) {
			t.Fatalf("roundtrip: %v", err)
		}
		for _, change := range []func(*Wrapper){
			func(w *Wrapper) { w.Version = 2 }, func(w *Wrapper) { w.Kind = "other" }, func(w *Wrapper) { w.VaultID = credential },
			func(w *Wrapper) { w.CredentialID = "wrong" }, func(w *Wrapper) { w.IV = "AA" },
			func(w *Wrapper) { w.KDFSalt = strings.Repeat("A", 43) }, func(w *Wrapper) { w.Ciphertext = w.Ciphertext[:10] },
			func(w *Wrapper) {
				b, _ := base64.RawURLEncoding.DecodeString(w.Ciphertext)
				b[0] ^= 1
				w.Ciphertext = base64.RawURLEncoding.EncodeToString(b)
			},
		} {
			bad := w
			change(&bad)
			plain, err := bad.Unwrap(key, kind, vault, id)
			if err == nil || len(plain) != 0 {
				t.Fatal("accepted malformed/tampered wrapper")
			}
		}
		plain, err := w.Unwrap(bytes.Repeat([]byte{9}, 32), kind, vault, id)
		if err == nil || len(plain) != 0 {
			t.Fatal("wrong key accepted")
		}
	}
	if _, err := Wrap(key, dek, "recovery", vault, "", bytes.NewReader(nil)); err == nil {
		t.Fatal("RNG failure accepted")
	}
	if _, err := Wrap(key, dek[:31], "recovery", vault, "", nil); err == nil {
		t.Fatal("bad DEK accepted")
	}
	a, _ := Wrap(key, dek, "recovery", vault, "", nil)
	b, _ := Wrap(key, dek, "recovery", vault, "", nil)
	if a.IV == b.IV {
		t.Fatal("reused IV")
	}
}

func TestWrapSharedWebCryptoVector(t *testing.T) {
	for _, path := range []string{"testdata/wrap-v1.json", "testdata/wrap-recovery-v1.json"} {
		t.Run(path, func(t *testing.T) {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var v struct {
				Material, DEK, KEK, AAD string
				Wrapper                 Wrapper
				RecoveryAuth            string `json:"recovery_auth"`
				RecoveryVerifier        string `json:"recovery_verifier"`
			}
			if err := json.Unmarshal(data, &v); err != nil {
				t.Fatal(err)
			}
			material, _ := Decode(v.Material, 32)
			salt, _ := Decode(v.Wrapper.KDFSalt, 32)
			kek, err := Derive(material, salt, "warden/v1/"+v.Wrapper.Kind+"-wrap")
			if err != nil || Encode(kek) != v.KEK {
				t.Fatal("KDF bytes differ", err)
			}
			aad, _ := v.Wrapper.AAD()
			if string(aad) != v.AAD {
				t.Fatal("AAD bytes differ")
			}
			dek, err := v.Wrapper.Unwrap(material, v.Wrapper.Kind, v.Wrapper.VaultID, v.Wrapper.CredentialID)
			if err != nil || Encode(dek) != v.DEK {
				t.Fatal("WebCrypto vector differs", err)
			}
			if v.RecoveryAuth != "" {
				proof, err := Derive(material, salt, "warden/v1/recovery-auth")
				if err != nil || Encode(proof) != v.RecoveryAuth {
					t.Fatal("recovery auth bytes differ", err)
				}
				hash := sha256.Sum256(proof)
				if Encode(hash[:]) != v.RecoveryVerifier {
					t.Fatal("recovery verifier bytes differ")
				}
			}
		})
	}
}

func TestVaultKeyCheckHasNoKeyFallback(t *testing.T) {
	key := bytes.Repeat([]byte{2}, 32)
	vault := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{3}, 16))
	check, err := NewKeyCheck(key, vault)
	if err != nil {
		t.Fatal(err)
	}
	if err := check.Verify(key, vault); err != nil {
		t.Fatal(err)
	}
	if err := check.Verify(bytes.Repeat([]byte{4}, 32), vault); err == nil {
		t.Fatal("wrong key accepted")
	}
	if err := check.Verify(key, base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{4}, 16))); err == nil {
		t.Fatal("wrong vault accepted")
	}
}
