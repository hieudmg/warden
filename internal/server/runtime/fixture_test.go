package runtime

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"testing"

	"warden/internal/crypto"
)

func fixtureRegistration(t *testing.T, challenge, origin, rp string, uv bool, extraFlags ...byte) ([]byte, *ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := bytes.Repeat([]byte{7}, 20)
	cose := []byte{0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20}
	cose = append(cose, key.X.FillBytes(make([]byte, 32))...)
	cose = append(cose, 0x22, 0x58, 0x20)
	cose = append(cose, key.Y.FillBytes(make([]byte, 32))...)
	hash := sha256.Sum256([]byte(rp))
	flags := byte(0x41)
	if len(extraFlags) > 0 {
		flags |= extraFlags[0]
	}
	if uv {
		flags |= 4
	}
	ad := append(hash[:], flags, 0, 0, 0, 0)
	ad = append(ad, make([]byte, 16)...)
	ad = append(ad, 0, byte(len(id)))
	ad = append(ad, id...)
	ad = append(ad, cose...)
	att := []byte{0xa3, 0x63, 'f', 'm', 't', 0x64, 'n', 'o', 'n', 'e', 0x67, 'a', 't', 't', 'S', 't', 'm', 't', 0xa0, 0x68, 'a', 'u', 't', 'h', 'D', 'a', 't', 'a', 0x58, byte(len(ad))}
	att = append(att, ad...)
	cd, _ := json.Marshal(map[string]any{"type": "webauthn.create", "challenge": challenge, "origin": origin, "crossOrigin": false})
	b, _ := json.Marshal(map[string]any{"id": crypto.Encode(id), "rawId": crypto.Encode(id), "type": "public-key", "response": map[string]any{"clientDataJSON": crypto.Encode(cd), "attestationObject": crypto.Encode(att)}, "clientExtensionResults": map[string]any{}})
	return b, key, id
}
func fixtureAssertion(t *testing.T, key *ecdsa.PrivateKey, id, owner []byte, challenge, origin, rp string, uv bool, counts ...uint32) []byte {
	t.Helper()
	cd, _ := json.Marshal(map[string]any{"type": "webauthn.get", "challenge": challenge, "origin": origin, "crossOrigin": false})
	hash := sha256.Sum256([]byte(rp))
	flags := byte(1)
	if len(counts) > 1 {
		flags |= byte(counts[1])
	}
	if uv {
		flags |= 4
	}
	ad := append(hash[:], flags)
	counter := make([]byte, 4)
	var count uint32
	if len(counts) > 0 {
		count = counts[0]
	}
	binary.BigEndian.PutUint32(counter, count)
	ad = append(ad, counter...)
	ch := sha256.Sum256(cd)
	msg := append(append([]byte{}, ad...), ch[:]...)
	digest := sha256.Sum256(msg)
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(map[string]any{"id": crypto.Encode(id), "rawId": crypto.Encode(id), "type": "public-key", "response": map[string]any{"clientDataJSON": crypto.Encode(cd), "authenticatorData": crypto.Encode(ad), "signature": crypto.Encode(sig), "userHandle": crypto.Encode(owner)}, "clientExtensionResults": map[string]any{}})
	return b
}
