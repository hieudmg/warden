package auth

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"testing"
	"time"

	"warden/internal/crypto"
)

func fixtureRegistration(t *testing.T, challenge, origin, rp string, uv bool) ([]byte, *ecdsa.PrivateKey, []byte) {
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
func fixtureAssertion(t *testing.T, key *ecdsa.PrivateKey, id, owner []byte, challenge, origin, rp string, uv bool) []byte {
	t.Helper()
	cd, _ := json.Marshal(map[string]any{"type": "webauthn.get", "challenge": challenge, "origin": origin, "crossOrigin": false})
	hash := sha256.Sum256([]byte(rp))
	flags := byte(1)
	if uv {
		flags |= 4
	}
	ad := append(hash[:], flags)
	counter := make([]byte, 4)
	binary.BigEndian.PutUint32(counter, 0)
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

func TestCeremonyRealSignedFixtures(t *testing.T) {
	v, err := NewVerifier("https://warden.example", "warden.example")
	if err != nil {
		t.Fatal(err)
	}
	owner := Owner{ID: bytes.Repeat([]byte{8}, 32)}
	creation, session, err := v.BeginRegistration(owner)
	if err != nil {
		t.Fatal(err)
	}
	if creation.Response.AuthenticatorSelection.UserVerification != "required" || creation.Response.AuthenticatorSelection.ResidentKey != "required" || len(creation.Response.Challenge) != 32 || session.Expires.IsZero() {
		t.Fatal("unsafe registration options")
	}
	body, key, id := fixtureRegistration(t, session.Challenge, "https://warden.example", "warden.example", true)
	cred, err := v.FinishRegistration(owner, *session, body)
	if err != nil {
		t.Fatal(err)
	}
	owner.Credentials = append(owner.Credentials, *cred)
	if _, err := v.FinishRegistration(owner, *session, body); err == nil {
		t.Fatal("accepted duplicate credential")
	}
	registrationExpired := *session
	registrationExpired.Expires = time.Now().Add(-time.Second)
	if _, err := v.FinishRegistration(Owner{ID: owner.ID}, registrationExpired, body); err == nil {
		t.Fatal("accepted expired registration")
	}
	if _, err := v.FinishRegistration(Owner{ID: bytes.Repeat([]byte{9}, 32)}, *session, body); err == nil {
		t.Fatal("accepted different registration owner")
	}
	for _, field := range []string{"type", "crossOrigin"} {
		var wire map[string]any
		json.Unmarshal(body, &wire)
		response := wire["response"].(map[string]any)
		raw, _ := crypto.Decode(response["clientDataJSON"].(string), -1)
		var client map[string]any
		json.Unmarshal(raw, &client)
		if field == "type" {
			client[field] = "webauthn.get"
		} else {
			client[field] = true
		}
		raw, _ = json.Marshal(client)
		response["clientDataJSON"] = crypto.Encode(raw)
		invalid, _ := json.Marshal(wire)
		if _, err := v.FinishRegistration(Owner{ID: owner.ID}, *session, invalid); err == nil {
			t.Fatal("accepted registration purpose/cross-origin mismatch", field)
		}
	}
	_, assertion, err := v.BeginAssertion(owner)
	if err != nil {
		t.Fatal(err)
	}
	signed := fixtureAssertion(t, key, id, owner.ID, assertion.Challenge, "https://warden.example", "warden.example", true)
	if _, err := v.FinishAssertion(owner, *assertion, signed); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(map[string]any){
		func(w map[string]any) { w["id"] = "AA"; w["rawId"] = "AA" },
		func(w map[string]any) { w["rawId"] = w["rawId"].(string) + "=" },
		func(w map[string]any) {
			w["clientExtensionResults"] = map[string]any{"prf": map[string]any{"results": map[string]string{"first": "raw-secret"}}}
		},
	} {
		var wire map[string]any
		json.Unmarshal(signed, &wire)
		change(wire)
		invalid, _ := json.Marshal(wire)
		if _, err := v.FinishAssertion(owner, *assertion, invalid); err == nil {
			t.Fatal("accepted unknown/malformed credential or raw PRF outputs")
		}
	}
	if _, err := v.FinishAssertion(owner, *assertion, append(append([]byte{}, signed...), []byte(` {}`)...)); err == nil {
		t.Fatal("accepted trailing JSON")
	}
	for _, tc := range []struct {
		name       string
		origin, rp string
		uv         bool
		handle     []byte
	}{
		{"origin", "https://attacker.example", "warden.example", true, owner.ID},
		{"rp", "https://warden.example", "attacker.example", true, owner.ID},
		{"uv", "https://warden.example", "warden.example", false, owner.ID},
		{"owner", "https://warden.example", "warden.example", true, bytes.Repeat([]byte{9}, 32)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := fixtureAssertion(t, key, id, tc.handle, assertion.Challenge, tc.origin, tc.rp, tc.uv)
			if _, err := v.FinishAssertion(owner, *assertion, b); err == nil {
				t.Fatal("accepted invalid assertion")
			}
		})
	}
	expired := *assertion
	expired.Expires = time.Now().Add(-time.Second)
	if _, err := v.FinishAssertion(owner, expired, signed); err == nil {
		t.Fatal("accepted expired")
	}
	other := *assertion
	other.Challenge = "wrong"
	if _, err := v.FinishAssertion(owner, other, signed); err == nil {
		t.Fatal("accepted wrong challenge")
	}
	var tamper map[string]any
	json.Unmarshal(signed, &tamper)
	tamper["response"].(map[string]any)["signature"] = crypto.Encode(make([]byte, 70))
	bad, _ := json.Marshal(tamper)
	if _, err := v.FinishAssertion(owner, *assertion, bad); err == nil {
		t.Fatal("accepted bad signature")
	}
	for _, tc := range []struct {
		origin, rp string
		uv         bool
	}{{"https://attacker.example", "warden.example", true}, {"https://warden.example", "attacker.example", true}, {"https://warden.example", "warden.example", false}} {
		b, _, _ := fixtureRegistration(t, session.Challenge, tc.origin, tc.rp, tc.uv)
		if _, err := v.FinishRegistration(Owner{ID: owner.ID}, *session, b); err == nil {
			t.Fatal("accepted invalid registration")
		}
	}
}
