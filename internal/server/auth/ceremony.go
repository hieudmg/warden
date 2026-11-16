// Package auth verifies WebAuthn identity independently of client PRF output.
package auth

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"warden/internal/crypto"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

type Owner struct {
	ID          []byte                `json:"id"`
	Credentials []webauthn.Credential `json:"credentials"`
}

func (o Owner) WebAuthnID() []byte                         { return o.ID }
func (o Owner) WebAuthnName() string                       { return "owner" }
func (o Owner) WebAuthnDisplayName() string                { return "Warden owner" }
func (o Owner) WebAuthnCredentials() []webauthn.Credential { return o.Credentials }

type Verifier struct{ w *webauthn.WebAuthn }

func NewVerifier(origin, rp string) (*Verifier, error) {
	timeout := webauthn.TimeoutConfig{Enforce: true, Timeout: 5 * time.Minute, TimeoutUVD: 5 * time.Minute}
	w, err := webauthn.New(&webauthn.Config{RPID: rp, RPDisplayName: "Warden", RPOrigins: []string{origin}, AttestationPreference: protocol.PreferNoAttestation, AuthenticatorSelection: protocol.AuthenticatorSelection{UserVerification: protocol.VerificationRequired}, Timeouts: webauthn.TimeoutsConfig{Login: timeout, Registration: timeout}})
	if err != nil {
		return nil, err
	}
	return &Verifier{w}, nil
}
func (v *Verifier) BeginRegistration(o Owner) (*protocol.CredentialCreation, *webauthn.SessionData, error) {
	return v.w.BeginRegistration(o, webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired), webauthn.WithExtensions(protocol.AuthenticationExtensions{"prf": map[string]any{}}))
}
func (v *Verifier) BeginAssertion(o Owner) (*protocol.CredentialAssertion, *webauthn.SessionData, error) {
	return v.w.BeginLogin(o)
}
func ceremonyRequest(body []byte) (*http.Request, error) {
	// Intentionally no generic client-extension serialization: PRF values belong
	// only to WebCrypto. Canonical credential IDs also prevent alternate encodings.
	var c struct {
		ID         string                     `json:"id"`
		RawID      string                     `json:"rawId"`
		Type       string                     `json:"type"`
		Response   json.RawMessage            `json:"response"`
		Extensions map[string]json.RawMessage `json:"clientExtensionResults"`
		Attachment string                     `json:"authenticatorAttachment,omitempty"`
	}
	d := json.NewDecoder(bytes.NewReader(body))
	d.DisallowUnknownFields()
	if err := d.Decode(&c); err != nil {
		return nil, err
	}
	id, err := crypto.Decode(c.RawID, -1)
	if err != nil || len(id) == 0 || len(id) > 1024 || c.ID != c.RawID || c.Type != "public-key" || len(c.Extensions) != 0 {
		return nil, errors.New("invalid credential response")
	}
	return http.NewRequest(http.MethodPost, "https://ceremony.invalid", bytes.NewReader(body))
}
func (v *Verifier) FinishRegistration(o Owner, s webauthn.SessionData, body []byte) (*webauthn.Credential, error) {
	r, err := ceremonyRequest(body)
	if err != nil {
		return nil, err
	}
	cred, err := v.w.FinishRegistration(o, s, r)
	if err != nil {
		return nil, err
	}
	for _, existing := range o.Credentials {
		if bytes.Equal(existing.ID, cred.ID) {
			return nil, errors.New("duplicate credential")
		}
	}
	return cred, nil
}
func (v *Verifier) FinishAssertion(o Owner, s webauthn.SessionData, body []byte) (*webauthn.Credential, error) {
	r, err := ceremonyRequest(body)
	if err != nil {
		return nil, err
	}
	return v.w.FinishLogin(o, s, r)
}
