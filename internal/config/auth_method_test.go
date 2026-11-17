package config

import (
	"encoding/json"
	"testing"
)

func TestAuthMethodLegacyAndExplicit(t *testing.T) {
	var s Setup
	if e := json.Unmarshal([]byte(`{"public_origin":"https://localhost","rp_id":"localhost","mode":"proxy","backend_authority":"127.0.0.1:8080"}`), &s); e != nil {
		t.Fatal(e)
	}
	if s.AuthenticationMethod() != "passkey" {
		t.Fatal("legacy reinterpreted")
	}
	for _, m := range []string{"account", "passkey"} {
		s.AuthMethod = m
		if s.AuthenticationMethod() != m || s.Validate("127.0.0.1:8080") != nil {
			t.Fatal(m)
		}
	}
	for _, m := range []string{"none", "Account", "disabled"} {
		s.AuthMethod = m
		if s.Validate("127.0.0.1:8080") == nil {
			t.Fatal("accepted mode", m)
		}
	}
}
