package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"warden/internal/crypto"
	"warden/internal/server/setup"
)

func TestInitializedPasskeyCollectionPreservesCheckpoint(t *testing.T) {
	p, _, original, key, _ := runtimeFixture(t)
	raw, _ := json.Marshal(original)
	var fields map[string]json.RawMessage
	json.Unmarshal(raw, &fields)
	if _, ok := fields["passkey_wrappers"]; !ok {
		t.Fatal("init still writes singular wrapper")
	}
	// The already-supported T1/T2 checkpoint remains readable, not discarded.
	delete(fields, "passkey_wrappers")
	fields["passkey_wrapper"], _ = json.Marshal(original.Passkey)
	legacy, _ := json.Marshal(fields)
	converted, err := validateInstallation(legacy, p.cfg)
	if err != nil {
		t.Fatal(err)
	}
	saved, _ := json.Marshal(converted)
	if !bytes.Contains(saved, []byte(`"passkey_wrappers"`)) {
		t.Fatal("checkpoint not evolved")
	}
	if converted.KeyCheck.Verify(key, original.Passkey.VaultID) != nil || converted.Recovery != original.Recovery {
		t.Fatal("checkpoint material lost")
	}
	var round setup.Installation
	if json.Unmarshal(saved, &round) != nil || len(round.Passkeys) != 1 || round.Passkeys[0] != original.Passkey {
		t.Fatal("wrapper lost")
	}
	// Multiple credentials require exactly one wrapper each, with one vault.
	extra := original.Owner.Credentials[0]
	extra.ID = []byte("second credential")
	round.Owner.Credentials = append(round.Owner.Credentials, extra)
	w, _ := crypto.Wrap(bytes.Repeat([]byte{9}, 32), key, "passkey", original.Passkey.VaultID, crypto.Encode(extra.ID), nil)
	round.Passkeys = append(round.Passkeys, w)
	raw, _ = json.Marshal(round)
	if _, err = validateInstallation(raw, p.cfg); err != nil {
		t.Fatal(err)
	}
	round.Passkeys = round.Passkeys[:1]
	raw, _ = json.Marshal(round)
	if _, err = validateInstallation(raw, p.cfg); err == nil {
		t.Fatal("credential without wrapper accepted")
	}
}

func TestDeletedCredentialSessionChecksCurrentInstallation(t *testing.T) {
	p, _, i, _, _ := runtimeFixture(t)
	browser, csrf := sessionFor(t, p)
	// Simulate a committed removal/replacement while the plane still has its old snapshot.
	i.Owner.Credentials[0].ID = []byte("replacement")
	i.Passkey.CredentialID = crypto.Encode(i.Owner.Credentials[0].ID)
	raw, _ := json.Marshal(i)
	if err := p.store.UpdateInstallation(context.Background(), raw); err != nil {
		t.Fatal(err)
	}
	if got := call(p, "GET", "/api/v1/auth/status", nil, browser, csrf); got.Code != 401 {
		t.Fatalf("deleted credential session accepted: %d", got.Code)
	}
}
