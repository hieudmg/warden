package setup

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"warden/internal/crypto"
)

type installationWire Installation

// Unreleased format-1 checkpoints used a singular wrapper. Read them without
// changing any key or credential; reject conflicting representations.
func (i Installation) MarshalJSON() ([]byte, error) {
	if len(i.Passkeys) == 0 && i.Passkey.Version != 0 {
		i.Passkeys = []crypto.Wrapper{i.Passkey}
	}
	return json.Marshal(installationWire(i))
}
func (i *Installation) UnmarshalJSON(raw []byte) error {
	var wire struct {
		installationWire
		Legacy *crypto.Wrapper `json:"passkey_wrapper,omitempty"`
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&wire); err != nil {
		return err
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("invalid installation")
	}
	*i = Installation(wire.installationWire)
	if wire.Legacy != nil {
		if len(i.Passkeys) != 0 {
			return errors.New("ambiguous passkey wrappers")
		}
		i.Passkeys = []crypto.Wrapper{*wire.Legacy}
	}
	if len(i.Passkeys) > 0 {
		i.Passkey = i.Passkeys[0]
	}
	return nil
}
