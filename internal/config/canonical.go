package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

// encoding/json's case-insensitive field matching and last-duplicate-wins
// behavior cannot define a persisted initialization-state boundary. Validate
// exact keys (including nested security fields) before the struct decoder.
func canonicalObject(raw []byte, allowed map[string]bool) (map[string]json.RawMessage, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	start, e := d.Token()
	if e != nil || start != json.Delim('{') {
		return nil, errors.New("config must be an object")
	}
	result := make(map[string]json.RawMessage)
	for d.More() {
		key, e := d.Token()
		if e != nil {
			return nil, e
		}
		s, ok := key.(string)
		if !ok || !allowed[s] {
			return nil, errors.New("unknown field or noncanonical config field")
		}
		if _, exists := result[s]; exists {
			return nil, errors.New("duplicate config field")
		}
		var value json.RawMessage
		if e = d.Decode(&value); e != nil {
			return nil, e
		}
		result[s] = value
	}
	if _, e = d.Token(); e != nil {
		return nil, e
	}
	if d.Decode(new(any)) != io.EOF {
		return nil, errors.New("invalid config JSON")
	}
	return result, nil
}
func canonicalServerKeys(raw []byte) error {
	fields, e := canonicalObject(raw, map[string]bool{"initialization_draft": true, "security": true, "listen_addr": true, "db_path": true, "master_key_path": true, "static_fs": true})
	if e != nil {
		return e
	}
	if security, ok := fields["security"]; ok && !bytes.Equal(bytes.TrimSpace(security), []byte("null")) {
		_, e = canonicalObject(security, map[string]bool{"auth_method": true, "public_origin": true, "rp_id": true, "mode": true, "tls_certificate": true, "tls_key": true, "backend_authority": true})
	}
	return e
}
