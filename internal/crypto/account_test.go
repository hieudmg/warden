package crypto

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestAccountEnvelope(t *testing.T) {
	vault, id := Encode(bytes.Repeat([]byte{1}, 16)), Encode(bytes.Repeat([]byte{2}, 32))
	dek := bytes.Repeat([]byte{3}, 32)
	password := []byte(" a long exact password ")
	w, err := WrapPassword(password, dek, vault, id)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(w)
	if bytes.Contains(raw, password) || bytes.Contains(raw, []byte(Encode(dek))) {
		t.Fatal("plaintext persisted")
	}
	round, err := w.Unwrap(password, vault, id)
	if err != nil || !bytes.Equal(round, dek) {
		t.Fatalf("roundtrip %v", err)
	}
	clear(round)
	for _, p := range [][]byte{[]byte("wrong password"), []byte(strings.TrimSpace(string(password)))} {
		if k, e := w.Unwrap(p, vault, id); e == nil {
			clear(k)
			t.Fatal("accepted wrong password")
		}
	}
	if _, e := w.Unwrap(password, Encode(bytes.Repeat([]byte{4}, 16)), id); e == nil {
		t.Fatal("vault binding")
	}
	if _, e := w.Unwrap(password, vault, Encode(bytes.Repeat([]byte{4}, 32))); e == nil {
		t.Fatal("credential binding")
	}
	for _, change := range []func(*AccountEnvelope){
		func(x *AccountEnvelope) { x.Version++ }, func(x *AccountEnvelope) { x.Kind = "recovery" },
		func(x *AccountEnvelope) { x.Memory = 1 << 30 }, func(x *AccountEnvelope) { x.Time = 0 }, func(x *AccountEnvelope) { x.Threads = 255 },
		func(x *AccountEnvelope) { x.Ciphertext = Encode(bytes.Repeat([]byte{9}, 48)) }, func(x *AccountEnvelope) { x.KDFSalt = "bad" },
	} {
		x := w
		change(&x)
		if k, e := x.Unwrap(password, vault, id); e == nil {
			clear(k)
			t.Fatal("accepted corrupt envelope")
		}
	}
	other, e := WrapPassword(password, dek, vault, id)
	if e != nil || other.KDFSalt == w.KDFSalt || other.IV == w.IV {
		t.Fatal("not randomized", e)
	}
	for _, p := range [][]byte{nil, []byte("short"), bytes.Repeat([]byte{'x'}, 1025)} {
		if _, e := WrapPassword(p, dek, vault, id); e == nil {
			t.Fatal("password bounds")
		}
	}
	for _, name := range []string{"", " leading", "trailing ", strings.Repeat("x", 65), "a\nb"} {
		if ValidUsername(name) {
			t.Fatal("username bounds", name)
		}
	}
	if !ValidUsername("owner") {
		t.Fatal("valid username")
	}
}
