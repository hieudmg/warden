package main

import (
	"io"
	"path/filepath"
	"strings"
	"testing"
)

func TestInitAuthenticationSelectionAndResume(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	answers := filepath.Join(dir, "vault.db") + "\nhttps://warden.example\nwarden.example\nproxy\n127.0.0.1:8080\n\n\n"
	cfg, _, e := promptInitialization(strings.NewReader(answers), io.Discard, path)
	if e != nil || cfg.Security.AuthMethod != "account" {
		t.Fatalf("new default: %+v %v", cfg.Security, e)
	}
	cfg, _, e = promptInitialization(strings.NewReader("\n\n\n\n\n\npasskey\n"), io.Discard, path)
	if e != nil || cfg.Security.AuthMethod != "passkey" {
		t.Fatalf("explicit method: %+v %v", cfg.Security, e)
	}
	cfg, _, e = promptInitialization(strings.NewReader("\n\n\n\n\n\n\n"), io.Discard, path)
	if e != nil || cfg.Security.AuthMethod != "passkey" {
		t.Fatalf("saved default: %+v %v", cfg.Security, e)
	}
}
