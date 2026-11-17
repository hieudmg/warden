package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"warden/internal/config"
)

func TestInitConfigPrivateReusableAndNeverSilentlyReplaced(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.json")
	cfg := config.DefaultServer()
	cfg.DBPath = filepath.Join(t.TempDir(), "vault.db")
	cfg.Security = &config.Setup{PublicOrigin: "https://warden.example", RPID: "warden.example", Mode: "proxy", BackendAuthority: cfg.ListenAddr}
	session, err := openInitializationConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	defer session.lease.Close()
	session.cfg = cfg
	if err := session.save(); err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatal("nonprivate config")
	}
	if err := session.save(); err != nil {
		t.Fatal("cannot resume after precommit interruption", err)
	}
	if other, err := openInitializationConfig(path); err == nil {
		other.lease.Close()
		t.Fatal("accepted another initializer's conflicting config ownership")
	}
	got, _ := os.ReadFile(path)
	if !bytes.Equal(got, original) {
		t.Fatal("changed existing config")
	}
	if bytes.Contains(original, []byte("master_key_path")) {
		t.Fatal("persisted disk-key fallback setting")
	}
}
