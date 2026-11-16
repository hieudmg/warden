package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadServerRejectsUnfinishedInitialization(t *testing.T) {
	for _, data := range []string{
		`{"security":{}}`,
		`{"security":{"public_origin":"https://warden.example","rp_id":"warden.example","mode":"proxy","backend_authority":"127.0.0.1:8080"},"initialization_draft":true}`,
	} {
		t.Run(data, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "server.json")
			writeTestFile(t, path, data)
			if _, err := LoadServer(ServerOptions{ConfigPath: path, ConfigPathSet: true, LookupEnv: emptyLookupEnv}); err == nil {
				t.Fatal("runtime loader accepted incomplete setup")
			}
		})
	}
}

func TestParseServerDraftKeepsLegacyStorageDefault(t *testing.T) {
	// Pure decode only: never create/read a real /etc config or legacy database.
	cfg, err := ParseServerDraft("/etc/warden/server.json", []byte(`{"security":{}}`))
	if err != nil || cfg.DBPath != "/var/lib/warden/warden.db" {
		t.Fatalf("init lost legacy storage protection: %+v %v", cfg, err)
	}
}

func TestServerConfigDiscoveryPrefersHomeThenLegacyWithoutMigration(t *testing.T) {
	// Override only the legacy path for isolation; the production default is /etc/warden/server.json.
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	path := DefaultServerConfigPath()
	legacy := filepath.Join(t.TempDir(), "legacy.json")
	writeTestFile(t, legacy, `{}`)
	legacyDefaults, err := LoadServer(ServerOptions{LookupEnv: emptyLookupEnv, legacyConfigPath: legacy})
	if err != nil || legacyDefaults.DBPath != "/var/lib/warden/warden.db" {
		t.Fatalf("changed discovered legacy DB default: %+v %v", legacyDefaults, err)
	}
	writeTestFile(t, legacy, `{"db_path":"retained-legacy.db"}`)
	opts := ServerOptions{LookupEnv: emptyLookupEnv, legacyConfigPath: legacy}
	cfg, err := LoadServer(opts)
	if err != nil || cfg.DBPath != "retained-legacy.db" {
		t.Fatalf("lost implicit legacy config: %+v %v", cfg, err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("copied legacy config: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, path, `{"db_path":"home.db"}`)
	cfg, err = LoadServer(opts)
	if err != nil || cfg.DBPath != "home.db" {
		t.Fatalf("home not preferred: %+v %v", cfg, err)
	}
	opts.ConfigPath = legacy
	opts.ConfigPathSet = true
	cfg, err = LoadServer(opts)
	if err != nil || cfg.DBPath != "retained-legacy.db" {
		t.Fatalf("explicit path lost: %+v %v", cfg, err)
	}
	opts.ConfigPath = ""
	opts.ConfigPathSet = false
	opts.LookupEnv = lookupEnvFromMap(map[string]string{serverConfigEnv: legacy})
	cfg, err = LoadServer(opts)
	if err != nil || cfg.DBPath != "retained-legacy.db" {
		t.Fatalf("environment path lost: %+v %v", cfg, err)
	}
	opts.LookupEnv = emptyLookupEnv
	writeTestFile(t, path, `{"security":`)
	if _, err := LoadServer(opts); err == nil {
		t.Fatal("silently fell back from malformed home config")
	}
}
