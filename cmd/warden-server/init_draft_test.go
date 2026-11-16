package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"warden/internal/config"
)

func readInitJSON(t *testing.T, path string) map[string]json.RawMessage {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]json.RawMessage
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	return got
}

func TestInitPersistsEachAnswerBeforeReadingNext(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server.json")
	db := filepath.Join(dir, "vault.db")
	lines := []string{db, "http://invalid.example", "bad/rp", "tls", "invalid-listen", "custom.crt", "custom.key"}
	for n := 0; n <= len(lines); n++ {
		t.Run(string(rune('0'+n)), func(t *testing.T) {
			path := filepath.Join(dir, string(rune('0'+n)), filepath.Base(path))
			input := strings.Join(lines[:n], "\n")
			if n > 0 {
				input += "\n"
			}
			_, _, err := promptInitialization(strings.NewReader(input), io.Discard, path)
			if err == nil {
				t.Fatal("accepted incomplete/invalid answers")
			}
			got := readInitJSON(t, path)
			if string(got["initialization_draft"]) != "true" {
				t.Fatal("missing draft marker", got)
			}
			var saved struct {
				DB       string       `json:"db_path"`
				Listen   string       `json:"listen_addr"`
				Security config.Setup `json:"security"`
			}
			data, _ := os.ReadFile(path)
			if err := json.Unmarshal(data, &saved); err != nil {
				t.Fatal(err)
			}
			want := []struct{ got, want string }{{saved.DB, db}, {saved.Security.PublicOrigin, lines[1]}, {saved.Security.RPID, lines[2]}, {saved.Security.Mode, lines[3]}, {saved.Listen, lines[4]}, {saved.Security.TLSCertificate, lines[5]}, {saved.Security.TLSKey, lines[6]}}
			for i := 0; i < n; i++ {
				if want[i].got != want[i].want {
					t.Fatalf("answer %d lost: got %q want %q", i, want[i].got, want[i].want)
				}
			}
			if _, err := config.LoadServer(config.ServerOptions{ConfigPath: path, ConfigPathSet: true, LookupEnv: emptyLookupEnv}); err == nil {
				t.Fatal("serve accepted a draft")
			}
			info, _ := os.Stat(path)
			if info.Mode().Perm() != 0600 {
				t.Fatal("nonprivate draft")
			}
		})
	}
}

func TestInitRetryRepromptsSavedInvalidAnswersAndPreservesOtherSettings(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "custom.json")
	db := filepath.Join(dir, "vault.db")
	data := `{"initialization_draft":true,"listen_addr":"bad","db_path":` + quoteInit(db) + `,"static_fs":"custom-ui","master_key_path":"legacy-retained-only","security":{"public_origin":"http://invalid.example","rp_id":"bad/rp","mode":"tls","tls_certificate":"saved.crt","tls_key":"saved.key"}}`
	if err := os.WriteFile(path, []byte(data), 0640); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	answers := "\nhttps://warden.example\nwarden.example\nproxy\n127.0.0.1:9443\n\n"
	cfg, gotPath, err := promptInitialization(strings.NewReader(answers), &out, path)
	if err != nil {
		t.Fatal(err)
	}
	if gotPath != path || cfg.DBPath != db || cfg.StaticFS != "custom-ui" || cfg.MasterKeyPath != "legacy-retained-only" {
		t.Fatalf("lost custom settings: %+v %q", cfg, gotPath)
	}
	for _, text := range []string{"[" + db + "]", "[http://invalid.example]", "[bad/rp]", "[tls]", "[bad]"} {
		if !strings.Contains(out.String(), text) {
			t.Fatalf("did not reprompt saved %s: %s", text, &out)
		}
	}
	if cfg.Security.TLSCertificate != "" || cfg.Security.TLSKey != "" || cfg.Security.BackendAuthority != cfg.ListenAddr {
		t.Fatalf("wrong mode fields: %+v", cfg.Security)
	}
	got := readInitJSON(t, path)
	if string(got["static_fs"]) != `"custom-ui"` || string(got["master_key_path"]) != `"legacy-retained-only"` {
		t.Fatal("nonprompted settings changed", got)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatal("update not private")
	}
}

func quoteInit(s string) string { b, _ := json.Marshal(s); return string(b) }

func TestInitDraftStorageRefusalCanBeCorrectedWithoutTouchingStorage(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server.json")
	db := filepath.Join(dir, "occupied.db")
	for _, suffix := range []string{"", "-wal", "-shm", "-journal"} {
		if err := os.WriteFile(db+suffix, []byte("preserve"+suffix), 0640); err != nil {
			t.Fatal(err)
		}
	}
	answers := db + "\nhttps://warden.example\nwarden.example\nproxy\n127.0.0.1:8080\n\n"
	if _, _, err := promptInitialization(strings.NewReader(answers), io.Discard, path); err == nil {
		t.Fatal("accepted occupied storage")
	}
	got := readInitJSON(t, path)
	if string(got["db_path"]) != quoteInit(db) {
		t.Fatal("storage answer not saved")
	}
	fresh := filepath.Join(dir, "fresh.db")
	cfg, _, err := promptInitialization(strings.NewReader(fresh+"\n\n\n\n\n\n"), io.Discard, path)
	if err != nil || cfg.DBPath != fresh {
		t.Fatalf("cannot correct refused storage: %+v %v", cfg, err)
	}
	for _, suffix := range []string{"", "-wal", "-shm", "-journal"} {
		data, err := os.ReadFile(db + suffix)
		if err != nil || string(data) != "preserve"+suffix {
			t.Fatal("changed occupied storage", suffix, err)
		}
	}
}

func TestInitNeverRewritesMalformedLegacyOrInitializedConfig(t *testing.T) {
	for _, kind := range []string{"malformed", "legacy", "initialized", "unknown-field"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "server.json")
			db := filepath.Join(dir, "vault.db")
			data := `{"security":`
			switch kind {
			case "legacy":
				data = `{"db_path":` + quoteInit(db) + `}`
			case "unknown-field":
				data = `{"security":{},"future_setting":true}`
			case "initialized":
				data = `{"db_path":` + quoteInit(db) + `,"security":{"public_origin":"https://warden.example","rp_id":"warden.example","mode":"proxy","backend_authority":"127.0.0.1:8080"}}`
				if err := os.WriteFile(db, []byte("existing identity"), 0640); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(path, []byte(data), 0640); err != nil {
				t.Fatal(err)
			}
			if _, _, err := promptInitialization(strings.NewReader("changed\n"), io.Discard, path); err == nil {
				t.Fatal("accepted protected config")
			}
			got, err := os.ReadFile(path)
			if err != nil || string(got) != data {
				t.Fatal("changed protected config", err)
			}
			info, _ := os.Stat(path)
			if info.Mode().Perm() != 0640 {
				t.Fatal("changed protected permissions")
			}
		})
	}
}

// Return only one submitted line per read, so checks run before the next prompt
// can consume input; this checks immediate persistence rather than final output.
type initAnswerReader struct {
	lines  []string
	before func(int)
	n      int
}

func (r *initAnswerReader) Read(p []byte) (int, error) {
	r.before(r.n)
	if r.n == len(r.lines) {
		return 0, io.EOF
	}
	line := r.lines[r.n] + "\n"
	r.n++
	return copy(p, line), nil
}

func TestInitConfigOwnershipCoversPromptsAndRejectsExternalReplacement(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server.json")
	db := filepath.Join(dir, "vault.db")
	external := []byte(`{"security":{},"db_path":"external"}`)
	reader := &initAnswerReader{lines: []string{db, "https://warden.example"}}
	reader.before = func(n int) {
		if n == 1 {
			got := readInitJSON(t, path)
			if string(got["db_path"]) != quoteInit(db) {
				t.Fatal("answer not persisted before next read")
			}
			_, _, err := promptInitialization(strings.NewReader("\n"), io.Discard, path)
			if err == nil || !strings.Contains(err.Error(), "initialization already running") {
				t.Fatalf("concurrent config owner not excluded: %v", err)
			}
			if err := os.WriteFile(path, external, 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	_, _, err := promptInitialization(reader, io.Discard, path)
	if err == nil || !strings.Contains(err.Error(), "changed") {
		t.Fatalf("accepted external replacement: %v", err)
	}
	got, _ := os.ReadFile(path)
	if !bytes.Equal(got, external) {
		t.Fatal("overwrote external config")
	}
	// Kernel ownership must be released on every error path.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	_, _, err = promptInitialization(strings.NewReader(""), io.Discard, path)
	if err == nil || !errors.Is(err, io.EOF) && !strings.Contains(err.Error(), "input ended") {
		t.Fatalf("config lease leaked: %v", err)
	}
}

func TestInitSetupFailureKeepsAnswersAndLeaseThenProtectsCommittedConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server.json")
	db := filepath.Join(dir, "vault.db")
	answers := db + "\nhttps://warden.example\nwarden.example\nproxy\n127.0.0.1:8080\n\n"
	stopped := errors.New("fixture setup stopped")
	_, _, err := initializeWithAnswers(strings.NewReader(answers), io.Discard, path, func(cfg config.Server) error {
		if _, err := config.LoadServer(config.ServerOptions{ConfigPath: path, ConfigPathSet: true, LookupEnv: emptyLookupEnv}); err != nil {
			t.Fatal("setup received unpublished config", err)
		}
		if _, _, err := promptInitialization(strings.NewReader(""), io.Discard, path); err == nil || !strings.Contains(err.Error(), "initialization already running") {
			t.Fatalf("config lease not held during setup: %v", err)
		}
		return stopped
	})
	if !errors.Is(err, stopped) {
		t.Fatalf("lost setup error: %v", err)
	}
	// All saved defaults are prompted again after listener/certificate/expiry failure.
	var out bytes.Buffer
	cfg, _, err := promptInitialization(strings.NewReader("\n\n\n\n\n\n"), &out, path)
	if err != nil || cfg.DBPath != db || cfg.Security.PublicOrigin != "https://warden.example" {
		t.Fatalf("failed setup cannot resume: %+v %v", cfg, err)
	}
	// Simulate successful publication followed by a lost completion response.
	_, _, err = initializeWithAnswers(strings.NewReader("\n\n\n\n\n\n"), io.Discard, path, func(config.Server) error {
		if err := os.WriteFile(db, []byte("published identity"), 0600); err != nil {
			t.Fatal(err)
		}
		return stopped
	})
	if !errors.Is(err, stopped) {
		t.Fatal(err)
	}
	original, _ := os.ReadFile(path)
	if _, _, err := promptInitialization(strings.NewReader("different.db\n"), io.Discard, path); err == nil {
		t.Fatal("reinitialized committed config after ambiguous failure")
	}
	got, _ := os.ReadFile(path)
	if !bytes.Equal(original, got) {
		t.Fatal("changed committed config")
	}
}

func TestInitConfigSelectionRejectsEmptyFlagAndEnv(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		env  map[string]string
		want string
	}{
		{"empty-flag", []string{"init", "--config="}, nil, "--config must not be empty"},
		{"empty-env", []string{"init"}, map[string]string{"WARDEN_SERVER_CONFIG": "  "}, "WARDEN_SERVER_CONFIG must not be empty"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			lookup := func(key string) (string, bool) { value, ok := tc.env[key]; return value, ok }
			if code := run(tc.args, &out, &errOut, lookup); code != 1 || !strings.Contains(errOut.String(), tc.want) {
				t.Fatalf("exit/error: %d %s", code, &errOut)
			}
		})
	}
}

func TestInitHomeDefaultsMatchServeAndTLS(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	wantDir := filepath.Join(home, ".warden")
	if got := config.DefaultServerConfigPath(); got != filepath.Join(wantDir, "server.json") {
		t.Fatalf("config default %q", got)
	}
	var out bytes.Buffer
	cfg, path, err := promptInitialization(strings.NewReader("\n\nhttps://warden.example\nwarden.example\n\n\n\n\n"), &out, "")
	if err != nil {
		t.Fatal(err)
	}
	if path != filepath.Join(wantDir, "server.json") || cfg.DBPath != filepath.Join(wantDir, "warden.db") || cfg.Security.TLSCertificate != filepath.Join(wantDir, "tls", "fullchain.pem") || cfg.Security.TLSKey != filepath.Join(wantDir, "tls", "private.key") {
		t.Fatalf("unexpected defaults: %+v %+v %q", cfg, cfg.Security, path)
	}
	if got := config.DefaultServer().DBPath; got != cfg.DBPath {
		t.Fatalf("serve DB default %q", got)
	}
}
