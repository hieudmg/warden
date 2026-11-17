package config

import (
	"path/filepath"
	"testing"
)

func TestCustomLegacyOmittedDBAndDraftAliases(t *testing.T) {
	path := filepath.Join(t.TempDir(), "custom.json")
	raw := `{"security":{"public_origin":"https://warden.example","rp_id":"warden.example","mode":"proxy","backend_authority":"127.0.0.1:8080"}}`
	writeTestFile(t, path, raw)
	s, e := LoadServer(ServerOptions{ConfigPath: path, ConfigPathSet: true, LookupEnv: emptyLookupEnv})
	if e != nil || s.DBPath != "/var/lib/warden/warden.db" {
		t.Fatalf("custom legacy runtime: %+v %v", s, e)
	}
	s, e = ParseServerDraft(path, []byte(raw))
	if e != nil || s.DBPath != "/var/lib/warden/warden.db" {
		t.Fatalf("custom legacy draft: %+v %v", s, e)
	}
}
func TestServerCanonicalKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "custom.json")
	for _, bad := range []string{
		`{"Initialization_Draft":true,"security":{}}`,
		`{"initialization_draft":true,"Initialization_Draft":false,"security":{}}`,
		`{"initialization_draft":true,"initialization_draft":false,"security":{}}`,
		`{"DB_PATH":"wrong","security":{}}`,
		`{"security":{"Mode":"tls"}}`,
		`{"security":{},"security":{}}`,
	} {
		writeTestFile(t, path, bad)
		if _, e := ParseServerDraft(path, []byte(bad)); e == nil {
			t.Fatal("draft alias accepted", bad)
		}
		if _, e := LoadServer(ServerOptions{ConfigPath: path, ConfigPathSet: true, LookupEnv: emptyLookupEnv}); e == nil {
			t.Fatal("runtime alias accepted", bad)
		}
	}
}
