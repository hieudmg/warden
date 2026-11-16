package config

import (
	"path/filepath"
	"testing"
)

func TestClientPrivateCACertificatePathIsStableForDetachedAgent(t *testing.T) {
	cfg, err := LoadClient(ClientOptions{defaultConfigPath: "fixture.json", readFile: func(string) ([]byte, error) {
		return []byte(`{"api_base_url":"https://warden.example","ca_certificate":"ca.pem"}`), nil
	}, LookupEnv: emptyLookupEnv})
	if err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(cfg.CACertificate) {
		t.Fatal("relative CA path depends on detached agent working directory", cfg.CACertificate)
	}
}

func TestClientCommandsRequirePairedHTTPSCredential(t *testing.T) {
	for _, origin := range []string{"http://127.0.0.1:8080", "http://warden.example", "https://user:secret@warden.example", "https://warden.example/path"} {
		cfg := DefaultClient()
		cfg.APIBaseURL = origin
		if err := validateClient(&cfg); err == nil {
			t.Errorf("insecure or non-origin endpoint accepted: %s", origin)
		}
	}
}
