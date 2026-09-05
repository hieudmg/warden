package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadServerDefaults(t *testing.T) {
	t.Parallel()

	cfg, err := LoadServer(ServerOptions{
		LookupEnv:         emptyLookupEnv,
		defaultConfigPath: filepath.Join(t.TempDir(), "server.json"),
	})
	if err != nil {
		t.Fatalf("LoadServer() error = %v", err)
	}

	if cfg.ListenAddr != "127.0.0.1:8080" {
		t.Fatalf("ListenAddr = %q, want %q", cfg.ListenAddr, "127.0.0.1:8080")
	}
	if cfg.DBPath != "/var/lib/warden/warden.db" {
		t.Fatalf("DBPath = %q, want %q", cfg.DBPath, "/var/lib/warden/warden.db")
	}
	if cfg.MasterKeyPath != "/etc/warden/master.key" {
		t.Fatalf("MasterKeyPath = %q, want %q", cfg.MasterKeyPath, "/etc/warden/master.key")
	}
	if cfg.StaticFS != "" {
		t.Fatalf("StaticFS = %q, want empty", cfg.StaticFS)
	}
}

func TestLoadServerEnvOverridesConfigFile(t *testing.T) {
	t.Parallel()

	configPath := filepath.Join(t.TempDir(), "server.json")
	writeTestFile(t, configPath, `{
  "listen_addr": "127.0.0.1:9000",
  "db_path": "/srv/warden/warden.db",
  "master_key_path": "/srv/warden/master.key",
  "static_fs": "/srv/warden/static"
}`)

	cfg, err := LoadServer(ServerOptions{
		ConfigPath: configPath,
		LookupEnv: lookupEnvFromMap(map[string]string{
			"WARDEN_SERVER_DB_PATH":   "/env/warden.db",
			"WARDEN_SERVER_STATIC_FS": "/env/static",
		}),
	})
	if err != nil {
		t.Fatalf("LoadServer() error = %v", err)
	}

	if cfg.ListenAddr != "127.0.0.1:9000" {
		t.Fatalf("ListenAddr = %q, want %q", cfg.ListenAddr, "127.0.0.1:9000")
	}
	if cfg.DBPath != "/env/warden.db" {
		t.Fatalf("DBPath = %q, want %q", cfg.DBPath, "/env/warden.db")
	}
	if cfg.MasterKeyPath != "/srv/warden/master.key" {
		t.Fatalf("MasterKeyPath = %q, want %q", cfg.MasterKeyPath, "/srv/warden/master.key")
	}
	if cfg.StaticFS != "/env/static" {
		t.Fatalf("StaticFS = %q, want %q", cfg.StaticFS, "/env/static")
	}
}

func TestLoadServerRejectsInvalidListenAddr(t *testing.T) {
	t.Parallel()

	configPath := filepath.Join(t.TempDir(), "server.json")
	writeTestFile(t, configPath, `{"listen_addr": "localhost"}`)

	_, err := LoadServer(ServerOptions{ConfigPath: configPath, LookupEnv: emptyLookupEnv})
	if err == nil {
		t.Fatal("LoadServer() error = nil, want error")
	}
	if !strings.Contains(err.Error(), "listen") {
		t.Fatalf("LoadServer() error = %v, want listen validation error", err)
	}
}

func TestValidateListenAddrAllowsLoopbackAndTailscaleHosts(t *testing.T) {
	t.Parallel()

	for _, address := range []string{
		"localhost:8080",
		"127.0.0.1:8080",
		"[::1]:8080",
		"100.64.0.1:8080",
		"[fd7a:115c:a1e0::1]:8080",
	} {
		if err := validateListenAddr(address); err != nil {
			t.Errorf("validateListenAddr(%q) error = %v", address, err)
		}
	}
}

func TestValidateListenAddrRejectsPublicAndWildcardHosts(t *testing.T) {
	t.Parallel()

	for _, address := range []string{
		"0.0.0.0:8080",
		"192.168.1.20:8080",
		"203.0.113.20:8080",
		"[::]:8080",
		"[0:0:0:0:0:0::]:8080",
		"warden.example:8080",
	} {
		if err := validateListenAddr(address); err == nil {
			t.Errorf("validateListenAddr(%q) error = nil, want unsafe-host error", address)
		}
	}
}

func TestLoadClientRejectsInvalidAPIBaseURL(t *testing.T) {
	t.Parallel()

	configPath := filepath.Join(t.TempDir(), "client.json")
	writeTestFile(t, configPath, `{"api_base_url": "://bad"}`)

	_, err := LoadClient(ClientOptions{ConfigPath: configPath, LookupEnv: emptyLookupEnv})
	if err == nil {
		t.Fatal("LoadClient() error = nil, want error")
	}
	if !strings.Contains(err.Error(), "api base") {
		t.Fatalf("LoadClient() error = %v, want API base URL validation error", err)
	}
}

func TestLoadClientParsesTimeoutWithEnvOverride(t *testing.T) {
	t.Parallel()

	configPath := filepath.Join(t.TempDir(), "client.json")
	writeTestFile(t, configPath, `{
  "api_base_url": "http://warden.internal:8080",
  "timeout": "10s"
}`)

	cfg, err := LoadClient(ClientOptions{
		ConfigPath: configPath,
		LookupEnv: lookupEnvFromMap(map[string]string{
			"WARDEN_CLIENT_TIMEOUT": "45s",
		}),
	})
	if err != nil {
		t.Fatalf("LoadClient() error = %v", err)
	}

	if cfg.Timeout != 45*time.Second {
		t.Fatalf("Timeout = %v, want %v", cfg.Timeout, 45*time.Second)
	}
}

func TestLoadServerRejectsUnknownJSONField(t *testing.T) {
	t.Parallel()

	configPath := filepath.Join(t.TempDir(), "server.json")
	writeTestFile(t, configPath, `{"listen_addr": "127.0.0.1:8080", "extra": true}`)

	_, err := LoadServer(ServerOptions{ConfigPath: configPath, LookupEnv: emptyLookupEnv})
	if err == nil {
		t.Fatal("LoadServer() error = nil, want error")
	}
	if !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("LoadServer() error = %v, want strict JSON error", err)
	}
}

func TestLoadServerRejectsEmptyConfigPathEnvBeforeRead(t *testing.T) {
	t.Parallel()

	readCalled := false
	_, err := LoadServer(ServerOptions{
		LookupEnv: lookupEnvFromMap(map[string]string{
			serverConfigEnv: "   ",
		}),
		defaultConfigPath: filepath.Join(t.TempDir(), "server.json"),
		readFile: func(string) ([]byte, error) {
			readCalled = true
			return nil, nil
		},
	})
	if err == nil {
		t.Fatal("LoadServer() error = nil, want error")
	}
	if !strings.Contains(err.Error(), serverConfigEnv) {
		t.Fatalf("LoadServer() error = %v, want %q in error", err, serverConfigEnv)
	}
	if readCalled {
		t.Fatal("LoadServer() read config file, want early rejection")
	}
}

func TestLoadClientRejectsEmptyConfigPathEnvBeforeRead(t *testing.T) {
	t.Parallel()

	readCalled := false
	_, err := LoadClient(ClientOptions{
		LookupEnv: lookupEnvFromMap(map[string]string{
			clientConfigEnv: "   ",
		}),
		defaultConfigPath: filepath.Join(t.TempDir(), "client.json"),
		readFile: func(string) ([]byte, error) {
			readCalled = true
			return nil, nil
		},
	})
	if err == nil {
		t.Fatal("LoadClient() error = nil, want error")
	}
	if !strings.Contains(err.Error(), clientConfigEnv) {
		t.Fatalf("LoadClient() error = %v, want %q in error", err, clientConfigEnv)
	}
	if readCalled {
		t.Fatal("LoadClient() read config file, want early rejection")
	}
}

func TestReadConfigFileRejectsEmptyRequiredPath(t *testing.T) {
	t.Parallel()

	readCalled := false
	_, err := readConfigFile("", true, func(string) ([]byte, error) {
		readCalled = true
		return nil, nil
	})
	if err == nil {
		t.Fatal("readConfigFile() error = nil, want error")
	}
	if !strings.Contains(err.Error(), "config path") {
		t.Fatalf("readConfigFile() error = %v, want config path error", err)
	}
	if readCalled {
		t.Fatal("readConfigFile() called readFile, want early rejection")
	}
}

func writeTestFile(t *testing.T, path, content string) {
	t.Helper()

	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("os.WriteFile(%q) error = %v", path, err)
	}
}

func lookupEnvFromMap(values map[string]string) func(string) (string, bool) {
	return func(key string) (string, bool) {
		value, ok := values[key]
		return value, ok
	}
}

func emptyLookupEnv(string) (string, bool) {
	return "", false
}
