package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"warden/internal/client/clienthttp"
)

const (
	defaultListenAddr    = "127.0.0.1:8080"
	defaultMasterKey     = "/etc/warden/master.key"
	defaultAPIBaseURL    = "https://127.0.0.1:8080"
	defaultClientTimeout = 30 * time.Second
)

const (
	serverConfigEnv    = "WARDEN_SERVER_CONFIG"
	serverListenEnv    = "WARDEN_SERVER_LISTEN_ADDR"
	serverDBPathEnv    = "WARDEN_SERVER_DB_PATH"
	serverMasterKeyEnv = "WARDEN_SERVER_MASTER_KEY_PATH"
	serverStaticFSEnv  = "WARDEN_SERVER_STATIC_FS"

	clientConfigEnv  = "WARDEN_CLIENT_CONFIG"
	clientAPIBaseEnv = "WARDEN_CLIENT_API_BASE_URL"
	clientTimeoutEnv = "WARDEN_CLIENT_TIMEOUT"
)

type Server struct {
	InitializationDraft bool
	Security            *Setup
	ListenAddr          string
	DBPath              string
	MasterKeyPath       string
	StaticFS            string
}

type Client struct {
	APIBaseURL    string
	Timeout       time.Duration
	CACertificate string
}

type ServerOptions struct {
	ConfigPath    string
	ConfigPathSet bool
	LookupEnv     func(string) (string, bool)

	legacyConfigPath  string
	defaultConfigPath string
	readFile          func(string) ([]byte, error)
}

type ClientOptions struct {
	ConfigPath    string
	ConfigPathSet bool
	LookupEnv     func(string) (string, bool)

	defaultConfigPath string
	readFile          func(string) ([]byte, error)
}

type serverFileConfig struct {
	InitializationDraft bool    `json:"initialization_draft,omitempty"`
	Security            *Setup  `json:"security"`
	ListenAddr          *string `json:"listen_addr"`
	DBPath              *string `json:"db_path"`
	MasterKeyPath       *string `json:"master_key_path"`
	StaticFS            *string `json:"static_fs"`
}

type clientFileConfig struct {
	APIBaseURL    *string `json:"api_base_url"`
	Timeout       *string `json:"timeout"`
	CACertificate *string `json:"ca_certificate"`
}

func DefaultServer() Server {
	return Server{
		ListenAddr:    defaultListenAddr,
		DBPath:        filepath.Join(defaultServerDir(), "warden.db"),
		MasterKeyPath: defaultMasterKey,
	}
}

func DefaultClient() Client {
	return Client{
		APIBaseURL: defaultAPIBaseURL,
		Timeout:    defaultClientTimeout,
	}
}

func defaultServerDir() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ".warden"
	}
	return filepath.Join(home, ".warden")
}

func DefaultServerConfigPath() string {
	return filepath.Join(defaultServerDir(), "server.json")
}

// DefaultSetup supplies file locations, not certificates or valid RP settings.
func DefaultSetup() Setup {
	return Setup{Mode: "tls", TLSCertificate: filepath.Join(defaultServerDir(), "tls", "fullchain.pem"), TLSKey: filepath.Join(defaultServerDir(), "tls", "private.key")}
}

// ParseServerDraft strictly decodes one non-secret setup snapshot without
// environment overrides or runtime validation. Only init may edit drafts.
func ParseServerDraft(path string, data []byte) (Server, error) {
	cfg := DefaultServer()
	if err := decodeServerFile(&cfg, data); err != nil {
		return Server{}, err
	}
	if cfg.Security == nil {
		return Server{}, errors.New("existing config has no initialization security settings; choose a fresh config path")
	}
	return cfg, nil
}

func DefaultClientConfigPath() string {
	configDir, err := os.UserConfigDir()
	if err != nil || configDir == "" {
		return filepath.Join(".config", "warden", "client.json")
	}

	return filepath.Join(configDir, "warden", "client.json")
}

func LoadServer(opts ServerOptions) (Server, error) {
	lookupEnv := opts.LookupEnv
	if lookupEnv == nil {
		lookupEnv = os.LookupEnv
	}

	cfg := DefaultServer()
	configPath, required, err := serverConfigPath(opts, lookupEnv)
	if err != nil {
		return Server{}, err
	}
	if err := mergeServerFile(&cfg, configPath, required, opts.readFile); err != nil {
		return Server{}, err
	}

	applyServerEnv(&cfg, lookupEnv)
	if err := validateServer(cfg); err != nil {
		return Server{}, err
	}

	return cfg, nil
}

func LoadClient(opts ClientOptions) (Client, error) {
	lookupEnv := opts.LookupEnv
	if lookupEnv == nil {
		lookupEnv = os.LookupEnv
	}

	cfg := DefaultClient()
	configPath, required, err := clientConfigPath(opts, lookupEnv)
	if err != nil {
		return Client{}, err
	}
	if err := mergeClientFile(&cfg, configPath, required, opts.readFile); err != nil {
		return Client{}, err
	}

	if err := applyClientEnv(&cfg, lookupEnv); err != nil {
		return Client{}, err
	}
	if err := validateClient(&cfg); err != nil {
		return Client{}, err
	}
	if cfg.CACertificate != "" {
		// Anchor in the invoking CLI, never in an older detached agent's cwd.
		cfg.CACertificate, err = filepath.Abs(cfg.CACertificate)
		if err != nil {
			return Client{}, errors.New("resolve public CA certificate path")
		}
	}

	return cfg, nil
}

func serverConfigPath(opts ServerOptions, lookupEnv func(string) (string, bool)) (string, bool, error) {
	path, required, err := resolveConfigPath(opts.ConfigPath, opts.ConfigPathSet, serverConfigEnv, lookupEnv, opts.defaultConfigPath, DefaultServerConfigPath())
	if err != nil || required {
		return path, required, err
	}
	// Discovery only: never copy/migrate an old installation, and never fall
	// back when a new default exists but is malformed, inaccessible or a link.
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		legacy := opts.legacyConfigPath
		if legacy == "" {
			legacy = "/etc/warden/server.json"
		}
		if _, err := os.Lstat(legacy); !os.IsNotExist(err) {
			return legacy, true, nil
		}
	}
	return path, required, nil
}

func clientConfigPath(opts ClientOptions, lookupEnv func(string) (string, bool)) (string, bool, error) {
	return resolveConfigPath(opts.ConfigPath, opts.ConfigPathSet, clientConfigEnv, lookupEnv, opts.defaultConfigPath, DefaultClientConfigPath())
}

func resolveConfigPath(explicitPath string, explicitPathSet bool, envKey string, lookupEnv func(string) (string, bool), defaultPath string, fallbackPath string) (string, bool, error) {
	if path := strings.TrimSpace(explicitPath); path != "" {
		return path, true, nil
	}
	if explicitPathSet {
		return "", false, errors.New("--config must not be empty")
	}
	if value, ok := lookupTrimmed(lookupEnv, envKey); ok {
		if value == "" {
			return "", false, fmt.Errorf("%s must not be empty when set", envKey)
		}
		return value, true, nil
	}
	if defaultPath != "" {
		return defaultPath, false, nil
	}
	return fallbackPath, false, nil
}

func mergeServerFile(cfg *Server, path string, required bool, readFile func(string) ([]byte, error)) error {
	data, err := readConfigFile(path, required, readFile)
	if err != nil || data == nil {
		return err
	}

	if err := decodeServerFile(cfg, data); err != nil {
		return fmt.Errorf("decode server config %q: %w", path, err)
	}
	return nil
}

func decodeServerFile(cfg *Server, data []byte) error {
	if err := canonicalServerKeys(data); err != nil {
		return err
	}
	var fileCfg serverFileConfig
	if err := decodeStrictJSON(data, &fileCfg); err != nil {
		return err
	}

	// All existing unmarked configs predate the new-init path default, regardless
	// of pathname. New init always persists an explicit DB path.
	if fileCfg.DBPath == nil && !fileCfg.InitializationDraft {
		cfg.DBPath = "/var/lib/warden/warden.db"
	}
	cfg.InitializationDraft = fileCfg.InitializationDraft
	if fileCfg.Security != nil {
		cfg.Security = fileCfg.Security
	}
	if fileCfg.ListenAddr != nil {
		cfg.ListenAddr = *fileCfg.ListenAddr
	}
	if fileCfg.DBPath != nil {
		cfg.DBPath = *fileCfg.DBPath
	}
	if fileCfg.MasterKeyPath != nil {
		cfg.MasterKeyPath = *fileCfg.MasterKeyPath
	}
	if fileCfg.StaticFS != nil {
		cfg.StaticFS = *fileCfg.StaticFS
	}

	return nil
}

func mergeClientFile(cfg *Client, path string, required bool, readFile func(string) ([]byte, error)) error {
	data, err := readConfigFile(path, required, readFile)
	if err != nil || data == nil {
		return err
	}

	var fileCfg clientFileConfig
	if err := decodeStrictJSON(data, &fileCfg); err != nil {
		return fmt.Errorf("decode client config %q: %w", path, err)
	}

	if fileCfg.APIBaseURL != nil {
		cfg.APIBaseURL = *fileCfg.APIBaseURL
	}
	if fileCfg.CACertificate != nil {
		cfg.CACertificate = *fileCfg.CACertificate
	}
	if fileCfg.Timeout != nil {
		timeout, err := parseDuration(*fileCfg.Timeout)
		if err != nil {
			return fmt.Errorf("parse client timeout: %w", err)
		}
		cfg.Timeout = timeout
	}

	return nil
}

func readConfigFile(path string, required bool, readFile func(string) ([]byte, error)) ([]byte, error) {
	if path == "" {
		if required {
			return nil, errors.New("config path must not be empty")
		}
		return nil, nil
	}
	if readFile == nil {
		readFile = os.ReadFile
	}

	data, err := readFile(path)
	if err == nil {
		return data, nil
	}
	if !required && errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}

	return nil, fmt.Errorf("read config %q: %w", path, err)
}

func decodeStrictJSON(data []byte, dst any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(dst); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("config file must contain a single JSON object")
		}
		return err
	}

	return nil
}

func applyServerEnv(cfg *Server, lookupEnv func(string) (string, bool)) {
	if value, ok := lookupTrimmed(lookupEnv, serverListenEnv); ok {
		cfg.ListenAddr = value
	}
	if value, ok := lookupTrimmed(lookupEnv, serverDBPathEnv); ok {
		cfg.DBPath = value
	}
	if value, ok := lookupTrimmed(lookupEnv, serverMasterKeyEnv); ok {
		cfg.MasterKeyPath = value
	}
	if value, ok := lookupTrimmed(lookupEnv, serverStaticFSEnv); ok {
		cfg.StaticFS = value
	}
}

func applyClientEnv(cfg *Client, lookupEnv func(string) (string, bool)) error {
	if value, ok := lookupTrimmed(lookupEnv, clientAPIBaseEnv); ok {
		cfg.APIBaseURL = value
	}
	if value, ok := lookupTrimmed(lookupEnv, clientTimeoutEnv); ok {
		timeout, err := parseDuration(value)
		if err != nil {
			return fmt.Errorf("parse client timeout: %w", err)
		}
		cfg.Timeout = timeout
	}

	return nil
}

func validateServer(cfg Server) error {
	if cfg.InitializationDraft {
		return errors.New("initialization answers are a draft; rerun warden-server init with the same config")
	}
	if cfg.Security != nil {
		if err := cfg.Security.Validate(cfg.ListenAddr); err != nil {
			return err
		}
	}
	if err := validateListenAddr(cfg.ListenAddr); err != nil {
		return err
	}
	if strings.TrimSpace(cfg.DBPath) == "" {
		return errors.New("db path must not be empty")
	}
	if strings.TrimSpace(cfg.MasterKeyPath) == "" {
		return errors.New("master key path must not be empty")
	}

	return nil
}

func validateClient(cfg *Client) error {
	apiBaseURL, err := validateAPIBaseURL(cfg.APIBaseURL)
	if err != nil {
		return err
	}
	cfg.APIBaseURL = apiBaseURL
	if cfg.Timeout <= 0 {
		return errors.New("timeout must be greater than zero")
	}

	return nil
}

// IsUnsafeListenAddr reports whether a syntactically valid listen address
// binds outside localhost, loopback, or Tailscale ranges.
func IsUnsafeListenAddr(value string) bool {
	host, _, err := net.SplitHostPort(value)
	return err == nil && !isAllowedListenHost(host)
}

func validateListenAddr(value string) error {
	host, port, err := net.SplitHostPort(value)
	if err != nil {
		return fmt.Errorf("invalid listen address %q: %w", value, err)
	}
	if strings.TrimSpace(host) == "" {
		return fmt.Errorf("invalid listen address %q: host must not be empty", value)
	}
	// Public and wildcard binds, including 0.0.0.0, are intentionally accepted.
	// They expose the server by user choice; the server command warns about this
	// risk, which remains the user's responsibility.

	parsedPort, err := strconv.Atoi(port)
	if err != nil || parsedPort < 1 || parsedPort > 65535 {
		return fmt.Errorf("invalid listen address %q: port must be between 1 and 65535", value)
	}

	return nil
}

func isAllowedListenHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() {
		return true
	}

	_, tailscaleCGNAT, _ := net.ParseCIDR("100.64.0.0/10")
	_, tailscaleIPv6, _ := net.ParseCIDR("fd7a:115c:a1e0::/48")
	return tailscaleCGNAT.Contains(ip) || tailscaleIPv6.Contains(ip)
}

func validateAPIBaseURL(value string) (string, error) {
	return clienthttp.Origin(strings.TrimSpace(value))
}

func parseDuration(value string) (time.Duration, error) {
	timeout, err := time.ParseDuration(strings.TrimSpace(value))
	if err != nil {
		return 0, fmt.Errorf("invalid timeout %q: %w", value, err)
	}
	if timeout <= 0 {
		return 0, fmt.Errorf("invalid timeout %q: must be greater than zero", value)
	}

	return timeout, nil
}

func lookupTrimmed(lookupEnv func(string) (string, bool), key string) (string, bool) {
	value, ok := lookupEnv(key)
	if !ok {
		return "", false
	}

	return strings.TrimSpace(value), true
}
