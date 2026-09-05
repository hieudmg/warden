package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	defaultListenAddr    = "127.0.0.1:8080"
	defaultDBPath        = "/var/lib/warden/warden.db"
	defaultMasterKey     = "/etc/warden/master.key"
	defaultAPIBaseURL    = "http://127.0.0.1:8080"
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
	ListenAddr    string
	DBPath        string
	MasterKeyPath string
	StaticFS      string
}

type Client struct {
	APIBaseURL string
	Timeout    time.Duration
}

type ServerOptions struct {
	ConfigPath    string
	ConfigPathSet bool
	LookupEnv     func(string) (string, bool)

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
	ListenAddr    *string `json:"listen_addr"`
	DBPath        *string `json:"db_path"`
	MasterKeyPath *string `json:"master_key_path"`
	StaticFS      *string `json:"static_fs"`
}

type clientFileConfig struct {
	APIBaseURL *string `json:"api_base_url"`
	Timeout    *string `json:"timeout"`
}

func DefaultServer() Server {
	return Server{
		ListenAddr:    defaultListenAddr,
		DBPath:        defaultDBPath,
		MasterKeyPath: defaultMasterKey,
	}
}

func DefaultClient() Client {
	return Client{
		APIBaseURL: defaultAPIBaseURL,
		Timeout:    defaultClientTimeout,
	}
}

func DefaultServerConfigPath() string {
	return "/etc/warden/server.json"
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

	return cfg, nil
}

func serverConfigPath(opts ServerOptions, lookupEnv func(string) (string, bool)) (string, bool, error) {
	return resolveConfigPath(opts.ConfigPath, opts.ConfigPathSet, serverConfigEnv, lookupEnv, opts.defaultConfigPath, DefaultServerConfigPath())
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

	var fileCfg serverFileConfig
	if err := decodeStrictJSON(data, &fileCfg); err != nil {
		return fmt.Errorf("decode server config %q: %w", path, err)
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

func validateListenAddr(value string) error {
	host, port, err := net.SplitHostPort(value)
	if err != nil {
		return fmt.Errorf("invalid listen address %q: %w", value, err)
	}
	if strings.TrimSpace(host) == "" {
		return fmt.Errorf("invalid listen address %q: host must not be empty", value)
	}
	if !isAllowedListenHost(host) {
		return fmt.Errorf("invalid listen address %q: host must be localhost, loopback, or a Tailscale address", value)
	}

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
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return "", errors.New("api base url must not be empty")
	}

	u, err := url.Parse(trimmed)
	if err != nil {
		return "", fmt.Errorf("invalid api base url %q: %w", value, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("invalid api base url %q: scheme must be http or https", value)
	}
	if u.Host == "" {
		return "", fmt.Errorf("invalid api base url %q: host must not be empty", value)
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("invalid api base url %q: query and fragment are not supported", value)
	}

	return strings.TrimRight(trimmed, "/"), nil
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
