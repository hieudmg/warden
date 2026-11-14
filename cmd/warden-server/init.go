package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"warden/internal/config"
	"warden/internal/server/setup"
	"warden/internal/web"

	"golang.org/x/term"
)

func printInitUsage(w io.Writer) {
	fmt.Fprintln(w, "Usage: warden-server init [--config path]\n\nPrompts on the controlling terminal for fresh storage and HTTPS/RP/TLS or\nliteral-loopback proxy configuration. Creates only a temporary password-gated\nsetup plane, confirms passkey PRF and saved recovery, then exits. Existing\nstorage is never reset. Normal serve starts locked after initialization.")
	fmt.Fprint(w, transferHelp)
}
func runInit(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("init", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	cmd.Usage = func() {}
	path := cmd.String("config", "", "non-secret server config path")
	if err := cmd.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			printInitUsage(stdout)
			return 0
		}
		return 2
	}
	if cmd.NArg() != 0 {
		printInitUsage(stderr)
		return 2
	}
	input, output, err := initTerminal()
	if err != nil {
		fmt.Fprintln(stderr, "init requires a controlling terminal; no password is written to redirected output")
		return 1
	}
	defer input.Close()
	if input != output {
		defer output.Close()
	}
	cfg, configPath, err := promptInitialization(input, output, *path)
	if err != nil {
		fmt.Fprintf(stderr, "invalid initialization config: %v\n", err)
		return 1
	}
	// Refuse old/unknown/initialized storage before creating even a config file.
	for _, suffix := range []string{"", "-wal", "-shm", "-journal"} {
		if _, err := os.Lstat(cfg.DBPath + suffix); !os.IsNotExist(err) {
			fmt.Fprintln(stderr, "storage exists; preserve config/DB/WAL/SHM/key, export using old release if legacy, and run warden-server init with fresh storage")
			return 1
		}
	}
	if err := saveInitializationConfig(configPath, cfg); err != nil {
		fmt.Fprintf(stderr, "save initialization config: %v\n", err)
		return 1
	}
	assets, err := web.SetupDistribution()
	if err != nil {
		fmt.Fprintln(stderr, "embedded setup distribution unavailable; rebuild web assets")
		return 1
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := setup.Run(ctx, setup.Options{Config: *cfg.Security, Bind: cfg.ListenAddr, DBPath: cfg.DBPath, Assets: assets}, output); err != nil {
		fmt.Fprintf(stderr, "initialization stopped: %v\n", err)
		return 1
	}
	return 0
}
func initTerminal() (*os.File, *os.File, error) {
	if runtime.GOOS == "windows" {
		in, err := os.OpenFile("CONIN$", os.O_RDWR, 0)
		if err != nil {
			return nil, nil, err
		}
		out, err := os.OpenFile("CONOUT$", os.O_WRONLY, 0)
		if err != nil {
			in.Close()
			return nil, nil, err
		}
		if !term.IsTerminal(int(in.Fd())) || !term.IsTerminal(int(out.Fd())) {
			in.Close()
			out.Close()
			return nil, nil, errors.New("not terminal")
		}
		return in, out, nil
	}
	f, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, nil, err
	}
	if !term.IsTerminal(int(f.Fd())) {
		f.Close()
		return nil, nil, errors.New("not terminal")
	}
	return f, f, nil
}
func promptInitialization(input io.Reader, out io.Writer, configPath string) (config.Server, string, error) {
	reader := bufio.NewReader(input)
	ask := func(label, def string) (string, error) {
		fmt.Fprintf(out, "%s", label)
		if def != "" {
			fmt.Fprintf(out, " [%s]", def)
		}
		fmt.Fprint(out, ": ")
		v, err := reader.ReadString('\n')
		if err != nil {
			return "", errors.New("configuration input ended")
		}
		v = strings.TrimSpace(v)
		if v == "" {
			v = def
		}
		return v, nil
	}
	var err error
	if configPath == "" {
		configPath, err = ask("Config path", config.DefaultServerConfigPath())
		if err != nil {
			return config.Server{}, "", err
		}
	}
	// A precommit crash may leave non-secret config. Reuse only explicitly
	// initialized-format configuration; never overwrite an old config.
	if _, err := os.Lstat(configPath); err == nil {
		cfg, err := config.LoadServer(config.ServerOptions{ConfigPath: configPath, ConfigPathSet: true, LookupEnv: func(string) (string, bool) { return "", false }})
		if err != nil {
			return cfg, "", err
		}
		if cfg.Security == nil {
			return cfg, "", errors.New("existing config has no initialization security settings; choose a fresh config path")
		}
		if err = cfg.Security.Validate(cfg.ListenAddr); err != nil {
			return cfg, "", err
		}
		return cfg, configPath, nil
	} else if !os.IsNotExist(err) {
		return config.Server{}, "", err
	}
	cfg := config.DefaultServer()
	cfg.Security = &config.Setup{}
	fields := []struct {
		label, def string
		target     *string
	}{{"Fresh storage path", cfg.DBPath, &cfg.DBPath}, {"Public HTTPS origin", "", &cfg.Security.PublicOrigin}, {"WebAuthn RP ID", "", &cfg.Security.RPID}, {"Mode (tls or proxy)", "tls", &cfg.Security.Mode}, {"Listen address", cfg.ListenAddr, &cfg.ListenAddr}}
	for _, f := range fields {
		*f.target, err = ask(f.label, f.def)
		if err != nil {
			return cfg, "", err
		}
	}
	switch cfg.Security.Mode {
	case "tls":
		cfg.Security.TLSCertificate, err = ask("TLS certificate path", "")
		if err == nil {
			cfg.Security.TLSKey, err = ask("TLS private key path", "")
		}
	case "proxy":
		cfg.Security.BackendAuthority, err = ask("Explicit loopback backend authority", cfg.ListenAddr)
	}
	if err != nil {
		return cfg, "", err
	}
	if err = cfg.Security.Validate(cfg.ListenAddr); err != nil {
		return cfg, "", err
	}
	return cfg, configPath, nil
}
func saveInitializationConfig(path string, cfg config.Server) error {
	if _, err := os.Lstat(path); err == nil {
		existing, err := config.LoadServer(config.ServerOptions{ConfigPath: path, ConfigPathSet: true, LookupEnv: func(string) (string, bool) { return "", false }})
		if err != nil {
			return err
		}
		if existing.Security == nil || cfg.Security == nil || *existing.Security != *cfg.Security || existing.DBPath != cfg.DBPath || existing.ListenAddr != cfg.ListenAddr {
			return errors.New("existing config differs; choose a fresh config path without overwriting it")
		}
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	data := struct {
		ListenAddr string        `json:"listen_addr"`
		DBPath     string        `json:"db_path"`
		Security   *config.Setup `json:"security"`
	}{cfg.ListenAddr, cfg.DBPath, cfg.Security}
	if err = json.NewEncoder(f).Encode(data); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		os.Remove(path)
		return err
	}
	return closeErr
}
