package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"

	"warden/internal/config"
	"warden/internal/server/setup"
	"warden/internal/web"

	"golang.org/x/term"
)

func printInitUsage(w io.Writer) {
	fmt.Fprintln(w, "Usage: warden-server init [--config path]\n\nDefaults to ~/.warden/server.json, ~/.warden/warden.db and ~/.warden/tls/.\nSaves each non-secret answer immediately; rerun to edit saved defaults.\nPrompts on the controlling terminal for fresh storage and HTTPS/RP/TLS or\nliteral-loopback proxy configuration. Creates only a temporary password-gated\nsetup plane, creates an account (default) or passkey, confirms saved recovery,\nthen exits. No unauthenticated mode. Existing\nstorage and initialized configuration are never reset. Normal serve starts\nlocked after initialization.")
	fmt.Fprint(w, transferHelp)
}
func runInit(args []string, stdout, stderr io.Writer, lookupEnv func(string) (string, bool)) int {
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
	if flagWasSet(cmd, "config") {
		*path = strings.TrimSpace(*path)
		if *path == "" {
			fmt.Fprintln(stderr, "--config must not be empty")
			return 1
		}
	} else if value, ok := lookupEnv("WARDEN_SERVER_CONFIG"); ok {
		*path = strings.TrimSpace(value)
		if *path == "" {
			fmt.Fprintln(stderr, "WARDEN_SERVER_CONFIG must not be empty when set")
			return 1
		}
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
	_, _, err = initializeWithAnswers(input, output, *path, func(cfg config.Server) error {
		assets, err := web.SetupDistribution()
		if err != nil {
			return errors.New("embedded setup distribution unavailable; rebuild web assets")
		}
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		return setup.Run(ctx, setup.Options{Config: *cfg.Security, Bind: cfg.ListenAddr, DBPath: cfg.DBPath, Assets: assets}, output)
	})
	if err != nil {
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
	return initializeWithAnswers(input, out, configPath, nil)
}

func initializeWithAnswers(input io.Reader, out io.Writer, configPath string, runSetup func(config.Server) error) (config.Server, string, error) {
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
	session, err := openInitializationConfig(configPath)
	if err != nil {
		return config.Server{}, configPath, err
	}
	defer session.lease.Close()
	cfg := &session.cfg
	cfg.InitializationDraft = true
	if err := session.save(); err != nil {
		return *cfg, configPath, err
	}
	answer := func(label string, target *string, fallback string, changed func()) error {
		def := *target
		if def == "" {
			def = fallback
		}
		value, err := ask(label, def)
		if err != nil {
			return err
		}
		*target = value
		if changed != nil {
			changed()
		}
		return session.save()
	}
	fields := []struct {
		label  string
		target *string
	}{
		{"Fresh storage path", &cfg.DBPath},
		{"Public HTTPS origin", &cfg.Security.PublicOrigin},
		{"WebAuthn RP ID", &cfg.Security.RPID},
	}
	for _, field := range fields {
		if err := answer(field.label, field.target, "", nil); err != nil {
			return *cfg, configPath, err
		}
	}
	if err := answer("Mode (tls or proxy)", &cfg.Security.Mode, "tls", func() {
		switch cfg.Security.Mode {
		case "tls":
			cfg.Security.BackendAuthority = ""
		case "proxy":
			cfg.Security.TLSCertificate = ""
			cfg.Security.TLSKey = ""
		}
	}); err != nil {
		return *cfg, configPath, err
	}
	if err := answer("Listen address", &cfg.ListenAddr, "", nil); err != nil {
		return *cfg, configPath, err
	}
	switch cfg.Security.Mode {
	case "tls":
		defaults := config.DefaultSetup()
		if err := answer("TLS certificate path", &cfg.Security.TLSCertificate, defaults.TLSCertificate, nil); err != nil {
			return *cfg, configPath, err
		}
		err = answer("TLS private key path", &cfg.Security.TLSKey, defaults.TLSKey, nil)
	case "proxy":
		err = answer("Explicit loopback backend authority", &cfg.Security.BackendAuthority, cfg.ListenAddr, nil)
	}
	if err != nil {
		return *cfg, configPath, err
	}
	if err := answer("Authentication method (account or passkey)", &cfg.Security.AuthMethod, "account", nil); err != nil {
		return *cfg, configPath, err
	}
	if err := cfg.Security.Validate(cfg.ListenAddr); err != nil {
		return *cfg, configPath, err
	}
	if strings.TrimSpace(cfg.DBPath) == "" {
		return *cfg, configPath, errors.New("db path must not be empty")
	}
	if err := freshInitializationStorage(cfg.DBPath); err != nil {
		return *cfg, configPath, err
	}
	if runSetup != nil {
		// Publish only validated answers before setup can commit an identity.
		// A crash after commit therefore cannot leave an editable draft pointing
		// at initialized storage. The config lease stays held through setup.
		cfg.InitializationDraft = false
		if err := session.save(); err != nil {
			return *cfg, configPath, err
		}
		if err := runSetup(*cfg); err != nil {
			return *cfg, configPath, err
		}
	}
	return *cfg, configPath, nil
}
