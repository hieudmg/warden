package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"warden/internal/config"
	"warden/internal/crypto"
	"warden/internal/server"
	"warden/internal/server/audit"
	"warden/internal/server/profiles"
	"warden/internal/server/reports"
	"warden/internal/store"
	"warden/internal/web"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, os.LookupEnv))
}

func run(args []string, stdout, stderr io.Writer, lookupEnv func(string) (string, bool)) int {
	if len(args) == 0 || isHelp(args[0]) {
		printUsage(stdout)
		return 0
	}

	switch args[0] {
	case "serve":
		return runServe(args[1:], stdout, stderr, lookupEnv)
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n", args[0])
		printUsage(stderr)
		return 2
	}
}

func runServe(args []string, stdout, stderr io.Writer, lookupEnv func(string) (string, bool)) int {
	cmd := flag.NewFlagSet("serve", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	cmd.Usage = func() {}

	configPath := cmd.String("config", "", "path to server config JSON")
	if err := cmd.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			printServeUsage(stdout)
			return 0
		}
		return 2
	}
	if cmd.NArg() != 0 {
		fmt.Fprintln(stderr, "serve does not accept positional arguments")
		printServeUsage(stderr)
		return 2
	}

	cfg, err := config.LoadServer(config.ServerOptions{
		ConfigPath:    *configPath,
		ConfigPathSet: flagWasSet(cmd, "config"),
		LookupEnv:     lookupEnv,
	})
	if err != nil {
		fmt.Fprintf(stderr, "invalid server config: %v\n", err)
		return 1
	}

	key, err := crypto.LoadMasterKey(cfg.MasterKeyPath)
	if err != nil {
		fmt.Fprintf(stderr, "load master key: %v\n", err)
		return 1
	}
	s, err := store.Open(context.Background(), cfg.DBPath, key)
	if err != nil {
		fmt.Fprintf(stderr, "open store: %v\n", err)
		return 1
	}
	defer s.Close()

	rec := audit.New(s)
	mux := http.NewServeMux()
	profiles.New(s, rec).Register(mux)
	reports.New(s, rec).Register(mux)

	// The management UI is embedded by default; WARDEN_SERVER_STATIC_FS
	// overrides it with a directory containing index.html at its root.
	handler := server.ServeUI(mux, uiAssets(cfg.StaticFS))

	srv := server.New(cfg.ListenAddr, handler)
	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe() }()

	fmt.Fprintf(stdout, "warden-server listening on %s\n", cfg.ListenAddr)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	select {
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintf(stderr, "server error: %v\n", err)
			return 1
		}
		return 0
	case sig := <-sigCh:
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			fmt.Fprintf(stderr, "shutdown: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "received %s, shutting down\n", sig)
		return 0
	}
}

// uiAssets returns the filesystem the management UI is served from. The
// default is the generated Vite distribution embedded in the binary;
// WARDEN_SERVER_STATIC_FS overrides it with a directory that contains
// index.html directly at its root (the layout the frontend build emits).
func uiAssets(staticFS string) fs.FS {
	if staticFS != "" {
		return os.DirFS(staticFS)
	}
	return web.Distribution()
}

func printUsage(w io.Writer) {
	fmt.Fprint(w, `Usage:
  warden-server serve [--config path]
  warden-server --help

Environment overrides:
  WARDEN_SERVER_CONFIG
  WARDEN_SERVER_LISTEN_ADDR
  WARDEN_SERVER_DB_PATH
  WARDEN_SERVER_MASTER_KEY_PATH
  WARDEN_SERVER_STATIC_FS
`)
}

func printServeUsage(w io.Writer) {
	fmt.Fprint(w, `Usage:
  warden-server serve [--config path]
`)
}

func isHelp(value string) bool {
	return value == "-h" || value == "--help" || value == "help"
}

func flagWasSet(fs *flag.FlagSet, name string) bool {
	found := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}
