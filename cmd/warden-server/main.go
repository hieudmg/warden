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
	"warden/internal/upgrade"
	"warden/internal/web"
)

// runUpgrade is the shared updater seam, replaced in tests to verify command
// plumbing without network or filesystem effects.
var runUpgrade = upgrade.Upgrade

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
	case "upgrade":
		return runServerUpgrade(args[1:], stdout, stderr, lookupEnv)
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

	warnUnsafeListenAddr(stderr, cfg.ListenAddr)
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

// runServerUpgrade replaces this executable with the latest released server
// binary. It takes no settings and never reads or writes server config, the
// database, the master key, or the service unit. The running service is left
// untouched, so a successful upgrade keeps serving the old binary until the
// operator restarts it.
func runServerUpgrade(args []string, stdout, stderr io.Writer, lookupEnv func(string) (string, bool)) int {
	if len(args) == 1 && isHelp(args[0]) {
		printUpgradeUsage(stdout)
		return 0
	}
	if len(args) != 0 {
		fmt.Fprintln(stderr, "usage: warden-server upgrade")
		return 2
	}

	repo, _ := lookupEnv("WARDEN_REPO")
	releaseBaseURL, _ := lookupEnv("WARDEN_RELEASE_BASE_URL")
	result, err := runUpgrade(context.Background(), upgrade.Server, upgrade.Options{
		Repo:           repo,
		ReleaseBaseURL: releaseBaseURL,
	})
	if err != nil {
		fmt.Fprintf(stderr, "warden-server upgrade: %v\n", err)
		return 1
	}
	writeUpgradeResult(stdout, "warden-server upgrade", result)
	printRestartGuide(stdout)
	return 0
}

// writeUpgradeResult reports how the verified download was applied. A
// scheduled replacement is asynchronous (Windows cannot replace a running
// executable), so it must not claim the executable already changed.
func writeUpgradeResult(w io.Writer, prefix string, result upgrade.Result) {
	if result.Scheduled {
		fmt.Fprintf(w, "%s: verified %s; replacement of %s is scheduled after this process exits\n", prefix, result.Asset, result.ExecutablePath)
		return
	}
	fmt.Fprintf(w, "%s: replaced %s with %s\n", prefix, result.ExecutablePath, result.Asset)
}

// printRestartGuide prints the manual restart steps from docs/deployment.md.
// warden-server upgrade never restarts the service itself: restarting is an
// operator decision, and the generated unit may be installed per user or as a
// system service.
func printRestartGuide(w io.Writer) {
	fmt.Fprint(w, `
The running service was not restarted. Restart it manually to run the new binary.

User scope:
  systemctl --user daemon-reload
  systemctl --user restart warden-server
  systemctl --user status warden-server

System scope:
  sudo systemctl daemon-reload
  sudo systemctl restart warden-server
  sudo systemctl status warden-server
`)
}

const unsafeListenWarning = "listen host must be loopback or a Tailscale address; public and wildcard binds are unsafe"

// warnUnsafeListenAddr reports the accepted exposure risk without preventing
// the server from binding. Public and wildcard binds are the user's concern.
func warnUnsafeListenAddr(w io.Writer, listenAddr string) {
	if config.IsUnsafeListenAddr(listenAddr) {
		fmt.Fprintf(w, "WARNING: %s\n", unsafeListenWarning)
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
  warden-server upgrade
  warden-server --help

Environment overrides:
  WARDEN_SERVER_CONFIG
  WARDEN_SERVER_LISTEN_ADDR
  WARDEN_SERVER_DB_PATH
  WARDEN_SERVER_MASTER_KEY_PATH
  WARDEN_SERVER_STATIC_FS
  WARDEN_REPO
  WARDEN_RELEASE_BASE_URL
`)
}

func printUpgradeUsage(w io.Writer) {
	fmt.Fprint(w, `Usage:
  warden-server upgrade

Downloads the latest released server binary, verifies it against the release
checksums, and replaces this executable. Server config, the database, the
master key, and the service unit are left untouched. The running service is
not restarted; the command prints the manual restart steps. Set WARDEN_REPO or
WARDEN_RELEASE_BASE_URL to upgrade from a different release source.
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
