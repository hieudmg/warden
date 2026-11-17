package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/signal"
	"syscall"

	runtimeplane "warden/internal/server/runtime"

	"warden/internal/config"
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
	case "init":
		return runInit(args[1:], stdout, stderr, lookupEnv)
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

	if cfg.Security == nil {
		fmt.Fprintln(stderr, "storage requires explicit HTTPS security configuration and warden-server init; retain DB/WAL/SHM/config/master key, export legacy data with the old release and initialize fresh storage; never reset existing storage")
		return 1
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := runtimeplane.Run(ctx, runtimeplane.Options{Config: *cfg.Security, Bind: cfg.ListenAddr, DBPath: cfg.DBPath, Assets: uiAssets(cfg.StaticFS)}); err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintf(stderr, "serve refused: %v; run warden-server init only with fresh storage; retain legacy DB/WAL/SHM/config/master key and export using the old release\n", err)
		return 1
	}
	return 0
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

const transferHelp = `
Legacy transfer (no in-place encrypted database upgrade):
  Use the old release to export warden-data version 1 (plaintext secrets).
  Initialize fresh storage; serve, authenticate and unlock, then import into
  empty managed tables. Manually verify records and secrets before cutover.
  Retain the old binary/config/DB/WAL/SHM/key together for rollback; never delete
  or overwrite them to make startup work. See docs/migration.md.
`

func printUsage(w io.Writer) {
	fmt.Fprint(w, `Usage:
  warden-server init [--config path]
  warden-server serve [--config path]
  warden-server upgrade
  warden-server --help

Environment overrides:
  WARDEN_SERVER_CONFIG
  WARDEN_SERVER_LISTEN_ADDR
  WARDEN_SERVER_DB_PATH
  WARDEN_SERVER_STATIC_FS
  WARDEN_REPO
  WARDEN_RELEASE_BASE_URL
`)
	fmt.Fprint(w, transferHelp)
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

Defaults to ~/.warden/server.json; when absent, discovers /etc/warden/server.json
without copying or migrating it. --config and WARDEN_SERVER_CONFIG take precedence.
Unfinished initialization drafts are refused; rerun init with the same config.
`)
	fmt.Fprint(w, transferHelp)
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
