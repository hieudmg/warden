package main

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"warden/internal/upgrade"
)

func TestRunServeRejectsEmptyExplicitConfigFlag(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := run([]string{"serve", "--config="}, &stdout, &stderr, emptyLookupEnv)
	if exitCode != 1 {
		t.Fatalf("run() exitCode = %d, want 1, stdout=%q stderr=%q", exitCode, stdout.String(), stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("run() stdout = %q, want empty", stdout.String())
	}
	if !strings.Contains(stderr.String(), "--config") {
		t.Fatalf("run() stderr = %q, want --config error", stderr.String())
	}
}

func TestRunServerUpgradeRejectsArguments(t *testing.T) {
	oldRunUpgrade := runUpgrade
	defer func() { runUpgrade = oldRunUpgrade }()
	called := false
	runUpgrade = func(context.Context, upgrade.Kind, upgrade.Options) (upgrade.Result, error) {
		called = true
		return upgrade.Result{}, nil
	}

	var stdout, stderr bytes.Buffer
	exitCode := run([]string{"upgrade", "extra"}, &stdout, &stderr, emptyLookupEnv)
	if exitCode != 2 {
		t.Fatalf("run() exitCode = %d, want 2, stderr=%q", exitCode, stderr.String())
	}
	if !strings.Contains(stderr.String(), "usage: warden-server upgrade") {
		t.Fatalf("stderr = %q, want upgrade usage", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
	if called {
		t.Fatal("runUpgrade called for invalid arguments")
	}
}

func TestRunServerUpgradeReportsSuccess(t *testing.T) {
	oldRunUpgrade := runUpgrade
	defer func() { runUpgrade = oldRunUpgrade }()

	var gotKind upgrade.Kind
	var gotOptions upgrade.Options
	runUpgrade = func(_ context.Context, kind upgrade.Kind, opts upgrade.Options) (upgrade.Result, error) {
		gotKind = kind
		gotOptions = opts
		return upgrade.Result{Asset: "warden-server-linux-amd64", ExecutablePath: "/usr/local/bin/warden-server"}, nil
	}

	// The server config path is deliberately set to a file that does not
	// exist: upgrade must not load server config, and no WARDEN_SERVER_ key
	// may be requested.
	var requestedKeys []string
	lookupEnv := func(key string) (string, bool) {
		requestedKeys = append(requestedKeys, key)
		switch key {
		case "WARDEN_REPO":
			return "acme/warden", true
		case "WARDEN_RELEASE_BASE_URL":
			return "https://mirror.example/releases/latest/download", true
		case "WARDEN_SERVER_CONFIG":
			return filepath.Join(t.TempDir(), "missing-server.json"), true
		}
		return "", false
	}

	var stdout, stderr bytes.Buffer
	exitCode := run([]string{"upgrade"}, &stdout, &stderr, lookupEnv)
	if exitCode != 0 {
		t.Fatalf("run() exitCode = %d, want 0, stderr=%q", exitCode, stderr.String())
	}
	if gotKind != upgrade.Server {
		t.Fatalf("runUpgrade kind = %v, want upgrade.Server", gotKind)
	}
	if gotOptions.Repo != "acme/warden" {
		t.Errorf("runUpgrade repo = %q, want acme/warden", gotOptions.Repo)
	}
	if gotOptions.ReleaseBaseURL != "https://mirror.example/releases/latest/download" {
		t.Errorf("runUpgrade release base = %q, want env override", gotOptions.ReleaseBaseURL)
	}
	out := stdout.String()
	if !strings.Contains(out, "warden-server-linux-amd64") || !strings.Contains(out, "/usr/local/bin/warden-server") {
		t.Fatalf("stdout = %q, want asset and executable path", out)
	}
	if strings.Contains(out, "listening on") || strings.Contains(stderr.String(), "listening on") {
		t.Fatalf("upgrade must not start the server: stdout=%q stderr=%q", out, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
	for _, key := range requestedKeys {
		if strings.HasPrefix(key, "WARDEN_SERVER_") {
			t.Errorf("upgrade requested server config key %q, want none", key)
		}
	}
}

func TestRunServerUpgradePrintsRestartGuide(t *testing.T) {
	oldRunUpgrade := runUpgrade
	defer func() { runUpgrade = oldRunUpgrade }()

	runUpgrade = func(_ context.Context, _ upgrade.Kind, _ upgrade.Options) (upgrade.Result, error) {
		return upgrade.Result{Asset: "warden-server-linux-amd64", ExecutablePath: "/usr/local/bin/warden-server"}, nil
	}

	var stdout, stderr bytes.Buffer
	exitCode := run([]string{"upgrade"}, &stdout, &stderr, emptyLookupEnv)
	if exitCode != 0 {
		t.Fatalf("run() exitCode = %d, want 0, stderr=%q", exitCode, stderr.String())
	}
	out := stdout.String()
	for _, want := range []string{
		"systemctl --user daemon-reload",
		"systemctl --user restart warden-server",
		"sudo systemctl daemon-reload",
		"sudo systemctl restart warden-server",
		"was not restarted",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("stdout = %q, want restart guide line %q", out, want)
		}
	}
	if strings.Contains(out, "listening on") {
		t.Fatalf("stdout = %q, upgrade must not start the server", out)
	}
}

func TestRunServerUpgradeReportsFailure(t *testing.T) {
	oldRunUpgrade := runUpgrade
	defer func() { runUpgrade = oldRunUpgrade }()

	runUpgrade = func(context.Context, upgrade.Kind, upgrade.Options) (upgrade.Result, error) {
		return upgrade.Result{}, errors.New("no suitable release binary for warden-server (darwin/arm64)")
	}

	var stdout, stderr bytes.Buffer
	exitCode := run([]string{"upgrade"}, &stdout, &stderr, emptyLookupEnv)
	if exitCode != 1 {
		t.Fatalf("run() exitCode = %d, want 1, stderr=%q", exitCode, stderr.String())
	}
	if !strings.Contains(stderr.String(), "warden-server upgrade: no suitable release binary") {
		t.Fatalf("stderr = %q, want prefixed upgrade error", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty on failure", stdout.String())
	}
}

func TestRunServerUpgradeHelp(t *testing.T) {
	var stdout, stderr bytes.Buffer
	exitCode := run([]string{"upgrade", "--help"}, &stdout, &stderr, emptyLookupEnv)
	if exitCode != 0 {
		t.Fatalf("run() exitCode = %d, want 0, stderr=%q", exitCode, stderr.String())
	}
	if !strings.Contains(stdout.String(), "warden-server upgrade") {
		t.Fatalf("stdout = %q, want upgrade usage", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func emptyLookupEnv(string) (string, bool) {
	return "", false
}

func TestWarnUnsafeListenAddrWarnsOnlyForUnsafeHosts(t *testing.T) {
	t.Parallel()

	const want = "WARNING: listen host must be loopback or a Tailscale address; public and wildcard binds are unsafe\n"
	for _, test := range []struct {
		name    string
		address string
		want    string
	}{
		{name: "wildcard", address: "0.0.0.0:8080", want: want},
		{name: "loopback", address: "127.0.0.1:8080"},
		{name: "tailscale", address: "100.64.0.1:8080"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var stderr bytes.Buffer
			warnUnsafeListenAddr(&stderr, test.address)
			if stderr.String() != test.want {
				t.Errorf("warning = %q, want %q", stderr.String(), test.want)
			}
		})
	}
}

func TestUIAssetsStaticFSPointsAtRootContainingIndexHTML(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("<html>override</html>"), 0o644); err != nil {
		t.Fatalf("write index.html: %v", err)
	}

	assets := uiAssets(dir)
	data, err := fs.ReadFile(assets, "index.html")
	if err != nil {
		t.Fatalf("index.html not readable at fs root: %v", err)
	}
	if !strings.Contains(string(data), "override") {
		t.Errorf("served index.html = %q, want override fixture", data)
	}
}

func TestUIAssetsDefaultsToEmbeddedDistribution(t *testing.T) {
	t.Parallel()

	assets := uiAssets("")
	data, err := fs.ReadFile(assets, "index.html")
	if err != nil {
		t.Fatalf("embedded distribution missing index.html at fs root: %v", err)
	}
	if len(data) == 0 {
		t.Errorf("embedded index.html is empty")
	}
}
