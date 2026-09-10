package main

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
