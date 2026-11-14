package web

import (
	"io/fs"
	"strings"
	"testing"
)

func TestEmbeddedSetupDependencyAllowlist(t *testing.T) {
	setup, err := SetupDistribution()
	if err != nil {
		t.Fatal(err)
	}
	html, err := fs.ReadFile(setup, "setup.html")
	if err != nil || !strings.Contains(string(html), "/assets/setup-") {
		t.Fatal("missing production setup entry", err)
	}
	for _, name := range []string{"index.html", ".vite/manifest.json", "setup-assets.json"} {
		if _, err := fs.ReadFile(setup, name); err == nil {
			t.Fatal("exposed nonsetup asset", name)
		}
	}
	files, err := fs.Glob(Distribution(), "assets/*")
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, name := range files {
		b, err := fs.ReadFile(setup, name)
		if strings.Contains(name, "management-") && err == nil {
			t.Fatal("exposed management asset", name)
		}
		if err == nil {
			count++
			if strings.Contains(string(b), "/api/v1/export") || strings.Contains(string(b), "/api/v1/ssh") {
				t.Fatal("setup imports management API")
			}
		}
	}
	if count == 0 {
		t.Fatal("no setup dependencies allowed")
	}
}
