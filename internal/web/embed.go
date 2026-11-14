// Package web embeds the generated management UI distribution into the
// warden-server binary so the server is self-contained and never depends
// on a static directory or CDN at runtime. The UI is management-only: it
// uses the same JSON API as the CLI and provides no terminal,
// credential-reveal, SQL, or remote-command controls.
//
// The embedded layout is the Vite build output rooted at dist/: index.html
// at the distribution root with hashed sibling assets under assets/.
// Distribution() returns that root so callers can serve it directly.
package web

import (
	"embed"
	"encoding/json"
	"errors"
	"io/fs"
	"strings"
)

//go:embed dist
var assets embed.FS

// SetupDistribution exposes only the generated setup entry's dependency graph.
// Static overrides and the management entry are intentionally not considered.
func SetupDistribution() (fs.FS, error) {
	dist := Distribution()
	data, err := fs.ReadFile(dist, "setup-assets.json")
	if err != nil {
		return nil, err
	}
	var names []string
	if err := json.Unmarshal(data, &names); err != nil {
		return nil, err
	}
	allowed := make(map[string]bool, len(names))
	for _, name := range names {
		if !fs.ValidPath(name) || (name != "setup.html" && !strings.HasPrefix(name, "assets/")) || strings.Contains(name, "management-") {
			return nil, errors.New("invalid setup dependency allowlist")
		}
		if _, err := fs.Stat(dist, name); err != nil {
			return nil, err
		}
		allowed[name] = true
	}
	if !allowed["setup.html"] {
		return nil, errors.New("missing setup entry")
	}
	return setupFS{dist, allowed}, nil
}

type setupFS struct {
	dist    fs.FS
	allowed map[string]bool
}

func (s setupFS) Open(name string) (fs.File, error) {
	if !s.allowed[name] {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
	}
	return s.dist.Open(name)
}

// Distribution returns the embedded Vite distribution rooted so that
// index.html is directly readable at the fs root.
func Distribution() fs.FS {
	dist, err := fs.Sub(assets, "dist")
	if err != nil {
		panic("embedded web distribution: " + err.Error())
	}
	return dist
}
