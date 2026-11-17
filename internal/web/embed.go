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
	"io/fs"
)

//go:embed dist
var assets embed.FS

// Distribution returns the embedded Vite distribution rooted so that
// index.html is directly readable at the fs root.
func Distribution() fs.FS {
	dist, err := fs.Sub(assets, "dist")
	if err != nil {
		panic("embedded web distribution: " + err.Error())
	}
	return dist
}
