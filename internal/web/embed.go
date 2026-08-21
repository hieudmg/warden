// Package web embeds the management UI static assets into the warden-server
// binary so the server is self-contained and never depends on a static
// directory at runtime. The UI is management-only: it uses the same JSON
// API as the CLI and provides no terminal, credential-reveal, SQL, or
// remote-command controls.
package web

import "embed"

// Assets holds the embedded management UI. The static directory contains
// index.html, app.js, and styles.css; index.html is the single-page shell
// and references the other assets with absolute /static/... paths.
//
//go:embed static
var Assets embed.FS
