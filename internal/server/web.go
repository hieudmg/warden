// Web UI serving: one listener serves both the embedded management UI and
// the JSON API. Requests under /api/v1/ are delegated to the API handler;
// everything else is served from the assets fs. Top-level UI routes serve the
// entrypoint so browser refreshes work with client-side routing. The UI is
// management-only, so no route here exposes terminals, credentials, or remote
// execution.
package server

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io/fs"
	"mime"
	"net/http"
	"path/filepath"
	"strings"
	"time"
)

// ServeUI wraps the API handler with the embedded management UI. Requests
// whose path starts with /api/ are delegated unchanged to api. The root
// path, /index.html, and top-level UI routes are served with Cache-Control:
// no-store because the UI is stateful and must always reflect current server
// state. Every other existing asset is hashed at build time, so it is served
// with a long immutable cache lifetime. Asset names come from a whitelist of
// existing embedded files; traversal attempts fail path validation before any
// file access. Unknown non-API paths return 404.
func ServeUI(api http.Handler, assets fs.FS) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			api.ServeHTTP(w, r)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var name string
		switch r.URL.Path {
		case "/", "/index.html", "/ssh", "/databases", "/groups", "/key-pairs", "/projects":
			// The management UI entrypoint must never be cached: a
			// stale index could hide newer server capabilities or
			// retain stale page state.
			name = "index.html"
			w.Header().Set("Cache-Control", "no-store")
		default:
			name = strings.TrimPrefix(r.URL.Path, "/")
			if !fs.ValidPath(name) {
				http.NotFound(w, r)
				return
			}
			// Vite emits content-hashed asset filenames, so any
			// asset that exists today is immutable for its lifetime.
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		}
		serveAsset(w, r, assets, name)
	})
}

// serveAsset writes one file from the assets fs with content-type
// detection, a strong ETag, and standard conditional-request handling via
// http.ServeContent. Directories and missing files return 404.
func serveAsset(w http.ResponseWriter, r *http.Request, assets fs.FS, name string) {
	data, err := fs.ReadFile(assets, name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	modtime := time.Time{}
	if info, serr := fs.Stat(assets, name); serr == nil && !info.IsDir() {
		modtime = info.ModTime()
	}

	sum := sha256.Sum256(data)
	w.Header().Set("Etag", fmt.Sprintf(`"%x"`, sum))
	if w.Header().Get("Content-Type") == "" {
		ct := mime.TypeByExtension(filepath.Ext(name))
		if ct == "" {
			ct = "application/octet-stream"
		}
		w.Header().Set("Content-Type", ct)
	}
	http.ServeContent(w, r, filepath.Base(name), modtime, bytes.NewReader(data))
}
