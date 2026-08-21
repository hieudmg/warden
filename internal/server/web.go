// Web UI serving: one listener serves both the embedded management UI and
// the JSON API. Requests under /api/v1/ are delegated to the API handler;
// everything else is served from the embedded assets. The UI is
// management-only, so no route here exposes terminals, credentials, or
// remote execution.
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
// path and /index.html are served with Cache-Control: no-store because the
// UI is stateful and must always reflect current server state. Asset paths
// are whitelisted (only the embedded files exist), served with content-type
// detection and a strong ETag so browsers revalidate efficiently. Unknown
// non-API paths return 404.
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
		case "/", "/index.html":
			// The management UI entrypoint must never be cached: a
			// stale index could hide newer server capabilities or
			// retain stale page state.
			name = "static/index.html"
			w.Header().Set("Cache-Control", "no-store")
		case "/static/app.js", "/static/styles.css":
			name = strings.TrimPrefix(r.URL.Path, "/")
		default:
			http.NotFound(w, r)
			return
		}
		serveAsset(w, r, assets, name)
	})
}

// serveAsset writes one embedded file with content-type detection, a strong
// ETag, and standard conditional-request handling via http.ServeContent.
// The name comes from the whitelist above, so no path-cleaning pass is
// needed.
func serveAsset(w http.ResponseWriter, r *http.Request, assets fs.FS, name string) {
	data, err := fs.ReadFile(assets, name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	modtime := time.Time{}
	if info, serr := fs.Stat(assets, name); serr == nil {
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
