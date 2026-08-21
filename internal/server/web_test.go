package server

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"warden/internal/web"
)

// apiStub is a minimal API handler that answers the management UI's calls
// with a fixed JSON document so delegation is observable without a store.
func apiStub() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/projects":
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `[{"id":1,"name":"demo"}]`)
		default:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			io.WriteString(w, `{"code":"not_found","message":"no such api route"}`)
		}
	})
}

func serveUIHandler() http.Handler {
	return ServeUI(apiStub(), web.Assets)
}

func TestServeUIServesIndexAtRoot(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	serveUIHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET / status = %d, want 200", rec.Code)
	}
	ct := rec.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "text/html") {
		t.Errorf("GET / Content-Type = %q, want text/html", ct)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("GET / Cache-Control = %q, want no-store", cc)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "<html") || !strings.Contains(body, "app.js") {
		t.Errorf("GET / body does not look like the management UI shell")
	}
}

func TestServeUIServesIndexAtExplicitPath(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/index.html", nil)
	serveUIHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /index.html status = %d, want 200", rec.Code)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("GET /index.html Cache-Control = %q, want no-store", cc)
	}
}

func TestServeUIServesStaticAssetsWithTypeAndETag(t *testing.T) {
	for _, tc := range []struct {
		path    string
		wantCT  string
	}{
		{"/static/app.js", "text/javascript"},
		{"/static/styles.css", "text/css"},
	} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, tc.path, nil)
		serveUIHandler().ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s status = %d, want 200", tc.path, rec.Code)
		}
		ct := rec.Header().Get("Content-Type")
		if !strings.HasPrefix(ct, tc.wantCT) {
			t.Errorf("GET %s Content-Type = %q, want prefix %q", tc.path, ct, tc.wantCT)
		}
		if rec.Header().Get("Etag") == "" {
			t.Errorf("GET %s missing ETag header", tc.path)
		}
		if rec.Body.Len() == 0 {
			t.Errorf("GET %s empty body", tc.path)
		}
	}
}

func TestServeUIDelegatesAPIPaths(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/projects", nil)
	serveUIHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/projects status = %d, want 200", rec.Code)
	}
	if got := strings.TrimSpace(rec.Body.String()); got != `[{"id":1,"name":"demo"}]` {
		t.Errorf("API body = %q, want stub response", got)
	}
}

func TestServeUIUnknownPathsReturn404(t *testing.T) {
	for _, path := range []string{"/does-not-exist", "/static/missing.js", "/api/v1/nope"} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		serveUIHandler().ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Errorf("GET %s status = %d, want 404", path, rec.Code)
		}
	}
}

// TestServeUIApiAndUIOnSameListener starts one net/http server with the
// wrapped handler and verifies both the embedded UI and the API are served
// from the same listener.
func TestServeUIApiAndUIOnSameListener(t *testing.T) {
	srv := New("", serveUIHandler())
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- srv.Serve(l) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		<-done
	})

	client := &http.Client{Timeout: 2 * time.Second}
	base := "http://" + l.Addr().String()

	uiResp, err := client.Get(base + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	uiResp.Body.Close()
	if uiResp.StatusCode != http.StatusOK {
		t.Errorf("GET / status = %d, want 200", uiResp.StatusCode)
	}
	if cc := uiResp.Header.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("GET / Cache-Control = %q, want no-store", cc)
	}

	apiResp, err := client.Get(base + "/api/v1/projects")
	if err != nil {
		t.Fatalf("GET /api/v1/projects: %v", err)
	}
	apiBody, _ := io.ReadAll(apiResp.Body)
	apiResp.Body.Close()
	if apiResp.StatusCode != http.StatusOK {
		t.Errorf("GET /api/v1/projects status = %d, want 200", apiResp.StatusCode)
	}
	if !strings.Contains(string(apiBody), "demo") {
		t.Errorf("API body = %q, want stub response", apiBody)
	}
}
