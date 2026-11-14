package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"warden/internal/client/api"
	"warden/internal/config"
)

// Existing command/SSH fixtures isolate presentation and local execution from
// enrollment. Only this test seam selects their verified TLS client; production
// always uses NewAgent. The integrated enrollment journey exercises that default.
func newCLITestAPI(t *testing.T, h http.Handler) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/v1/client/") {
			t.Errorf("command escaped client audience: %s", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		clone := r.Clone(r.Context())
		u := *r.URL
		clone.URL = &u
		clone.URL.Path = strings.Replace(u.Path, "/api/v1/client/", "/api/v1/", 1)
		h.ServeHTTP(w, clone)
	}))
	previous := newAPIClient
	newAPIClient = func(cfg config.Client) *api.Client { return api.New(cfg.APIBaseURL, srv.Client()) }
	t.Cleanup(func() { newAPIClient = previous; srv.Close() })
	return srv
}
