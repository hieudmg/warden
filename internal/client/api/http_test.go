package api_test

import (
	"context"
	"crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"warden/internal/client/api"
	"warden/internal/model"
	"warden/internal/server"
	"warden/internal/server/audit"
	"warden/internal/server/profiles"
	"warden/internal/store"
)

func TestHTTPClientProductionContract(t *testing.T) {
	ctx := context.Background()
	var key [32]byte
	rand.Read(key[:])
	s, err := store.Open(ctx, filepath.Join(t.TempDir(), "fixture.db"), key)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500); w.Write([]byte("upstream failure")) }))
	defer up.Close()
	mux := http.NewServeMux()
	profiles.New(s, audit.New(s)).Register(mux)
	srv := httptest.NewServer(server.New("", mux).Handler())
	defer srv.Close()
	c := api.New(srv.URL, nil)
	token := "first"
	req := model.HTTPConnectionRequest{Name: "api", Origin: up.URL, AuthType: "x_api_key", Credential: &token}
	p, err := c.CreateHTTP(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	list, err := c.ListHTTP(ctx)
	if err != nil || len(list) != 1 {
		t.Fatal(list, err)
	}
	p, err = c.GetHTTP(ctx, p.ID)
	if err != nil || !p.HasCredential {
		t.Fatal(p, err)
	}
	req.Credential = nil
	req.Note = "edited"
	p, err = c.UpdateHTTP(ctx, p.ID, req)
	if err != nil || !p.HasCredential || p.Note != "edited" {
		t.Fatal(p, err)
	}
	out, err := c.RequestHTTP(ctx, p.ID, model.HTTPProxyRequest{Method: "GET", Path: "/"})
	if err != nil || out.StatusCode != 500 || string(out.Body) != "upstream failure" {
		t.Fatalf("upstream non-2xx confused with API failure: %+v %v", out, err)
	}
	if err := c.SetHTTPArchived(ctx, p.ID, true); err != nil {
		t.Fatal(err)
	}
	_, err = c.RequestHTTP(ctx, p.ID, model.HTTPProxyRequest{Method: "GET", Path: "/"})
	var apiErr *api.APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != 404 {
		t.Fatalf("archive=%v", err)
	}
	if err := c.DeleteHTTP(ctx, p.ID); err != nil {
		t.Fatal(err)
	}
	list, err = c.ListHTTP(ctx)
	if err != nil || len(list) != 0 {
		t.Fatal(list, err)
	}
}
