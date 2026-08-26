package api

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const sshConnJSON = `{
	"id": 7,
	"name": "prod",
	"host": "10.0.0.7",
	"port": 2222,
	"username": "ops",
	"has_password": true,
	"key_pair_id": 0,
	"proxy_host": "",
	"proxy_port": 0,
	"proxy_username": "",
	"has_proxy_password": false,
	"jump_connection_ids": "[]",
	"created_at": "2026-08-21T00:00:00Z",
	"updated_at": "2026-08-21T00:00:00Z"
}`

const dbConnJSON = `{
	"id": 3,
	"name": "analytics",
	"host": "db.invalid",
	"port": 3306,
	"username": "reader",
	"has_password": true,
	"database": "warehouse",
	"ssh_connection_id": 0,
	"created_at": "2026-08-21T00:00:00Z",
	"updated_at": "2026-08-21T00:00:00Z"
}`

const sshBundleJSON = `{
	"target": {
		"id": 7,
		"name": "prod",
		"host": "10.0.0.7",
		"port": 2222,
		"username": "ops",
		"password": "dG9wLXNlY3JldA==",
		"private_key": "LS0tLS1CRUdJTiBLRVktLS0tLQ==",
		"proxy_host": "",
		"proxy_port": 0
	},
	"jumps": [
		{
			"id": 2,
			"name": "bastion",
			"host": "10.0.0.2",
			"port": 22,
			"username": "ops",
			"password": "anVtcC1zZWNyZXQ=",
			"proxy_host": "",
			"proxy_port": 0
		}
	]
}`

const dbBundleJSON = `{
	"host": "db.invalid",
	"port": 3306,
	"username": "reader",
	"password": "ZGItc2VjcmV0",
	"database": "warehouse",
	"ssh": null
}`

func TestListSSHPathAndDecode(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/v1/ssh-connections" {
			t.Errorf("request = %s %s, want GET /api/v1/ssh-connections", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, "["+sshConnJSON+"]")
	}))
	defer srv.Close()

	conns, err := New(srv.URL, nil).ListSSH(context.Background())
	if err != nil {
		t.Fatalf("ListSSH: %v", err)
	}
	if len(conns) != 1 || conns[0].ID != 7 || conns[0].Name != "prod" || conns[0].HasPassword != true || conns[0].KeyPairID != 0 {
		t.Fatalf("ListSSH = %+v, want one decoded prod connection", conns)
	}
}

func TestGetSSHPathAndDecode(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/ssh-connections/7" {
			t.Errorf("path = %q, want /api/v1/ssh-connections/7", r.URL.Path)
		}
		io.WriteString(w, sshConnJSON)
	}))
	defer srv.Close()

	conn, err := New(srv.URL, nil).GetSSH(context.Background(), 7)
	if err != nil {
		t.Fatalf("GetSSH: %v", err)
	}
	if conn.ID != 7 || conn.Username != "ops" || conn.JumpConnectionIDs != "[]" || conn.KeyPairID != 0 {
		t.Fatalf("GetSSH = %+v", conn)
	}
}

func TestListDBAndGetDB(t *testing.T) {
	t.Parallel()

	got := make([]string, 0, 2)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.Method+" "+r.URL.Path)
		switch r.URL.Path {
		case "/api/v1/db-connections":
			io.WriteString(w, "["+dbConnJSON+"]")
		case "/api/v1/db-connections/3":
			io.WriteString(w, dbConnJSON)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	cl := New(srv.URL, nil)
	dbs, err := cl.ListDB(context.Background())
	if err != nil || len(dbs) != 1 || dbs[0].Name != "analytics" {
		t.Fatalf("ListDB = %+v, err = %v", dbs, err)
	}
	db, err := cl.GetDB(context.Background(), 3)
	if err != nil || db.Database != "warehouse" {
		t.Fatalf("GetDB = %+v, err = %v", db, err)
	}
	want := []string{"GET /api/v1/db-connections", "GET /api/v1/db-connections/3"}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("request[%d] = %q, want %q", i, got[i], w)
		}
	}
}

func TestGetSSHBundleDecodesSecretsAndNoStore(t *testing.T) {
	t.Parallel()

	var gotHeader string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/transport/ssh/7" {
			t.Errorf("path = %q, want /api/v1/transport/ssh/7", r.URL.Path)
		}
		w.Header().Set("Cache-Control", "no-store")
		gotHeader = w.Header().Get("Cache-Control")
		io.WriteString(w, sshBundleJSON)
	}))
	defer srv.Close()

	bundle, err := New(srv.URL, nil).GetSSHBundle(context.Background(), 7)
	if err != nil {
		t.Fatalf("GetSSHBundle: %v", err)
	}
	if string(bundle.Target.Password) != "top-secret" {
		t.Errorf("target password = %q, want decoded top-secret", bundle.Target.Password)
	}
	if string(bundle.Target.PrivateKey) != "-----BEGIN KEY-----" {
		t.Errorf("target private key = %q, want decoded PEM prefix", bundle.Target.PrivateKey)
	}
	if len(bundle.Jumps) != 1 || string(bundle.Jumps[0].Password) != "jump-secret" {
		t.Fatalf("jumps = %+v, want one jump with decoded password", bundle.Jumps)
	}
	if gotHeader != "no-store" {
		t.Errorf("transport response Cache-Control = %q, want no-store", gotHeader)
	}
}

func TestGetDBBundleDecodes(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/transport/db/3" {
			t.Errorf("path = %q, want /api/v1/transport/db/3", r.URL.Path)
		}
		w.Header().Set("Cache-Control", "no-store")
		io.WriteString(w, dbBundleJSON)
	}))
	defer srv.Close()

	bundle, err := New(srv.URL, nil).GetDBBundle(context.Background(), 3)
	if err != nil {
		t.Fatalf("GetDBBundle: %v", err)
	}
	if bundle.Host != "db.invalid" || string(bundle.Password) != "db-secret" || bundle.SSH != nil {
		t.Fatalf("GetDBBundle = %+v", bundle)
	}
}

func TestDependentsDecode(t *testing.T) {
	t.Parallel()

	body := `{"ssh":[{"id":9,"name":"via-prod"}],"db":[{"id":2,"name":"warehouse"}]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/ssh-connections/7/dependents":
			io.WriteString(w, body)
		case "/api/v1/db-connections/7/dependents":
			io.WriteString(w, `{"ssh":[],"db":[]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	cl := New(srv.URL, nil)
	deps, err := cl.SSHDependents(context.Background(), 7)
	if err != nil || len(deps.SSH) != 1 || deps.SSH[0].Name != "via-prod" || len(deps.DB) != 1 {
		t.Fatalf("SSHDependents = %+v, err = %v", deps, err)
	}
	empty, err := cl.DBDependents(context.Background(), 7)
	if err != nil || len(empty.SSH) != 0 || len(empty.DB) != 0 {
		t.Fatalf("DBDependents = %+v, err = %v", empty, err)
	}
}

func TestJSONErrorSurfacesAPIError(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		io.WriteString(w, `{"code":"not_found","message":"connection not found"}`)
	}))
	defer srv.Close()

	_, err := New(srv.URL, nil).GetSSH(context.Background(), 99)
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("GetSSH err = %v, want *APIError", err)
	}
	if apiErr.StatusCode != http.StatusNotFound || apiErr.Code != "not_found" || !strings.Contains(apiErr.Message, "connection not found") {
		t.Fatalf("APIError = %+v", apiErr)
	}
}

func TestNonJSONErrorBodySurfacesAPIError(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		io.WriteString(w, "boom")
	}))
	defer srv.Close()

	_, err := New(srv.URL, nil).ListSSH(context.Background())
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("ListSSH err = %v, want *APIError", err)
	}
	if apiErr.Code != "" || apiErr.Message != http.StatusText(http.StatusInternalServerError) {
		t.Fatalf("APIError = %+v, want status-text-only message (no raw body)", apiErr)
	}
	if strings.Contains(apiErr.Error(), "boom") {
		t.Fatalf("APIError leaks raw body text: %v", apiErr.Error())
	}
}

func TestJSONErrorMessageTruncated(t *testing.T) {
	t.Parallel()

	long := strings.Repeat("x", 10*maxErrorMessageBytes)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		io.WriteString(w, `{"code":"conflict","message":"`+long+`"}`)
	}))
	defer srv.Close()

	_, err := New(srv.URL, nil).GetSSH(context.Background(), 1)
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("GetSSH err = %v, want *APIError", err)
	}
	if apiErr.Code != "conflict" {
		t.Fatalf("APIError = %+v, want conflict code", apiErr)
	}
	if len(apiErr.Message) > maxErrorMessageBytes {
		t.Fatalf("message length = %d, want cap %d", len(apiErr.Message), maxErrorMessageBytes)
	}
}

func TestEmptyErrorBodySurfacesAPIError(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()

	_, err := New(srv.URL, nil).ListSSH(context.Background())
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("ListSSH err = %v, want *APIError", err)
	}
	if apiErr.StatusCode != http.StatusBadGateway || apiErr.Code != "" {
		t.Fatalf("APIError = %+v", apiErr)
	}
}

func TestContextDeadlineCancelsRequest(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		io.WriteString(w, "[]")
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := New(srv.URL, nil).ListSSH(ctx)
	if err == nil {
		t.Fatal("ListSSH succeeded, want context deadline error")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("ListSSH err = %v, want context.DeadlineExceeded", err)
	}
}

func TestResponseBodyClosed(t *testing.T) {
	t.Parallel()

	tr := &trackingRoundTripper{
		respond: func(w http.ResponseWriter) {
			io.WriteString(w, sshConnJSON)
		},
	}
	cl := New("http://example.invalid", &http.Client{Transport: tr})

	if _, err := cl.GetSSH(context.Background(), 7); err != nil {
		t.Fatalf("GetSSH: %v", err)
	}
	if !tr.bodyClosed.Load() {
		t.Fatal("response body was not closed after GetSSH")
	}
}

func TestStrictDecodingRejectsUnknownFields(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"id":1,"name":"x","host":"h","port":22,"username":"u","bogus":1}`)
	}))
	defer srv.Close()

	_, err := New(srv.URL, nil).GetSSH(context.Background(), 1)
	if err == nil || !strings.Contains(err.Error(), "bogus") {
		t.Fatalf("GetSSH err = %v, want unknown-field rejection", err)
	}
}

func TestOversizedResponseRejected(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "["+strings.Repeat(" ", maxResponseBytes)+"]")
	}))
	defer srv.Close()

	_, err := New(srv.URL, nil).ListSSH(context.Background())
	if err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("ListSSH err = %v, want too-large rejection", err)
	}
}

// trackingRoundTripper records whether the response body was closed.
type trackingRoundTripper struct {
	respond    func(w http.ResponseWriter)
	bodyClosed atomic.Bool
	mu         sync.Mutex
}

func (t *trackingRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	rec := httptest.NewRecorder()
	t.mu.Lock()
	fn := t.respond
	t.mu.Unlock()
	fn(rec)
	resp := rec.Result()
	resp.Body = &closeTrackingBody{ReadCloser: resp.Body, closed: &t.bodyClosed}
	return resp, nil
}

type closeTrackingBody struct {
	io.ReadCloser
	closed *atomic.Bool
}

func (b *closeTrackingBody) Close() error {
	b.closed.Store(true)
	return b.ReadCloser.Close()
}
