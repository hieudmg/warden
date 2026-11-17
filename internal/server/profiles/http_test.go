package profiles_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"warden/internal/model"
	"warden/internal/server"
)

type httpDeadlineWriter struct {
	*httptest.ResponseRecorder
	flushed, resetBeforeFlush   bool
	flushFailure                bool
	readDeadline, writeDeadline time.Time
}

func (w *httpDeadlineWriter) SetReadDeadline(t time.Time) error {
	if t.IsZero() && !w.flushed {
		w.resetBeforeFlush = true
	}
	w.readDeadline = t
	return nil
}
func (w *httpDeadlineWriter) SetWriteDeadline(t time.Time) error {
	if t.IsZero() && !w.flushed {
		w.resetBeforeFlush = true
	}
	w.writeDeadline = t
	return nil
}
func (w *httpDeadlineWriter) FlushError() error {
	w.flushed = true
	if w.flushFailure {
		return errors.New("fixture flush failure")
	}
	return nil
}

func TestHTTPProxyFlushesBeforeResettingDeadlines(t *testing.T) {
	h, _, _ := newTestAPI(t)
	for _, fail := range []bool{false, true} {
		w := &httpDeadlineWriter{ResponseRecorder: httptest.NewRecorder(), flushFailure: fail}
		req := httptest.NewRequest("POST", "/api/v1/http-connections/1/request", strings.NewReader(`{}`))
		server.New("", h).Handler().ServeHTTP(w, req)
		if !w.flushed || w.resetBeforeFlush {
			t.Fatalf("deadline reset before bounded response flush: flushed=%v early=%v", w.flushed, w.resetBeforeFlush)
		}
		if fail {
			if w.readDeadline.IsZero() || w.writeDeadline.IsZero() {
				t.Fatal("failed delivery cleared connection deadlines")
			}
		} else if !w.readDeadline.IsZero() || !w.writeDeadline.IsZero() {
			t.Fatal("successful delivery left connection deadlines")
		}
	}
}

func TestHTTPTransferAndGroupAPI(t *testing.T) {
	h, s, path := newTestAPI(t)
	ctx := context.Background()
	g, err := s.CreateGroup(ctx, model.Group{Name: "apis"})
	if err != nil {
		t.Fatal(err)
	}
	p, err := s.CreateHTTP(ctx, model.HTTPProfile{Name: "api", Origin: "http://localhost:9000", AuthType: "basic", Username: []byte("user"), Password: []byte("password"), Note: "note", GroupID: g.ID})
	if err != nil {
		t.Fatal(err)
	}
	route := fmt.Sprintf("/api/v1/groups/%d", g.ID)
	r := doRequest(t, h, "GET", route, "")
	var group model.Group
	json.Unmarshal(r.Body.Bytes(), &group)
	if r.Code != 200 || group.HTTPConnectionCount != 1 {
		t.Fatalf("group=%d %s", r.Code, r.Body.String())
	}
	r = doRequest(t, h, "GET", route+"/dependents", "")
	var deps model.DependentsResponse
	json.Unmarshal(r.Body.Bytes(), &deps)
	if r.Code != 200 || len(deps.HTTP) != 1 || deps.HTTP[0].ID != p.ID {
		t.Fatalf("deps=%d %s", r.Code, r.Body.String())
	}
	r = doRequest(t, h, "GET", "/api/v1/data/export", "")
	if r.Code != 200 || r.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("export=%d", r.Code)
	}
	var bundle model.DataBundle
	if err := json.Unmarshal(r.Body.Bytes(), &bundle); err != nil {
		t.Fatal(err)
	}
	if len(bundle.HTTPConnections) != 1 || bundle.HTTPConnections[0].Password != "password" {
		t.Fatal("HTTP lost from transfer")
	}
	event := lastAuditEvent(t, path)
	var metadata map[string]any
	json.Unmarshal([]byte(event.Metadata), &metadata)
	if metadata["http_connections"] != float64(1) {
		t.Fatalf("transfer audit missing HTTP count: %s", event.Metadata)
	}
	dst, _, _ := newTestAPI(t)
	restored := doRequest(t, dst, "POST", "/api/v1/data/import", r.Body.String())
	if restored.Code != 204 {
		t.Fatalf("import=%d %s", restored.Code, restored.Body.String())
	}
	read := doRequest(t, dst, "GET", fmt.Sprintf("/api/v1/http-connections/%d", p.ID), "")
	if read.Code != 200 || strings.Contains(read.Body.String(), `"password":"password"`) {
		t.Fatalf("import metadata=%d %s", read.Code, read.Body.String())
	}
	conflict := doRequest(t, h, "POST", "/api/v1/data/import", r.Body.String())
	if conflict.Code != 409 {
		t.Fatalf("overwrite=%d", conflict.Code)
	}
}

func TestHTTPProxyOperationTimeoutAndConnectionIsolation(t *testing.T) {
	t.Run("operation timeout during response body", func(t *testing.T) {
		started := make(chan struct{})
		stopped := make(chan struct{})
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(200)
			w.(http.Flusher).Flush()
			close(started)
			<-r.Context().Done()
			close(stopped)
		}))
		defer upstream.Close()
		h, s, _ := newTestAPI(t)
		p, err := s.CreateHTTP(context.Background(), model.HTTPProfile{Name: "timeout", Origin: upstream.URL, AuthType: "bearer", Credential: []byte("saved")})
		if err != nil {
			t.Fatal(err)
		}
		begin := time.Now()
		r := doRequest(t, h, "POST", fmt.Sprintf("/api/v1/http-connections/%d/request", p.ID), `{"method":"GET","path":"/"}`)
		if r.Code != 504 || time.Since(begin) > model.HTTPOperationTimeout+2*time.Second {
			t.Fatalf("timeout=%d elapsed=%v %s", r.Code, time.Since(begin), r.Body.String())
		}
		select {
		case <-started:
		default:
			t.Fatal("upstream never started")
		}
		select {
		case <-stopped:
		case <-time.After(2 * time.Second):
			t.Fatal("timeout did not cancel upstream body")
		}
	})
	t.Run("no connection or cookie reuse", func(t *testing.T) {
		var addresses []string
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			addresses = append(addresses, r.RemoteAddr)
			if r.Header.Get("Cookie") != "" {
				t.Error("upstream cookie replayed")
			}
			w.Header().Set("Set-Cookie", "session=secret")
			fmt.Fprint(w, "ok")
		}))
		defer upstream.Close()
		h, s, _ := newTestAPI(t)
		p, err := s.CreateHTTP(context.Background(), model.HTTPProfile{Name: "isolation", Origin: upstream.URL, AuthType: "bearer", Credential: []byte("saved")})
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 2; i++ {
			r := doRequest(t, h, "POST", fmt.Sprintf("/api/v1/http-connections/%d/request", p.ID), `{"method":"GET","path":"/"}`)
			if r.Code != 200 {
				t.Fatal(r.Code, r.Body.String())
			}
		}
		if len(addresses) != 2 || addresses[0] == addresses[1] {
			t.Fatalf("connection reused: %v", addresses)
		}
	})
	t.Run("wire cancellation", func(t *testing.T) {
		started, stopped := make(chan struct{}), make(chan struct{})
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(started); <-r.Context().Done(); close(stopped) }))
		defer upstream.Close()
		h, s, _ := newTestAPI(t)
		p, err := s.CreateHTTP(context.Background(), model.HTTPProfile{Name: "cancel", Origin: upstream.URL, AuthType: "bearer", Credential: []byte("saved")})
		if err != nil {
			t.Fatal(err)
		}
		srv := httptest.NewServer(server.New("", h).Handler())
		defer srv.Close()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		req, _ := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("%s/api/v1/http-connections/%d/request", srv.URL, p.ID), strings.NewReader(`{"method":"GET","path":"/"}`))
		done := make(chan struct{})
		go func() {
			defer close(done)
			resp, err := srv.Client().Do(req)
			if err == nil {
				resp.Body.Close()
			}
		}()
		select {
		case <-started:
		case <-time.After(2 * time.Second):
			t.Fatal("not started")
		}
		cancel()
		select {
		case <-stopped:
		case <-time.After(2 * time.Second):
			t.Fatal("wire cancellation did not reach upstream")
		}
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("client not joined")
		}
	})
}

func TestHTTPMetadataCRUD(t *testing.T) {
	h, s, path := newTestAPI(t)
	r := doRequest(t, h, "POST", "/api/v1/http-connections", `{"name":"api","origin":"https://example.test","auth_type":"bearer","credential":"hidden-token","note":"ops"}`)
	if r.Code != 201 {
		t.Fatalf("create=%d %s", r.Code, r.Body.String())
	}
	if strings.Contains(r.Body.String(), "hidden-token") {
		t.Fatal("create leaked credential")
	}
	var p model.HTTPConnection
	if err := json.Unmarshal(r.Body.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	if !p.HasCredential {
		t.Fatal("presence missing")
	}
	route := fmt.Sprintf("/api/v1/http-connections/%d", p.ID)
	for _, target := range []string{route, "/api/v1/http-connections"} {
		r = doRequest(t, h, "GET", target, "")
		if r.Code != 200 || strings.Contains(r.Body.String(), "hidden-token") {
			t.Fatalf("get=%d %s", r.Code, r.Body.String())
		}
	}
	r = doRequest(t, h, "PUT", route, `{"name":"renamed","origin":"https://example.test","auth_type":"bearer","note":"new"}`)
	if r.Code != 200 {
		t.Fatal(r.Body.String())
	}
	stored, _ := s.GetHTTP(context.Background(), p.ID)
	if string(stored.Credential) != "hidden-token" {
		t.Fatal("secret lost")
	}
	r = doRequest(t, h, "PUT", route+"/archive", `{"archived":true}`)
	if r.Code != 200 {
		t.Fatal(r.Body.String())
	}
	r = doRequest(t, h, "POST", route+"/request", `{"method":"GET","path":"/"}`)
	if r.Code != 404 {
		t.Fatalf("archived proxy=%d", r.Code)
	}
	r = doRequest(t, h, "PUT", route+"/archive", `{"archived":false}`)
	if r.Code != 200 {
		t.Fatal(r.Body.String())
	}
	r = doRequest(t, h, "PUT", route, `{"name":"renamed","origin":"https://example.test","auth_type":"x_api_key"}`)
	if r.Code != 200 {
		t.Fatal(r.Body.String())
	}
	stored, _ = s.GetHTTP(context.Background(), p.ID)
	if len(stored.Credential) != 0 {
		t.Fatal("auth switch preserved token")
	}
	e := lastAuditEvent(t, path)
	if strings.Contains(fmt.Sprintf("%+v", e), "hidden-token") {
		t.Fatal("audit leaked")
	}
	r = doRequest(t, h, "DELETE", route, "")
	if r.Code != 204 {
		t.Fatal(r.Code)
	}
	r = doRequest(t, h, "GET", route, "")
	if r.Code != 404 {
		t.Fatal(r.Code)
	}
	for _, body := range []string{`null`, `{"name":"x","unknown":true}`, `{} {}`} {
		if r := doRequest(t, h, "POST", "/api/v1/http-connections", body); r.Code != 400 {
			t.Fatalf("strict decode %q: %d", body, r.Code)
		}
	}
}

func TestHTTPProxyAuthAndIsolation(t *testing.T) {
	for _, mode := range []string{"bearer", "x_api_key", "basic"} {
		t.Run(mode, func(t *testing.T) {
			var calls atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.URL.RequestURI() != "/v1/items?x=a%2Fb" || r.Method != "POST" {
					t.Errorf("request=%s %s", r.Method, r.URL.RequestURI())
				}
				b, _ := io.ReadAll(r.Body)
				if string(b) != "{\"x\":1}" || r.Header.Get("Content-Type") != "application/json" {
					t.Errorf("body/type=%q %q", b, r.Header.Get("Content-Type"))
				}
				if r.Host == "attacker.invalid" {
					t.Error("incoming Host forwarded")
				}
				if r.Header.Get("Cookie") != "" || r.Header.Get("Proxy-Authorization") != "" || r.Header.Get("X-Incoming") != "" {
					t.Error("incoming headers forwarded")
				}
				switch mode {
				case "bearer":
					if r.Header.Get("Authorization") != "Bearer saved" || r.Header.Get("X-API-Key") != "" {
						t.Error("bearer")
					}
				case "x_api_key":
					if r.Header.Get("X-API-Key") != "saved" || r.Header.Get("Authorization") != "" {
						t.Error("api key")
					}
				case "basic":
					u, p, ok := r.BasicAuth()
					if !ok || u != "user" || p != "pass" || r.Header.Get("X-API-Key") != "" {
						t.Error("basic")
					}
				}
				w.Header().Set("Set-Cookie", "evil=1")
				w.Header().Set("Location", "https://unrelated.invalid")
				w.Header().Set("Content-Type", "text/html")
				w.WriteHeader(422)
				w.Write([]byte{0, 255, 'x'})
			}))
			defer upstream.Close()
			h, s, _ := newTestAPI(t)
			p := model.HTTPProfile{Name: "api", Origin: upstream.URL, AuthType: mode}
			if mode == "basic" {
				p.Username = []byte("user")
				p.Password = []byte("pass")
			} else {
				p.Credential = []byte("saved")
			}
			p, err := s.CreateHTTP(context.Background(), p)
			if err != nil {
				t.Fatal(err)
			}
			body, _ := json.Marshal(model.HTTPProxyRequest{Method: "POST", Path: "/v1/items?x=a%2Fb", Body: []byte(`{"x":1}`)})
			req := httptest.NewRequest("POST", fmt.Sprintf("/api/v1/http-connections/%d/request", p.ID), bytes.NewReader(body))
			req.Host = "attacker.invalid"
			req.Header.Set("Authorization", "caller")
			req.Header.Set("Cookie", "caller=1")
			req.Header.Set("Proxy-Authorization", "proxy")
			req.Header.Set("X-Incoming", "secret")
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != 200 {
				t.Fatalf("proxy=%d %s", rec.Code, rec.Body.String())
			}
			if rec.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("credentialed upstream response must not be cached")
			}
			var out model.HTTPProxyResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
				t.Fatal(err)
			}
			if out.StatusCode != 422 || !bytes.Equal(out.Body, []byte{0, 255, 'x'}) {
				t.Fatalf("out=%+v", out)
			}
			if rec.Header().Get("Set-Cookie") != "" || rec.Header().Get("Location") != "" || !strings.HasPrefix(rec.Header().Get("Content-Type"), "application/json") {
				t.Fatal("upstream headers affected Warden")
			}
			if calls.Load() != 1 {
				t.Fatal(calls.Load())
			}
		})
	}
}

func TestHTTPProxyRejectsOverridesAndRedirects(t *testing.T) {
	var targetCalls atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { targetCalls.Add(1) }))
	defer target.Close()
	var originCalls atomic.Int32
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originCalls.Add(1)
		w.Header().Set("Location", target.URL+"/stolen")
		w.WriteHeader(307)
		w.Write([]byte("redirect"))
	}))
	defer origin.Close()
	h, s, _ := newTestAPI(t)
	p, err := s.CreateHTTP(context.Background(), model.HTTPProfile{Name: "api", Origin: origin.URL, AuthType: "bearer", Credential: []byte("saved")})
	if err != nil {
		t.Fatal(err)
	}
	route := fmt.Sprintf("/api/v1/http-connections/%d/request", p.ID)
	for _, path := range []string{target.URL, "//" + strings.TrimPrefix(target.URL, "http://"), "relative", "/x#fragment", "/x#", "/bad%zz", "/bad\r\n", "/\\host", ""} {
		b, _ := json.Marshal(model.HTTPProxyRequest{Method: "GET", Path: path})
		r := doRequest(t, h, "POST", route, string(b))
		if r.Code != 400 {
			t.Fatalf("path %q: %d %s", path, r.Code, r.Body.String())
		}
	}
	for _, method := range []string{"", "BAD METHOD", "GET\r\nX: x", "CONNECT", "TRACE", "get"} {
		b, _ := json.Marshal(model.HTTPProxyRequest{Method: method, Path: "/"})
		if r := doRequest(t, h, "POST", route, string(b)); r.Code != 400 {
			t.Fatalf("method %q accepted: %d", method, r.Code)
		}
	}
	if r := doRequest(t, h, "POST", route, `{"method":"GET","path":"/","headers":{"Authorization":"evil"}}`); r.Code != 400 {
		t.Fatal("headers accepted")
	}
	if originCalls.Load() != 0 {
		t.Fatal("invalid requests reached upstream")
	}
	r := doRequest(t, h, "POST", route, `{"method":"GET","path":"/"}`)
	var out model.HTTPProxyResponse
	json.Unmarshal(r.Body.Bytes(), &out)
	if r.Code != 200 || out.StatusCode != 307 || string(out.Body) != "redirect" {
		t.Fatalf("redirect=%d %s", r.Code, r.Body.String())
	}
	if targetCalls.Load() != 0 {
		t.Fatal("redirect followed")
	}
}

func TestHTTPProxyTLSBoundsAndCancellation(t *testing.T) {
	t.Run("untrusted TLS", func(t *testing.T) {
		up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("untrusted TLS reached handler") }))
		defer up.Close()
		h, s, _ := newTestAPI(t)
		p, _ := s.CreateHTTP(context.Background(), model.HTTPProfile{Name: "tls", Origin: up.URL, AuthType: "bearer", Credential: []byte("saved")})
		r := doRequest(t, h, "POST", fmt.Sprintf("/api/v1/http-connections/%d/request", p.ID), `{"method":"GET","path":"/"}`)
		if r.Code != 502 || strings.Contains(r.Body.String(), "x509") || strings.Contains(r.Body.String(), up.URL) {
			t.Fatalf("TLS error=%d %s", r.Code, r.Body.String())
		}
	})
	t.Run("sizes", func(t *testing.T) {
		var calls atomic.Int32
		up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls.Add(1)
			if _, err := io.Copy(io.Discard, r.Body); err != nil {
				t.Errorf("read fixture request: %v", err)
			}
			if r.URL.Path == "/exact" {
				w.Write(bytes.Repeat([]byte("x"), model.HTTPMaxResponseBytes))
				return
			}
			w.Write(bytes.Repeat([]byte("x"), model.HTTPMaxResponseBytes+1))
		}))
		defer up.Close()
		h, s, _ := newTestAPI(t)
		p, _ := s.CreateHTTP(context.Background(), model.HTTPProfile{Name: "size", Origin: up.URL, AuthType: "bearer", Credential: []byte("saved")})
		route := fmt.Sprintf("/api/v1/http-connections/%d/request", p.ID)
		b, _ := json.Marshal(model.HTTPProxyRequest{Method: "POST", Path: "/", Body: bytes.Repeat([]byte("x"), model.HTTPMaxRequestBytes+1)})
		if r := doRequest(t, h, "POST", route, string(b)); r.Code != 413 {
			t.Fatalf("request limit=%d", r.Code)
		}
		if calls.Load() != 0 {
			t.Fatal("oversize sent")
		}
		if r := doRequest(t, h, "POST", route, strings.Repeat(" ", 2<<20)+`{}`); r.Code != 413 {
			t.Fatalf("envelope limit=%d", r.Code)
		}
		if r := doRequest(t, h, "POST", route, `{"method":"GET","path":"/"}`); r.Code != 502 {
			t.Fatalf("response limit=%d", r.Code)
		}
		b, _ = json.Marshal(model.HTTPProxyRequest{Method: "POST", Path: "/exact", Body: bytes.Repeat([]byte("x"), model.HTTPMaxRequestBytes)})
		r := doRequest(t, h, "POST", route, string(b))
		var out model.HTTPProxyResponse
		json.Unmarshal(r.Body.Bytes(), &out)
		if r.Code != 200 || len(out.Body) != model.HTTPMaxResponseBytes {
			t.Fatalf("exact limits=%d len=%d", r.Code, len(out.Body))
		}
	})
	t.Run("caller cancellation", func(t *testing.T) {
		started := make(chan struct{})
		stopped := make(chan struct{})
		up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(started); <-r.Context().Done(); close(stopped) }))
		defer up.Close()
		h, s, _ := newTestAPI(t)
		p, _ := s.CreateHTTP(context.Background(), model.HTTPProfile{Name: "cancel", Origin: up.URL, AuthType: "bearer", Credential: []byte("saved")})
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		req := httptest.NewRequest("POST", fmt.Sprintf("/api/v1/http-connections/%d/request", p.ID), strings.NewReader(`{"method":"GET","path":"/"}`)).WithContext(ctx)
		done := make(chan struct{})
		go func() { defer close(done); h.ServeHTTP(httptest.NewRecorder(), req) }()
		select {
		case <-started:
		case <-time.After(2 * time.Second):
			t.Fatal("not started")
		}
		cancel()
		select {
		case <-stopped:
		case <-time.After(2 * time.Second):
			t.Fatal("upstream not canceled")
		}
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("handler not joined")
		}
	})
}
