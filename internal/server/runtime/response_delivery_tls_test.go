package runtime

import (
	"bytes"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"warden/internal/server"
)

type flushObserver struct {
	http.ResponseWriter
	completed bool
}

func (w *flushObserver) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *flushObserver) FlushError() error {
	err := http.NewResponseController(w.ResponseWriter).Flush()
	w.completed = err == nil
	return err
}

// Production uses tls.NewListener + Server.Serve, without ALPN h2. Exercise
// that supported TLS1.3/HTTP1 boundary, including the production middleware.
func TestManagedResponseTLSFlushBeforeOuterHandlerReturn(t *testing.T) {
	p, _, _, key, _ := runtimeFixture(t)
	session, csrf := sessionFor(t, p)
	p.cfg.Mode = "tls"
	p.vault.Unlock(key, p.vault.Generation())
	p.managed = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, deliverySecret) })
	returned := make(chan bool, 1)
	resume := make(chan struct{})
	var once sync.Once
	middleware := server.New("", p).Handler()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		observer := &flushObserver{ResponseWriter: w}
		middleware.ServeHTTP(observer, r)
		if r.URL.Path == "/api/v1/ssh-connections" {
			returned <- observer.completed
			<-resume
		}
	}))
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	srv.StartTLS()
	defer srv.Close()
	defer once.Do(func() { close(resume) })
	client := srv.Client() // trusts the test certificate, not InsecureSkipVerify.
	client.Timeout = 5 * time.Second
	req, _ := http.NewRequest("GET", srv.URL+"/api/v1/ssh-connections", nil)
	req.Host = "warden.example"
	req.AddCookie(session)
	type result struct {
		res *http.Response
		err error
	}
	response := make(chan result, 1)
	go func() { res, err := client.Do(req); response <- result{res, err} }()
	select {
	case flushed := <-returned:
		if !flushed {
			t.Fatal("TLS response retained until outer handler return")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("plane did not return")
	}
	got := <-response
	if got.err != nil {
		t.Fatal(got.err)
	}
	defer got.res.Body.Close()
	if got.res.ProtoMajor != 1 || got.res.TLS == nil || got.res.TLS.Version != tls.VersionTLS13 {
		t.Fatal("not the supported TLS1.3 HTTP/1 path")
	}
	// Body availability characterizes TLS flush only. It is not used to assert
	// arrival ordering against lock: network/proxy queues are irretractable.
	body := make([]byte, len(deliverySecret))
	if _, err := io.ReadFull(got.res.Body, body); err != nil || string(body) != deliverySecret {
		t.Fatalf("TLS body: %q %v", body, err)
	}
	lock, _ := http.NewRequest("POST", srv.URL+"/api/v1/auth/lock", bytes.NewBufferString("{}"))
	lock.Host = "warden.example"
	lock.AddCookie(session)
	lock.Header.Set("Origin", p.cfg.PublicOrigin)
	lock.Header.Set("Content-Type", "application/json")
	lock.Header.Set("X-CSRF-Token", csrf)
	res, err := client.Do(lock)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, res.Body)
	res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatalf("lock status %d", res.StatusCode)
	}
	once.Do(func() { close(resume) })
	if _, err := io.Copy(io.Discard, got.res.Body); err != nil {
		t.Fatal(err)
	}
}
