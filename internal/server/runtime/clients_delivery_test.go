package runtime

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"warden/internal/server"
)

func TestClientTransportResponseLeaseExtendsThroughCheckedFlush(t *testing.T) {
	p, _, _, key, signer := runtimeFixture(t)
	browser, csrf := sessionFor(t, p)
	p.vault.Unlock(key, p.vault.Generation())
	secret, _, _ := pairedFixture(t, p, func(id, commitment string) {
		body := `{"id":"` + id + `","commitment":"` + commitment + `"}`
		g := requestGrant(t, p, signer, browser, csrf, "client_approve", "POST", "/api/v1/auth/clients/approve", body)
		if w := callGranted(p, "POST", "/api/v1/auth/clients/approve", body, browser, csrf, g); w.Code != 200 {
			t.Fatal(w.Code, w.Body)
		}
	}, 88)
	p.clientManaged = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, deliverySecret) })
	returned, resume := make(chan struct{}), make(chan struct{})
	var once sync.Once
	middleware := server.New("", p).Handler()
	outer := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		middleware.ServeHTTP(w, r)
		if strings.HasPrefix(r.URL.Path, "/api/v1/client/transport/") {
			close(returned)
			<-resume
		}
	})
	log := new(emissionLog)
	srv := httptest.NewUnstartedServer(outer)
	srv.Listener = &emissionListener{Listener: srv.Listener, log: log}
	srv.Start()
	defer srv.Close()
	defer once.Do(func() { close(resume) })
	hc := &http.Client{Timeout: 3 * time.Second}
	defer hc.CloseIdleConnections()
	done := make(chan error, 1)
	go func() {
		req, _ := http.NewRequest("GET", srv.URL+"/api/v1/client/transport/ssh/1", nil)
		req.Host = "warden.example"
		req.Header.Set("Authorization", "Bearer "+secret)
		res, e := hc.Do(req)
		if e == nil {
			_, e = io.Copy(io.Discard, res.Body)
			res.Body.Close()
		}
		done <- e
	}()
	waitDelivery(t, returned, "client plane return")
	req, _ := http.NewRequest("POST", srv.URL+"/api/v1/auth/lock", strings.NewReader(`{}`))
	req.Host = "warden.example"
	req.AddCookie(browser)
	req.Header.Set("Origin", p.cfg.PublicOrigin)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", csrf)
	res, e := hc.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatal(res.StatusCode)
	}
	before, after := log.snapshot(true)
	if before != 1 || after != 0 {
		t.Fatal("client secret was not flushed inside lease", before, after)
	}
	once.Do(func() { close(resume) })
	if e = <-done; e != nil {
		t.Fatal(e)
	}
	_, after = log.snapshot(false)
	if after != 0 {
		t.Fatal("post-lock client secret emission")
	}
}
