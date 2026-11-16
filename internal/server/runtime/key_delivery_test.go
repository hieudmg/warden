package runtime

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
	"warden/internal/crypto"
	"warden/internal/server"
)

type keyEmissionConn struct {
	net.Conn
	needle              []byte
	log                 *emissionLog
	writing, reading    chan struct{}
	writeOnce, readOnce sync.Once
	reads               int
}

func (c *keyEmissionConn) Write(b []byte) (int, error) {
	c.writeOnce.Do(func() {
		if c.writing != nil {
			close(c.writing)
		}
	})
	n, err := c.Conn.Write(b)
	if bytes.Contains(b[:n], c.needle) {
		c.log.mu.Lock()
		if c.log.ack {
			c.log.after++
		} else {
			c.log.before++
		}
		c.log.mu.Unlock()
	}
	return n, err
}
func (c *keyEmissionConn) Read(b []byte) (int, error) {
	c.reads++
	if c.reads > 1 && c.reading != nil {
		c.readOnce.Do(func() { close(c.reading) })
	}
	return c.Conn.Read(b)
}
func TestRuntimeKeyDeliveryHTTPFinalizationBeforeLockAck(t *testing.T) {
	p, _, _, key, signer := runtimeFixture(t)
	browser, csrf := sessionFor(t, p)
	p.vault.Unlock(key, p.vault.Generation())
	id, _ := prepareEnrollment(t, p, browser, csrf, signer, false)
	body := `{"id":"` + id + `"}`
	grant := requestGrant(t, p, signer, browser, csrf, "passkey_add", "POST", "/api/v1/auth/passkeys/key", body)
	returned, resume := make(chan struct{}), make(chan struct{})
	var once sync.Once
	log := new(emissionLog)
	middleware := server.New("", p).Handler()
	outer := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		middleware.ServeHTTP(w, r)
		if r.URL.Path == "/api/v1/auth/passkeys/key" {
			close(returned)
			<-resume
		}
	})
	srv := httptest.NewUnstartedServer(outer)
	srv.Listener = &keyEmissionListener{Listener: srv.Listener, log: log, needle: []byte(crypto.Encode(key))}
	srv.Start()
	defer srv.Close()
	defer once.Do(func() { close(resume) })
	client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{DisableKeepAlives: true}}
	defer client.CloseIdleConnections()
	done := make(chan error, 1)
	go func() {
		r, _ := http.NewRequest("POST", srv.URL+"/api/v1/auth/passkeys/key", bytes.NewBufferString(body))
		r.Host = "warden.example"
		r.AddCookie(browser)
		r.Header.Set("Origin", p.cfg.PublicOrigin)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-CSRF-Token", csrf)
		r.Header.Set("X-Warden-Action", grant)
		res, err := client.Do(r)
		if err == nil {
			_, err = io.Copy(io.Discard, res.Body)
			res.Body.Close()
		}
		done <- err
	}()
	waitDelivery(t, returned, "key plane return before outer finalization")
	r, _ := http.NewRequest("POST", srv.URL+"/api/v1/auth/lock", bytes.NewBufferString("{}"))
	r.Host = "warden.example"
	r.AddCookie(browser)
	r.Header.Set("Origin", p.cfg.PublicOrigin)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-CSRF-Token", csrf)
	res, err := client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, res.Body)
	res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatal(res.StatusCode)
	}
	before, _ := log.snapshot(true)
	once.Do(func() { close(resume) })
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	_, after := log.snapshot(false)
	if before != 1 || after != 0 {
		t.Fatalf("DEK server emission before lock ack=%d after=%d", before, after)
	}
}

type keyEmissionListener struct {
	net.Listener
	log    *emissionLog
	needle []byte
}

func (l *keyEmissionListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &keyEmissionConn{Conn: c, log: l.log, needle: l.needle}, nil
}

func TestRuntimeKeyDeliveryHTTPCancellationAndSlowBodyReleaseLease(t *testing.T) {
	for _, variant := range []string{"blocked-write", "slow-body"} {
		t.Run(variant, func(t *testing.T) {
			p, _, _, key, signer := runtimeFixture(t)
			browser, csrf := sessionFor(t, p)
			p.vault.Unlock(key, p.vault.Generation())
			id, _ := prepareEnrollment(t, p, browser, csrf, signer, false)
			body := `{"id":"` + id + `"}`
			g := requestGrant(t, p, signer, browser, csrf, "passkey_add", "POST", "/api/v1/auth/passkeys/key", body)
			backend, peer := net.Pipe()
			defer peer.Close()
			log := new(emissionLog)
			observed := &keyEmissionConn{Conn: backend, needle: []byte(crypto.Encode(key)), log: log, writing: make(chan struct{}), reading: make(chan struct{})}
			listener := &deliveryPipeListener{connections: make(chan net.Conn), closed: make(chan struct{})}
			terminated := make(chan struct{})
			middleware := server.New("", p).Handler()
			srv := &http.Server{ReadTimeout: 120 * time.Second, WriteTimeout: 120 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api/v1/auth/passkeys/key" {
					defer close(terminated)
				}
				middleware.ServeHTTP(w, r)
			})}
			serving := make(chan error, 1)
			go func() { serving <- srv.Serve(listener) }()
			defer func() { srv.Close(); <-serving }()
			listener.connections <- observed
			req, _ := http.NewRequest("POST", "https://warden.example/api/v1/auth/passkeys/key", bytes.NewBufferString(body))
			req.AddCookie(browser)
			req.Header.Set("Origin", p.cfg.PublicOrigin)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-CSRF-Token", csrf)
			req.Header.Set("X-Warden-Action", g)
			peer.SetDeadline(time.Now().Add(3 * time.Second))
			if variant == "slow-body" {
				req.ContentLength = int64(len(body) + 1)
				req.Body = io.NopCloser(bytes.NewBufferString(body + " "))
			}
			var wire bytes.Buffer
			req.Write(&wire)
			data := wire.Bytes()
			if variant == "slow-body" {
				data = data[:len(data)-1]
			}
			if _, err := peer.Write(data); err != nil {
				t.Fatal(err)
			}
			if variant == "slow-body" {
				waitDelivery(t, observed.reading, "authorized body read")
			} else {
				waitDelivery(t, observed.writing, "blocked DEK write")
			}
			lockBackend, lockPeer := net.Pipe()
			defer lockPeer.Close()
			listener.connections <- lockBackend
			lockPeer.SetDeadline(time.Now().Add(time.Second))
			lock, _ := http.NewRequest("POST", "https://warden.example/api/v1/auth/lock", bytes.NewBufferString("{}"))
			lock.AddCookie(browser)
			lock.Header.Set("Origin", p.cfg.PublicOrigin)
			lock.Header.Set("Content-Type", "application/json")
			lock.Header.Set("X-CSRF-Token", csrf)
			if err := lock.Write(lockPeer); err != nil {
				t.Fatal(err)
			}
			res, err := http.ReadResponse(bufio.NewReader(lockPeer), lock)
			if err != nil {
				t.Fatalf("lock blocked by key delivery: %v", err)
			}
			io.Copy(io.Discard, res.Body)
			res.Body.Close()
			if res.StatusCode != 200 {
				t.Fatal(res.StatusCode)
			}
			log.snapshot(true)
			waitDelivery(t, terminated, "key delivery cancellation")
			remaining, err := io.ReadAll(peer)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(remaining, []byte(crypto.Encode(key))) {
				t.Fatal("DEK finalized after cancellation")
			}
			before, after := log.snapshot(false)
			if before != 0 || after != 0 {
				t.Fatalf("DEK emission before=%d after=%d", before, after)
			}
		})
	}
}
