package runtime

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"warden/internal/server"
)

const deliverySecret = "synthetic-managed-delivery-secret"

// Observe the server's socket Write, not when the client receives the bytes.
type emissionLog struct {
	mu            sync.Mutex
	ack           bool
	before, after int
}

func (l *emissionLog) snapshot(ack bool) (int, int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if ack {
		l.ack = true
	}
	return l.before, l.after
}

type emissionConn struct {
	net.Conn
	log *emissionLog
}

func (c *emissionConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if bytes.Contains(b[:n], []byte(deliverySecret)) {
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

type emissionListener struct {
	net.Listener
	log *emissionLog
}

func (l *emissionListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &emissionConn{Conn: c, log: l.log}, nil
}

func TestManagedResponseEmittedBeforeLockAckAtHTTPFinalization(t *testing.T) {
	p, _, _, key, _ := runtimeFixture(t)
	session, csrf := sessionFor(t, p)
	if err := p.vault.Unlock(key, p.vault.Generation()); err != nil {
		t.Fatal(err)
	}
	p.managed = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, deliverySecret) })
	planeReturned, finishHandler := make(chan struct{}), make(chan struct{})
	var resume sync.Once
	middleware := server.New("", p).Handler()
	outer := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		middleware.ServeHTTP(w, r)
		if r.URL.Path == "/api/v1/ssh-connections" {
			close(planeReturned)
			<-finishHandler // net/http cannot run finishRequest yet.
		}
	})
	log := new(emissionLog)
	srv := httptest.NewUnstartedServer(outer)
	srv.Listener = &emissionListener{Listener: srv.Listener, log: log}
	srv.Start()
	defer srv.Close()
	// Always unblock the outer handler before server cleanup, even on failure.
	defer resume.Do(func() { close(finishHandler) })
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{DisableKeepAlives: true}}
	defer client.CloseIdleConnections()
	response := make(chan error, 1)
	go func() {
		req, _ := http.NewRequest("GET", srv.URL+"/api/v1/ssh-connections", nil)
		req.Host = "warden.example"
		req.AddCookie(session)
		res, err := client.Do(req)
		if err == nil {
			var body []byte
			body, err = io.ReadAll(res.Body)
			res.Body.Close()
			if err == nil && string(body) != deliverySecret {
				err = errors.New("wrong managed body")
			}
		}
		response <- err
	}()
	waitDelivery(t, planeReturned, "plane return")
	req, _ := http.NewRequest("POST", srv.URL+"/api/v1/auth/lock", bytes.NewBufferString("{}"))
	req.Host = "warden.example"
	req.AddCookie(session)
	req.Header.Set("Origin", p.cfg.PublicOrigin)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", csrf)
	res, err := client.Do(req) // A different connection; GET is still in outer handler.
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, res.Body)
	res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatalf("lock status %d", res.StatusCode)
	}
	before, _ := log.snapshot(true)
	resume.Do(func() { close(finishHandler) })
	if err := <-response; err != nil {
		t.Fatal(err)
	}
	_, after := log.snapshot(false)
	t.Logf("socket secret writes at lock ack=%d; after ack/outer return=%d", before, after)
	if before != 1 || after != 0 {
		t.Fatalf("secret emission crossed lock acknowledgement: before=%d after=%d", before, after)
	}
}

func waitDelivery(t *testing.T, ch <-chan struct{}, label string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for %s", label)
	}
}

type deliveryWriter struct {
	header                    http.Header
	writeErr, flushErr        error
	short                     bool
	flushEntered, flushResume chan struct{}
	deadline                  chan struct{}
	once                      sync.Once
	flushed                   bool
}

func (w *deliveryWriter) Header() http.Header { return w.header }
func (w *deliveryWriter) WriteHeader(int)     {}
func (w *deliveryWriter) Write(b []byte) (int, error) {
	if w.writeErr != nil {
		return 0, w.writeErr
	}
	if w.short {
		return len(b) - 1, nil
	}
	return len(b), nil
}
func (w *deliveryWriter) FlushError() error {
	if w.flushEntered != nil {
		close(w.flushEntered)
	}
	if w.flushResume != nil {
		<-w.flushResume
	}
	if w.deadline != nil {
		<-w.deadline
		return os.ErrDeadlineExceeded
	}
	w.flushed = true
	return w.flushErr
}
func (w *deliveryWriter) SetWriteDeadline(time.Time) error {
	if w.deadline != nil {
		w.once.Do(func() { close(w.deadline) })
	}
	return nil
}

func deliveryRequest(session *http.Cookie) *http.Request {
	req := httptest.NewRequest("GET", "https://warden.example/api/v1/ssh-connections", nil)
	req.AddCookie(session)
	return req
}
func invokeDelivery(h http.Handler, w http.ResponseWriter, r *http.Request) (recovered any) {
	defer func() { recovered = recover() }()
	h.ServeHTTP(w, r)
	return nil
}

func TestManagedResponseFlushRetainsLeaseThroughMiddleware(t *testing.T) {
	p, _, _, key, _ := runtimeFixture(t)
	session, _ := sessionFor(t, p)
	p.vault.Unlock(key, p.vault.Generation())
	ctxs := make(chan context.Context, 1)
	p.managed = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { ctxs <- r.Context(); io.WriteString(w, deliverySecret) })
	w := &deliveryWriter{header: make(http.Header), flushEntered: make(chan struct{}), flushResume: make(chan struct{})}
	var resume sync.Once
	defer resume.Do(func() { close(w.flushResume) })
	done := make(chan any, 1)
	go func() { done <- invokeDelivery(server.New("", p).Handler(), w, deliveryRequest(session)) }()
	waitDelivery(t, w.flushEntered, "flush through middleware")
	ctx := <-ctxs
	locked := make(chan struct{})
	go func() { p.vault.Lock(); close(locked) }()
	waitDelivery(t, ctx.Done(), "lease cancellation")
	select {
	case <-locked:
		t.Fatal("lock acknowledged before flush returned")
	default:
	}
	resume.Do(func() { close(w.flushResume) })
	<-done
	waitDelivery(t, locked, "drained lock")
	if !w.flushed {
		t.Fatal("flush not completed")
	}
}

func TestManagedResponseDeliveryFailuresReleaseLease(t *testing.T) {
	for _, variant := range []string{"write", "short-write", "flush", "lock-cancel", "request-cancel", "deadline"} {
		t.Run(variant, func(t *testing.T) {
			p, _, _, key, _ := runtimeFixture(t)
			session, _ := sessionFor(t, p)
			p.vault.Unlock(key, p.vault.Generation())
			w := &deliveryWriter{header: make(http.Header)}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch variant {
			case "write":
				w.writeErr = io.ErrClosedPipe
			case "short-write":
				w.short = true
			case "flush":
				w.flushErr = io.ErrClosedPipe
			case "lock-cancel", "request-cancel":
				w.flushEntered = make(chan struct{})
				w.deadline = make(chan struct{})
			case "deadline":
				w.flushErr = os.ErrDeadlineExceeded
			}
			defer func() {
				if w.deadline != nil {
					w.once.Do(func() { close(w.deadline) })
				}
			}()
			done := make(chan any, 1)
			go func() {
				done <- invokeDelivery(server.New("", p).Handler(), w, deliveryRequest(session).WithContext(ctx))
			}()
			locked := make(chan struct{})
			if w.flushEntered != nil {
				waitDelivery(t, w.flushEntered, "blocked flush")
				if variant == "request-cancel" {
					cancel()
				}
			}
			if variant == "lock-cancel" {
				go func() { p.vault.Lock(); close(locked) }()
			}
			select {
			case recovered := <-done:
				if recovered != http.ErrAbortHandler {
					t.Errorf("delivery failure panic=%v, want ErrAbortHandler", recovered)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("delivery did not terminate")
			}
			if variant != "lock-cancel" {
				go func() { p.vault.Lock(); close(locked) }()
			}
			waitDelivery(t, locked, "lock after failed delivery")
		})
	}
}
