package runtime

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"warden/internal/server"
)

// Arm only once the managed handler has finished. With an unread body, the
// next socket read is net/http's pre-header body drain, not header parsing or
// a bodyless response's blocked socket write.
type drainEmissionConn struct {
	*emissionConn
	armed   atomic.Bool
	reading chan struct{}
	once    sync.Once
}

func (c *drainEmissionConn) Read(b []byte) (int, error) {
	if c.armed.Load() {
		c.once.Do(func() { close(c.reading) })
	}
	return c.Conn.Read(b)
}

func TestManagedResponseUnreadBodyDrainTerminates(t *testing.T) {
	for _, variant := range []string{"lock-cancel", "closed-client", "malformed-chunk"} {
		t.Run(variant, func(t *testing.T) {
			p, _, _, key, _ := runtimeFixture(t)
			session, csrf := sessionFor(t, p)
			if err := p.vault.Unlock(key, p.vault.Generation()); err != nil {
				t.Fatal(err)
			}
			backend, peer := net.Pipe()
			defer peer.Close()
			log := new(emissionLog)
			observed := &drainEmissionConn{emissionConn: &emissionConn{Conn: backend, log: log}, reading: make(chan struct{})}
			p.managed = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				io.WriteString(w, deliverySecret)
				observed.armed.Store(true)
			})
			terminated := make(chan struct{})
			listener := &deliveryPipeListener{connections: make(chan net.Conn), closed: make(chan struct{})}
			middleware := server.New("", p).Handler()
			srv := &http.Server{ReadTimeout: 120 * time.Second, WriteTimeout: 120 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api/v1/ssh-connections" {
					defer close(terminated)
				}
				middleware.ServeHTTP(w, r)
			})}
			serving := make(chan error, 1)
			go func() { serving <- srv.Serve(listener) }()
			defer func() { srv.Close(); <-serving }()
			listener.connections <- observed
			peer.SetDeadline(time.Now().Add(3 * time.Second))
			framing := "Content-Length: 1\r\n"
			if variant == "malformed-chunk" {
				framing = "Transfer-Encoding: chunked\r\n"
			}
			// Keepalive is intentional: Connection: close skips the body drain.
			_, err := io.WriteString(peer, "GET /api/v1/ssh-connections HTTP/1.1\r\nHost: warden.example\r\nCookie: "+session.String()+"\r\n"+framing+"\r\n")
			if err != nil {
				t.Fatal(err)
			}
			waitDelivery(t, observed.reading, "net/http unread-body read-drain")
			if before, after := log.snapshot(false); before != 0 || after != 0 {
				t.Fatal("secret emitted before body drain")
			}
			if variant == "closed-client" {
				peer.Close()
			}
			if variant == "malformed-chunk" {
				if _, err := io.WriteString(peer, "not-a-chunk\r\n"); err != nil {
					t.Fatal(err)
				}
				// Consume any response emitted before lock; malformed drain must
				// still finish and release its lease without reusing this connection.
				readDone := make(chan struct{})
				go func() { io.Copy(io.Discard, peer); close(readDone) }()
				waitDelivery(t, readDone, "malformed-body connection close")
			}
			if variant != "lock-cancel" {
				waitDelivery(t, terminated, "failed-body cleanup")
			}
			backendLock, peerLock := net.Pipe()
			defer peerLock.Close()
			listener.connections <- backendLock
			peerLock.SetDeadline(time.Now().Add(time.Second))
			lock, _ := http.NewRequest("POST", "https://warden.example/api/v1/auth/lock", bytes.NewBufferString("{}"))
			lock.AddCookie(session)
			lock.Header.Set("Origin", p.cfg.PublicOrigin)
			lock.Header.Set("Content-Type", "application/json")
			lock.Header.Set("X-CSRF-Token", csrf)
			if err := lock.Write(peerLock); err != nil {
				t.Fatal(err)
			}
			response, err := http.ReadResponse(bufio.NewReader(peerLock), lock)
			if err != nil {
				t.Fatalf("lock did not promptly cancel read-drain and release lease: %v", err)
			}
			io.Copy(io.Discard, response.Body)
			response.Body.Close()
			if response.StatusCode != 200 {
				t.Fatalf("lock status %d", response.StatusCode)
			}
			log.snapshot(true)
			waitDelivery(t, terminated, "canceled read-drain")
			if variant == "lock-cancel" {
				body, err := io.ReadAll(peer)
				if err != nil {
					t.Fatal(err)
				}
				if bytes.Contains(body, []byte(deliverySecret)) {
					t.Fatal("canceled drain finalized secret bytes")
				}
			}
			before, after := log.snapshot(false)
			if after != 0 || variant == "lock-cancel" && before != 0 {
				t.Fatalf("unexpected secret emission before=%d after=%d", before, after)
			}
		})
	}
}

func TestManagedResponseOrdinaryKeepaliveUnaffected(t *testing.T) {
	p, _, _, key, _ := runtimeFixture(t)
	session, _ := sessionFor(t, p)
	if err := p.vault.Unlock(key, p.vault.Generation()); err != nil {
		t.Fatal(err)
	}
	p.managed = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, deliverySecret) })
	listener := &deliveryPipeListener{connections: make(chan net.Conn), closed: make(chan struct{})}
	srv := &http.Server{ReadTimeout: 120 * time.Second, WriteTimeout: 120 * time.Second, Handler: server.New("", p).Handler()}
	serving := make(chan error, 1)
	go func() { serving <- srv.Serve(listener) }()
	defer func() { srv.Close(); <-serving }()
	backend, peer := net.Pipe()
	defer peer.Close()
	listener.connections <- backend
	peer.SetDeadline(time.Now().Add(3 * time.Second))
	reader := bufio.NewReader(peer)
	for _, body := range []string{"x", ""} {
		req := deliveryRequest(session)
		req.RequestURI = ""
		req.Body = io.NopCloser(bytes.NewBufferString(body))
		req.ContentLength = int64(len(body))
		if err := req.Write(peer); err != nil {
			t.Fatal(err)
		}
		res, err := http.ReadResponse(reader, req)
		if err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(res.Body)
		res.Body.Close()
		if err != nil || res.Close || string(got) != deliverySecret {
			t.Fatalf("keepalive response body=%q close=%v err=%v", got, res.Close, err)
		}
	}
}

type joinedDeadlineWriter struct {
	*deliveryWriter
	readEntered, readResume chan struct{}
}

func (w *joinedDeadlineWriter) SetReadDeadline(time.Time) error {
	close(w.readEntered)
	<-w.readResume
	return nil
}

func TestManagedResponseCancellationJoinsReadDeadlineCallback(t *testing.T) {
	p, _, _, key, _ := runtimeFixture(t)
	session, _ := sessionFor(t, p)
	p.vault.Unlock(key, p.vault.Generation())
	p.managed = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, deliverySecret) })
	w := &joinedDeadlineWriter{deliveryWriter: &deliveryWriter{header: make(http.Header), flushEntered: make(chan struct{}), deadline: make(chan struct{})}, readEntered: make(chan struct{}), readResume: make(chan struct{})}
	var resume sync.Once
	defer resume.Do(func() { close(w.readResume) })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan any, 1)
	go func() { done <- invokeDelivery(p, w, deliveryRequest(session).WithContext(ctx)) }()
	waitDelivery(t, w.flushEntered, "flush")
	cancel()
	waitDelivery(t, w.readEntered, "cancellation read deadline callback")
	select {
	case <-done:
		t.Fatal("handler returned before callback joined")
	default:
	}
	resume.Do(func() { close(w.readResume) })
	select {
	case got := <-done:
		if got != http.ErrAbortHandler {
			t.Fatalf("abort=%v", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("handler did not join callback")
	}
	p.vault.Lock()
}

func TestManagedResponseCompletedRequestStopsCancellationCallback(t *testing.T) {
	p, _, _, key, _ := runtimeFixture(t)
	session, _ := sessionFor(t, p)
	p.vault.Unlock(key, p.vault.Generation())
	p.managed = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, deliverySecret) })
	w := &joinedDeadlineWriter{deliveryWriter: &deliveryWriter{header: make(http.Header)}, readEntered: make(chan struct{}), readResume: make(chan struct{})}
	close(w.readResume)
	ctx, cancel := context.WithCancel(context.Background())
	if got := invokeDelivery(p, w, deliveryRequest(session).WithContext(ctx)); got != nil {
		t.Fatalf("abort=%v", got)
	}
	cancel()
	// Lock also cancels any forgotten lease; neither cancellation may retain
	// the old ResponseWriter or advance deadlines on the next request.
	p.vault.Lock()
	select {
	case <-w.readEntered:
		t.Fatal("completed callback advanced next request deadline")
	default:
	}
}
