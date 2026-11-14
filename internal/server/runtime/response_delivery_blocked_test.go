package runtime

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"warden/internal/server"
)

// net.Pipe has no socket send buffer: a peer that does not read deterministically
// saturates the server write. Unlike a fake Flush, this blocks inside net/http.
type deliveryPipeListener struct {
	connections chan net.Conn
	closed      chan struct{}
	once        sync.Once
}

func (l *deliveryPipeListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.connections:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}
func (l *deliveryPipeListener) Close() error   { l.once.Do(func() { close(l.closed) }); return nil }
func (l *deliveryPipeListener) Addr() net.Addr { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)} }

type blockedEmissionConn struct {
	net.Conn
	entered chan struct{}
	once    sync.Once
}

func (c *blockedEmissionConn) Write(b []byte) (int, error) {
	if bytes.Contains(b, []byte(deliverySecret)) {
		c.once.Do(func() { close(c.entered) })
	}
	return c.Conn.Write(b)
}

func TestManagedResponseBlockedHTTPFlushTerminates(t *testing.T) {
	for _, variant := range []string{"lock-cancel", "closed-client", "write-deadline"} {
		t.Run(variant, func(t *testing.T) {
			p, _, _, key, _ := runtimeFixture(t)
			session, csrf := sessionFor(t, p)
			p.vault.Unlock(key, p.vault.Generation())
			p.managed = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, deliverySecret) })
			entered, terminated := make(chan struct{}), make(chan struct{})
			listener := &deliveryPipeListener{connections: make(chan net.Conn), closed: make(chan struct{})}
			middleware := server.New("", p).Handler()
			srv := &http.Server{WriteTimeout: 120 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api/v1/ssh-connections" {
					defer close(terminated)
				}
				middleware.ServeHTTP(w, r)
			})}
			if variant == "write-deadline" {
				srv.WriteTimeout = 50 * time.Millisecond
			}
			serving := make(chan error, 1)
			go func() { serving <- srv.Serve(listener) }()
			defer func() { srv.Close(); <-serving }()
			backend, peer := net.Pipe()
			defer peer.Close()
			listener.connections <- &blockedEmissionConn{Conn: backend, entered: entered}
			peer.SetDeadline(time.Now().Add(3 * time.Second))
			req := deliveryRequest(session)
			req.RequestURI = ""
			if err := req.Write(peer); err != nil {
				t.Fatal(err)
			}
			waitDelivery(t, entered, "saturated net/http socket write")
			if variant == "closed-client" {
				peer.Close()
			}
			if variant != "lock-cancel" {
				waitDelivery(t, terminated, "deadline/disconnect abort")
			}
			// A second actual net/http connection issues the authenticated lock while
			// the first peer never consumes the buffered secret response.
			backendLock, peerLock := net.Pipe()
			defer peerLock.Close()
			listener.connections <- backendLock
			peerLock.SetDeadline(time.Now().Add(3 * time.Second))
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
				t.Fatal(err)
			}
			io.Copy(io.Discard, response.Body)
			response.Body.Close()
			if response.StatusCode != 200 {
				t.Fatalf("lock status %d", response.StatusCode)
			}
			waitDelivery(t, terminated, "canceled delivery")
			if variant != "closed-client" {
				body, err := io.ReadAll(peer)
				if err != nil {
					t.Fatal(err)
				}
				if bytes.Contains(body, []byte(deliverySecret)) {
					t.Fatal("aborted net/http response finalized secret bytes")
				}
			}
		})
	}
}
