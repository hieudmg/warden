package runtime

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
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

// Observe the actual pipe deadlines and writes without changing either.
type deliveryWriteDeadline struct {
	setAt, deadline time.Time
}

type deliverySocketWrite struct {
	at       time.Time
	n        int
	err      error
	statusOK bool
}

type deliveryDeadlineConn struct {
	net.Conn
	mu     sync.Mutex
	first  deliveryWriteDeadline
	writes []deliverySocketWrite
}

func (c *deliveryDeadlineConn) SetWriteDeadline(deadline time.Time) error {
	at := time.Now()
	err := c.Conn.SetWriteDeadline(deadline)
	c.mu.Lock()
	if c.first.deadline.IsZero() && !deadline.IsZero() {
		c.first = deliveryWriteDeadline{setAt: at, deadline: deadline}
	}
	c.mu.Unlock()
	return err
}

func (c *deliveryDeadlineConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	c.mu.Lock()
	c.writes = append(c.writes, deliverySocketWrite{at: time.Now(), n: n, err: err, statusOK: bytes.HasPrefix(b, []byte("HTTP/1.1 200 "))})
	c.mu.Unlock()
	return n, err
}

func (c *deliveryDeadlineConn) snapshot() (deliveryWriteDeadline, []deliverySocketWrite) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.first, append([]deliverySocketWrite(nil), c.writes...)
}

func TestManagedResponseBlockedHTTPFlushTerminates(t *testing.T) {
	for _, variant := range []string{"lock-cancel", "closed-client", "write-deadline"} {
		t.Run(variant, func(t *testing.T) {
			testManagedResponseBlockedHTTPFlush(t, variant, false)
		})
	}
}

func TestManagedResponseBlockedHTTPFlushDeadlineIsConnectionScoped(t *testing.T) {
	testManagedResponseBlockedHTTPFlush(t, "write-deadline", true)
}

func testManagedResponseBlockedHTTPFlush(t *testing.T, variant string, delayedLock bool) {
	t.Helper()
	p, _, _, key, _ := runtimeFixture(t)
	session, csrf := sessionFor(t, p)
	p.vault.Unlock(key, p.vault.Generation())
	p.managed = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, deliverySecret) })
	entered, terminated := make(chan struct{}), make(chan struct{})
	backendLock, peerLock := net.Pipe()
	defer peerLock.Close()
	observedLock := &deliveryDeadlineConn{Conn: backendLock}
	listener := &deliveryPipeListener{connections: make(chan net.Conn), closed: make(chan struct{})}
	middleware := server.New("", p).Handler()
	srv := &http.Server{WriteTimeout: 120 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/ssh-connections" {
			defer close(terminated)
		}
		if delayedLock && r.URL.Path == "/api/v1/auth/lock" {
			first, _ := observedLock.snapshot()
			// Cross precisely the blocked connection's short-budget interval
			// after lock headers, not an arbitrary scheduling padding sleep.
			timer := time.NewTimer(time.Until(first.setAt.Add(50 * time.Millisecond)))
			defer timer.Stop()
			select {
			case <-timer.C:
			case <-r.Context().Done():
				return
			}
		}
		middleware.ServeHTTP(w, r)
	})}
	if variant == "write-deadline" {
		srv.WriteTimeout = 50 * time.Millisecond
	}
	serving := make(chan error, 1)
	go func() { serving <- srv.Serve(listener) }()
	defer func() { srv.Close(); <-serving }()
	lockListener := listener
	if variant == "write-deadline" {
		// Only the deliberately blocked secret connection gets the short budget.
		// Share the actual plane/middleware, not that server's WriteTimeout.
		lockListener = &deliveryPipeListener{connections: make(chan net.Conn), closed: make(chan struct{})}
		lockServer := &http.Server{WriteTimeout: 120 * time.Second, Handler: srv.Handler}
		lockServing := make(chan error, 1)
		go func() { lockServing <- lockServer.Serve(lockListener) }()
		defer func() { lockServer.Close(); <-lockServing }()
	}
	backend, peer := net.Pipe()
	defer peer.Close()
	observedSecret := &deliveryDeadlineConn{Conn: backend}
	if delayedLock {
		defer func() {
			for name, observed := range map[string]*deliveryDeadlineConn{"secret": observedSecret, "lock": observedLock} {
				first, writes := observed.snapshot()
				t.Logf("%s first write budget=%s", name, first.deadline.Sub(first.setAt))
				for _, write := range writes {
					t.Logf("%s actual socket Write at=%s bytes=%d status200=%v err=%v", name, write.at.Sub(first.setAt), write.n, write.statusOK, write.err)
				}
			}
		}()
	}
	listener.connections <- &blockedEmissionConn{Conn: observedSecret, entered: entered}
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
	if delayedLock {
		first, writes := observedSecret.snapshot()
		if first.deadline.IsZero() || first.deadline.After(first.setAt.Add(50*time.Millisecond)) {
			t.Fatal("blocked secret connection did not retain its 50ms write deadline")
		}
		if len(writes) != 1 || writes[0].n != 0 || !errors.Is(writes[0].err, os.ErrDeadlineExceeded) {
			t.Fatalf("blocked secret write did not expire without emitting bytes: %+v", writes)
		}
	}
	// A second actual net/http connection issues the authenticated lock while
	// the first peer never consumes the buffered secret response.
	lockListener.connections <- observedLock
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
	if delayedLock {
		first, _ := observedLock.snapshot()
		if !first.deadline.After(first.setAt.Add(50 * time.Millisecond)) {
			t.Fatal("short secret deadline leaked onto the independent lock connection")
		}
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
}
