package upgrade

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptrace"
	"sync"
	"sync/atomic"
	"time"
)

// The dial deadline covers the complete connection: TCP, proxy TLS, CONNECT,
// origin TLS and protocol setup. Closing the owned raw socket also interrupts
// CONNECT when the routing seam cannot implement SetDeadline.
type establishmentConn struct {
	net.Conn
	timer               *time.Timer
	deadline            time.Time
	fired               chan struct{}
	expired             atomic.Bool
	stopOnce, closeOnce sync.Once
	closeErr            error
}

func newEstablishmentConn(conn net.Conn, deadline time.Time) *establishmentConn {
	c := &establishmentConn{Conn: conn, fired: make(chan struct{}), deadline: deadline}
	c.timer = time.AfterFunc(time.Until(deadline), func() {
		defer close(c.fired)
		c.expired.Store(true)
		_ = c.closeRaw()
	})
	return c
}

func (c *establishmentConn) stopEstablishment() {
	c.stopOnce.Do(func() {
		// Stop(false) does not join an AfterFunc. No abort may outlive readiness
		// and subsequently close a connection published for another request.
		if !c.timer.Stop() {
			<-c.fired
		} else if !time.Now().Before(c.deadline) {
			// The deadline can elapse before its callback gets CPU time.
			c.expired.Store(true)
			_ = c.closeRaw()
		}
	})
}
func (c *establishmentConn) closeRaw() error {
	c.closeOnce.Do(func() { c.closeErr = c.Conn.Close() })
	return c.closeErr
}
func (c *establishmentConn) Close() error {
	c.stopEstablishment()
	return c.closeRaw()
}
func (c *establishmentConn) Read(buffer []byte) (int, error) {
	n, err := c.Conn.Read(buffer)
	if err != nil && c.expired.Load() {
		err = context.DeadlineExceeded
	}
	return n, err
}
func (c *establishmentConn) Write(buffer []byte) (int, error) {
	n, err := c.Conn.Write(buffer)
	if err != nil && c.expired.Load() {
		err = context.DeadlineExceeded
	}
	return n, err
}

type establishmentTransport struct{ *http.Transport }

func (t *establishmentTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	trace := &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) {
		conn := info.Conn
		// HTTPS proxies have two TLS layers. TLSHandshakeDone for the proxy is
		// not origin readiness; only GotConn means the verified connection is ready.
		for {
			switch layer := conn.(type) {
			case *tls.Conn:
				conn = layer.NetConn()
			case *establishmentConn:
				layer.stopEstablishment()
				return
			default:
				return
			}
		}
	}}
	return t.Transport.RoundTrip(request.WithContext(httptrace.WithClientTrace(request.Context(), trace)))
}
