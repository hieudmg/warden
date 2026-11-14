package server

import (
	"crypto/tls"
	"net"
)

// TLSListener keeps *tls.Conn visible to net/http (including Request.TLS), but
// aborts the raw stream on a failed write. Otherwise net/http's error cleanup
// calls tls.Close, whose close_notify installs a NEW five-second write deadline
// after the request's write deadline has already expired. TLS writes cannot
// resume after a timeout; no useful response can be preserved on this stream.
func TLSListener(l net.Listener, certificate tls.Certificate) net.Listener {
	return tls.NewListener(abortFailedWritesListener{l}, &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}})
}

type abortFailedWritesListener struct{ net.Listener }

func (l abortFailedWritesListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return abortFailedWritesConn{c}, nil
}

type abortFailedWritesConn struct{ net.Conn }

func (c abortFailedWritesConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if err != nil {
		c.Conn.Close()
	}
	return n, err
}
