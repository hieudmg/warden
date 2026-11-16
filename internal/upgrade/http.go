package upgrade

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/url"
	"time"
)

const (
	maxBinaryBytes   int64 = 256 << 20
	maxChecksumBytes int64 = 1 << 20
	connectTimeout         = 10 * time.Second
	operationTimeout       = 5 * time.Minute
)

// downloadSettings is internal so tests can exercise the same streaming and
// deadline boundaries without downloading hundreds of MiB or waiting minutes.
type downloadSettings struct {
	binaryBytes, checksumBytes int64
	connect, total             time.Duration
}

var defaultDownloadSettings = downloadSettings{maxBinaryBytes, maxChecksumBytes, connectTimeout, operationTimeout}

func httpsURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return errors.New("release URL must use HTTPS with a verified certificate and no userinfo or fragment")
	}
	return nil
}

// The updater owns its transport, not the API client's one-origin policy.
// Copy only public roots and ordinary TCP routing. Fresh standard protocol state
// cannot inherit TLS dialers, ServerName, ALPN or registered scheme delegates.
func downloadClient(in *http.Client, settings downloadSettings) (*http.Client, error) {
	var source http.RoundTripper = http.DefaultTransport
	if in != nil && in.Transport != nil {
		source = in.Transport
	}
	tr, ok := source.(*http.Transport)
	if !ok || tr == nil {
		return nil, errors.New("custom updater transport cannot establish verified HTTPS")
	}
	own := &http.Transport{Proxy: tr.Proxy, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13}, ForceAttemptHTTP2: true, TLSHandshakeTimeout: settings.connect, ResponseHeaderTimeout: settings.connect, MaxResponseHeaderBytes: 1 << 20, IdleConnTimeout: 30 * time.Second}
	if tr.TLSClientConfig != nil && tr.TLSClientConfig.RootCAs != nil {
		own.TLSClientConfig.RootCAs = tr.TLSClientConfig.RootCAs.Clone()
	}
	dial := tr.DialContext
	if dial == nil {
		dial = (&net.Dialer{Timeout: settings.connect, KeepAlive: 30 * time.Second}).DialContext
	}
	own.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		ctx, cancel := context.WithTimeout(ctx, settings.connect)
		defer cancel()
		deadline, _ := ctx.Deadline()
		conn, err := dial(ctx, network, addr)
		if err != nil {
			if conn != nil {
				_ = conn.Close()
			}
			return nil, err
		}
		if conn == nil {
			return nil, errors.New("updater TCP dial returned a nil connection")
		}
		if err := ctx.Err(); err != nil {
			_ = conn.Close()
			return nil, err
		}
		if !time.Now().Before(deadline) {
			_ = conn.Close()
			return nil, context.DeadlineExceeded
		}
		return newEstablishmentConn(conn, deadline), nil
	}
	return &http.Client{Transport: &establishmentTransport{own}, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return errors.New("too many release redirects")
		}
		return httpsURL(req.URL.String())
	}}, nil
}
