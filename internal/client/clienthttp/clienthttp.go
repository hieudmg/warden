// Package clienthttp fixes the HTTPS origin and redirect boundary for enrollment
// and the explicit client audience. It never follows a redirected credential/body.
package clienthttp

import (
	"crypto/tls"
	"errors"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"
)

func Origin(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || u.RawPath != "" {
		return "", errors.New("client endpoint must be an HTTPS origin with verified certificate")
	}
	return "https://" + u.Host, nil
}
func Client(in *http.Client, timeout time.Duration) *http.Client {
	var out http.Client
	if in != nil {
		out = *in
	} else {
		out.Timeout = timeout
	}
	transport := out.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	if transport, ok := transport.(*http.Transport); ok && transport != nil {
		// Transport.Clone copies protocol delegates and initializes caller state.
		// Copy only network settings into fresh state: Go alone installs HTTP/1+2
		// handlers, never inherited TLSNextProto or RegisterProtocol RoundTrippers.
		own := &http.Transport{
			Proxy:                  transport.Proxy,
			OnProxyConnectResponse: transport.OnProxyConnectResponse,
			DialContext:            transport.DialContext,
			Dial:                   transport.Dial,
			TLSClientConfig:        transport.TLSClientConfig.Clone(),
			TLSHandshakeTimeout:    transport.TLSHandshakeTimeout,
			DisableKeepAlives:      transport.DisableKeepAlives,
			DisableCompression:     transport.DisableCompression,
			MaxIdleConns:           transport.MaxIdleConns,
			MaxIdleConnsPerHost:    transport.MaxIdleConnsPerHost,
			MaxConnsPerHost:        transport.MaxConnsPerHost,
			IdleConnTimeout:        transport.IdleConnTimeout,
			ResponseHeaderTimeout:  transport.ResponseHeaderTimeout,
			ExpectContinueTimeout:  transport.ExpectContinueTimeout,
			ProxyConnectHeader:     transport.ProxyConnectHeader.Clone(),
			GetProxyConnectHeader:  transport.GetProxyConnectHeader,
			MaxResponseHeaderBytes: transport.MaxResponseHeaderBytes,
			WriteBufferSize:        transport.WriteBufferSize,
			ReadBufferSize:         transport.ReadBufferSize,
			ForceAttemptHTTP2:      true,
		}
		if transport.HTTP2 != nil {
			config := *transport.HTTP2
			own.HTTP2 = &config
		}
		if own.TLSClientConfig == nil {
			own.TLSClientConfig = &tls.Config{}
		}
		own.TLSClientConfig.NextProtos = nil // Regenerated with Go's standard handlers.
		own.TLSClientConfig.ServerName = ""  // Verify the request origin, not an override.
		own.TLSClientConfig.InsecureSkipVerify = false
		own.TLSClientConfig.MinVersion = max(own.TLSClientConfig.MinVersion, tls.VersionTLS13)
		out.Transport = own
	} else {
		out.Transport = rejectUnverifiedTransport{}
	}
	out.Jar = nil // API audience never sends browser cookies.
	out.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &out
}

// Arbitrary RoundTrippers need not use TLS at all. Agent IPC is installed only
// by its explicit constructor, never accepted as general network injection.
type rejectUnverifiedTransport struct{}

func (rejectUnverifiedTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Body != nil {
		r.Body.Close()
	}
	return nil, errors.New("custom HTTP transport cannot establish verified HTTPS")
}

// Allowed is intentionally duplicated at the local credential delivery boundary:
// neither IPC callers nor public API helpers can turn this into a URL proxy.
func Allowed(method, target string) bool {
	u, err := url.ParseRequestURI(target)
	if err != nil || u.IsAbs() || u.Host != "" || u.RawPath != "" || path.Clean(u.Path) != u.Path || strings.HasSuffix(u.Path, "/") {
		return false
	}
	rest := strings.TrimPrefix(u.Path, "/api/v1/client/")
	if rest == u.Path {
		return false
	}
	a := strings.Split(rest, "/")
	if u.RawQuery != "" {
		q, e := url.ParseQuery(u.RawQuery)
		if e != nil || len(q) != 1 || len(q["database"]) != 1 || len(a) != 3 || a[0] != "transport" || a[1] != "db" {
			return false
		}
	}
	switch a[0] {
	case "ssh-connections", "db-connections":
		if len(a) == 1 {
			return method == "GET"
		}
		if len(a) > 3 || a[1] == "" {
			return false
		}
		for _, r := range a[1] {
			if r < '0' || r > '9' {
				return false
			}
		}
		if len(a) == 2 {
			return method == "GET"
		}
		return a[2] == "dependents" && method == "GET" || a[2] == "archive" && method == "PUT"
	case "transport":
		return method == "GET" && len(a) == 3 && (a[1] == "ssh" || a[1] == "db") && digits(a[2])
	case "projects":
		return len(a) == 1 && (method == "GET" || method == "POST") || len(a) == 3 && a[1] != "" && a[2] == "reports" && method == "GET"
	case "reports":
		return len(a) == 1 && method == "POST"
	}
	return false
}
func digits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
