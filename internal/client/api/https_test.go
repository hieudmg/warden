package api

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestAPIRedirectPolicyBeforeCredentialSend(t *testing.T) {
	for _, status := range []int{301, 302, 303, 307, 308} {
		for _, method := range []string{"GET", "POST"} {
			for _, relation := range []string{"host", "port", "subdomain", "downgrade", "same-origin"} {
				for _, injected := range []bool{false, true} {
					t.Run(http.StatusText(status)+"/"+method+"/"+relation+"/injected="+strconv.FormatBool(injected), func(t *testing.T) {
						var sinkRequests, originRequests, followed atomic.Int32
						sink := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
							sinkRequests.Add(1)
							io.Copy(io.Discard, r.Body)
							w.Write([]byte(`[]`))
						}))
						defer sink.Close()
						plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { sinkRequests.Add(1); io.Copy(io.Discard, r.Body) }))
						defer plain.Close()
						var location string
						origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
							if r.URL.Path == "/redirected" {
								followed.Add(1)
								return
							}
							originRequests.Add(1)
							if r.TLS == nil || r.TLS.ServerName != "example.com" {
								t.Error("request origin not TLS verified")
							}
							if r.Header.Get("Cookie") != "" {
								t.Error("API request sent browser cookie")
							}
							if method == "POST" {
								body, _ := io.ReadAll(r.Body)
								if !strings.Contains(string(body), "synthetic-private-body") {
									t.Error("origin did not receive POST body")
								}
							}
							http.Redirect(w, r, location, status)
						}))
						defer origin.Close()
						_, port, _ := net.SplitHostPort(strings.TrimPrefix(origin.URL, "https://"))
						originURL := "https://example.com:" + port
						sinkPort := strings.TrimPrefix(sink.URL, "https://127.0.0.1:")
						switch relation {
						case "host":
							location = sink.URL + "/redirected"
						case "port":
							location = "https://example.com:" + sinkPort + "/redirected"
						case "subdomain":
							location = "https://sub.example.com:" + sinkPort + "/redirected"
						case "downgrade":
							location = plain.URL + "/redirected"
						case "same-origin":
							location = originURL + "/redirected"
						}
						roots := x509.NewCertPool()
						roots.AddCert(origin.Certificate())
						roots.AddCert(sink.Certificate())
						dial := func(ctx context.Context, network, address string) (net.Conn, error) {
							_, p, e := net.SplitHostPort(address)
							if e != nil {
								return nil, e
							}
							return (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort("127.0.0.1", p))
						}
						tr := &http.Transport{Proxy: nil, DialContext: dial, TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}}
						jar, _ := cookiejar.New(nil)
						u, _ := url.Parse(originURL)
						jar.SetCookies(u, []*http.Cookie{{Name: "browser", Value: "must-not-send"}})
						var callback atomic.Int32
						input := &http.Client{Transport: tr, Timeout: 3 * time.Second, Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { callback.Add(1); return nil }}
						// Prove the redirect target really is reachable with this ordinary TCP
						// route and certificate trust, rather than failing on DNS or TLS.
						probe, probeErr := input.Get(location)
						if probeErr != nil {
							t.Fatalf("redirect target unreachable: %v", probeErr)
						}
						probe.Body.Close()
						if probe.StatusCode != 200 {
							t.Fatalf("target status=%d", probe.StatusCode)
						}
						sinkRequests.Store(0)
						followed.Store(0)
						callbackPointer := reflect.ValueOf(input.CheckRedirect).Pointer()
						originalTLS := tr.TLSClientConfig
						var client *Client
						if injected {
							client = New(originURL, input)
						} else {
							client = New(originURL, nil)
							// Test-only trusted roots and ordinary TCP routing, with normal TLS
							// hostname verification still performed for the request origin.
							owned := client.http.Transport.(*http.Transport)
							owned.Proxy = nil
							owned.DialContext = dial
							owned.TLSClientConfig.RootCAs = roots
						}
						defer client.http.CloseIdleConnections()
						var err error
						if method == "GET" {
							_, err = client.ListSSH(context.Background())
						} else {
							var result any
							err = client.PostJSON(context.Background(), "/api/v1/client/reports", map[string]string{"summary": "synthetic-private-body"}, &result)
						}
						var ae *APIError
						if !errors.As(err, &ae) || ae.StatusCode != status || originRequests.Load() != 1 {
							t.Fatalf("did not reach verified origin redirect: %v, origin=%d", err, originRequests.Load())
						}
						if sinkRequests.Load() != 0 || followed.Load() != 0 {
							t.Fatal("followed redirect before rejection")
						}
						if input.Transport != tr || input.Jar != jar || input.Timeout != 3*time.Second || input.CheckRedirect == nil || reflect.ValueOf(input.CheckRedirect).Pointer() != callbackPointer || callback.Load() != 0 || tr.TLSClientConfig != originalTLS || tr.TLSClientConfig.RootCAs != roots || tr.TLSClientConfig.ServerName != "" || tr.TLSClientConfig.InsecureSkipVerify || tr.TLSClientConfig.MinVersion != tls.VersionTLS13 || len(jar.Cookies(u)) != 1 {
							t.Fatal("caller configuration mutated")
						}
					})
				}
			}
		}
	}
	var reached atomic.Int32
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached.Add(1) }))
	defer plain.Close()
	if _, err := New(plain.URL, nil).ListSSH(context.Background()); err == nil || reached.Load() != 0 {
		t.Fatal("initial HTTP accepted", err)
	}
}
func TestInjectedClientCannotDisableCertificateVerification(t *testing.T) {
	var reached atomic.Int32
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached.Add(1); w.Write([]byte(`[]`)) }))
	defer origin.Close()
	// The injected client deliberately lacks trust and requests an insecure bypass.
	transport := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	injected := &http.Client{Transport: transport}
	if _, err := New(origin.URL, injected).ListSSH(context.Background()); err == nil || reached.Load() != 0 {
		t.Fatal("injected client bypassed certificate verification")
	}
	if !transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("shared injected transport mutated")
	}
}
