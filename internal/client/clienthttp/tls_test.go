package clienthttp

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// A configured HTTPS URL must not delegate TLS authentication to an injected
// dial hook or verify a caller-selected name instead of the configured origin.
func TestInjectedTransportCannotReplaceOriginTLSVerification(t *testing.T) {
	for _, kind := range []string{"plaintext DialTLSContext", "plaintext DialTLS", "insecure DialTLSContext", "insecure DialTLS", "hostname override"} {
		t.Run(kind, func(t *testing.T) {
			var delivered, hookCalls atomic.Int32
			peer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				delivered.Add(1)
				_, _ = io.Copy(io.Discard, r.Body)
				w.Write([]byte(`{}`))
			}))
			plaintext := strings.HasPrefix(kind, "plaintext")
			if plaintext {
				peer.Start()
			} else {
				peer.StartTLS()
			}
			defer peer.Close()
			transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
			address := peer.Listener.Addr().String()
			endpoint := "https://" + address
			if kind == "hostname override" {
				// The roots are trusted, but only the override matches this certificate.
				transport.TLSClientConfig = peer.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
				transport.TLSClientConfig.ServerName = peer.Certificate().DNSNames[0]
				if err := peer.Certificate().VerifyHostname(transport.TLSClientConfig.ServerName); err != nil {
					t.Fatal(err)
				}
				endpoint = "https://configured-origin.invalid"
				transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, network, address)
				}
			} else {
				dial := func(ctx context.Context, network, _ string) (net.Conn, error) {
					hookCalls.Add(1)
					if plaintext {
						return (&net.Dialer{}).DialContext(ctx, network, address)
					}
					// This hook ignores the transport's TLSClientConfig, exactly as Go permits.
					return (&tls.Dialer{Config: &tls.Config{InsecureSkipVerify: true}}).DialContext(ctx, network, address)
				}
				if strings.HasSuffix(kind, "Context") {
					transport.DialTLSContext = dial
				} else {
					transport.DialTLS = func(network, addr string) (net.Conn, error) { return dial(context.Background(), network, addr) }
				}
			}
			originalConfig := transport.TLSClientConfig
			originalName := originalConfig.ServerName
			client := Client(&http.Client{Transport: transport, Timeout: time.Second}, time.Second)
			defer client.CloseIdleConnections()
			req, err := http.NewRequest("POST", endpoint+"/api/v1/client/reports", strings.NewReader("synthetic-private-body"))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Authorization", "Bearer synthetic-test-credential")
			response, err := client.Do(req)
			if response != nil {
				response.Body.Close()
			}
			if err == nil || delivered.Load() != 0 {
				t.Fatal("unverified endpoint received bearer/body", err, delivered.Load())
			}
			if hookCalls.Load() != 0 {
				t.Fatal("injected TLS hook was invoked")
			}
			if transport.TLSClientConfig != originalConfig || originalConfig.ServerName != originalName {
				t.Fatal("caller TLS config mutated")
			}
			if kind != "hostname override" && transport.DialTLS == nil && transport.DialTLSContext == nil {
				t.Fatal("caller TLS hook removed")
			}
		})
	}
}

func TestInjectedTransportPreservesTrustedRootsAndOrdinaryTCPDial(t *testing.T) {
	var delivered, dials atomic.Int32
	peer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { delivered.Add(1); w.Write([]byte(`{}`)) }))
	defer peer.Close()
	transport := peer.Client().Transport.(*http.Transport).Clone()
	defer transport.CloseIdleConnections()
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		dials.Add(1)
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	config := transport.TLSClientConfig
	config.ServerName = "wrong-override.invalid"
	config.InsecureSkipVerify = true
	config.MinVersion = tls.VersionTLS12
	client := Client(&http.Client{Transport: transport}, time.Second)
	defer client.CloseIdleConnections()
	response, err := client.Get(peer.URL)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if delivered.Load() != 1 || dials.Load() != 1 {
		t.Fatal("ordinary TCP dial/private roots not retained")
	}
	if transport.TLSClientConfig != config || config.ServerName != "wrong-override.invalid" || !config.InsecureSkipVerify || config.MinVersion != tls.VersionTLS12 {
		t.Fatal("caller transport/config mutated")
	}
}

type unverifiedTransport struct{ called atomic.Bool }

func (t *unverifiedTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	t.called.Store(true)
	return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{}`)), Request: r}, nil
}
func TestInjectedUnknownRoundTripperFailsClosed(t *testing.T) {
	transport := &unverifiedTransport{}
	client := Client(&http.Client{Transport: transport}, time.Second)
	response, err := client.Get("https://configured-origin.invalid/api/v1/client/projects")
	if response != nil {
		response.Body.Close()
	}
	if err == nil || transport.called.Load() {
		t.Fatal("arbitrary injected RoundTripper bypassed HTTPS policy")
	}
}
