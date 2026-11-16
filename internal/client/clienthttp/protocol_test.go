package clienthttp

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// This is a deliberately hostile injected protocol implementation, not an HTTP
// redirect. Go passes the original request to the negotiated RoundTripper.
type forwardingProtocol struct {
	destination *url.URL
	called      *atomic.Int32
}

func (p forwardingProtocol) RoundTrip(r *http.Request) (*http.Response, error) {
	p.called.Add(1)
	forwarded := r.Clone(r.Context())
	target := *r.URL
	target.Scheme = p.destination.Scheme
	target.Host = p.destination.Host
	forwarded.URL = &target
	forwarded.Host = target.Host
	return http.DefaultTransport.RoundTrip(forwarded)
}

func TestInjectedTLSNextProtoCannotDelegateBearerOrBody(t *testing.T) {
	for _, protocol := range []string{"h2", "warden-test-protocol"} {
		t.Run(protocol, func(t *testing.T) {
			var forwarded, leaked, originRequests, originHTTP2 atomic.Int32
			var trustedNegotiation atomic.Bool
			attacker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				if r.TLS == nil && r.Header.Get("Authorization") == "Bearer synthetic-test-credential" && string(body) == "synthetic-private-body" {
					leaked.Add(1)
				}
				w.Write([]byte(`{}`))
			}))
			defer attacker.Close()
			destination, err := url.Parse(attacker.URL)
			if err != nil {
				t.Fatal(err)
			}
			origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				originRequests.Add(1)
				io.Copy(io.Discard, r.Body)
				if r.ProtoMajor == 2 && r.TLS != nil && r.TLS.NegotiatedProtocol == "h2" {
					originHTTP2.Add(1)
				}
				w.Write([]byte(`{}`))
			}))
			origin.EnableHTTP2 = true
			origin.TLS = &tls.Config{NextProtos: []string{protocol, "h2", "http/1.1"}}
			origin.StartTLS()
			defer origin.Close()
			config := origin.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
			config.NextProtos = []string{protocol}
			protocols := &http.Protocols{}
			protocols.SetHTTP1(true)
			protocols.SetHTTP2(true)
			protocols.SetUnencryptedHTTP2(true)
			callback := func(_ string, conn *tls.Conn) http.RoundTripper {
				state := conn.ConnectionState()
				trustedNegotiation.Store(state.HandshakeComplete && len(state.VerifiedChains) > 0 && state.NegotiatedProtocol == protocol)
				// The callback no longer needs the verified connection; it handles the
				// request over a different, plaintext connection instead.
				conn.NetConn().Close()
				conn.Close()
				return forwardingProtocol{destination: destination, called: &forwarded}
			}
			transport := &http.Transport{TLSClientConfig: config, TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{protocol: callback}, Protocols: protocols, ForceAttemptHTTP2: true}
			originalProtos := append([]string(nil), config.NextProtos...)
			originalProtocols := *protocols
			client := Client(&http.Client{Transport: transport, Timeout: time.Second}, time.Second)
			defer client.CloseIdleConnections()
			req, err := http.NewRequest("POST", origin.URL+"/api/v1/client/reports", io.NopCloser(strings.NewReader("synthetic-private-body")))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Authorization", "Bearer synthetic-test-credential")
			response, err := client.Do(req)
			if response != nil {
				response.Body.Close()
			}
			if leaked.Load() != 0 || forwarded.Load() != 0 || trustedNegotiation.Load() {
				t.Fatalf("caller ALPN callback forwarded bearer/body: verified TLS=%v callbacks=%d plaintext deliveries=%d", trustedNegotiation.Load(), forwarded.Load(), leaked.Load())
			}
			if err != nil || originRequests.Load() != 1 || originHTTP2.Load() != 1 {
				t.Fatal("owned standard HTTP/2 handling failed", err, originRequests.Load(), originHTTP2.Load())
			}
			if transport.TLSClientConfig != config || !reflect.DeepEqual(config.NextProtos, originalProtos) || transport.Protocols != protocols || *protocols != originalProtocols || !transport.ForceAttemptHTTP2 || len(transport.TLSNextProto) != 1 || transport.TLSNextProto[protocol] == nil {
				t.Fatal("caller protocol configuration mutated")
			}
		})
	}
}

func TestOwnedStandardHTTP2DoesNotInitializeCallerProtocolState(t *testing.T) {
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 {
			t.Error("standard HTTP/2 not negotiated")
		}
		w.Write([]byte(`{}`))
	}))
	origin.EnableHTTP2 = true
	origin.StartTLS()
	defer origin.Close()
	config := origin.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	config.NextProtos = nil
	transport := &http.Transport{TLSClientConfig: config, ForceAttemptHTTP2: true}
	client := Client(&http.Client{Transport: transport, Timeout: time.Second}, time.Second)
	defer client.CloseIdleConnections()
	response, err := client.Get(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if transport.TLSNextProto != nil || config.NextProtos != nil || transport.Protocols != nil {
		t.Fatal("owned protocol setup initialized caller state")
	}
}

func TestInjectedRegisteredHTTPSProtocolIsNotInherited(t *testing.T) {
	var alternate atomic.Int32
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil {
			t.Error("TLS missing")
		}
		w.Write([]byte(`{}`))
	}))
	defer origin.Close()
	transport := &http.Transport{TLSClientConfig: origin.Client().Transport.(*http.Transport).TLSClientConfig.Clone()}
	attacker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{}`)) }))
	defer attacker.Close()
	destination, err := url.Parse(attacker.URL)
	if err != nil {
		t.Fatal(err)
	}
	transport.RegisterProtocol("https", forwardingProtocol{destination: destination, called: &alternate})
	client := Client(&http.Client{Transport: transport, Timeout: time.Second}, time.Second)
	defer client.CloseIdleConnections()
	response, err := client.Get(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if alternate.Load() != 0 {
		t.Fatal("registered alternate HTTPS RoundTripper inherited")
	}
	// The caller retains its own registration; only the owned transport omits it.
	req, err := http.NewRequest("GET", origin.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	original, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	original.Body.Close()
	transport.CloseIdleConnections()
	if alternate.Load() != 1 {
		t.Fatal("caller registration mutated")
	}
}
