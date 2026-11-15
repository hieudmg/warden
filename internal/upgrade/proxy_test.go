package upgrade

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Only disposable loopback sockets: a silent proxy never replies to CONNECT;
// a successful proxy relays both directions and joins them before signaling done.
func upgradeProxyFixture(t *testing.T, secure, silent bool, origin string) (*httptest.Server, <-chan struct{}, <-chan struct{}, *atomic.Int32) {
	t.Helper()
	seen, joined := make(chan struct{}), make(chan struct{})
	count := new(atomic.Int32)
	var mu sync.Mutex
	var downstream, upstream net.Conn
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if count.Add(1) != 1 {
			t.Error("unexpected additional proxy tunnel")
			http.Error(w, "extra tunnel", 500)
			return
		}
		if r.Method != http.MethodConnect {
			t.Errorf("proxy method=%s", r.Method)
			return
		}
		conn, buffer, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		mu.Lock()
		downstream = conn
		mu.Unlock()
		defer close(joined)
		defer conn.Close()
		close(seen)
		if silent {
			if _, err := buffer.ReadByte(); err == nil {
				t.Error("origin TLS started before CONNECT response")
			}
			return
		}
		peer, err := net.Dial("tcp", origin)
		if err != nil {
			t.Error(err)
			return
		}
		mu.Lock()
		upstream = peer
		mu.Unlock()
		defer peer.Close()
		if _, err = buffer.WriteString("HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
			t.Error(err)
			return
		}
		if err = buffer.Flush(); err != nil {
			t.Error(err)
			return
		}
		finished := make(chan struct{})
		go func() { defer close(finished); io.Copy(peer, buffer); peer.Close(); conn.Close() }()
		io.Copy(conn, peer)
		conn.Close()
		peer.Close()
		<-finished
	})
	var server *httptest.Server
	if secure {
		server = httptest.NewTLSServer(handler)
	} else {
		server = httptest.NewServer(handler)
	}
	t.Cleanup(func() {
		server.Close()
		mu.Lock()
		if downstream != nil {
			downstream.Close()
		}
		if upstream != nil {
			upstream.Close()
		}
		mu.Unlock()
		if count.Load() != 0 {
			select {
			case <-joined:
			case <-time.After(time.Second):
				t.Error("proxy handler/relay did not join during cleanup")
			}
		}
	})
	return server, seen, joined, count
}

type observedProxyTCP struct {
	net.Conn
	unsupported bool
	once        sync.Once
	closed      chan struct{}
	err         error
}

func (c *observedProxyTCP) Close() error {
	c.once.Do(func() { c.err = c.Conn.Close(); close(c.closed) })
	return c.err
}
func (c *observedProxyTCP) SetDeadline(deadline time.Time) error {
	if c.unsupported {
		return errors.ErrUnsupported
	}
	return c.Conn.SetDeadline(deadline)
}
func (c *observedProxyTCP) SetReadDeadline(deadline time.Time) error {
	if c.unsupported {
		return errors.ErrUnsupported
	}
	return c.Conn.SetReadDeadline(deadline)
}
func (c *observedProxyTCP) SetWriteDeadline(deadline time.Time) error {
	if c.unsupported {
		return errors.ErrUnsupported
	}
	return c.Conn.SetWriteDeadline(deadline)
}

func proxyFixtureClient(t *testing.T, proxy *httptest.Server, origin *httptest.Server, unsupported bool) (*http.Client, <-chan *observedProxyTCP, *atomic.Int32) {
	t.Helper()
	roots := x509.NewCertPool()
	if proxy.TLS != nil {
		roots.AddCert(proxy.Certificate())
	}
	if origin != nil {
		roots.AddCert(origin.Certificate())
	}
	proxyURL, err := url.Parse(proxy.URL)
	if err != nil {
		t.Fatal(err)
	}
	sockets := make(chan *observedProxyTCP, 8)
	dials := new(atomic.Int32)
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{RootCAs: roots}, DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := (&net.Dialer{}).DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		observed := &observedProxyTCP{Conn: conn, unsupported: unsupported, closed: make(chan struct{})}
		dials.Add(1)
		sockets <- observed
		return observed, nil
	}}
	return &http.Client{Transport: transport}, sockets, dials
}

func requireProxyEvent(t *testing.T, event <-chan struct{}, name string) {
	t.Helper()
	select {
	case <-event:
	case <-time.After(time.Second):
		t.Fatalf("%s did not finish before fixture-forced cleanup", name)
	}
}

func TestUpgradeProxyEstablishmentDeadline(t *testing.T) {
	for _, secure := range []bool{false, true} {
		for _, unsupported := range []bool{false, true} {
			t.Run(fmt.Sprintf("HTTPS=%t/deadlinesUnsupported=%t", secure, unsupported), func(t *testing.T) {
				proxy, seen, joined, _ := upgradeProxyFixture(t, secure, true, "")
				client, sockets, dials := proxyFixtureClient(t, proxy, nil, unsupported)
				settings := defaultDownloadSettings
				settings.connect = 80 * time.Millisecond
				settings.total = 900 * time.Millisecond
				dir, exe := newExecutable(t, "warden", "old fixture")
				handshakes := new(atomic.Int32)
				ctx := httptrace.WithClientTrace(context.Background(), &httptrace.ClientTrace{TLSHandshakeDone: func(_ tls.ConnectionState, err error) {
					if err == nil {
						handshakes.Add(1)
					}
				}})
				start := time.Now()
				_, err := Upgrade(ctx, Client, Options{ReleaseBaseURL: "https://origin.invalid", HTTPClient: client, GOOS: "linux", GOARCH: "amd64", ExecutablePath: exe, settings: &settings})
				elapsed := time.Since(start)
				if err == nil {
					t.Error("silent CONNECT accepted")
				}
				requireProxyEvent(t, seen, "actual CONNECT reception")
				if secure && handshakes.Load() != 1 {
					t.Errorf("verified proxy TLS handshakes=%d, want 1 before stalled CONNECT", handshakes.Load())
				}
				if elapsed > 400*time.Millisecond {
					t.Errorf("CONNECT used operation budget instead of complete establishment bound: elapsed=%v phase=%v total=%v err=%v", elapsed, settings.connect, settings.total, err)
				}
				requireProxyEvent(t, joined, "proxy EOF/handler join")
				if dials.Load() != 1 {
					t.Fatalf("dials=%d", dials.Load())
				}
				socket := <-sockets
				requireProxyEvent(t, socket.closed, "owned raw TCP close")
				assertFileContent(t, exe, "old fixture")
				assertDirEntries(t, dir, "warden")
			})
		}
	}
}

func TestUpgradeProxyEstablishedStreamAndReuse(t *testing.T) {
	for _, secure := range []bool{false, true} {
		for _, http2 := range []bool{false, true} {
			t.Run(fmt.Sprintf("HTTPS=%t/HTTP2=%t", secure, http2), func(t *testing.T) {
				settings := defaultDownloadSettings
				settings.connect = 120 * time.Millisecond
				settings.total = 3 * time.Second
				var requests atomic.Int32
				origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					requests.Add(1)
					if r.TLS == nil || r.TLS.Version < tls.VersionTLS13 {
						t.Error("origin not verified TLS1.3")
					}
					if http2 && r.ProtoMajor != 2 {
						t.Errorf("origin protocol=%s, want actual HTTP/2", r.Proto)
					}
					if r.URL.Path == "/SHA256SUMS" {
						fmt.Fprintf(w, "%s  warden-linux-amd64\n", sha256Hex("binary"))
						return
					}
					w.WriteHeader(http.StatusOK)
					w.(http.Flusher).Flush()
					select {
					case <-r.Context().Done():
						return
					case <-time.After(3 * settings.connect):
					}
					io.WriteString(w, "binary")
				}))
				origin.EnableHTTP2 = http2
				origin.StartTLS()
				defer origin.Close()
				proxy, seen, joined, tunnels := upgradeProxyFixture(t, secure, false, origin.Listener.Addr().String())
				client, sockets, dials := proxyFixtureClient(t, proxy, origin, true)
				var reused, handshakes atomic.Int32
				ctx := httptrace.WithClientTrace(context.Background(), &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) {
					if info.Reused {
						reused.Add(1)
					}
				}, TLSHandshakeDone: func(_ tls.ConnectionState, err error) {
					if err == nil {
						handshakes.Add(1)
					}
				}})
				dir, exe := newExecutable(t, "warden", "old")
				var socket *observedProxyTCP
				replacements := 0
				_, err := Upgrade(ctx, Client, Options{ReleaseBaseURL: origin.URL, HTTPClient: client, GOOS: "linux", GOARCH: "amd64", ExecutablePath: exe, settings: &settings, Replace: func(path, target string, mode fs.FileMode) (bool, error) {
					replacements++
					socket = <-sockets
					select {
					case <-socket.closed:
						t.Error("establishment timer closed established/reused connection")
					default:
					}
					assertFileContent(t, path, "binary")
					return false, nil
				}})
				if err != nil {
					t.Fatal(err)
				}
				requireProxyEvent(t, seen, "CONNECT reception")
				requireProxyEvent(t, joined, "proxy relay join")
				if socket == nil {
					t.Fatal("no replacement")
				}
				requireProxyEvent(t, socket.closed, "normal raw TCP close")
				if replacements != 1 || dials.Load() != 1 || tunnels.Load() != 1 || requests.Load() != 2 || reused.Load() != 1 {
					t.Fatalf("replace=%d dials=%d tunnels=%d origin requests=%d reused=%d", replacements, dials.Load(), tunnels.Load(), requests.Load(), reused.Load())
				}
				wantTLS := int32(1)
				if secure {
					wantTLS = 2
				}
				if handshakes.Load() != wantTLS {
					t.Fatalf("handshakes=%d want=%d", handshakes.Load(), wantTLS)
				}
				assertFileContent(t, exe, "old")
				assertDirEntries(t, dir, "warden")
			})
		}
	}
}
