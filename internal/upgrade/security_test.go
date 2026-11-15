package upgrade

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

type unsafeRoundTripper struct{ calls *atomic.Int32 }

func (u unsafeRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	u.calls.Add(1)
	return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("binary")), Header: make(http.Header)}, nil
}

func TestUpgradeHTTPSRedirectAndTransportPolicy(t *testing.T) {
	const asset = "warden-linux-amd64"
	var targetHits atomic.Int32
	target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetHits.Add(1)
		if r.ProtoMajor != 2 {
			t.Errorf("owned standard HTTP/2 was not used: %s", r.Proto)
		}
		if r.URL.Path == "/SHA256SUMS" {
			io.WriteString(w, sha256Hex("binary")+"  ./"+asset+"\n")
		} else {
			io.WriteString(w, "binary")
		}
	}))
	target.EnableHTTP2 = true
	target.TLS = &tls.Config{NextProtos: []string{"h2", "http/1.1", "warden-unsafe"}}
	target.StartTLS()
	defer target.Close()
	var plainHits atomic.Int32
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { plainHits.Add(1); io.WriteString(w, "binary") }))
	defer plain.Close()
	for _, redirectStatus := range []int{301, 302, 303, 307, 308} {
		for _, tc := range []struct {
			name, redirect string
			allow          bool
		}{{"cross-host CDN", strings.Replace(target.URL, "127.0.0.1", "cdn.example.com", 1), true}, {"downgrade", plain.URL, false}, {"initial HTTP", "", false}} {
			t.Run(fmt.Sprintf("%d/%s", redirectStatus, tc.name), func(t *testing.T) {
				origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					http.Redirect(w, r, tc.redirect+r.URL.Path, redirectStatus)
				}))
				defer origin.Close()
				roots := x509.NewCertPool()
				roots.AddCert(origin.Certificate())
				roots.AddCert(target.Certificate())
				var callback atomic.Int32
				tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}, DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					if strings.HasPrefix(addr, "cdn.example.com:") {
						addr = strings.TrimPrefix(target.URL, "https://")
					}
					return (&net.Dialer{}).DialContext(ctx, network, addr)
				}}
				in := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { callback.Add(1); return nil }}
				dir, exe := newExecutable(t, "warden", "old")
				base := origin.URL
				if tc.name == "initial HTTP" {
					base = plain.URL
				}
				_, err := Upgrade(context.Background(), Client, Options{ReleaseBaseURL: base, HTTPClient: in, GOOS: "linux", GOARCH: "amd64", ExecutablePath: exe, Replace: func(p, e string, m fs.FileMode) (bool, error) { return false, nil }})
				if (err == nil) != tc.allow {
					t.Fatalf("err=%v allow=%v", err, tc.allow)
				}
				if callback.Load() != 0 {
					t.Fatal("inherited caller redirect callback")
				}
				if in.Transport != tr || tr.TLSClientConfig.RootCAs != roots || tr.TLSClientConfig.InsecureSkipVerify {
					t.Fatal("mutated injected client")
				}
				assertFileContent(t, exe, "old")
				assertDirEntries(t, dir, "warden")
			})
		}
	}
	if targetHits.Load() != 10 {
		t.Errorf("CDN requests=%d", targetHits.Load())
	}
	if plainHits.Load() != 0 {
		t.Errorf("unverified HTTP requests=%d", plainHits.Load())
	}
	t.Run("untrusted TLS", func(t *testing.T) {
		dir, exe := newExecutable(t, "warden", "old")
		_, err := Upgrade(context.Background(), Client, Options{ReleaseBaseURL: target.URL, HTTPClient: &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}, GOOS: "linux", GOARCH: "amd64", ExecutablePath: exe})
		if err == nil {
			t.Fatal("accepted untrusted certificate")
		}
		assertDirEntries(t, dir, "warden")
	})
	t.Run("hostname override cannot authenticate wrong origin", func(t *testing.T) {
		roots := x509.NewCertPool()
		roots.AddCert(target.Certificate())
		tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "example.com"}, DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, strings.TrimPrefix(target.URL, "https://"))
		}}
		before := targetHits.Load()
		dir, exe := newExecutable(t, "warden", "old")
		_, err := Upgrade(context.Background(), Client, Options{ReleaseBaseURL: strings.Replace(target.URL, "127.0.0.1", "wrong.invalid", 1), HTTPClient: &http.Client{Transport: tr}, GOOS: "linux", GOARCH: "amd64", ExecutablePath: exe})
		if err == nil {
			t.Fatal("authenticated wrong request hostname using injected ServerName")
		}
		if targetHits.Load() != before {
			t.Fatal("wrong-host TLS reached HTTP handler")
		}
		if tr.TLSClientConfig.ServerName != "example.com" {
			t.Fatal("mutated caller override")
		}
		assertDirEntries(t, dir, "warden")
	})
	for _, hook := range []string{"DialTLSContext", "DialTLS", "ServerName", "ALPN h2", "ALPN custom", "registered HTTPS", "unknown"} {
		t.Run(hook, func(t *testing.T) {
			var calls atomic.Int32
			roots := x509.NewCertPool()
			roots.AddCert(target.Certificate())
			tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, InsecureSkipVerify: true}}
			// The public HTTP peer must never receive bytes via a caller-supplied TLS dialer.
			dial := func() (net.Conn, error) {
				calls.Add(1)
				return net.Dial("tcp", strings.TrimPrefix(plain.URL, "http://"))
			}
			switch hook {
			case "DialTLSContext":
				tr.DialTLSContext = func(context.Context, string, string) (net.Conn, error) { return dial() }
			case "DialTLS":
				tr.DialTLS = func(string, string) (net.Conn, error) { return dial() }
			case "ServerName":
				tr.TLSClientConfig.ServerName = "wrong.invalid"
			case "ALPN h2", "ALPN custom":
				proto := "h2"
				if hook == "ALPN custom" {
					proto = "warden-unsafe"
				}
				tr.TLSClientConfig.NextProtos = []string{proto}
				tr.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{proto: func(string, *tls.Conn) http.RoundTripper { return unsafeRoundTripper{&calls} }}
			case "registered HTTPS":
				tr.RegisterProtocol("https", unsafeRoundTripper{&calls})
			}
			in := &http.Client{Transport: tr}
			if hook == "unknown" {
				in.Transport = unsafeRoundTripper{&calls}
			}
			dir, exe := newExecutable(t, "warden", "old")
			var replaces int
			_, err := Upgrade(context.Background(), Client, Options{ReleaseBaseURL: target.URL, HTTPClient: in, GOOS: "linux", GOARCH: "amd64", ExecutablePath: exe, Replace: func(p, e string, m fs.FileMode) (bool, error) { replaces++; return false, nil }})
			if hook == "unknown" {
				if err == nil {
					t.Fatal("accepted unknown transport")
				}
			} else if err != nil {
				t.Error(err)
			}
			if calls.Load() != 0 {
				t.Fatalf("unsafe delegate invoked %d times", calls.Load())
			}
			if !tr.TLSClientConfig.InsecureSkipVerify || tr.TLSClientConfig.RootCAs != roots {
				t.Fatal("mutated caller TLS configuration")
			}
			if hook == "ServerName" && tr.TLSClientConfig.ServerName != "wrong.invalid" {
				t.Fatal("mutated caller hostname override")
			}
			if hook != "unknown" && replaces != 1 {
				t.Fatalf("replaces=%d", replaces)
			}
			assertDirEntries(t, dir, "warden")
		})
	}
}

func TestUpgradeChecksumExactEntry(t *testing.T) {
	const asset = "warden-linux-amd64"
	good := sha256Hex("binary")
	for name, entry := range map[string]string{"valid": good + "  ./" + asset + "\n", "star": good + " *" + asset + "\n", "duplicate": good + "  " + asset + "\n" + good + "  ./" + asset + "\n", "path ambiguity": good + "  dir/" + asset + "\n", "substring": good + "  " + asset + ".sig\n", "wrong algorithm": strings.Repeat("a", 128) + "  " + asset + "\n", "invalid hex": strings.Repeat("z", 64) + "  " + asset + "\n", "truncated": good[:63] + "  " + asset + "\n", "extra field": good + "  " + asset + " extra\n"} {
		t.Run(name, func(t *testing.T) {
			srv, _ := releaseServer(t, map[string]string{"/SHA256SUMS": entry})
			got, err := fetchChecksum(context.Background(), srv.Client(), srv.URL+"/SHA256SUMS", asset)
			valid := name == "valid" || name == "star"
			if valid && (err != nil || got != good) {
				t.Fatalf("%q %v", got, err)
			}
			if !valid && err == nil {
				t.Fatalf("accepted %q", entry)
			}
		})
	}
}

func TestUpgradeRejectsSymlinkExecutable(t *testing.T) {
	if os.PathSeparator == '\\' {
		t.Skip("native symlink privilege required")
	}
	dir, exe := newExecutable(t, "warden", "old")
	link := filepath.Join(dir, "alias")
	if err := os.Symlink(exe, link); err != nil {
		t.Fatal(err)
	}
	srv, _ := releaseServer(t, map[string]string{"/warden-linux-amd64": "binary", "/SHA256SUMS": sha256Hex("binary") + "  warden-linux-amd64\n"})
	_, err := Upgrade(context.Background(), Client, Options{ReleaseBaseURL: srv.URL, HTTPClient: srv.Client(), GOOS: "linux", GOARCH: "amd64", ExecutablePath: link})
	if err == nil {
		t.Fatal("replaced symlink executable")
	}
	assertFileContent(t, exe, "old")
	info, e := os.Lstat(link)
	if e != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatal("changed alias")
	}
}
