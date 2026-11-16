package runtime

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	goruntime "runtime"
	"strings"
	"testing"
	"time"

	"warden/internal/model"
	"warden/internal/server"
)

// Both paths use the production server factory. The proxy variant exercises the
// configured plaintext literal-loopback hop, with verified HTTPS in front when
// using client(). No h2 ALPN or insecure certificate bypass is introduced.
func boundaryListener(t *testing.T, p *Plane, mode string, short bool) (func() net.Conn, *http.Client) {
	t.Helper()
	cert, roots, _, _ := testCertificate(t, t.TempDir())
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	p.cfg.Mode = mode
	p.cfg.BackendAuthority = addr
	srv := server.NewHTTPServer(server.New("", p).Handler())
	if short {
		srv.ReadHeaderTimeout = 180 * time.Millisecond
		srv.ReadTimeout = 250 * time.Millisecond
		srv.WriteTimeout = 250 * time.Millisecond
		srv.IdleTimeout = 180 * time.Millisecond
	}
	listener := l
	if mode == "tls" {
		listener = server.TLSListener(l, cert)
	}
	done := make(chan error, 1)
	go func() { done <- srv.Serve(listener) }()
	t.Cleanup(func() { srv.Close(); <-done })
	dial := func() net.Conn {
		t.Helper()
		c, e := net.DialTimeout("tcp", addr, time.Second)
		if e != nil {
			t.Fatal(e)
		}
		if tcp, ok := c.(*net.TCPConn); ok {
			tcp.SetReadBuffer(4096)
		}
		if mode == "tls" {
			secure := tls.Client(c, &tls.Config{RootCAs: roots, ServerName: "warden.example", MinVersion: tls.VersionTLS13})
			if e := secure.Handshake(); e != nil {
				c.Close()
				t.Fatal(e)
			}
			c = secure
		}
		c.SetDeadline(time.Now().Add(3 * time.Second))
		return c
	}
	endpoint := addr
	if mode == "proxy" {
		target, _ := url.Parse("http://" + addr)
		proxy := httputil.NewSingleHostReverseProxy(target)
		front, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		endpoint = front.Addr().String()
		frontServer := server.NewHTTPServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Host != "warden.example" {
				w.Header().Set("Cache-Control", "no-store")
				http.Error(w, "forbidden", 403)
				return
			}
			for _, h := range []string{"Forwarded", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Forwarded-For"} {
				r.Header.Del(h)
			}
			proxy.ServeHTTP(w, r)
		}))
		frontDone := make(chan error, 1)
		go func() {
			frontDone <- frontServer.Serve(server.TLSListener(front, cert))
		}()
		t.Cleanup(func() { frontServer.Close(); <-frontDone })
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}, DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, network, endpoint)
	}}
	t.Cleanup(transport.CloseIdleConnections)
	return dial, &http.Client{Transport: transport, Timeout: 120 * time.Second}
}

func TestSlowHeadersBodiesAndIdleConnectionsTerminate(t *testing.T) {
	for _, mode := range []string{"tls", "proxy"} {
		t.Run(mode, func(t *testing.T) {
			p, _, _, key, signer := runtimeFixture(t)
			browser, csrf := sessionFor(t, p)
			p.vault.Unlock(key, p.vault.Generation())
			mountProfiles(p)
			dial, _ := boundaryListener(t, p, mode, true)
			t.Run("headers", func(t *testing.T) {
				c := dial()
				defer c.Close()
				io.WriteString(c, "GET /api/v1/auth/status HTTP/1.1\r\nHost:")
				start := time.Now()
				_, err := io.ReadAll(c)
				if e, ok := err.(net.Error); ok && e.Timeout() {
					t.Fatal("header connection retained until client timeout")
				}
				if time.Since(start) > time.Second {
					t.Fatal("slow header not bounded")
				}
			})
			t.Run("idle", func(t *testing.T) {
				c := dial()
				defer c.Close()
				fmt.Fprintf(c, "GET /api/v1/auth/status HTTP/1.1\r\nHost: warden.example\r\nCookie: %s=%s\r\n\r\n", browser.Name, browser.Value)
				reader := bufio.NewReader(c)
				res, err := http.ReadResponse(reader, nil)
				if err != nil {
					t.Fatal(err)
				}
				io.Copy(io.Discard, res.Body)
				res.Body.Close()
				if res.StatusCode != 200 {
					t.Fatal(res.StatusCode)
				}
				start := time.Now()
				_, err = reader.ReadByte()
				if err == nil {
					t.Fatal("idle socket still producing data")
				}
				if time.Since(start) > time.Second {
					t.Fatal("idle not bounded")
				}
			})
			for _, cancelUpload := range []bool{false, true} {
				t.Run(fmt.Sprintf("body-cancel=%v", cancelUpload), func(t *testing.T) {
					g := requestGrant(t, p, signer, browser, csrf, "import", "POST", "/api/v1/data/import", "{}")
					c := dial()
					defer c.Close()
					fmt.Fprintf(c, "POST /api/v1/data/import HTTP/1.1\r\nHost: warden.example\r\nOrigin: https://warden.example\r\nContent-Type: application/json\r\nCookie: %s=%s\r\nX-CSRF-Token: %s\r\nX-Warden-Action: %s\r\nContent-Length: 2\r\n\r\n{", browser.Name, browser.Value, csrf, g)
					if cancelUpload {
						until := time.Now().Add(time.Second)
						for len(p.transfers) == 0 && time.Now().Before(until) {
							time.Sleep(time.Millisecond)
						}
						if len(p.transfers) == 0 {
							t.Fatal("upload did not acquire transfer slot")
						}
						c.Close()
					} else {
						start := time.Now()
						_, err := io.ReadAll(c)
						if e, ok := err.(net.Error); ok && e.Timeout() {
							t.Fatal("body retained until client timeout")
						}
						if time.Since(start) > time.Second {
							t.Fatal("body not bounded")
						}
					}
					waitForTransferDrain(t, p)
					// A subsequent ordinary request on another socket plus lock must finish;
					// the incomplete request cannot retain a vault lease or transfer slot.
					done := make(chan struct{})
					go func() { p.vault.Lock(); close(done) }()
					select {
					case <-done:
					case <-time.After(time.Second):
						t.Fatal("upload retained vault lease")
					}
					if err := p.vault.Unlock(key, p.vault.Generation()); err != nil {
						t.Fatal(err)
					}
					if groups, err := p.store.ListGroups(context.Background()); err != nil || len(groups) != 0 {
						t.Fatal("incomplete upload mutated data", err)
					}
				})
			}
			t.Run("duplicate-malformed-authority", func(t *testing.T) {
				for _, headers := range []string{"Host: warden.example\r\nHost: attacker.example", "Host: warden.example@attacker.example", "Host: warden.example:444"} {
					c := dial()
					fmt.Fprintf(c, "GET /api/v1/auth/status HTTP/1.1\r\n%s\r\nConnection: close\r\n\r\n", headers)
					res, err := http.ReadResponse(bufio.NewReader(c), nil)
					if err != nil {
						c.Close()
						t.Fatal(err)
					}
					io.Copy(io.Discard, res.Body)
					res.Body.Close()
					c.Close()
					if res.StatusCode != 400 && res.StatusCode != 403 {
						t.Fatal("ambiguous Host accepted", res.StatusCode)
					}
				}
			})
		})
	}
}

func TestStalledWritesReleaseResponseLeaseAndExpensiveSlot(t *testing.T) {
	for _, mode := range []string{"tls", "proxy"} {
		t.Run(mode, func(t *testing.T) {
			p, _, _, key, signer := runtimeFixture(t)
			browser, csrf := sessionFor(t, p)
			p.vault.Unlock(key, p.vault.Generation())
			entered := make(chan struct{})
			returned := make(chan struct{})
			p.managed = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				close(entered)
				w.Write(bytes.Repeat([]byte("s"), 16<<20))
			})
			dial, _ := boundaryListener(t, p, mode, true)
			// Observe slot release BEFORE invoking lock, so cancellation by Lock
			// cannot hide a missing write timeout.
			g := requestGrant(t, p, signer, browser, csrf, "export", "GET", "/api/v1/data/export", "")
			c := dial()
			defer c.Close()
			fmt.Fprintf(c, "GET /api/v1/data/export HTTP/1.1\r\nHost: warden.example\r\nCookie: %s=%s\r\nX-Warden-Action: %s\r\n\r\n", browser.Name, browser.Value, g)
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("export did not enter")
			}
			// Do not read any response bytes: a 16MiB response exceeds socket buffers.
			waitForTransferDrain(t, p)
			if !p.vault.Unlocked() {
				t.Fatal("write timeout globally locked vault")
			}
			go func() { p.vault.Lock(); close(returned) }()
			select {
			case <-returned:
			case <-time.After(time.Second):
				t.Fatal("stalled write retained lease")
			}
			if len(p.transfers) != 0 {
				t.Fatal("stalled write retained transfer slot")
			}
		})
	}
}

func TestFullSizeImportWithinDeadline(t *testing.T) {
	if testing.Short() {
		t.Skip("bounded 50MiB socket/import acceptance")
	}
	for _, mode := range []string{"tls", "proxy"} {
		t.Run(mode, func(t *testing.T) {
			p, _, _, key, signer := runtimeFixture(t)
			browser, csrf := sessionFor(t, p)
			p.vault.Unlock(key, p.vault.Generation())
			mountProfiles(p)
			_, client := boundaryListener(t, p, mode, false)
			stamp := time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC)
			bundle := model.DataBundle{Format: "warden-data", Version: 1, ExportedAt: stamp, Groups: []model.TransferGroup{}, KeyPairs: []model.TransferKeyPair{}, SSHConnections: []model.TransferSSHConnection{}, DBConnections: []model.TransferDBConnection{}, Projects: []model.TransferProject{}, Reports: []model.TransferReport{}, ConnectionNotes: []model.TransferConnectionNote{}}
			// Thousands of real profiles/notes, encrypted password fields and references,
			// not one tiny record padded by 50MiB of whitespace.
			for n := 1; n <= 4096; n++ {
				bundle.SSHConnections = append(bundle.SSHConnections, model.TransferSSHConnection{ID: int64(n), Name: fmt.Sprintf("synthetic-%d", n), Host: "host.example", Port: 22, Username: "fixture", Password: "synthetic-password", JumpConnectionIDs: "[]", CreatedAt: stamp, UpdatedAt: stamp})
				bundle.ConnectionNotes = append(bundle.ConnectionNotes, model.TransferConnectionNote{ConnectionType: "ssh", ConnectionID: int64(n), Note: strings.Repeat("n", 12350)})
			}
			raw, err := json.Marshal(bundle)
			if err != nil {
				t.Fatal(err)
			}
			bundle = model.DataBundle{}
			if len(raw) < 49<<20 || len(raw) > 50<<20 {
				t.Fatalf("representative body size=%d", len(raw))
			}
			send := func(body []byte, status int, pace bool) {
				t.Helper()
				g := requestGrant(t, p, signer, browser, csrf, "import", "POST", "/api/v1/data/import", string(body))
				var reader io.Reader = bytes.NewReader(body)
				if pace {
					reader = &pacedImport{source: bytes.NewReader(body), start: time.Now(), rate: 16 << 20}
				}
				r, _ := http.NewRequest("POST", "https://warden.example/api/v1/data/import", reader)
				r.ContentLength = int64(len(body))
				r.AddCookie(browser)
				r.Header.Set("Origin", p.cfg.PublicOrigin)
				r.Header.Set("Content-Type", "application/json")
				r.Header.Set("X-CSRF-Token", csrf)
				r.Header.Set("X-Warden-Action", g)
				res, err := client.Do(r)
				if err != nil {
					t.Fatal(err)
				}
				defer res.Body.Close()
				b, _ := io.ReadAll(res.Body)
				if res.StatusCode != status || res.Header.Get("Cache-Control") != "no-store" {
					t.Fatal(res.StatusCode, string(b))
				}
			}
			oversized := make([]byte, (50<<20)+1)
			copy(oversized, raw)
			for n := len(raw); n < len(oversized); n++ {
				oversized[n] = ' '
			}
			send(oversized, 400, false)
			oversized = nil
			send(append(append([]byte(nil), raw...), []byte(" {}")...), 400, false)
			if rows, err := p.store.ListSSH(context.Background()); err != nil || len(rows) != 0 {
				t.Fatal("rejected import changed data", err)
			}
			goruntime.GC()
			var before, after goruntime.MemStats
			goruntime.ReadMemStats(&before)
			start := time.Now()
			send(raw, 204, true)
			elapsed := time.Since(start)
			goruntime.ReadMemStats(&after)
			t.Logf("mode=%s bytes=%d profiles=4096 link=16MiB/s elapsed=%s total_alloc_delta=%d heap_sys=%d", mode, len(raw), elapsed, after.TotalAlloc-before.TotalAlloc, after.HeapSys)
			if elapsed >= 120*time.Second || after.TotalAlloc-before.TotalAlloc > 2<<30 {
				t.Fatal("bounded full-size acceptance stopping condition exceeded")
			}
			row, err := p.store.GetSSH(context.Background(), 4096)
			if err != nil || string(row.Password) != "synthetic-password" {
				t.Fatal("encrypted import incomplete", err)
			}
			g := requestGrant(t, p, signer, browser, csrf, "export", "GET", "/api/v1/data/export", "")
			r, _ := http.NewRequest("GET", "https://warden.example/api/v1/data/export", nil)
			r.AddCookie(browser)
			r.Header.Set("X-Warden-Action", g)
			res, err := client.Do(r)
			if err != nil {
				t.Fatal(err)
			}
			n, err := io.Copy(io.Discard, res.Body)
			res.Body.Close()
			if err != nil || res.StatusCode != 200 || n < 49<<20 || res.Header.Get("Cache-Control") != "no-store" {
				t.Fatal("large export capped or failed", n, err, res.StatusCode)
			}
		})
	}
}

type pacedImport struct {
	source *bytes.Reader
	start  time.Time
	rate   int64
	sent   int64
}

func (p *pacedImport) Read(b []byte) (int, error) {
	if len(b) > 64<<10 {
		b = b[:64<<10]
	}
	n, err := p.source.Read(b)
	p.sent += int64(n)
	if wait := time.Until(p.start.Add(time.Duration(float64(p.sent) / float64(p.rate) * float64(time.Second)))); wait > 0 {
		time.Sleep(wait)
	}
	return n, err
}

// A slot is held through handler, checked write/flush and joined cancellation.
// Observing it drain while unlocked cannot be satisfied by a later Lock call.
func waitForTransferDrain(t *testing.T, p *Plane) {
	t.Helper()
	deadline := time.Now().Add(1500 * time.Millisecond)
	for len(p.transfers) != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(p.transfers) != 0 {
		t.Fatal("network timeout/disconnect retained transfer slot")
	}
}
