package runtime

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	goruntime "runtime"
	"testing"
	"time"

	"warden/internal/config"
	"warden/internal/crypto"
	"warden/internal/store"
	"warden/internal/web"
)

func TestRuntimeSubprocessHelper(t *testing.T) {
	configPath := os.Getenv("WARDEN_T2_TEST_CONFIG")
	if configPath == "" {
		return
	}
	raw, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	var o Options
	if err = json.Unmarshal(raw, &o); err != nil {
		t.Fatal(err)
	}
	o.Assets = web.Distribution()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	if err = Run(ctx, o); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
func testCertificate(t *testing.T, dir string) (tls.Certificate, *x509.CertPool, string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "warden.example"}, DNSNames: []string{"warden.example"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	pk, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPath, keyPath := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	if err = os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk}), 0600); err != nil {
		t.Fatal(err)
	}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	parsed, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(parsed)
	return cert, pool, certPath, keyPath
}
func TestHTTPSRuntimeSubprocessRestartAuthentication(t *testing.T) {
	if goruntime.GOOS == "windows" {
		t.Skip("requires native Windows lifecycle validation separately; POSIX interrupt harness")
	}
	for _, mode := range []string{"tls", "proxy"} {
		t.Run(mode, func(t *testing.T) {
			p, _, install, dek, signer := runtimeFixture(t)
			raw, err := p.store.Installation(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			dbPath := filepath.Join(dir, "runtime.db")
			if err = store.CommitInstallation(context.Background(), dbPath, raw); err != nil {
				t.Fatal(err)
			}
			cert, pool, certPath, keyPath := testCertificate(t, dir)
			reserved, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			backend := reserved.Addr().String()
			reserved.Close()
			cfg := config.Setup{PublicOrigin: install.PublicOrigin, RPID: install.RPID, Mode: mode, TLSCertificate: certPath, TLSKey: keyPath}
			endpoint := backend
			if mode == "proxy" {
				cfg.TLSCertificate = ""
				cfg.TLSKey = ""
				cfg.BackendAuthority = backend
				target, _ := url.Parse("http://" + backend)
				proxy := httputil.NewSingleHostReverseProxy(target)
				// This disposable proxy enforces the configured public Host and strips
				// untrusted forwarding headers before the same-host loopback backend hop.
				handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Host != "warden.example" {
						http.Error(w, "forbidden", 403)
						return
					}
					r.Header.Del("Forwarded")
					r.Header.Del("X-Forwarded-Host")
					r.Header.Del("X-Forwarded-Proto")
					r.Header.Del("X-Forwarded-For")
					proxy.ServeHTTP(w, r)
				})
				l, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				endpoint = l.Addr().String()
				srv := &http.Server{Handler: handler, ReadHeaderTimeout: time.Second}
				go srv.Serve(tls.NewListener(l, &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}}))
				defer srv.Close()
			}
			configPath := filepath.Join(dir, "runtime.json")
			encoded, _ := json.Marshal(Options{Config: cfg, Bind: backend, DBPath: dbPath})
			os.WriteFile(configPath, encoded, 0600)
			var process *exec.Cmd
			var output bytes.Buffer
			start := func() {
				t.Helper()
				output.Reset()
				process = exec.Command(os.Args[0], "-test.run=^TestRuntimeSubprocessHelper$", "-test.count=1")
				process.Env = append(os.Environ(), "WARDEN_T2_TEST_CONFIG="+configPath)
				process.Stdout = &output
				process.Stderr = &output
				if err := process.Start(); err != nil {
					t.Fatal(err)
				}
			}
			stop := func() {
				t.Helper()
				if process == nil {
					return
				}
				process.Process.Signal(os.Interrupt)
				done := make(chan error, 1)
				go func() { done <- process.Wait() }()
				select {
				case err := <-done:
					if err != nil {
						t.Fatalf("subprocess: %v %s", err, &output)
					}
				case <-time.After(5 * time.Second):
					process.Process.Kill()
					<-done
					t.Fatal("subprocess failed to stop")
				}
				process = nil
			}
			defer func() {
				if process != nil {
					process.Process.Kill()
					process.Wait()
				}
			}()
			jar, _ := cookiejar.New(nil)
			transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}, DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, network, endpoint)
			}}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Jar: jar, Timeout: 3 * time.Second}
			csrf := ""
			request := func(method, path string, value any, status int) []byte {
				t.Helper()
				var b []byte
				if value != nil {
					b, _ = json.Marshal(value)
				}
				r, _ := http.NewRequest(method, install.PublicOrigin+path, bytes.NewReader(b))
				r.Header.Set("Origin", install.PublicOrigin)
				r.Header.Set("Content-Type", "application/json")
				r.Header.Set("X-CSRF-Token", csrf)
				response, err := client.Do(r)
				if err != nil {
					t.Fatal(err)
				}
				defer response.Body.Close()
				body, err := io.ReadAll(response.Body)
				if err != nil {
					t.Fatal(err)
				}
				if response.StatusCode != status || response.Header.Get("Cache-Control") != "no-store" {
					t.Fatalf("%s %s: %d want %d %s", method, path, response.StatusCode, status, body)
				}
				if response.TLS == nil || response.TLS.Version < tls.VersionTLS13 {
					t.Fatal("TLS boundary missing")
				}
				return body
			}
			ready := func() {
				t.Helper()
				deadline := time.Now().Add(5 * time.Second)
				for time.Now().Before(deadline) {
					r, err := client.Get(install.PublicOrigin + "/api/v1/auth/status")
					if err == nil {
						r.Body.Close()
						if r.StatusCode == 401 || r.StatusCode == 200 {
							return
						}
					}
					time.Sleep(20 * time.Millisecond)
				}
				t.Fatal("runtime not ready")
			}
			login := func() {
				t.Helper()
				body := request("POST", "/api/v1/auth/login/begin", struct{}{}, 200)
				var begin struct {
					ID      string `json:"id"`
					Options struct {
						PublicKey struct {
							Challenge string `json:"challenge"`
						} `json:"publicKey"`
					} `json:"options"`
				}
				json.Unmarshal(body, &begin)
				signed := fixtureAssertion(t, signer, install.Owner.Credentials[0].ID, install.Owner.ID, begin.Options.PublicKey.Challenge, install.PublicOrigin, install.RPID, true)
				body = request("POST", "/api/v1/auth/login/finish", map[string]any{"id": begin.ID, "credential": json.RawMessage(signed)}, 200)
				var state struct {
					CSRF     string `json:"csrf"`
					Unlocked bool   `json:"unlocked"`
				}
				json.Unmarshal(body, &state)
				csrf = state.CSRF
				u, _ := url.Parse(install.PublicOrigin)
				for _, c := range jar.Cookies(u) {
					if c.Name == sessionCookie && bytes.Contains(raw, []byte(c.Value)) {
						t.Fatal("plaintext session persisted")
					}
				}
			}
			unlock := func() {
				t.Helper()
				body := request("POST", "/api/v1/auth/fresh/begin", map[string]string{"action": "unlock", "credential_id": install.Passkey.CredentialID}, 200)
				var begin struct {
					ID      string `json:"id"`
					Options struct {
						PublicKey struct {
							Challenge string `json:"challenge"`
						} `json:"publicKey"`
					} `json:"options"`
				}
				json.Unmarshal(body, &begin)
				signed := fixtureAssertion(t, signer, install.Owner.Credentials[0].ID, install.Owner.ID, begin.Options.PublicKey.Challenge, install.PublicOrigin, install.RPID, true)
				body = request("POST", "/api/v1/auth/fresh/finish", map[string]any{"id": begin.ID, "credential": json.RawMessage(signed)}, 200)
				var grant struct {
					Grant string `json:"grant"`
				}
				json.Unmarshal(body, &grant)
				request("POST", "/api/v1/auth/unlock", map[string]string{"grant": grant.Grant, "dek": crypto.Encode(dek)}, 200)
			}
			start()
			ready()
			if mode == "tls" {
				conn, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", endpoint, &tls.Config{RootCAs: pool, ServerName: "warden.example", MinVersion: tls.VersionTLS13})
				if err != nil {
					t.Fatal(err)
				}
				conn.SetDeadline(time.Now().Add(time.Second))
				io.WriteString(conn, "OPTIONS * HTTP/1.1\r\nHost: attacker.example\r\nConnection: close\r\n\r\n")
				response, err := http.ReadResponse(bufio.NewReader(conn), nil)
				if err != nil {
					conn.Close()
					t.Fatal(err)
				}
				response.Body.Close()
				conn.Close()
				if response.StatusCode != 403 || response.Header.Get("Cache-Control") != "no-store" {
					t.Fatal("OPTIONS star bypassed outer Host gate", response.StatusCode)
				}
			}
			request("GET", "/api/v1/ssh-connections", nil, 401)
			login()
			request("GET", "/api/v1/ssh-connections", nil, 423)
			unlock()
			request("POST", "/api/v1/ssh-connections", map[string]any{"name": "synthetic", "host": "127.0.0.1", "port": 22, "username": "test", "password": "synthetic-secret", "jump_connection_ids": "[]"}, 201)
			var profile struct {
				HasPassword bool `json:"has_password"`
			}
			if err := json.Unmarshal(request("GET", "/api/v1/ssh-connections/1", nil, 200), &profile); err != nil || !profile.HasPassword {
				t.Fatal("encrypted profile getter did not work", err)
			}
			request("GET", "/api/v1/transport/ssh/1", nil, 403)
			stop()
			transport.CloseIdleConnections()
			start()
			ready()
			// Browser cookie survives SERVER restart, but key availability never does.
			status := request("GET", "/api/v1/auth/status", nil, 200)
			if !bytes.Contains(status, []byte(`"unlocked":false`)) {
				t.Fatal("restart restored key", string(status))
			}
			request("GET", "/api/v1/transport/ssh/1", nil, 423)
			unlock()
			request("GET", "/api/v1/ssh-connections/1", nil, 200)
			request("POST", "/api/v1/auth/logout", struct{}{}, 200)
			request("GET", "/api/v1/ssh-connections", nil, 401)
			login()
			request("GET", "/api/v1/ssh-connections", nil, 200)
			request("POST", "/api/v1/auth/lock", struct{}{}, 200)
			request("GET", "/api/v1/ssh-connections", nil, 423)
			stop()
		})
	}
}
