package agent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"warden/internal/client/clienthttp"
)

func TestAPIRedirectPolicyBeforeCredentialSend(t *testing.T) {
	const secret = "synthetic-bearer-only-origin"
	const payload = `{"summary":"synthetic-private-post-body"}`
	for _, status := range []int{301, 302, 303, 307, 308} {
		for _, method := range []string{"GET", "POST"} {
			for _, relation := range []string{"host", "port", "subdomain", "downgrade", "same-origin"} {
				for _, injected := range []bool{false, true} {
					t.Run(strconv.Itoa(status)+"/"+method+"/"+relation+"/injected="+strconv.FormatBool(injected), func(t *testing.T) {
						var sinkRequests, sinkAuthBytes, sinkBodyBytes, originRequests, redirected atomic.Int32
						sinkHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
							sinkRequests.Add(1)
							sinkAuthBytes.Add(int32(len(r.Header.Get("Authorization"))))
							body, _ := io.ReadAll(r.Body)
							sinkBodyBytes.Add(int32(len(body)))
							w.Write([]byte(`[]`))
						})
						sink := httptest.NewTLSServer(sinkHandler)
						defer sink.Close()
						plain := httptest.NewServer(sinkHandler)
						defer plain.Close()
						var location string
						origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
							if r.URL.Path == "/redirected" {
								redirected.Add(1)
								sinkHandler.ServeHTTP(w, r)
								return
							}
							originRequests.Add(1)
							if r.TLS == nil || r.TLS.ServerName != "example.com" || r.Header.Get("Authorization") != "Bearer "+secret {
								t.Error("origin did not receive verified bearer request")
							}
							body, _ := io.ReadAll(r.Body)
							if method == "POST" && string(body) != payload {
								t.Error("origin did not receive actual POST payload")
							}
							if method == "GET" && len(body) != 0 {
								t.Error("unexpected GET payload")
							}
							http.Redirect(w, r, location, status)
						}))
						defer origin.Close()
						port := strings.TrimPrefix(origin.URL, "https://127.0.0.1:")
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
						ca := filepath.Join(t.TempDir(), "ca.pem")
						if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: origin.Certificate().Raw}), 0600); err != nil {
							t.Fatal(err)
						}
						dial := func(ctx context.Context, network, address string) (net.Conn, error) {
							_, p, e := net.SplitHostPort(address)
							if e != nil {
								return nil, e
							}
							return (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort("127.0.0.1", p))
						}
						var callback atomic.Int32
						inputTransport := &http.Transport{DialContext: dial, TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}}
						input := &http.Client{Transport: inputTransport, Timeout: 7 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { callback.Add(1); return nil }}
						// Positive target reachability without any credential/body rules out a
						// false negative caused by DNS, routing, or untrusted target TLS.
						probe, probeErr := input.Get(location)
						if probeErr != nil {
							t.Fatalf("target unreachable: %v", probeErr)
						}
						probe.Body.Close()
						if probe.StatusCode != 200 {
							t.Fatalf("target status=%d", probe.StatusCode)
						}
						sinkRequests.Store(0)
						sinkAuthBytes.Store(0)
						sinkBodyBytes.Store(0)
						redirected.Store(0)
						callbackPointer := reflect.ValueOf(input.CheckRedirect).Pointer()
						originalTLS := inputTransport.TLSClientConfig
						var hc *http.Client
						if injected {
							hc = clienthttp.Client(input, 3*time.Second)
						} else {
							var err error
							hc, err = apiHTTPClient(ca, 3*time.Second)
							if err != nil {
								t.Fatal(err)
							}
							// Only route ordinary TCP; TLS still verifies example.com using roots.
							tr := hc.Transport.(*http.Transport)
							tr.Proxy = nil
							tr.DialContext = dial
						}
						defer hc.CloseIdleConnections()
						initialTimeout := hc.Timeout
						path := "/api/v1/client/ssh-connections"
						var body []byte
						if method == "POST" {
							path = "/api/v1/client/reports"
							body = []byte(payload)
						}
						if !clienthttp.Allowed(method, path) {
							t.Fatal("fixture bypassed capability policy")
						}
						result, err := agentHTTP(context.Background(), hc, originURL, method, path, body, secret, time.Second)
						if err != nil || result.Status != status || originRequests.Load() != 1 {
							t.Fatalf("verified origin redirect not reached: status=%d error=%v count=%d", result.Status, err, originRequests.Load())
						}
						if sinkRequests.Load() != 0 || sinkAuthBytes.Load() != 0 || sinkBodyBytes.Load() != 0 || redirected.Load() != 0 {
							t.Fatalf("redirect leaked: requests=%d authbytes=%d bodybytes=%d sameorigin=%d", sinkRequests.Load(), sinkAuthBytes.Load(), sinkBodyBytes.Load(), redirected.Load())
						}
						if hc.Timeout != initialTimeout || input.Timeout != 7*time.Second || input.Transport != inputTransport || input.CheckRedirect == nil || reflect.ValueOf(input.CheckRedirect).Pointer() != callbackPointer || callback.Load() != 0 || inputTransport.TLSClientConfig != originalTLS || inputTransport.TLSClientConfig.RootCAs != roots || inputTransport.TLSClientConfig.InsecureSkipVerify || inputTransport.TLSClientConfig.ServerName != "" || inputTransport.TLSClientConfig.MinVersion != tls.VersionTLS13 {
							t.Fatal("shared caller configuration mutated")
						}
					})
				}
			}
		}
	}
}
