package upgrade

import (
	"context"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestDownloadClientRejectsNilTCPConnection(t *testing.T) {
	client, err := downloadClient(&http.Client{Transport: &http.Transport{DialContext: func(context.Context, string, string) (net.Conn, error) { return nil, nil }}}, defaultDownloadSettings)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := client.Transport.(*establishmentTransport).DialContext(context.Background(), "tcp", "fixture.invalid:443")
	if guard, ok := conn.(*establishmentConn); ok {
		guard.stopEstablishment()
	}
	if conn != nil || err == nil {
		t.Fatalf("nil TCP result must remain a dial error, not a nonnil wrapper: conn=%T err=%v", conn, err)
	}
}

func TestUpgradeConnectAndTLSHandshakeBudgets(t *testing.T) {
	for _, phase := range []string{"TCP context", "TLS handshake"} {
		t.Run(phase, func(t *testing.T) {
			settings := defaultDownloadSettings
			settings.connect = 40 * time.Millisecond
			settings.total = time.Second
			tr := &http.Transport{}
			base := "https://example.com"
			if phase == "TCP context" {
				tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) { <-ctx.Done(); return nil, ctx.Err() }
			} else {
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				base = "https://" + listener.Addr().String()
				done := make(chan struct{})
				stop := make(chan struct{})
				go func() {
					defer close(done)
					conn, err := listener.Accept()
					if err != nil {
						return
					}
					defer conn.Close()
					<-stop
				}()
				defer func() { close(stop); listener.Close(); <-done }()
			}
			dir, exe := newExecutable(t, "warden", "old")
			start := time.Now()
			_, err := Upgrade(context.Background(), Client, Options{ReleaseBaseURL: base, HTTPClient: &http.Client{Transport: tr}, GOOS: "linux", GOARCH: "amd64", ExecutablePath: exe, settings: &settings})
			if err == nil {
				t.Fatal("stalled establishment accepted")
			}
			var timeout net.Error
			if phase == "TLS handshake" && (!errors.As(err, &timeout) || !timeout.Timeout()) {
				t.Fatalf("stalled TLS must report a timeout from either establishment bound: %v", err)
			}
			if time.Since(start) > 500*time.Millisecond {
				t.Fatalf("establishment used total timeout instead of connect budget: %v", err)
			}
			assertFileContent(t, exe, "old")
			assertDirEntries(t, dir, "warden")
		})
	}
}
