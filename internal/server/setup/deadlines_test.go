package setup

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"testing"
	"testing/fstest"
	"time"

	"warden/internal/server"
)

func TestSetupSlowHeadersBodiesIdleAndWritesTerminate(t *testing.T) {
	for _, mode := range []string{"tls", "proxy"} {
		t.Run(mode, func(t *testing.T) {
			p, _ := plane(t)
			p.cfg.Mode = mode
			p.assets = fstest.MapFS{"setup.html": {Data: []byte("setup")}, "large.js": {Data: bytes.Repeat([]byte("s"), 16<<20)}}
			l, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			p.cfg.BackendAuthority = l.Addr().String()
			srv := server.NewHTTPServer(p)
			srv.ReadHeaderTimeout = 180 * time.Millisecond
			srv.ReadTimeout = 250 * time.Millisecond
			srv.WriteTimeout = 250 * time.Millisecond
			srv.IdleTimeout = 180 * time.Millisecond
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			template := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "warden.example"}, DNSNames: []string{"warden.example"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
			der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
			if err != nil {
				t.Fatal(err)
			}
			leaf, err := x509.ParseCertificate(der)
			if err != nil {
				t.Fatal(err)
			}
			roots := x509.NewCertPool()
			roots.AddCert(leaf)
			listener := l
			if mode == "tls" {
				listener = server.TLSListener(l, tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key})
			}
			done := make(chan error, 1)
			go func() { done <- srv.Serve(listener) }()
			defer func() { srv.Close(); <-done }()
			dial := func() net.Conn {
				t.Helper()
				raw, e := net.Dial("tcp", l.Addr().String())
				if e != nil {
					t.Fatal(e)
				}
				raw.(*net.TCPConn).SetReadBuffer(4096)
				var c net.Conn = raw
				if mode == "tls" {
					s := tls.Client(raw, &tls.Config{RootCAs: roots, ServerName: "warden.example", MinVersion: tls.VersionTLS13})
					if e = s.Handshake(); e != nil {
						raw.Close()
						t.Fatal(e)
					}
					c = s
				}
				c.SetDeadline(time.Now().Add(3 * time.Second))
				return c
			}
			t.Run("headers", func(t *testing.T) {
				c := dial()
				defer c.Close()
				io.WriteString(c, "GET / HTTP/1.1\r\nHost:")
				start := time.Now()
				_, err := io.ReadAll(c)
				if e, ok := err.(net.Error); ok && e.Timeout() {
					t.Fatal("header not bounded")
				}
				if time.Since(start) > time.Second {
					t.Fatal("header not bounded")
				}
			})
			t.Run("idle", func(t *testing.T) {
				c := dial()
				defer c.Close()
				io.WriteString(c, "GET / HTTP/1.1\r\nHost: warden.example\r\n\r\n")
				reader := bufio.NewReader(c)
				res, e := http.ReadResponse(reader, nil)
				if e != nil {
					t.Fatal(e)
				}
				io.Copy(io.Discard, res.Body)
				res.Body.Close()
				if res.StatusCode != 200 {
					t.Fatal(res.StatusCode)
				}
				start := time.Now()
				_, e = reader.ReadByte()
				if e == nil || time.Since(start) > time.Second {
					t.Fatal("idle not bounded", e)
				}
			})
			t.Run("body", func(t *testing.T) {
				c := dial()
				defer c.Close()
				io.WriteString(c, "POST /api/v1/setup/password HTTP/1.1\r\nHost: warden.example\r\nOrigin: https://warden.example\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{")
				start := time.Now()
				_, err := io.ReadAll(c)
				if e, ok := err.(net.Error); ok && e.Timeout() {
					t.Fatal("upload not bounded")
				}
				if time.Since(start) > time.Second {
					t.Fatal("upload not bounded")
				}
			})
			t.Run("write", func(t *testing.T) {
				c := dial()
				defer c.Close()
				io.WriteString(c, "GET /large.js HTTP/1.1\r\nHost: warden.example\r\n\r\n")
				until := time.Now().Add(time.Second)
				for len(p.requests) == 0 && time.Now().Before(until) {
					time.Sleep(time.Millisecond)
				}
				if len(p.requests) == 0 {
					t.Fatal("write did not enter")
				}
				for len(p.requests) > 0 && time.Now().Before(until) {
					time.Sleep(time.Millisecond)
				}
				if len(p.requests) != 0 {
					t.Fatal("stalled write held setup state")
				}
			})
			for _, authority := range []string{"attacker.example", "warden.example:444", "warden.example@attacker.example", "warden.example\r\nHost: attacker.example"} {
				c := dial()
				fmt.Fprintf(c, "GET / HTTP/1.1\r\nHost: %s\r\nForwarded: host=warden.example;proto=https\r\nX-Forwarded-Host: warden.example\r\nConnection: close\r\n\r\n", authority)
				res, err := http.ReadResponse(bufio.NewReader(c), nil)
				if err != nil {
					c.Close()
					t.Fatal(err)
				}
				io.Copy(io.Discard, res.Body)
				res.Body.Close()
				c.Close()
				if res.StatusCode != 400 && res.StatusCode != 403 {
					t.Fatal("host spoof accepted", res.StatusCode)
				}
			}
			if p.initialized.Load() {
				t.Fatal("timeouts initialized setup")
			}
		})
	}
}
