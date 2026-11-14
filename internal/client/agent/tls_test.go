package agent

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net"
	"path/filepath"
	"testing"
	"time"

	clientssh "warden/internal/client/ssh"
)

func testAgentCertificate(t *testing.T, name string, before, after time.Time) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name}, NotBefore: before, NotAfter: after, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func TestAgentAuthenticatesServerBeforeSecretBytes(t *testing.T) {
	runtime, _ := NewRuntimeAt(filepath.Join(t.TempDir(), "agent"))
	legitimate, err := runtime.Listen()
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Cleanup()
	token, err := runtime.ReadToken()
	if err != nil {
		t.Fatal(err)
	}
	if err := legitimate.Close(); err != nil {
		t.Fatal(err)
	}
	impostor, err := listenRuntime(runtime, runtime.EndpointPath())
	if err != nil {
		t.Fatal(err)
	}
	defer impostor.Close()
	captured := make(chan []byte, 1)
	go func() {
		conn, err := impostor.Accept()
		if err != nil {
			captured <- nil
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(100 * time.Millisecond))
		wire, _ := io.ReadAll(io.LimitReader(conn, 2*MaxFrameBytes))
		captured <- wire
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, actualToken, err := tryRuntime(ctx, runtime)
	if err == nil {
		_ = relayRequest(ctx, conn, actualToken, Request{Operation: operationDB, SQL: "protected-sql", Command: "protected-command", Payload: json.RawMessage(`{"secret":"protected-bundle"}`)}, clientssh.Streams{Stdin: bytes.NewBufferString("protected-stdin")}, true)
	}
	wire := <-captured
	for _, secret := range [][]byte{token, []byte(base64.StdEncoding.EncodeToString(token)), []byte("protected-sql"), []byte("protected-command"), []byte("protected-bundle"), []byte("protected-stdin"), []byte(base64.StdEncoding.EncodeToString([]byte("protected-stdin")))} {
		if bytes.Contains(wire, secret) {
			t.Fatal("impostor received protected payload before authentication")
		}
	}
	if len(wire) < 3 || wire[0] != 22 || wire[1] != 3 {
		t.Fatalf("first exchange is not TLS: %x", wire)
	}
}

func TestAgentTLSRejectsWrongStaleExpiredCertificateAndTimeout(t *testing.T) {
	now := time.Now()
	valid := testAgentCertificate(t, "warden-agent", now.Add(-time.Hour), now.Add(time.Hour))
	tests := []struct {
		name             string
		cert             tls.Certificate
		plaintext, stall bool
		maxVersion       uint16
	}{
		{name: "wrong runtime", cert: testAgentCertificate(t, "warden-agent", now.Add(-time.Hour), now.Add(time.Hour))},
		{name: "stale certificate", cert: valid},
		{name: "expired", cert: testAgentCertificate(t, "warden-agent", now.Add(-2*time.Hour), now.Add(-time.Hour))},
		{name: "not yet valid", cert: testAgentCertificate(t, "warden-agent", now.Add(time.Hour), now.Add(2*time.Hour))},
		{name: "TLS1.2", cert: valid, maxVersion: tls.VersionTLS12},
		{name: "wrong name", cert: testAgentCertificate(t, "other-agent", now.Add(-time.Hour), now.Add(time.Hour))},
		{name: "plaintext", plaintext: true}, {name: "timeout", stall: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			client, err := net.Dial("tcp", listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			peerDone := make(chan struct{})
			go func() {
				defer close(peerDone)
				server, err := listener.Accept()
				if err != nil {
					return
				}
				defer server.Close()
				if test.stall {
					_, _ = io.Copy(io.Discard, server)
					return
				}
				if test.plaintext {
					_, _ = server.Write([]byte("not TLS"))
					return
				}
				config := agentServerTLS(test.cert)
				if test.maxVersion != 0 {
					config.MinVersion = test.maxVersion
					config.MaxVersion = test.maxVersion
				}
				_ = tls.Server(server, config).Handshake()
			}()
			pin := valid.Certificate[0]
			if test.name == "expired" || test.name == "wrong name" || test.name == "not yet valid" {
				pin = test.cert.Certificate[0]
			}
			if test.name == "stale certificate" {
				pin = testAgentCertificate(t, agentTLSName, now.Add(-time.Minute), now.Add(time.Hour)).Certificate[0]
			}
			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
			defer cancel()
			secured, err := authenticateAgent(ctx, client, pin)
			if err == nil {
				secured.Close()
				t.Fatal("untrusted endpoint accepted")
			}
			if !test.plaintext && !test.stall && test.maxVersion == 0 {
				var verifyError *tls.CertificateVerificationError
				if !errors.As(err, &verifyError) {
					t.Fatalf("wrong/expired/name certificate did not fail verification: %v", err)
				}
			}
			client.Close()
			<-peerDone
		})
	}
}

func TestAgentTLSRelayCannotReadPayload(t *testing.T) {
	cert := testAgentCertificate(t, "warden-agent", time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	client, relayClient := net.Pipe()
	relayServer, server := net.Pipe()
	defer client.Close()
	defer relayClient.Close()
	defer relayServer.Close()
	defer server.Close()
	payload := []byte("protected-bundle-command-sql-stdin")
	captured := make(chan []byte, 1)
	relayDone := make(chan struct{})
	go func() {
		defer close(relayDone)
		var wire bytes.Buffer
		_, _ = io.Copy(relayServer, io.TeeReader(relayClient, &wire))
		captured <- wire.Bytes()
	}()
	go func() { _, _ = io.Copy(relayClient, relayServer); relayClient.Close() }()
	serverDone := make(chan error, 1)
	go func() {
		secured := tls.Server(server, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13, SessionTicketsDisabled: true})
		defer secured.Close()
		got := make([]byte, len(payload))
		_, err := io.ReadFull(secured, got)
		if err == nil && !bytes.Equal(got, payload) {
			err = errors.New("relay changed payload")
		}
		if err == nil {
			_, err = secured.Write([]byte("ok"))
		}
		serverDone <- err
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	secured, err := authenticateAgent(ctx, client, cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if secured.ConnectionState().Version != tls.VersionTLS13 || secured.ConnectionState().DidResume {
		t.Fatal("not a fresh TLS1.3 session")
	}
	if _, err := secured.Write(payload); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(secured, reply); err != nil {
		t.Fatal(err)
	}
	client.Close()
	relayClient.Close()
	relayServer.Close()
	server.Close()
	<-relayDone
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
	wire := <-captured
	if bytes.Contains(wire, payload) || len(wire) == 0 {
		t.Fatal("relay obtained plaintext or saw no TLS traffic")
	}
}
