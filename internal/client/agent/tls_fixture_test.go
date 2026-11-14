package agent

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"testing"
	"time"
)

// Protocol/operation tests still use real TLS handshakes, not auth verdict mocks.
func agentTLSTestPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	cert := testAgentCertificate(t, agentTLSName, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	client, server := net.Pipe()
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	_ = server.SetDeadline(time.Now().Add(3 * time.Second))
	return tls.Client(client, &tls.Config{RootCAs: roots, ServerName: agentTLSName, MinVersion: tls.VersionTLS13, SessionTicketsDisabled: true}), tls.Server(server, agentServerTLS(cert))
}
