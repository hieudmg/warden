package agent

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"time"
)

const agentHandshakeTimeout = 2 * time.Second
const agentTLSName = "warden-agent"

// newAgentIdentity never serializes the private key. The pin is authorized by
// native runtime-file ownership/ACLs, not a public CA or the endpoint's name.
func newAgentIdentity() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	template := &x509.Certificate{
		DNSNames: []string{agentTLSName}, NotBefore: time.Now().Add(-time.Minute),
		// A daemon has no time-based lifetime. The pin is replaced on each runtime,
		// not on a timer; this certificate cannot expire during a realistic runtime.
		NotAfter: time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

func agentServerTLS(cert tls.Certificate) *tls.Config {
	return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, SessionTicketsDisabled: true}
}

func authenticateAgent(ctx context.Context, raw net.Conn, pin []byte) (*tls.Conn, error) {
	certificate, err := x509.ParseCertificate(pin)
	if err != nil {
		raw.Close()
		return nil, errors.New("invalid agent trust certificate")
	}
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	conn := tls.Client(raw, &tls.Config{
		RootCAs: roots, ServerName: agentTLSName, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, SessionTicketsDisabled: true,
		VerifyConnection: func(state tls.ConnectionState) error {
			// Normal Go chain/name/time verification runs first. Also require the
			// exact runtime leaf, not another certificate signed by its key.
			if len(state.PeerCertificates) != 1 || !bytes.Equal(state.PeerCertificates[0].Raw, pin) {
				return errors.New("agent runtime certificate mismatch")
			}
			return nil
		},
	})
	handshakeCtx, cancel := context.WithTimeout(ctx, agentHandshakeTimeout)
	defer cancel()
	if err := conn.HandshakeContext(handshakeCtx); err != nil {
		raw.Close()
		return nil, err
	}
	return conn, nil
}
