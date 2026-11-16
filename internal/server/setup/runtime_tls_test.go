package setup

import (
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
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/cookiejar"
	"os"
	"path/filepath"
	"testing"
	"time"

	"warden/internal/config"
	"warden/internal/crypto"
	"warden/internal/store"
	"warden/internal/web"
)

type terminalSignal struct{ ready chan struct{} }

func (w terminalSignal) Write(b []byte) (int, error) { close(w.ready); return len(b), nil }
func TestProductionSetupHTTPSAtomicExitAndLockedRestart(t *testing.T) {
	dir := t.TempDir()
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
	os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600)
	os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk}), 0600)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	path := filepath.Join(dir, "vault.db")
	assets, err := web.SetupDistribution()
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Setup{PublicOrigin: "https://warden.example", RPID: "warden.example", Mode: "tls", TLSCertificate: certPath, TLSKey: keyPath}
	ready := make(chan struct{})
	done := make(chan error, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	go func() {
		done <- run(ctx, Options{Config: cfg, Bind: listener.Addr().String(), DBPath: path, Assets: assets}, terminalSignal{ready}, runtimeDeps{listen: func(string, string) (net.Listener, error) { return listener, nil }, password: func() (string, error) { return "23456789", nil }, now: time.Now, verifier: fakeVerifier{}})
	}()
	select {
	case <-ready:
	case err := <-done:
		t.Fatal(err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	cert, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}, DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, listener.Addr().String())
	}}
	defer transport.CloseIdleConnections()
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Transport: transport, Jar: jar, Timeout: 3 * time.Second}
	csrf := ""
	post := func(route string, b any, status int) []byte {
		t.Helper()
		body, _ := json.Marshal(b)
		r, _ := http.NewRequest("POST", cfg.PublicOrigin+"/api/v1/setup/"+route, bytes.NewReader(body))
		r.Header.Set("Origin", cfg.PublicOrigin)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-CSRF-Token", csrf)
		resp, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		data, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != status {
			t.Fatalf("%s status %d want %d: %s", route, resp.StatusCode, status, data)
		}
		return data
	}
	response := post("password", map[string]string{"password": "23456789"}, 200)
	var authorized struct {
		CSRF string `json:"csrf"`
	}
	json.Unmarshal(response, &authorized)
	csrf = authorized.CSRF
	post("registration/begin", struct{}{}, 200)
	var registered struct {
		Vault string `json:"vault_id"`
		Input string `json:"prf_input"`
	}
	json.Unmarshal(post("registration/finish", map[string]bool{"valid": true}, 200), &registered)
	post("assertion/finish", map[string]bool{"valid": true}, 200)
	dek := bytes.Repeat([]byte{11}, 32)
	root := bytes.Repeat([]byte{12}, 32)
	pass, _ := crypto.Wrap(bytes.Repeat([]byte{13}, 32), dek, "passkey", registered.Vault, crypto.Encode([]byte("credential")), nil)
	pass.PRFInput = registered.Input
	recovery, _ := crypto.Wrap(root, dek, "recovery", registered.Vault, "", nil)
	salt, _ := crypto.Decode(recovery.KDFSalt, 32)
	proof, _ := crypto.Derive(root, salt, "warden/v1/recovery-auth")
	post("prepare", Preparation{Passkey: pass, Recovery: recovery, RecoveryVerifier: hashToken(proof), DEK: crypto.Encode(dek)}, 200)
	post("finalize", Confirmation{RecoveryAuth: crypto.Encode(proof), DEK: crypto.Encode(dek)}, 200)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("setup did not exit")
	}
	record, err := store.ReadInstallation(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(record, []byte(crypto.Encode(dek))) || bytes.Contains(record, []byte(crypto.Encode(root))) || bytes.Contains(record, []byte(crypto.Encode(proof))) {
		t.Fatal("persisted unwrapped material")
	}
	var installation Installation
	if err := json.Unmarshal(record, &installation); err != nil {
		t.Fatal(err)
	}
	if installation.KeyCheck.Verify(dek, registered.Vault) != nil {
		t.Fatal("lost initialized key check")
	}
	if lease, err := store.ReserveInitialization(path); err == nil {
		lease.Close()
		t.Fatal("restart accepted init")
	}
}
