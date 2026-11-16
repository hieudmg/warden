package agent

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestIPCDiscoveryContainsNoAPIToken(t *testing.T) {
	runtime, _ := NewRuntimeAt(filepath.Join(t.TempDir(), "agent"))
	if _, err := runtime.Listen(); err != nil {
		t.Fatal(err)
	}
	defer runtime.Cleanup()
	file, err := os.ReadFile(runtime.tokenPath())
	if err != nil {
		t.Fatal(err)
	}
	var record struct {
		Version     uint8  `json:"version"`
		Token       []byte `json:"token"`
		Certificate []byte `json:"certificate"`
	}
	if err := json.Unmarshal(file, &record); err != nil {
		t.Fatalf("not versioned credentials: %v", err)
	}
	if record.Version != 2 || len(record.Token) != 32 {
		t.Fatal("wrong credential version or IPC token length")
	}
	if _, err := x509.ParseCertificate(record.Certificate); err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(file, &fields)
	if len(fields) != 3 {
		t.Fatalf("unexpected persisted fields: %v", fields)
	}
	// T4 is absent: no API secret exists here. This asserts the narrow schema,
	// not an unimplemented memory-only API-token flow or Go zeroization.
	if bytes.Contains(file, []byte("PRIVATE KEY")) {
		t.Fatal("persisted TLS private key")
	}
}

func TestRuntimeCollisionCannotReplaceTrustOrCleanupOwner(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "agent")
	owner, _ := NewRuntimeAt(dir)
	if _, err := owner.Listen(); err != nil {
		t.Fatal(err)
	}
	defer owner.Cleanup()
	before, err := os.ReadFile(owner.tokenPath())
	if err != nil {
		t.Fatal(err)
	}
	contender, _ := NewRuntimeAt(dir)
	if _, err := contender.Listen(); err == nil {
		t.Fatal("second listener won same runtime")
	}
	if err := contender.Cleanup(); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(owner.tokenPath())
	if err != nil {
		t.Fatal("contender removed owner credentials:", err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("collision changed trust pin")
	}
}

func TestRuntimeRejectsCorruptCredentialAndUnversionedToken(t *testing.T) {
	for _, data := range [][]byte{bytes.Repeat([]byte{1}, 32), []byte(`{}`), []byte(`{"version":1}`), []byte(`{"version":2,"token":"bad","certificate":"bad"}`), bytes.Repeat([]byte("x"), 16385)} {
		runtime, _ := NewRuntimeAt(filepath.Join(t.TempDir(), "agent"))
		if _, err := runtime.Listen(); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(runtime.tokenPath(), data, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := runtime.ReadToken(); err == nil {
			t.Fatal("accepted corrupt or stale credentials")
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*50)
		if conn, _, err := tryRuntime(ctx, runtime); err == nil {
			conn.Close()
			t.Fatal("dial used corrupt trust")
		}
		cancel()
		_ = runtime.Cleanup()
	}
}

func TestRuntimeRestartUsesFreshTrustAndToken(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "agent")
	first, _ := NewRuntimeAt(dir)
	listener, err := first.Listen()
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(first.tokenPath())
	if err != nil {
		t.Fatal(err)
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	// Simulate orderly ownership release without deleting crash leftovers.
	first.mu.Lock()
	first.listener = nil
	first.mu.Unlock()
	// The implementation's lock belongs to the runtime and is released by Cleanup.
	if err := first.Cleanup(); err != nil {
		t.Fatal(err)
	}
	second, _ := NewRuntimeAt(dir)
	if _, err := second.Listen(); err != nil {
		t.Fatal(err)
	}
	defer second.Cleanup()
	after, err := os.ReadFile(second.tokenPath())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(before, after) {
		t.Fatal("reused prior runtime trust or token")
	}
	var a, b struct{ Token, Certificate []byte }
	_ = json.Unmarshal(before, &a)
	_ = json.Unmarshal(after, &b)
	if bytes.Equal(a.Token, b.Token) || bytes.Equal(a.Certificate, b.Certificate) {
		t.Fatal("runtime material not fresh")
	}
	if _, err := os.Stat(second.tokenPath()); errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
}
