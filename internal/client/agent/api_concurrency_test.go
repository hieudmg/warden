package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	clientssh "warden/internal/client/ssh"
	"warden/internal/model"
)

func TestConcurrentLoginRequestsCannotSwapPairingSecrets(t *testing.T) {
	id, _ := randomAPISecret()
	poll, _ := randomAPISecret()
	var creations, polls atomic.Int32
	peer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/client/pairing" {
			creations.Add(1)
			var b struct {
				Commitment string `json:"commitment"`
			}
			json.NewDecoder(r.Body).Decode(&b)
			json.NewEncoder(w).Encode(map[string]any{"id": id, "poll_secret": poll, "fingerprint": b.Commitment, "expires": time.Now().Add(5 * time.Minute)})
			return
		}
		if polls.Add(1) > 1 {
			w.WriteHeader(429)
			return
		}
		w.Write([]byte(`{"status":"pending"}`))
	}))
	defer peer.Close()
	ca := filepath.Join(t.TempDir(), "ca.pem")
	os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: peer.Certificate().Raw}), 0600)
	runtime, _ := NewRuntimeAt(filepath.Join(t.TempDir(), "agent"))
	server, err := NewRuntimeServer(runtime, NewPool(func(context.Context, model.SSHBundle) (*clientssh.Graph, error) { return &clientssh.Graph{}, nil }, time.Now, time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	defer func() { cancel(); <-done }()
	old := runtimeFactory
	runtimeFactory = func() (*Runtime, error) { return runtime, nil }
	defer func() { runtimeFactory = old }()
	var wg sync.WaitGroup
	results := make(chan Enrollment, 8)
	errs := make(chan error, 8)
	for n := 0; n < 8; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			v, e := Authorization(context.Background(), peer.URL, ca, time.Second, "begin", "fixture")
			results <- v
			errs <- e
		}()
	}
	wg.Wait()
	close(results)
	close(errs)
	for e := range errs {
		if e != nil {
			t.Error("concurrent pending login lost actionable metadata", e)
		}
	}
	fingerprint := ""
	for v := range results {
		if fingerprint == "" {
			fingerprint = v.Fingerprint
		}
		if v.ID != id || v.Fingerprint != fingerprint || v.Status != "pending" {
			t.Error("pairing ownership swapped")
		}
		encoded, _ := json.Marshal(v)
		if bytes.Contains(encoded, []byte(poll)) {
			t.Error("poll secret returned")
		}
	}
	if creations.Load() != 1 {
		t.Fatal("concurrent begin replaced API secret", creations.Load())
	}
	server.api.mu.Lock()
	server.api.authorizations[peer.URL].Expires = time.Now().Add(-time.Second)
	server.api.mu.Unlock()
	if v, e := Authorization(context.Background(), peer.URL, ca, time.Second, "status", ""); e != nil || v.Status != "unpaired" {
		t.Fatal("expired pending authorization remains reported active", v.Status, e)
	}
}
