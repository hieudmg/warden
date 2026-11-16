package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	clientssh "warden/internal/client/ssh"
	"warden/internal/model"
)

// Synthetic HTTPS protocol peer isolates ownership/lifetime/streaming from the
// real signed web-approval and durable-store journey in server/runtime tests.
func TestAgentAPIMemoryLifetimeAndBoundedStreams(t *testing.T) {
	var mode atomic.Int32
	var redirected atomic.Int32
	destination := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { redirected.Add(1); w.Write([]byte(`{}`)) }))
	defer destination.Close()
	var committed atomic.Value
	committed.Store("")
	poll, _ := randomAPISecret()
	id, _ := randomAPISecret()
	payload := `{"summary":"` + strings.Repeat("s", (1<<20)-100) + `"}`
	response := `{"summary":"` + strings.Repeat("r", 2<<20) + `"}`
	peer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/client/pairing":
			var b struct {
				Commitment string `json:"commitment"`
			}
			json.NewDecoder(r.Body).Decode(&b)
			committed.Store(b.Commitment)
			json.NewEncoder(w).Encode(map[string]any{"id": id, "poll_secret": poll, "fingerprint": b.Commitment, "approval_url": "https://attacker.invalid/", "expires": time.Now().Add(5 * time.Minute)})
		case "/api/v1/client/poll":
			json.NewEncoder(w).Encode(map[string]string{"status": "approved"})
		default:
			secret := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			if commitment(secret) != committed.Load().(string) {
				http.Error(w, "bad bearer", 401)
				return
			}
			switch mode.Load() {
			case 1:
				http.Error(w, "locked", 423)
				return
			case 2:
				http.Error(w, "outage", 503)
				return
			case 3:
				http.Error(w, "revoked", 401)
				return
			case 4:
				w.Write([]byte(secret))
				return
			case 7:
				time.Sleep(50 * time.Millisecond)
			case 5:
				http.Redirect(w, r, destination.URL, 307)
				return
			case 6:
				w.WriteHeader(401)
				w.Write([]byte(secret))
				return
			}
			if r.URL.Path == "/api/v1/client/status" || r.URL.Path == "/api/v1/client/logout" {
				w.Write([]byte(`{"authenticated":true}`))
				return
			}
			if r.Method == "POST" {
				var b struct {
					Summary string `json:"summary"`
				}
				if json.NewDecoder(r.Body).Decode(&b) != nil || len(b.Summary) != (1<<20)-100 {
					t.Error("large request stream changed")
				}
			}
			w.Write([]byte(response))
		}
	}))
	defer peer.Close()
	ca := filepath.Join(t.TempDir(), "ca.crt")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: peer.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	clock := &poolClock{now: time.Unix(100, 0)}
	pool := NewPool(func(context.Context, model.SSHBundle) (*clientssh.Graph, error) { return &clientssh.Graph{}, nil }, clock.Now, 10*time.Minute)
	runtime, _ := NewRuntimeAt(filepath.Join(t.TempDir(), "agent"))
	server, err := NewRuntimeServer(runtime, pool)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	previous := runtimeFactory
	runtimeFactory = func() (*Runtime, error) { return runtime, nil }
	defer func() { runtimeFactory = previous }()
	request := func(action string) Enrollment {
		t.Helper()
		v, e := Authorization(context.Background(), peer.URL, ca, time.Second, action, "fixture")
		if e != nil {
			t.Fatal(e)
		}
		return v
	}
	if v := request("status"); v.Status != "unpaired" {
		t.Fatal(v.Status)
	}
	if v := request("begin"); v.Status != "approved" || !strings.HasPrefix(v.ApprovalURL, peer.URL+"/") {
		t.Fatal("unsafe enrollment metadata")
	}
	server.api.mu.Lock()
	secret := server.api.authorizations[peer.URL].secret
	server.api.mu.Unlock()
	if secret == "" || secret == poll {
		t.Fatal("missing distinct in-memory ownership")
	}
	var out apiResponse
	if err = callAPI(context.Background(), apiRequest{Origin: peer.URL, CA: ca, Method: "POST", Path: "/api/v1/client/reports", Body: []byte(payload)}, &out); err != nil || out.Status != 200 || string(out.Body) != response {
		t.Fatal("large API stream failed", err, out.Status, len(out.Body))
	}
	for _, state := range []int32{0, 1, 2, 0} {
		mode.Store(state)
		clock.Advance(365 * 24 * time.Hour)
		pool.Expire()
		if state == 2 {
			if _, e := Authorization(context.Background(), peer.URL, ca, time.Second, "status", ""); e == nil {
				t.Fatal("status falsely claimed reachable authorization during server outage")
			}
		} else if v := request("status"); v.Status != "approved" {
			t.Fatal("auth lost on independent state", state, v.Status)
		}
	}
	server.api.mu.Lock()
	same := server.api.authorizations[peer.URL].secret == secret
	server.api.mu.Unlock()
	if !same {
		t.Fatal("pool expiry/outage/lock rotated credential")
	}
	mode.Store(5)
	for _, method := range []string{"GET", "POST"} {
		path := "/api/v1/client/ssh-connections"
		var body []byte
		if method == "POST" {
			path = "/api/v1/client/reports"
			body = []byte(`{"summary":"synthetic-private-body"}`)
		}
		if e := callAPI(context.Background(), apiRequest{Origin: peer.URL, CA: ca, Method: method, Path: path, Body: body}, &out); e != nil || out.Status != 307 {
			t.Fatal("agent redirect policy", e, out.Status)
		}
	}
	if redirected.Load() != 0 {
		t.Fatal("redirect destination received bearer/body")
	}
	mode.Store(7)
	if e := callAPI(context.Background(), apiRequest{Origin: peer.URL, CA: ca, Timeout: 5 * time.Millisecond, Method: "GET", Path: "/api/v1/client/ssh-connections"}, &out); e == nil {
		t.Fatal("agent retained first caller timeout instead of current request timeout")
	}
	mode.Store(4)
	if e := callAPI(context.Background(), apiRequest{Origin: peer.URL, CA: ca, Method: "GET", Path: "/api/v1/client/ssh-connections"}, &out); e == nil {
		t.Fatal("raw authorization returned over IPC")
	}
	files := []string{ca}
	if e := filepath.WalkDir(filepath.Dir(runtime.tokenPath()), func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.Type().IsRegular() {
			files = append(files, path)
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	for _, file := range files {
		b, e := os.ReadFile(file)
		if e != nil {
			t.Fatal(e)
		}
		if bytes.Contains(b, []byte(secret)) || bytes.Contains(b, []byte(poll)) {
			t.Fatal("API secret persisted")
		}
	}
	mode.Store(6)
	if e := callAPI(context.Background(), apiRequest{Origin: peer.URL, CA: ca, Method: "GET", Path: "/api/v1/client/ssh-connections"}, &out); e == nil {
		t.Fatal("revocation response returned API secret over IPC")
	}
	mode.Store(3)
	if v := request("status"); v.Status != "revoked" {
		t.Fatal(v.Status)
	}
	clock.Advance(10 * 365 * 24 * time.Hour)
	pool.Expire()
	mode.Store(0)
	request("begin")
	peer.Close() // Actual connection refusal, not just an HTTP error response.
	if v := request("logout"); v.Status != "logged_out" {
		t.Fatal(v.Status)
	}
	if v := request("status"); v.Status != "unpaired" {
		t.Fatal("logout retained credential")
	}
	// No state transition above terminates the existing pinned daemon.
	if _, e := runtime.ReadToken(); e != nil {
		t.Fatal("daemon ended", e)
	}
	cancel()
	select {
	case e := <-done:
		if !errors.Is(e, context.Canceled) {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("external cancellation failed without SSH dial in flight")
	}
	if len(server.api.authorizations) != 0 {
		t.Fatal("server exit retained authorization")
	}
}
