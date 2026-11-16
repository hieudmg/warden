package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type apiBoundsFixture struct {
	server        *Server
	peer          *httptest.Server
	ca            string
	calls         atomic.Int32
	receivedBytes atomic.Int64
	responseBytes atomic.Int64
}

// Enrollment is covered separately. This fixture starts with approved in-memory
// custody, then uses real HTTPS and authenticated TLS IPC for boundary failures.
func newAPIBoundsFixture(t *testing.T) *apiBoundsFixture {
	t.Helper()
	f := &apiBoundsFixture{}
	secret, err := randomAPISecret()
	if err != nil {
		t.Fatal(err)
	}
	f.peer = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.calls.Add(1)
		if r.Header.Get("Authorization") != "Bearer "+secret {
			t.Error("fixture bearer missing")
			w.WriteHeader(401)
			return
		}
		n, err := io.Copy(io.Discard, r.Body)
		if err != nil {
			t.Error("fixture body interrupted", err)
			return
		}
		f.receivedBytes.Store(n)
		if n := int(f.responseBytes.Load()); n > 0 {
			io.WriteString(w, `{"value":"`+strings.Repeat("x", n-len(`{"value":""}`))+`"}`)
			return
		}
		w.Write([]byte(`{"fixture":true}`))
	}))
	t.Cleanup(f.peer.Close)
	f.ca = filepath.Join(t.TempDir(), "ca.pem")
	if err = os.WriteFile(f.ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.peer.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	hc, err := apiHTTPClient(f.ca, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(hc.CloseIdleConnections)
	f.server = &Server{api: apiOwner{authorizations: map[string]*agentAuthorization{f.peer.URL: {Enrollment: Enrollment{Status: "approved"}, secret: secret, client: hc, ca: f.ca}}}}
	return f
}
func (f *apiBoundsFixture) startRuntime(t *testing.T) *atomic.Int32 {
	t.Helper()
	runtime, err := NewRuntimeAt(filepath.Join(t.TempDir(), "agent"))
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewRuntimeServer(runtime, NewPool(nil, time.Now, time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	server.api.authorizations = f.server.api.authorizations
	f.server = server
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	previous := runtimeFactory
	var attaches atomic.Int32
	runtimeFactory = func() (*Runtime, error) { attaches.Add(1); return runtime, nil }
	t.Cleanup(func() {
		runtimeFactory = previous
		cancel()
		select {
		case err := <-done:
			if err != nil && !errors.Is(err, context.Canceled) {
				t.Error(err)
			}
		case <-time.After(3 * time.Second):
			t.Error("agent boundary operation did not clean up")
		}
		if _, err := os.Stat(runtime.tokenPath()); !os.IsNotExist(err) {
			t.Error("discovery survived explicit termination", err)
		}
		server.api.mu.Lock()
		defer server.api.mu.Unlock()
		if len(server.api.authorizations) != 0 {
			t.Error("termination retained authorization references")
		}
	})
	return &attaches
}
func (f *apiBoundsFixture) request() apiRequest {
	return apiRequest{Origin: f.peer.URL, CA: f.ca, Method: "POST", Path: "/api/v1/client/reports"}
}
func (f *apiBoundsFixture) assertUsable(t *testing.T) {
	t.Helper()
	f.server.api.mu.Lock()
	a := f.server.api.authorizations[f.peer.URL]
	valid := a != nil && a.Status == "approved" && a.secret != ""
	f.server.api.mu.Unlock()
	if !valid {
		t.Fatal("boundary failure discarded approved custody")
	}
	var response apiResponse
	r := f.request()
	r.Body = []byte(`{}`)
	if err := callAPI(context.Background(), r, &response); err != nil || response.Status != 200 {
		t.Fatal("agent unusable after rejected operation", err, response.Status)
	}
}

type closingAPIBody struct {
	io.Reader
	closed bool
}

func (b *closingAPIBody) Close() error { b.closed = true; return nil }
func TestAPITransportRejectsRequestLimitPlusOneBeforeIPC(t *testing.T) {
	f := newAPIBoundsFixture(t)
	attaches := f.startRuntime(t)
	body := &closingAPIBody{Reader: strings.NewReader(strings.Repeat("x", (1<<20)+1))}
	req, err := http.NewRequest("POST", f.peer.URL+"/api/v1/client/reports", body)
	if err != nil {
		t.Fatal(err)
	}
	response, err := (Transport{Origin: f.peer.URL, CA: f.ca}).RoundTrip(req)
	if err == nil || !strings.Contains(err.Error(), "API body exceeds bound") || response != nil {
		t.Fatal("oversized API request accepted", err)
	}
	if !body.closed || attaches.Load() != 0 || f.calls.Load() != 0 {
		t.Fatal("oversized producer contacted IPC/HTTPS or left body open")
	}
	// Bypass only the producer's local check: the real IPC consumer also rejects
	// the declared +1 body, without mutating the destination or reaching HTTPS.
	r := f.request()
	r.Body = bytes.Repeat([]byte("x"), (1<<20)+1)
	out := apiResponse{Status: 599, Body: []byte("untouched")}
	if err = callAPI(context.Background(), r, &out); err == nil || out.Status != 599 || string(out.Body) != "untouched" || f.calls.Load() != 0 {
		t.Fatal("consumer accepted oversized request or decoded success", err)
	}
	// The adjacent valid boundary still crosses the complete producer/consumer.
	payload := `{"summary":"` + strings.Repeat("x", (1<<20)-len(`{"summary":""}`)) + `"}`
	req, err = http.NewRequest("POST", f.peer.URL+"/api/v1/client/reports", strings.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	response, err = (Transport{Origin: f.peer.URL, CA: f.ca}).RoundTrip(req)
	if err != nil {
		t.Fatal("exact request limit rejected", err)
	}
	response.Body.Close()
	if response.StatusCode != 200 || f.receivedBytes.Load() != 1<<20 {
		t.Fatal("exact request body not delivered", response.StatusCode, f.receivedBytes.Load())
	}
	f.assertUsable(t)
}
func TestAgentAPIRejectsHTTPResponseLimitPlusOne(t *testing.T) {
	f := newAPIBoundsFixture(t)
	f.startRuntime(t)
	f.responseBytes.Store(maxAPIResponse + 1)
	r := f.request()
	r.Body = []byte(`{}`)
	out := apiResponse{Status: 599, Body: []byte("untouched")}
	err := callAPI(context.Background(), r, &out)
	if err == nil || !strings.Contains(err.Error(), "client response exceeds bound") || out.Status != 599 || string(out.Body) != "untouched" {
		t.Fatal("oversized HTTPS response became decoded success", err, out.Status)
	}
	if f.calls.Load() != 1 {
		t.Fatal("fixture did not reach the actual HTTPS producer")
	}
	f.responseBytes.Store(maxAPIResponse)
	if err = callAPI(context.Background(), r, &out); err != nil || out.Status != 200 || len(out.Body) != maxAPIResponse {
		t.Fatal("exact response limit rejected", err, out.Status, len(out.Body))
	}
	f.responseBytes.Store(0)
	f.assertUsable(t)
}

func TestAgentAPIRejectsMalformedBodyStreams(t *testing.T) {
	f := newAPIBoundsFixture(t)
	for _, tc := range []struct {
		name         string
		length       int
		inline       []byte
		frames       []Frame
		truncated    bool
		partialFrame bool
		want         string
	}{
		{name: "declared request plus one", length: (1 << 20) + 1, want: "API request exceeds bound"},
		{name: "negative declaration", length: -1, want: "API request exceeds bound"},
		{name: "inline body forbidden", inline: []byte("x"), want: "API request exceeds bound"},
		{name: "short declared stream", length: 3, frames: []Frame{{Kind: FrameStdin, Data: []byte("xx")}, {Kind: FrameEOF}}, want: "incomplete API body stream"},
		{name: "overlong declared stream", length: 1, frames: []Frame{{Kind: FrameStdin, Data: []byte("xx")}, {Kind: FrameEOF}}, want: "invalid API body stream"},
		{name: "unexpected stdout", length: 1, frames: []Frame{{Kind: FrameStdout, Data: []byte("x")}, {Kind: FrameEOF}}, want: "invalid API body stream"},
		{name: "unexpected terminal", length: 1, frames: []Frame{{Kind: FrameFinal, Response: &Response{}}}, want: "invalid API body stream"},
		{name: "truncated before EOF", length: 1, frames: []Frame{{Kind: FrameStdin, Data: []byte("x")}}, truncated: true},
		{name: "truncated frame", length: 1, truncated: true, partialFrame: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, server := agentTLSTestPair(t)
			token := bytes.Repeat([]byte{37}, TokenBytes)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			handled := make(chan struct{})
			go func() { defer close(handled); f.server.handleConn(ctx, server, token) }()
			closeClient := func() { client.(*tls.Conn).NetConn().Close() }
			written := make(chan struct{})
			go func() {
				defer close(written)
				r := f.request()
				r.BodyLength = tc.length
				r.Body = tc.inline
				payload, _ := json.Marshal(r)
				if WriteFrame(client, Frame{Version: Version, Kind: FrameRequest, Token: token, Request: &Request{Operation: operationAPI, Payload: payload}}) != nil {
					return
				}
				for _, frame := range tc.frames {
					frame.Version = Version
					if WriteFrame(client, frame) != nil {
						return
					}
				}
				if tc.partialFrame {
					var prefix [4]byte
					binary.BigEndian.PutUint32(prefix[:], 40)
					client.Write(prefix[:])
					client.Write([]byte(`{"version":`))
				}
				if tc.truncated {
					closeClient()
				}
			}()
			frame, err := ReadFrame(client)
			if tc.truncated {
				if err == nil {
					t.Error("truncated stream produced a terminal success")
				}
			} else if err != nil || frame.Kind != FrameFinal || frame.Response == nil || frame.Response.Error != tc.want {
				t.Error("missing bounded terminal rejection", err, frame.Kind, frame.Response)
			}
			closeClient()
			cancel()
			select {
			case <-written:
			case <-time.After(time.Second):
				t.Error("body producer did not join")
			}
			select {
			case <-handled:
			case <-time.After(time.Second):
				t.Error("body consumer did not join")
			}
			if f.calls.Load() != 0 {
				t.Fatal("malformed request reached HTTPS")
			}
		})
	}
}

// A synthetic authenticated IPC producer can exceed the real HTTP producer's
// cap or terminate midway. Exercise callAPI's consumer, not just its buffer type.
func TestAPIConsumerRejectsOversizedTruncatedAndUnexpectedResponses(t *testing.T) {
	valid, _ := json.Marshal(apiResponse{Status: 200, Body: []byte("synthetic-response")})
	for _, name := range []string{"serialized limit plus one", "truncated JSON", "truncated before final", "unexpected frame", "failure after stdout"} {
		t.Run(name, func(t *testing.T) {
			runtime, err := NewRuntimeAt(filepath.Join(t.TempDir(), "agent"))
			if err != nil {
				t.Fatal(err)
			}
			listener, err := runtime.Listen()
			if err != nil {
				t.Fatal(err)
			}
			token, err := runtime.ReadToken()
			if err != nil {
				t.Fatal(err)
			}
			previous := runtimeFactory
			runtimeFactory = func() (*Runtime, error) { return runtime, nil }
			done := make(chan struct{})
			var authenticated atomic.Bool
			go func() {
				defer close(done)
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				defer conn.(*tls.Conn).NetConn().Close()
				conn.SetDeadline(time.Now().Add(3 * time.Second))
				if _, err = ReadAuthenticatedFrame(conn, token); err != nil {
					return
				}
				authenticated.Store(true)
				data := valid
				if name == "serialized limit plus one" {
					data = append(append([]byte(nil), valid...), bytes.Repeat([]byte(" "), (6<<20)+1-len(valid))...)
				}
				if name == "truncated JSON" {
					data = []byte(`{"status":200,"body":"`)
				}
				for len(data) > 0 {
					n := min(len(data), 32<<10)
					if WriteFrame(conn, Frame{Version: Version, Kind: FrameStdout, Data: data[:n]}) != nil {
						return
					}
					data = data[n:]
				}
				switch name {
				case "truncated before final":
					return
				case "unexpected frame":
					WriteFrame(conn, Frame{Version: Version, Kind: FrameEOF})
					return
				case "failure after stdout":
					writeFinal(conn, Response{Error: "synthetic terminal failure"})
					return
				}
				writeFinal(conn, Response{})
			}()
			t.Cleanup(func() {
				runtimeFactory = previous
				listener.Close()
				select {
				case <-done:
				case <-time.After(4 * time.Second):
					t.Error("IPC producer did not join")
				}
				if err := runtime.Cleanup(); err != nil {
					t.Error("IPC runtime cleanup", err)
				}
				if _, err := os.Stat(runtime.tokenPath()); !os.IsNotExist(err) {
					t.Error("failed producer left discovery", err)
				}
			})
			out := apiResponse{Status: 599, Body: []byte("untouched")}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			err = callAPI(ctx, apiRequest{Origin: "https://fixture.invalid", Method: "GET", Path: "/api/v1/client/projects"}, &out)
			if err == nil || out.Status != 599 || string(out.Body) != "untouched" {
				t.Fatal("failed IPC response became partially decoded success", err, out.Status)
			}
			if !authenticated.Load() {
				t.Fatal("fixture did not pass real IPC authentication")
			}
			if name == "serialized limit plus one" && !strings.Contains(err.Error(), "agent API response exceeds bound") {
				t.Fatal("did not exercise serialized output cap", err)
			}
		})
	}
}
