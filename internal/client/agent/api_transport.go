package agent

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	"warden/internal/client/clienthttp"
	clientssh "warden/internal/client/ssh"
)

const operationAPI = "api"
const maxAPIResponse = 4 << 20

type apiRequest struct {
	Origin     string        `json:"origin"`
	CA         string        `json:"ca,omitempty"`
	Timeout    time.Duration `json:"timeout,omitempty"`
	Method     string        `json:"method,omitempty"`
	Path       string        `json:"path,omitempty"`
	Body       []byte        `json:"body,omitempty"`
	BodyLength int           `json:"body_length,omitempty"`
	Action     string        `json:"action,omitempty"`
	Label      string        `json:"label,omitempty"`
}
type apiResponse struct {
	Status int    `json:"status"`
	Body   []byte `json:"body"`
}

// Enrollment contains only public approval metadata. Secrets never cross IPC.
type Enrollment struct {
	ID          string    `json:"id"`
	Fingerprint string    `json:"fingerprint"`
	ApprovalURL string    `json:"approval_url"`
	Label       string    `json:"label"`
	Status      string    `json:"status"`
	Expires     time.Time `json:"expires"`
}
type agentAuthorization struct {
	Enrollment
	secret   string
	poll     string
	client   *http.Client
	ca       string
	lastPoll time.Time
}
type apiOwner struct {
	mu             sync.Mutex
	authorizations map[string]*agentAuthorization
}

func randomAPISecret() (string, error) {
	b := make([]byte, 32)
	defer clear(b)
	if _, e := io.ReadFull(rand.Reader, b); e != nil {
		return "", e
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
func commitment(secret string) string {
	h := sha256.Sum256([]byte(secret))
	return base64.RawURLEncoding.EncodeToString(h[:])
}
func apiHTTPClient(ca string, timeout time.Duration) (*http.Client, error) {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS13}
	if ca != "" {
		b, e := os.ReadFile(ca)
		if e != nil || len(b) > 1<<20 {
			return nil, errors.New("read private CA certificate")
		}
		roots, e := x509.SystemCertPool()
		if e != nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(b) {
			return nil, errors.New("invalid private CA certificate")
		}
		transport.TLSClientConfig.RootCAs = roots
	}
	return clienthttp.Client(&http.Client{Transport: transport, Timeout: timeout}, timeout), nil
}
func agentHTTP(ctx context.Context, hc *http.Client, origin, method, path string, body []byte, secret string, timeout time.Duration) (apiResponse, error) {
	req, e := http.NewRequestWithContext(ctx, method, origin+path, bytes.NewReader(body))
	if e != nil {
		return apiResponse{}, errors.New("invalid client request")
	}
	if method != "GET" {
		req.Header.Set("Content-Type", "application/json")
	}
	if secret != "" {
		req.Header.Set("Authorization", "Bearer "+secret)
	}
	// The credential outlives CLI invocations, not their configured HTTP timeout.
	// Copy the client without mutating shared transport/redirect/trust settings.
	requestClient := *hc
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	requestClient.Timeout = timeout
	res, e := requestClient.Do(req)
	if e != nil {
		return apiResponse{}, errors.New("HTTPS client request failed; check server availability and certificate trust")
	}
	defer res.Body.Close()
	b, e := io.ReadAll(io.LimitReader(res.Body, maxAPIResponse+1))
	if e != nil || len(b) > maxAPIResponse {
		return apiResponse{}, errors.New("client response exceeds bound or was interrupted")
	}
	return apiResponse{Status: res.StatusCode, Body: b}, nil
}
func enrollmentMessage(e Enrollment) string {
	return "Web approval required. Run warden login; open " + e.ApprovalURL + "; device " + e.Label + "; request " + e.ID + "; verify fingerprint " + e.Fingerprint + ". No data is available before fresh passkey approval."
}
func (s *Server) handleAPI(ctx context.Context, w net.Conn, request Request) {
	var b apiRequest
	if json.Unmarshal(request.Payload, &b) != nil {
		_ = writeFinal(w, Response{Error: "invalid API operation"})
		return
	}
	origin, err := clienthttp.Origin(b.Origin)
	if err != nil {
		_ = writeFinal(w, Response{Error: err.Error()})
		return
	}
	if b.BodyLength < 0 || b.BodyLength > 1<<20 || len(b.Body) != 0 {
		_ = writeFinal(w, Response{Error: "API request exceeds bound"})
		return
	}
	if b.BodyLength > 0 {
		for {
			f, e := ReadFrame(w)
			if e != nil {
				return
			}
			if f.Kind == FrameEOF {
				break
			}
			if f.Kind != FrameStdin || len(b.Body)+len(f.Data) > b.BodyLength {
				_ = writeFinal(w, Response{Error: "invalid API body stream"})
				return
			}
			b.Body = append(b.Body, f.Data...)
		}
		if len(b.Body) != b.BodyLength {
			_ = writeFinal(w, Response{Error: "incomplete API body stream"})
			return
		}
		defer clear(b.Body)
	}
	ctx, stop := watchDisconnect(ctx, w)
	defer stop()
	if b.Action == "" && !clienthttp.Allowed(b.Method, b.Path) {
		_ = writeFinal(w, Response{Error: "API capability not permitted"})
		return
	}
	if b.Action != "" && b.Action != "begin" && b.Action != "poll" && b.Action != "status" && b.Action != "logout" {
		_ = writeFinal(w, Response{Error: "invalid authorization operation"})
		return
	}
	o := &s.api
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.authorizations == nil {
		o.authorizations = make(map[string]*agentAuthorization)
	}
	a := o.authorizations[origin]
	if b.Action == "logout" {
		// Clear unconditionally, including cancellation/offline revoke failures.
		delete(o.authorizations, origin)
		if a != nil {
			defer func() { a.secret = ""; a.poll = ""; a.client.CloseIdleConnections() }()
			if a.Status == "approved" {
				_, _ = agentHTTP(ctx, a.client, origin, "POST", "/api/v1/client/logout", []byte(`{}`), a.secret, b.Timeout)
			}
		}
		s.writeAPIResult(w, Enrollment{Status: "logged_out"})
		return
	}
	if a != nil && a.ca != b.CA {
		_ = writeFinal(w, Response{Error: "CA configuration changed; log out before pairing again"})
		return
	}
	if a != nil && a.Status == "pending" && !time.Now().Before(a.Expires) {
		delete(o.authorizations, origin)
		a.secret = ""
		a.poll = ""
		a.client.CloseIdleConnections()
		a = nil
	}
	if b.Action == "status" {
		if a == nil {
			s.writeAPIResult(w, Enrollment{Status: "unpaired"})
			return
		}
		if a.Status == "approved" {
			res, e := agentHTTP(ctx, a.client, origin, "GET", "/api/v1/client/status", nil, a.secret, b.Timeout)
			if e != nil {
				_ = writeFinal(w, Response{Error: e.Error()})
				return
			}
			if res.Status == 401 {
				a.Status = "revoked"
				a.secret = ""
			} else if res.Status != 200 && res.Status != 423 {
				_ = writeFinal(w, Response{Error: "authorization status unavailable; agent credential retained in memory"})
				return
			}
		}
		s.writeAPIResult(w, a.Enrollment)
		return
	}
	if a == nil || a.Status == "denied" || a.Status == "revoked" {
		if b.Action == "poll" {
			_ = writeFinal(w, Response{Error: "pairing expired; run warden login"})
			return
		}
		if a == nil && len(o.authorizations) >= 8 {
			_ = writeFinal(w, Response{Error: "too many client origins; log out an unused origin"})
			return
		}
		hc, e := apiHTTPClient(b.CA, b.Timeout)
		if e != nil {
			_ = writeFinal(w, Response{Error: e.Error()})
			return
		}
		secret, e := randomAPISecret()
		if e != nil {
			_ = writeFinal(w, Response{Error: "credential generation failed"})
			return
		}
		label := b.Label
		if label == "" {
			label = "warden CLI"
		}
		payload, _ := json.Marshal(map[string]string{"commitment": commitment(secret), "label": label})
		res, e := agentHTTP(ctx, hc, origin, "POST", "/api/v1/client/pairing", payload, "", b.Timeout)
		if e != nil || res.Status != 200 {
			hc.CloseIdleConnections()
			_ = writeFinal(w, Response{Error: "HTTPS pairing failed; check server availability, certificate trust and rate limits"})
			return
		}
		var created struct {
			ID          string    `json:"id"`
			Poll        string    `json:"poll_secret"`
			Fingerprint string    `json:"fingerprint"`
			ApprovalURL string    `json:"approval_url"`
			Expires     time.Time `json:"expires"`
		}
		if json.Unmarshal(res.Body, &created) != nil || created.Fingerprint != commitment(secret) || !validAPISecret(created.ID) || !validAPISecret(created.Poll) || !created.Expires.After(time.Now()) || created.Expires.After(time.Now().Add(5*time.Minute+time.Second)) {
			hc.CloseIdleConnections()
			_ = writeFinal(w, Response{Error: "invalid enrollment response"})
			return
		}
		a = &agentAuthorization{Enrollment: Enrollment{ID: created.ID, Fingerprint: created.Fingerprint, ApprovalURL: origin + "/?device=" + url.QueryEscape(created.ID), Expires: created.Expires, Label: label, Status: "pending"}, secret: secret, poll: created.Poll, client: hc, ca: b.CA}
		o.authorizations[origin] = a
	}
	if (b.Action == "poll" || b.Action == "begin" || b.Action == "") && a.Status == "pending" && time.Since(a.lastPoll) >= time.Second {
		a.lastPoll = time.Now()
		payload, _ := json.Marshal(map[string]string{"id": a.ID, "poll_secret": a.poll})
		res, e := agentHTTP(ctx, a.client, origin, "POST", "/api/v1/client/poll", payload, "", b.Timeout)
		if e != nil {
			_ = writeFinal(w, Response{Error: e.Error()})
			return
		}
		if res.Status != 200 {
			_ = writeFinal(w, Response{Error: "pairing unavailable or rate limited; retry login"})
			return
		}
		var status struct {
			Status string `json:"status"`
		}
		if json.Unmarshal(res.Body, &status) != nil || (status.Status != "pending" && status.Status != "approved" && status.Status != "denied") {
			_ = writeFinal(w, Response{Error: "invalid pairing status"})
			return
		}
		a.Status = status.Status
		if a.Status != "pending" {
			a.poll = ""
		}
		if a.Status == "denied" {
			a.secret = ""
		}
	}
	if b.Action != "" {
		s.writeAPIResult(w, a.Enrollment)
		return
	}
	if a.Status != "approved" {
		_ = writeFinal(w, Response{Error: enrollmentMessage(a.Enrollment)})
		return
	}
	res, e := agentHTTP(ctx, a.client, origin, b.Method, b.Path, b.Body, a.secret, b.Timeout)
	if e != nil {
		_ = writeFinal(w, Response{Error: e.Error()})
		return
	}
	containsSecret := containsAuthorization(res.Body, a.secret, a.poll)
	if res.Status == 401 {
		a.Status = "revoked"
		a.secret = ""
	}
	if containsSecret {
		_ = writeFinal(w, Response{Error: "server response contained authorization material"})
		return
	}
	s.writeAPIResult(w, res)
}
func validAPISecret(s string) bool {
	b, e := base64.RawURLEncoding.DecodeString(s)
	return e == nil && len(b) == 32 && base64.RawURLEncoding.EncodeToString(b) == s
}
func containsAuthorization(body []byte, secrets ...string) bool {
	for _, s := range secrets {
		if s == "" {
			continue
		}
		raw, _ := base64.RawURLEncoding.DecodeString(s)
		if bytes.Contains(body, []byte(s)) || bytes.Contains(body, raw) || bytes.Contains(body, []byte(base64.StdEncoding.EncodeToString([]byte(s)))) {
			return true
		}
	}
	return false
}
func (s *Server) writeAPIResult(w io.Writer, v any) {
	data, e := json.Marshal(v)
	if e != nil {
		_ = writeFinal(w, Response{Error: "API encoding failed"})
		return
	}
	defer clear(data)
	stream := (&frameWriter{w: w}).stream(FrameStdout)
	for len(data) > 0 {
		n := min(len(data), 32<<10)
		if _, e = stream.Write(data[:n]); e != nil {
			return
		}
		data = data[n:]
	}
	_ = writeFinal(w, Response{})
}

// Transport carries only explicitly allowed operations over the existing pinned
// IPC channel. It never receives or synthesizes an API bearer credential.
type Transport struct {
	Origin, CA string
	Timeout    time.Duration
}

func (t Transport) RoundTrip(r *http.Request) (*http.Response, error) {
	origin, e := clienthttp.Origin(t.Origin)
	if e != nil {
		return nil, e
	}
	if r.URL.Scheme+"://"+r.URL.Host != origin || !clienthttp.Allowed(r.Method, r.URL.RequestURI()) {
		return nil, errors.New("API capability or origin not permitted")
	}
	var body []byte
	if r.Body != nil {
		body, e = io.ReadAll(io.LimitReader(r.Body, (1<<20)+1))
		_ = r.Body.Close()
		if e != nil || len(body) > 1<<20 {
			return nil, errors.New("API body exceeds bound")
		}
	}
	var result apiResponse
	e = callAPI(r.Context(), apiRequest{Origin: origin, CA: t.CA, Timeout: t.Timeout, Method: r.Method, Path: r.URL.RequestURI(), Body: body}, &result)
	if e != nil {
		return nil, e
	}
	return &http.Response{StatusCode: result.Status, Status: http.StatusText(result.Status), Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(bytes.NewReader(result.Body)), Request: r}, nil
}
func Authorization(ctx context.Context, origin, ca string, timeout time.Duration, action, label string) (Enrollment, error) {
	var result Enrollment
	err := callAPI(ctx, apiRequest{Origin: origin, CA: ca, Timeout: timeout, Action: action, Label: label}, &result)
	return result, err
}
func callAPI(ctx context.Context, r apiRequest, dst any) error {
	body := r.Body
	r.Body = nil
	r.BodyLength = len(body)
	payload, e := json.Marshal(r)
	if e != nil {
		return e
	}
	var out boundedAPIOutput
	e = runRequest(ctx, Request{Operation: operationAPI, Payload: payload}, clientssh.Streams{Stdout: &out, Stdin: bytes.NewReader(body)}, len(body) > 0)
	if e != nil {
		return e
	}
	if e = json.Unmarshal(out.Bytes(), dst); e != nil {
		return errors.New("invalid agent API response")
	}
	return nil
}

type boundedAPIOutput struct{ bytes.Buffer }

func (b *boundedAPIOutput) Write(p []byte) (int, error) {
	if b.Len()+len(p) > 6<<20 {
		return 0, errors.New("agent API response exceeds bound")
	}
	return b.Buffer.Write(p)
}
