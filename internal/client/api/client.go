// Package api implements the warden HTTP API client used by the CLI.
//
// The client talks only to the warden-server API over JSON. It never
// touches SQLite or server-side config files. Secret-bearing transport
// responses are held in client memory only and are never logged.
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"warden/internal/model"
)

// maxResponseBytes bounds API response bodies. Profiles and transport
// bundles are small; the bound protects against a compromised or buggy
// server sending unbounded data.
const maxResponseBytes = 4 << 20 // 4 MiB

// maxErrorMessageBytes bounds server-provided error message text. The CLI
// prints APIError messages to stderr, so a compromised or buggy server
// must not be able to push unbounded body text into process output.
const maxErrorMessageBytes = 1024

// APIError is the client-side representation of a non-2xx API response.
// Code is the stable machine-readable error code from the server.
type APIError struct {
	StatusCode int
	Code       string
	Message    string
}

func (e *APIError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("api: %s (%s): %s", e.Code, http.StatusText(e.StatusCode), e.Message)
	}
	return fmt.Sprintf("api: %s: %s", http.StatusText(e.StatusCode), e.Message)
}

// Client is a minimal HTTP client for the warden API.
type Client struct {
	baseURL string
	http    *http.Client
}

// New returns a client rooted at baseURL. A nil http client gets a default
// 30s timeout.
func New(baseURL string, hc *http.Client) *Client {
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	return &Client{baseURL: strings.TrimRight(baseURL, "/"), http: hc}
}

// ListSSH returns redacted SSH connection metadata.
func (c *Client) ListSSH(ctx context.Context) ([]model.SSHConnection, error) {
	var out []model.SSHConnection
	err := c.getJSON(ctx, "/api/v1/ssh-connections", &out)
	return out, err
}

// GetSSH returns one redacted SSH connection.
func (c *Client) GetSSH(ctx context.Context, id int64) (model.SSHConnection, error) {
	var out model.SSHConnection
	err := c.getJSON(ctx, "/api/v1/ssh-connections/"+strconv.FormatInt(id, 10), &out)
	return out, err
}

// GetSSHBundle returns the resolved SSH transport bundle for id. The
// response contains decrypted secrets and is intended for client-local
// execution only.
func (c *Client) GetSSHBundle(ctx context.Context, id int64) (model.SSHBundle, error) {
	var out model.SSHBundle
	err := c.getJSON(ctx, "/api/v1/transport/ssh/"+strconv.FormatInt(id, 10), &out)
	return out, err
}

// ListDB returns redacted DB connection metadata.
func (c *Client) ListDB(ctx context.Context) ([]model.DBConnection, error) {
	var out []model.DBConnection
	err := c.getJSON(ctx, "/api/v1/db-connections", &out)
	return out, err
}

// GetDB returns one redacted DB connection.
func (c *Client) GetDB(ctx context.Context, id int64) (model.DBConnection, error) {
	var out model.DBConnection
	err := c.getJSON(ctx, "/api/v1/db-connections/"+strconv.FormatInt(id, 10), &out)
	return out, err
}

// GetDBBundle returns the resolved DB transport bundle for id. An optional
// database selector chooses a named database; when omitted, the server uses
// the profile's default.
func (c *Client) GetDBBundle(ctx context.Context, id int64, databaseName ...string) (model.DBBundle, error) {
	path := "/api/v1/transport/db/" + strconv.FormatInt(id, 10)
	if len(databaseName) > 0 && databaseName[0] != "" {
		path += "?" + url.Values{"database": {databaseName[0]}}.Encode()
	}
	var out model.DBBundle
	err := c.getJSON(ctx, path, &out)
	return out, err
}

// SSHDependents returns profiles referencing an SSH connection id.
func (c *Client) SSHDependents(ctx context.Context, id int64) (model.DependentsResponse, error) {
	var out model.DependentsResponse
	err := c.getJSON(ctx, "/api/v1/ssh-connections/"+strconv.FormatInt(id, 10)+"/dependents", &out)
	return out, err
}

// DBDependents returns profiles referencing a DB connection id (always
// empty in the current schema; kept for API surface parity).
func (c *Client) DBDependents(ctx context.Context, id int64) (model.DependentsResponse, error) {
	var out model.DependentsResponse
	err := c.getJSON(ctx, "/api/v1/db-connections/"+strconv.FormatInt(id, 10)+"/dependents", &out)
	return out, err
}

// GetJSON performs a GET and strictly decodes a successful JSON response.
// It is the exported form of getJSON used by API surface extensions that
// live outside this package (e.g. reports).
func (c *Client) GetJSON(ctx context.Context, path string, dst any) error {
	return c.getJSON(ctx, path, dst)
}

// getJSON performs a GET and strictly decodes a successful JSON response.
// Bodies are bounded and always closed; errors are sanitized API errors.
func (c *Client) getJSON(ctx context.Context, path string, dst any) error {
	return c.requestJSON(ctx, http.MethodGet, path, nil, dst, http.StatusOK)
}

// PostJSON performs a POST with a JSON body and strictly decodes a
// successful JSON response (200 OK or 201 Created). It is used by API
// surface extensions (e.g. reports) that live outside this package.
func (c *Client) PostJSON(ctx context.Context, path string, body any, dst any) error {
	return c.requestJSON(ctx, http.MethodPost, path, body, dst, http.StatusOK, http.StatusCreated)
}

// requestJSON performs a request, bounds and closes the body, maps non-2xx
// responses to *APIError, and strictly decodes a successful response into
// dst. Accepting several success statuses is required by endpoints that
// create resources (201) and those that idempotently retrieve (200).
func (c *Client) requestJSON(ctx context.Context, method, path string, body any, dst any, successCodes ...int) error {
	var reader io.Reader
	if body != nil {
		payload, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("encode %s body: %w", path, err)
		}
		reader = bytes.NewReader(payload)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return fmt.Errorf("build request %s: %w", path, err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("request %s: %w", path, err)
	}
	defer resp.Body.Close()

	if !statusAccepted(resp.StatusCode, acceptCodes(successCodes)) {
		return parseErrError(resp)
	}

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return fmt.Errorf("read %s response: %w", path, err)
	}
	if len(bodyBytes) > maxResponseBytes {
		return fmt.Errorf("read %s response: body too large", path)
	}

	dec := json.NewDecoder(bytes.NewReader(bodyBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return fmt.Errorf("decode %s response: %w", path, err)
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return fmt.Errorf("decode %s response: unexpected trailing data", path)
	}
	return nil
}

func statusAccepted(status int, codes []int) bool {
	for _, c := range codes {
		if status == c {
			return true
		}
	}
	return false
}

// acceptCodes returns the effective set of accepted status codes.
func acceptCodes(codes []int) []int {
	if len(codes) == 0 {
		return []int{http.StatusOK}
	}
	return codes
}

// errorEnvelope mirrors the server's stable JSON error envelope.
type errorEnvelope struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// parseErrError converts a non-200 response into an *APIError. The
// server's JSON error envelope is decoded when present (message text
// bounded); otherwise the message is the HTTP status text only, never the
// raw body.
func parseErrError(resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	var envelope errorEnvelope
	if json.Unmarshal(body, &envelope) == nil && envelope.Code != "" {
		msg := strings.TrimSpace(envelope.Message)
		if len(msg) > maxErrorMessageBytes {
			msg = msg[:maxErrorMessageBytes]
		}
		return &APIError{StatusCode: resp.StatusCode, Code: envelope.Code, Message: msg}
	}
	msg := http.StatusText(resp.StatusCode)
	if msg == "" {
		msg = fmt.Sprintf("HTTP status %d", resp.StatusCode)
	}
	return &APIError{StatusCode: resp.StatusCode, Message: msg}
}
