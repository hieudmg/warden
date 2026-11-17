package model

import (
	"errors"
	"mime"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// HTTPProfile holds plaintext secrets only inside the server. Nil secret fields
// preserve on update; non-nil fields replace (including empty to clear).
// Changing AuthType clears all old secrets before applying supplied fields.
type HTTPProfile struct {
	ID         int64
	Name       string
	Origin     string
	AuthType   string
	Note       string
	Credential []byte
	Username   []byte
	Password   []byte
	GroupID    int64
	GroupName  string
	Archived   bool
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// HTTPConnection is metadata only, including for single-record GETs.
type HTTPConnection struct {
	ID            int64     `json:"id"`
	Name          string    `json:"name"`
	Origin        string    `json:"origin"`
	AuthType      string    `json:"auth_type"`
	Note          string    `json:"note"`
	GroupID       int64     `json:"group_id"`
	GroupName     string    `json:"group_name,omitempty"`
	HasCredential bool      `json:"has_credential"`
	HasUsername   bool      `json:"has_username"`
	HasPassword   bool      `json:"has_password"`
	Archived      bool      `json:"archived"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// HTTPConnectionRequest replaces metadata. Omitted or null secret fields keep
// values only when auth_type is unchanged; empty strings explicitly clear.
// credential is for bearer/x_api_key; username/password are for basic only.
type HTTPConnectionRequest struct {
	Name       string  `json:"name"`
	Origin     string  `json:"origin"`
	AuthType   string  `json:"auth_type"`
	Note       string  `json:"note"`
	GroupID    int64   `json:"group_id"`
	Credential *string `json:"credential,omitempty"`
	Username   *string `json:"username,omitempty"`
	Password   *string `json:"password,omitempty"`
}

const (
	HTTPMaxRequestBytes  = 1 << 20
	HTTPMaxResponseBytes = 2 << 20
	HTTPOperationTimeout = 15 * time.Second
)

// HTTPProxyRequest contains no caller-selected headers or host. []byte bodies
// use JSON base64, so arbitrary upstream bytes survive the JSON API envelope.
type HTTPProxyRequest struct {
	Method      string `json:"method"`
	Path        string `json:"path"`
	Body        []byte `json:"body,omitempty"`
	ContentType string `json:"content_type,omitempty"`
}

// HTTPProxyResponse uses a Warden 200 envelope even for upstream non-2xx.
// No upstream headers are returned to Warden's origin.
type HTTPProxyResponse struct {
	StatusCode int    `json:"status_code"`
	Body       []byte `json:"body"`
}

// TransferHTTPConnection carries plaintext credentials for explicit full-data
// migration only. Notes travel in the bundle's connection_notes collection.
type TransferHTTPConnection struct {
	ID         int64     `json:"id"`
	Name       string    `json:"name"`
	Origin     string    `json:"origin"`
	AuthType   string    `json:"auth_type"`
	Credential string    `json:"credential"`
	Username   string    `json:"username"`
	Password   string    `json:"password"`
	GroupID    int64     `json:"group_id"`
	Archived   bool      `json:"archived,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// ValidateHTTPProxyRequest shares method/path/media-type validation across the
// CLI and server. Size bounds are enforced separately before transport work.
func ValidateHTTPProxyRequest(req HTTPProxyRequest) error {
	switch req.Method {
	case "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS":
	default:
		return errors.New("method must be GET, HEAD, POST, PUT, PATCH, DELETE or OPTIONS")
	}
	if len(req.Path) > 8192 || !strings.HasPrefix(req.Path, "/") || strings.HasPrefix(req.Path, "//") || strings.ContainsAny(req.Path, "#\\") {
		return errors.New("path must be origin-relative without fragments")
	}
	for _, c := range req.Path {
		if c <= 0x20 || c == 0x7f {
			return errors.New("path must not contain whitespace or control characters")
		}
	}
	u, err := url.ParseRequestURI(req.Path)
	if err != nil || u.IsAbs() || u.Host != "" || u.User != nil {
		return errors.New("invalid origin-relative path")
	}
	if len(req.ContentType) > 256 || strings.ContainsAny(req.ContentType, "\r\n\x00") {
		return errors.New("invalid content_type")
	}
	if req.ContentType != "" {
		if _, _, err := mime.ParseMediaType(req.ContentType); err != nil {
			return errors.New("invalid content_type")
		}
	}
	return nil
}

// ValidateHTTPOrigin accepts exactly an HTTP(S) origin, never credentials,
// paths (even a trailing slash), queries, or fragments. Private hosts and
// plaintext HTTP are allowed by product policy; HTTPS uses verified TLS.
func ValidateHTTPOrigin(origin string) error {
	invalid := errors.New("origin must be http(s)://host[:port] without credentials, path, query or fragment")
	if len(origin) > 2048 || strings.ContainsAny(origin, "\\?#") {
		return invalid
	}
	u, err := url.Parse(origin)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.Hostname() == "" || u.User != nil || u.Path != "" || u.Opaque != "" || u.RawQuery != "" || u.Fragment != "" {
		return invalid
	}
	for _, r := range origin {
		if r <= 0x20 || r == 0x7f {
			return invalid
		}
	}
	if strings.HasPrefix(u.Host, "[") {
		address, err := netip.ParseAddr(u.Hostname())
		if err != nil || !address.Is6() {
			return invalid
		}
	} else if strings.Contains(u.Hostname(), ":") {
		return invalid // IPv6 literals require brackets, even without a port.
	}
	if strings.HasSuffix(u.Host, ":") {
		return invalid
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return invalid
		}
	}
	return nil
}
