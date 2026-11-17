package config

import (
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// Setup is non-secret immutable relying-party and HTTPS transport configuration.
type Setup struct {
	AuthMethod       string `json:"auth_method,omitempty"`
	PublicOrigin     string `json:"public_origin"`
	RPID             string `json:"rp_id"`
	Mode             string `json:"mode"`
	TLSCertificate   string `json:"tls_certificate,omitempty"`
	TLSKey           string `json:"tls_key,omitempty"`
	BackendAuthority string `json:"backend_authority,omitempty"`
}

// Missing mode is the legacy passkey contract, never the new-init default.
func (s Setup) AuthenticationMethod() string {
	if s.AuthMethod == "" {
		return "passkey"
	}
	return s.AuthMethod
}

func (s Setup) Validate(bind string) error {
	if s.AuthenticationMethod() != "passkey" && s.AuthenticationMethod() != "account" {
		return errors.New("authentication method must be account or passkey")
	}
	invalid := errors.New("setup requires a canonical HTTPS origin, valid RP ID, and direct TLS or literal-loopback proxy configuration")
	u, err := url.Parse(s.PublicOrigin)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || u.String() != s.PublicOrigin || u.Host != strings.ToLower(u.Host) {
		return invalid
	}
	host := u.Hostname()
	if host == "" || strings.HasSuffix(host, ".") || strings.ContainsAny(host, "%\\ \t\n") {
		return invalid
	}
	if strings.HasSuffix(u.Host, ":") {
		return invalid
	}
	if u.Port() != "" {
		port, err := strconv.Atoi(u.Port())
		if err != nil || port == 443 || strconv.Itoa(port) != u.Port() {
			return invalid
		}
		if err := validateListenAddr(net.JoinHostPort(host, u.Port())); err != nil {
			return invalid
		}
	}
	rp := s.RPID
	if rp == "" || rp != strings.ToLower(rp) || strings.ContainsAny(rp, ":/\\?#@% \t\n") || strings.HasSuffix(rp, ".") || (host != rp && !strings.HasSuffix(host, "."+rp)) {
		return invalid
	}
	if net.ParseIP(host) != nil {
		return invalid
	} // WebAuthn RP IDs are domain names, not IP addresses.
	suffix, _ := publicsuffix.PublicSuffix(rp)
	if rp != "localhost" && suffix == rp {
		return invalid
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return invalid
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return invalid
			}
		}
	}
	if err := validateListenAddr(bind); err != nil {
		return err
	}
	switch s.Mode {
	case "tls":
		if s.TLSCertificate == "" || s.TLSKey == "" || s.BackendAuthority != "" {
			return invalid
		}
	case "proxy":
		h, _, _ := net.SplitHostPort(bind)
		ip := net.ParseIP(h)
		if ip == nil || !ip.IsLoopback() || s.BackendAuthority != bind || s.TLSCertificate != "" || s.TLSKey != "" {
			return invalid
		}
	default:
		return invalid
	}
	return nil
}
