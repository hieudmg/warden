// Package hostkey provides host-key verification against the platform
// standard known_hosts file, with optional interactive first-use
// acceptance.
package hostkey

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// Callback returns an ssh.HostKeyCallback that verifies keys against the
// known_hosts file at path. Known keys are accepted. Changed keys are
// always rejected. Unknown keys are rejected unless acceptNew is true and
// the key is confirmed interactively on terminal; a nil terminal means
// noninteractive mode, where unknown keys always fail.
func Callback(path string, acceptNew bool, terminal io.ReadWriter) (ssh.HostKeyCallback, error) {
	base, err := loadKnownHosts(path)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
		// First use: no file yet, so no known keys.
		base = func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return &knownhosts.KeyError{}
		}
	}

	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		err := base(hostname, remote, key)
		if err == nil {
			return nil
		}
		var keyErr *knownhosts.KeyError
		if !errors.As(err, &keyErr) {
			return err
		}
		if len(keyErr.Want) > 0 {
			// A key was previously accepted for this host and now
			// differs: potential MITM, always fail.
			return fmt.Errorf("host key for %s has changed (remote SHA-256 %s); refusing to connect",
				knownhosts.Normalize(hostname), ssh.FingerprintSHA256(key))
		}
		return handleUnknown(hostname, key, path, acceptNew, terminal)
	}, nil
}

// loadKnownHosts returns a host-key database for the file at path.
// Malformed lines are tolerated the way OpenSSH tolerates them: a single
// bad line never fails every connection. The file is first loaded with the
// strict x/crypto parser; when a bad line makes that fail, only the lines
// passing the same validation rules are loaded from a filtered copy.
func loadKnownHosts(path string) (ssh.HostKeyCallback, error) {
	base, err := knownhosts.New(path)
	if err == nil {
		return base, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		filtered, skipped, ferr := filterKnownHosts(path)
		if ferr != nil {
			return nil, ferr
		}
		if skipped > 0 {
			fmt.Fprintf(os.Stderr, "warden: skipping %d malformed line(s) in known_hosts %q (OpenSSH-style tolerance)\n",
				skipped, path)
		}
		base, err = knownhosts.New(filtered)
		os.Remove(filtered)
		if err != nil {
			return nil, fmt.Errorf("load known_hosts %q: %w", path, err)
		}
		return base, nil
	}
	return nil, err
}

// filterKnownHosts writes the parseable lines of path to a temporary file
// and returns its name plus the number of lines skipped.
func filterKnownHosts(path string) (name string, skipped int, err error) {
	raw, rerr := os.ReadFile(path)
	if rerr != nil {
		return "", 0, fmt.Errorf("load known_hosts %q: %w", path, rerr)
	}

	tmp, terr := os.CreateTemp("", "warden-known-hosts-*.conf")
	if terr != nil {
		return "", 0, fmt.Errorf("create filtered known_hosts: %w", terr)
	}
	name = tmp.Name()
	fail := func(e error) (string, int, error) {
		tmp.Close()
		os.Remove(name)
		return "", 0, e
	}

	var kept bytes.Buffer
	sc := bufio.NewScanner(bytes.NewReader(raw))
	for sc.Scan() {
		line := sc.Bytes()
		trimmed := bytes.Trim(line, " \t")
		if len(trimmed) == 0 || trimmed[0] == '#' {
			kept.Write(line)
			kept.WriteByte('\n')
			continue
		}
		if validKnownHostsLine(trimmed) {
			kept.Write(line)
			kept.WriteByte('\n')
		} else {
			skipped++
		}
	}
	if serr := sc.Err(); serr != nil {
		return fail(fmt.Errorf("read known_hosts %q: %w", path, serr))
	}
	if _, werr := tmp.Write(kept.Bytes()); werr != nil {
		return fail(fmt.Errorf("write filtered known_hosts: %w", werr))
	}
	if cerr := tmp.Close(); cerr != nil {
		os.Remove(name)
		return "", 0, fmt.Errorf("write filtered known_hosts: %w", cerr)
	}
	return name, skipped, nil
}

// validKnownHostsLine reports whether line would parse under
// x/crypto/ssh/knownhosts, mirroring its parseLine and matcher validation
// so malformed lines can be skipped instead of failing every connection.
func validKnownHostsLine(line []byte) bool {
	fields := strings.Fields(string(line))
	if len(fields) == 0 {
		return false
	}
	i := 0
	if fields[0] == "@cert-authority" || fields[0] == "@revoked" {
		i = 1
	}
	// Marker alone, or an unknown/doubled marker.
	if i >= len(fields) || strings.HasPrefix(fields[i], "@") {
		return false
	}
	// Need a key type and a key blob after the host pattern.
	if i+2 >= len(fields) {
		return false
	}
	if !validHostPattern(fields[i]) {
		return false
	}
	blob, err := base64.StdEncoding.DecodeString(fields[i+2])
	if err != nil {
		return false
	}
	key, err := ssh.ParsePublicKey(blob)
	if err != nil {
		return false
	}
	return key.Type() == fields[i+1]
}

// validHostPattern mirrors knownhosts.newHostnameMatcher and
// newHashedHost error conditions for a host pattern.
func validHostPattern(pattern string) bool {
	if strings.HasPrefix(pattern, "|") {
		parts := strings.Split(pattern, "|")
		if len(parts) != 4 || parts[1] != "1" {
			return false
		}
		if _, err := base64.StdEncoding.DecodeString(parts[2]); err != nil {
			return false
		}
		if _, err := base64.StdEncoding.DecodeString(parts[3]); err != nil {
			return false
		}
		return true
	}
	for _, p := range strings.Split(pattern, ",") {
		if p == "" {
			continue
		}
		if p[0] == '!' {
			p = p[1:]
			if p == "" {
				return false
			}
		}
		if p[0] == '[' {
			if _, _, err := net.SplitHostPort(p); err != nil {
				return false
			}
		}
	}
	return true
}

// handleUnknown verifies an unknown host key. With acceptNew an interactive
// terminal is prompted, and confirmation persists the key. In every other
// case (no --accept-new, no terminal, or refused confirmation) the key is
// rejected.
func handleUnknown(hostname string, key ssh.PublicKey, path string, acceptNew bool, terminal io.ReadWriter) error {
	normalized := knownhosts.Normalize(hostname)
	if !acceptNew {
		return fmt.Errorf("unknown host key for %s: SHA-256 %s; use --accept-new with an interactive terminal to trust it",
			normalized, ssh.FingerprintSHA256(key))
	}
	if terminal == nil {
		return fmt.Errorf("unknown host key for %s: SHA-256 %s; --accept-new requires an interactive terminal",
			normalized, ssh.FingerprintSHA256(key))
	}
	if !confirmHost(terminal, normalized, key) {
		return fmt.Errorf("host key for %s was not accepted", normalized)
	}
	return persist(path, hostname, key)
}

// confirmHost prints the fingerprint and requires an explicit "yes".
func confirmHost(terminal io.ReadWriter, hostname string, key ssh.PublicKey) bool {
	fmt.Fprintf(terminal, "The authenticity of host %q can't be established.\n", hostname)
	fmt.Fprintf(terminal, "%s key fingerprint is %s.\n", key.Type(), ssh.FingerprintSHA256(key))
	fmt.Fprintf(terminal, "Are you sure you want to continue connecting (yes/no)? ")

	reader := bufio.NewReader(terminal)
	line, err := reader.ReadString('\n')
	if err != nil && line == "" {
		return false
	}
	return strings.TrimSpace(line) == "yes"
}

// persist appends the accepted key to the known_hosts file, creating the
// file and its directory with restrictive permissions.
func persist(path, hostname string, key ssh.PublicKey) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("create known_hosts directory: %w", err)
	}
	line := knownhosts.Line([]string{hostname}, key) + "\n"

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("open known_hosts %q: %w", path, err)
	}
	defer f.Close()
	if _, err := f.WriteString(line); err != nil {
		return fmt.Errorf("append to known_hosts %q: %w", path, err)
	}
	return nil
}
