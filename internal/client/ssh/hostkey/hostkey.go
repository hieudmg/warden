// Package hostkey provides host-key verification against the platform
// standard known_hosts file, with optional interactive first-use
// acceptance.
package hostkey

import (
	"bufio"
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
	base, err := knownhosts.New(path)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("load known_hosts %q: %w", path, err)
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
