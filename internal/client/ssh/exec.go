// Package ssh implements cross-platform SSH transport for the warden
// client: jump-chain dialing, HTTP CONNECT proxying, and noninteractive
// remote command execution. All networking uses Go libraries; no native
// ssh/sshpass tools are required.
package ssh

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"

	golangssh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"warden/internal/model"
)

// Streams carries the local I/O endpoints for a remote command.
type Streams struct {
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
}

// DialOptions controls how transport connections are established.
type DialOptions struct {
	// HostKeyCallback overrides host-key verification when non-nil.
	// When nil, verification uses known_hosts (see hostkey.Callback).
	HostKeyCallback golangssh.HostKeyCallback
	// KnownHostsPath is the known_hosts file used when HostKeyCallback
	// is nil. Empty means DefaultKnownHostsPath.
	KnownHostsPath string
	// AcceptNew allows unknown host keys to be accepted after
	// interactive confirmation (see hostkey.Callback).
	AcceptNew bool
	// Terminal is the interactive prompt used for --accept-new
	// confirmation. Nil means noninteractive: unknown keys always fail.
	Terminal io.ReadWriter
	// Progress receives non-secret interactive connection status messages.
	// It is ignored when nil.
	Progress func(string)
}

// ExitStatusError reports a remote command that exited nonzero.
type ExitStatusError struct {
	Status int
}

func (e *ExitStatusError) Error() string {
	return "remote command exited with status " + strconv.Itoa(e.Status)
}

// RunCommand connects through the bundle's jump chain using strict
// known_hosts verification and executes one remote command, streaming
// stdin/stdout/stderr. A nonzero remote exit status is returned as
// *ExitStatusError.
func RunCommand(ctx context.Context, bundle model.SSHBundle, command string, streams Streams) error {
	return runCommand(ctx, bundle, command, streams, DialOptions{})
}

// runCommand is RunCommand with explicit dial options (used by tests to
// inject host-key callbacks).
func runCommand(ctx context.Context, bundle model.SSHBundle, command string, streams Streams, opts DialOptions) error {
	client, err := DialTarget(ctx, bundle, opts)
	if err != nil {
		return err
	}
	defer client.Close()
	return runOnClient(ctx, client, command, streams)
}

// runOnClient executes one command on an established SSH client, streaming
// the local I/O endpoints and propagating the remote exit status.
func runOnClient(ctx context.Context, client *golangssh.Client, command string, streams Streams) error {
	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("open ssh session: %w", err)
	}
	defer session.Close()

	session.Stdout = streams.Stdout
	session.Stderr = streams.Stderr
	if streams.Stdin != nil {
		session.Stdin = streams.Stdin
	}

	forwardAgent(client, session)

	if err := session.Start(command); err != nil {
		return fmt.Errorf("start remote command: %w", err)
	}

	errCh := make(chan error, 1)
	go func() { errCh <- session.Wait() }()

	select {
	case err := <-errCh:
		if err == nil {
			return nil
		}
		var exitErr *golangssh.ExitError
		if errors.As(err, &exitErr) {
			return &ExitStatusError{Status: exitErr.ExitStatus()}
		}
		return fmt.Errorf("remote command failed: %w", err)
	case <-ctx.Done():
		// Closing the session aborts the running command; the Wait
		// goroutine then completes and exits.
		session.Close()
		return ctx.Err()
	}
}

// forwardAgent exposes the local ssh-agent to the remote session when the
// connection was authenticated through it. Failures are non-fatal: some
// servers disable agent forwarding.
func forwardAgent(client *golangssh.Client, session *golangssh.Session) {
	v, ok := clientAgents.Load(client)
	if !ok {
		return
	}
	keyring, ok := v.(agent.Agent)
	if !ok {
		return
	}
	if err := agent.ForwardToAgent(client, keyring); err != nil {
		return
	}
	_ = agent.RequestAgentForwarding(session)
}
