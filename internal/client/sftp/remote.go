package sftp

import (
	"context"
	"net"
	"strconv"
	"strings"
	"sync"

	pkgsftp "github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	clientssh "warden/internal/client/ssh"
	"warden/internal/model"
)

// Remote owns one SFTP session. A Remote returned by Dial also owns the SSH
// graph created for that one-shot operation; a Remote returned by Open borrows
// its target and never closes the graph.
type Remote struct {
	client       *pkgsftp.Client
	closeGraph   func() error
	identity     string
	hostIdentity string
	mu           sync.Mutex
}

// Dial connects through the bundle's ordered jump chain and opens an SFTP
// session on the target. The returned Remote owns the graph for this
// one-shot compatibility API and closes it after the SFTP session. If the
// SFTP handshake fails, every established SSH connection is closed before
// returning.
func Dial(ctx context.Context, bundle model.SSHBundle) (*Remote, error) {
	graph, err := clientssh.DialGraph(ctx, bundle, clientssh.DialOptions{})
	if err != nil {
		return nil, err
	}
	remote, err := Open(graph.Target(), bundle)
	if err != nil {
		_ = graph.Close()
		return nil, err
	}
	remote.closeGraph = graph.Close
	return remote, nil
}

// Open starts one SFTP session on an established SSH target. The returned
// Remote borrows target: its Close method closes only the SFTP session and
// leaves the SSH graph available to other operations.
func Open(target *ssh.Client, bundle model.SSHBundle) (*Remote, error) {
	client, err := pkgsftp.NewClient(target)
	if err != nil {
		return nil, err
	}
	return &Remote{
		client:       client,
		identity:     strconv.FormatInt(bundle.Target.ID, 10),
		hostIdentity: remoteHostIdentity(bundle.Target.Host, bundle.Target.Port),
	}, nil
}

// remoteHostIdentity identifies a configured target by its case-insensitive
// host and port. It deliberately uses the configured address rather than a
// DNS lookup so aliases remain distinct unless their profiles spell the same
// host and port.
func remoteHostIdentity(host string, port int) string {
	return net.JoinHostPort(strings.ToLower(host), strconv.Itoa(port))
}

// Endpoint returns an endpoint on this remote's filesystem. The identity is
// the selected profile ID from the transport bundle, so two independent
// dials for the same named profile still share a namespace identity.
func (r *Remote) Endpoint(name string) Endpoint {
	return Endpoint{
		FS:           NewRemoteFilesystem(r.client),
		Path:         name,
		Identity:     r.identity,
		HostIdentity: r.hostIdentity,
	}
}

// Close tears down the SFTP session and, when this Remote was created by
// Dial, then closes its owned SSH graph. A borrowed Remote created by Open
// leaves the target untouched. It retains the first error and is idempotent:
// a second Close returns nil.
func (r *Remote) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	var firstErr error
	if r.client != nil {
		if err := r.client.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		r.client = nil
	}
	closeGraph := r.closeGraph
	r.closeGraph = nil
	if closeGraph != nil {
		if err := closeGraph(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
