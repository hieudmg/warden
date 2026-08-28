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

// Remote owns one SFTP session and the whole SSH jump chain behind it.
// Closing the Remote tears down the SFTP session first and then every SSH
// connection in the chain, so no socket or goroutine outlives the copy.
type Remote struct {
	client       *pkgsftp.Client
	target       *ssh.Client
	chain        []*ssh.Client
	identity     string
	hostIdentity string
	mu           sync.Mutex
}

// Dial connects through the bundle's ordered jump chain and opens an SFTP
// session on the target. If the SFTP handshake fails, every established
// SSH connection is closed before returning.
func Dial(ctx context.Context, bundle model.SSHBundle) (*Remote, error) {
	target, chain, err := clientssh.DialChain(ctx, bundle, clientssh.DialOptions{})
	if err != nil {
		return nil, err
	}
	client, err := pkgsftp.NewClient(target)
	if err != nil {
		for _, c := range chain {
			c.Close()
		}
		return nil, err
	}
	return &Remote{
		client:       client,
		target:       target,
		chain:        chain,
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

// Close tears down the SFTP session and then every SSH connection in the
// chain, retaining the first error. The chain is closed from the target
// backwards: each hop's transport runs through the previous hop, so closing
// a jump first would tear down the connections behind it. It is idempotent:
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
	for i := len(r.chain) - 1; i >= 0; i-- {
		if err := r.chain[i].Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	r.chain = nil
	return firstErr
}
