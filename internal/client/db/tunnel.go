// Package db implements local MySQL/MariaDB execution for the warden
// client. Credentials and SQL text are held in memory only and are never
// written to files, command arguments, or logs. Profiles referencing an
// SSH graph are executed through an in-process tunnel dialer.
package db

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"

	golangssh "golang.org/x/crypto/ssh"

	"warden/internal/client/ssh"
	"warden/internal/model"
)

// TunnelDialer establishes SSH-tunneled connections to a database
// host:port. Each DialContext call opens a direct-tcpip channel through
// the resolved SSH graph and returns it as a net.Conn, so no local
// listener, ephemeral file, or config is needed. Close tears down every
// client in the chain synchronously.
type TunnelDialer struct {
	mu     sync.Mutex
	target *golangssh.Client
	chain  []*golangssh.Client
	dbAddr string
}

// NewTunnelDialer resolves the bundle's SSH graph and returns a dialer
// that tunnels to dbAddr. Any failure during graph setup closes every
// partially established connection; no partial dialer is returned.
func NewTunnelDialer(ctx context.Context, bundle model.SSHBundle, dbAddr string) (*TunnelDialer, error) {
	target, chain, err := ssh.DialChain(ctx, bundle, ssh.DialOptions{})
	if err != nil {
		return nil, err
	}
	return &TunnelDialer{target: target, chain: chain, dbAddr: dbAddr}, nil
}

// DialContext returns a direct-tcpip channel through the tunnel to the
// database host:port the dialer was created for. It is compatible with the
// mysql driver's Config.DialFunc: the network and addr passed by the
// driver are ignored because the tunnel destination is fixed at
// construction time. A canceled context fails the dial immediately; the
// mysql driver additionally closes the returned connection when its own
// query context is canceled, which unblocks any in-flight read.
func (d *TunnelDialer) DialContext(ctx context.Context, _ string, _ string) (net.Conn, error) {
	d.mu.Lock()
	target := d.target
	d.mu.Unlock()
	if target == nil {
		return nil, errors.New("db tunnel is closed")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	conn, err := target.Dial("tcp", d.dbAddr)
	if err != nil {
		return nil, fmt.Errorf("tunnel to %s: %w", d.dbAddr, err)
	}
	return conn, nil
}

// Close closes every SSH client in the tunnel's chain (jumps and target)
// synchronously. Subsequent DialContext calls fail. Close is idempotent.
func (d *TunnelDialer) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.target == nil {
		return nil
	}
	var firstErr error
	for _, c := range d.chain {
		if err := c.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	d.target = nil
	return firstErr
}
