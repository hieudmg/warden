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
// host:port. Each DialContext call opens a direct-tcpip channel through the
// target and returns it as a net.Conn, so no local listener, ephemeral file,
// or config is needed. A borrowed dialer owns only its operation state; an
// owned dialer also closes the graph it created.
type TunnelDialer struct {
	mu         sync.Mutex
	target     *golangssh.Client
	dbAddr     string
	closeGraph func() error
	abort      func(string)
	lifetime   context.Context
	cancel     context.CancelFunc
	opens      sync.WaitGroup
	closed     chan struct{}
	closeErr   error
}

// NewTunnelDialer resolves the bundle's SSH graph and returns a dialer
// that tunnels to dbAddr. Any failure during graph setup closes every
// partially established connection; no partial dialer is returned.
func NewTunnelDialer(ctx context.Context, bundle model.SSHBundle, dbAddr string) (*TunnelDialer, error) {
	graph, err := ssh.DialGraph(ctx, bundle, ssh.DialOptions{})
	if err != nil {
		return nil, err
	}
	d := newTunnelDialer(graph.Target(), dbAddr, func(string) { graph.Abort() })
	d.closeGraph = graph.Close
	return d, nil
}

// BorrowedGraph retains ownership in the pool. Invalidate must abort this
// transport, remove it from reuse and record why; canceling an unconfirmed
// SSH channel request necessarily disrupts other users of the SAME graph.
type BorrowedGraph interface {
	Target() *golangssh.Client
	Invalidate(reason string)
}

// NewBorrowedTunnelDialer leaves a healthy graph alive on Close. Cancellation
// during an unconfirmed channel open instead invalidates that graph explicitly.
func NewBorrowedTunnelDialer(graph BorrowedGraph, dbAddr string) *TunnelDialer {
	return newTunnelDialer(graph.Target(), dbAddr, graph.Invalidate)
}

func newTunnelDialer(target *golangssh.Client, addr string, abort func(string)) *TunnelDialer {
	ctx, cancel := context.WithCancel(context.Background())
	d := &TunnelDialer{target: target, dbAddr: addr, abort: abort, lifetime: ctx, cancel: cancel, closed: make(chan struct{})}
	if target == nil {
		cancel()
		close(d.closed)
	}
	return d
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
	if target == nil {
		d.mu.Unlock()
		return nil, errors.New("db tunnel is closed")
	}
	d.opens.Add(1)
	d.mu.Unlock()
	defer d.opens.Done()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	cancelDone := make(chan struct{})
	stop := context.AfterFunc(d.lifetime, func() { defer close(cancelDone); cancel() })
	defer func() {
		if !stop() {
			<-cancelDone
		}
	}()
	defer cancel()
	conn, err := ssh.DialTCPContext(ctx, target, d.dbAddr, d.abort)
	if err != nil {
		return nil, fmt.Errorf("tunnel to %s: %w", d.dbAddr, err)
	}
	return conn, nil
}

// Close disables future dials and cancels in-progress opens. A borrowed graph
// is untouched unless aborting a pending open requires invalidation. Owned
// graphs always close. Close is idempotent.
func (d *TunnelDialer) Close() error {
	d.mu.Lock()
	if d.target == nil {
		d.mu.Unlock()
		if d.closed != nil {
			<-d.closed
		}
		return d.closeErr
	}
	closeGraph := d.closeGraph
	d.target = nil
	d.closeGraph = nil
	d.cancel()
	d.mu.Unlock()
	if closeGraph != nil {
		d.closeErr = closeGraph()
	}
	d.opens.Wait()
	close(d.closed)
	return d.closeErr
}
