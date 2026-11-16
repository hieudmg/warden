package ssh

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	golangssh "golang.org/x/crypto/ssh"
)

// contextError also handles the interval where a socket deadline has fired
// but the context timer at that SAME deadline has not yet been scheduled.
func contextError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
		return context.DeadlineExceeded
	}
	return nil
}

// stopCancellation stops AND joins an abort callback. Joining before publishing
// a reusable connection prevents a late callback from closing the next borrow.
func stopCancellation(ctx context.Context, abort func()) func() error {
	done := make(chan struct{})
	var abortOnce sync.Once
	abortOwned := func() { abortOnce.Do(abort) }
	stop := context.AfterFunc(ctx, func() { defer close(done); abortOwned() })
	var once sync.Once
	var err error
	return func() error {
		once.Do(func() {
			if !stop() {
				<-done
			}
			err = contextError(ctx)
			// Stopping may win just before cancellation becomes observable,
			// including an elapsed deadline before timer delivery. A canceled
			// result still needs its owner aborted BEFORE channel cleanup.
			if err != nil {
				abortOwned()
			}
		})
		return err
	}
}

// onceConn makes raw transport ownership explicit, including aborts racing
// handshake failure, graph closure, and x/crypto's internal failure cleanup.
type onceConn struct {
	net.Conn
	once sync.Once
	err  error
}

func (c *onceConn) Close() error { c.once.Do(func() { c.err = c.Conn.Close() }); return c.err }

const ChannelOpenCanceled = "SSH channel open canceled; connection-level abort required"

// DialTCPContext bounds a direct-tcpip OpenChannel without leaving a worker
// blocked in x/crypto. v0.55.0 Client.DialContext only abandons its Dial worker;
// OpenChannel exposes neither a channel handle nor per-request cancellation
// before confirmation. abort MUST close the owning transport and, for borrowed
// graphs, invalidate it in its pool. Other leases on that SAME graph fail too.
// Successful opens stop/join cancellation before returning a reusable channel.
func DialTCPContext(ctx context.Context, target *golangssh.Client, addr string, abort func(string)) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if target == nil || abort == nil {
		return nil, errors.New("SSH channel dial requires a transport owner")
	}
	ctx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	defer cancel()
	finish := stopCancellation(ctx, func() { abort(ChannelOpenCanceled) })
	conn, err := target.Dial("tcp", addr)
	if canceled := finish(); canceled != nil {
		if conn != nil {
			conn.Close()
		}
		return nil, canceled
	}
	return conn, err
}

// finishNegotiation resets deadlines only AFTER stopping/joining cancellation.
// Deadlines are an optimization, never the cancellation mechanism: SSH channel
// connections implement SetDeadline but return an unsupported error.
func finishNegotiation(ctx context.Context, conn net.Conn, finish func() error, deadlineSet bool) error {
	if err := finish(); err != nil {
		return err
	}
	if deadlineSet {
		if err := conn.SetDeadline(time.Time{}); err != nil {
			return err
		}
	}
	return contextError(ctx)
}
