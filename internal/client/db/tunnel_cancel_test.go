package db

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	golangssh "golang.org/x/crypto/ssh"
	clientssh "warden/internal/client/ssh"
	"warden/internal/model"
)

type closingBorrowedGraph struct {
	client                *golangssh.Client
	entered, allow, abort chan struct{}
}

func (g *closingBorrowedGraph) Target() *golangssh.Client { return g.client }
func (g *closingBorrowedGraph) Invalidate(string)         { close(g.entered); <-g.allow; close(g.abort) }

type closingOpenConn struct {
	golangssh.Conn
	started, abort chan struct{}
}

func (c *closingOpenConn) OpenChannel(string, []byte) (golangssh.Channel, <-chan *golangssh.Request, error) {
	close(c.started)
	<-c.abort
	return nil, nil, io.EOF
}

func TestBorrowedTunnelMissingTargetClosesWithoutWaiting(t *testing.T) {
	d := NewBorrowedTunnelDialer(&closingBorrowedGraph{}, "127.0.0.1:3306")
	if c, err := d.DialContext(context.Background(), "tcp", ""); c != nil || err == nil {
		t.Fatal("missing target did not fail closed")
	}
	done := make(chan struct{})
	go func() { d.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Error("Close of missing target waited for nonexistent active opens")
		close(d.closed) // baseline-failure escape; joins the blocked Close.
		<-done
	}
}

func TestTunnelCloseJoinsPendingChannelOpenAndInvalidation(t *testing.T) {
	started := make(chan struct{})
	owner := &closingBorrowedGraph{entered: make(chan struct{}), allow: make(chan struct{}), abort: make(chan struct{})}
	owner.client = &golangssh.Client{Conn: &closingOpenConn{started: started, abort: owner.abort}}
	d := NewBorrowedTunnelDialer(owner, "127.0.0.1:3306")
	dialDone := make(chan error, 1)
	go func() { _, err := d.DialContext(context.Background(), "tcp", ""); dialDone <- err }()
	<-started
	closeDone := make(chan struct{})
	go func() { d.Close(); close(closeDone) }()
	<-owner.entered
	select {
	case <-closeDone:
		t.Error("Close returned before pending open/invalidation drained")
	case <-time.After(20 * time.Millisecond):
	}
	close(owner.allow)
	select {
	case <-closeDone:
	case <-time.After(time.Second):
		t.Fatal("Close did not join invalidation")
	}
	select {
	case <-dialDone:
	case <-time.After(time.Second):
		t.Fatal("pending dial did not finish")
	}
}

func TestDBChannelOpenCancellationReclaimsLateResult(t *testing.T) {
	for _, borrowed := range []bool{false, true} {
		name := "owned"
		if borrowed {
			name = "borrowed"
		}
		t.Run(name, func(t *testing.T) {
			signer := newTestSigner(t)
			cfg := &golangssh.ServerConfig{NoClientAuth: true}
			cfg.AddHostKey(signer)
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			accepted := make(chan net.Conn, 1)
			opened := make(chan struct{})
			requestsDrained := make(chan struct{})
			done := make(chan struct{})
			var once sync.Once
			go func() {
				defer close(done)
				c, err := ln.Accept()
				if err != nil {
					return
				}
				accepted <- c
				defer c.Close()
				s, chs, rs, err := golangssh.NewServerConn(c, cfg)
				if err != nil {
					return
				}
				go func() { defer close(requestsDrained); golangssh.DiscardRequests(rs) }()
				defer func() { s.Close(); <-requestsDrained }()
				for range chs {
					once.Do(func() { close(opened) })
				}
			}()
			node := targetNode("fixture", ln.Addr().String())
			writeKnownHosts(t, &tunnelSSHServer{addr: ln.Addr().String(), hostKey: signer.PublicKey()})
			bundle := model.SSHBundle{Target: node}
			var d *TunnelDialer
			var graph *clientssh.Graph
			if borrowed {
				graph, err = clientssh.DialGraph(context.Background(), bundle, clientssh.DialOptions{})
				if err == nil {
					d = NewBorrowedTunnelDialer(borrowedTestGraph{graph}, "127.0.0.1:3306")
				}
			} else {
				d, err = NewTunnelDialer(context.Background(), bundle, "127.0.0.1:3306")
			}
			if err != nil {
				t.Fatal(err)
			}
			raw := <-accepted
			defer raw.Close()
			defer d.Close()
			if graph != nil {
				defer graph.Close()
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			dialDone := make(chan error, 1)
			go func() {
				c, err := d.DialContext(ctx, "tcp", "")
				if c != nil {
					c.Close()
				}
				dialDone <- err
			}()
			select {
			case <-opened:
			case <-time.After(time.Second):
				t.Fatal("DB channel request did not reach server")
			}
			cancel()
			select {
			case err := <-dialDone:
				if !errors.Is(err, context.Canceled) {
					t.Errorf("dial error=%v", err)
				}
			case <-time.After(200 * time.Millisecond):
				t.Error("DB channel open left a blocked worker")
				raw.Close()
				<-dialDone
			}
			select {
			case <-done:
			case <-time.After(time.Second):
				raw.Close()
				<-done
				t.Error("cancellation did not terminate the connection handler")
			}
			select {
			case <-requestsDrained:
			default:
				t.Error("handler completion preceded global request drain")
			}
		})
	}
}
