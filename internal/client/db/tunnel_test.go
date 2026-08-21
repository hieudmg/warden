package db

import (
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"warden/internal/model"
)

// targetNode builds an SSH node from a host:port string.
func targetNode(name, addr string) model.SSHNode {
	host, portStr, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(portStr)
	return model.SSHNode{Name: name, Host: host, Port: port}
}

func sshBundle(target model.SSHNode, jumps ...model.SSHNode) model.SSHBundle {
	return model.SSHBundle{Target: target, Jumps: jumps}
}

// TestNewTunnelDialerFailureBeforeDBDial verifies a broken SSH graph fails
// before any tunnel or DB connection exists.
func TestNewTunnelDialerFailureBeforeDBDial(t *testing.T) {
	// Closed port: SSH dial fails immediately.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedAddr := ln.Addr().String()
	ln.Close()

	target := targetNode("gone", closedAddr)
	target.Username = "user"
	target.Password = []byte("pw")

	d, err := NewTunnelDialer(context.Background(), sshBundle(target), "127.0.0.1:3306")
	if err == nil {
		d.Close()
		t.Fatal("NewTunnelDialer: want error, got nil")
	}
}

// TestTunnelDialAndClose verifies DialContext returns a working connection
// through the SSH tunnel and that Close makes further dials fail.
func TestTunnelDialAndClose(t *testing.T) {
	echo := newEchoServer(t)
	sshSrv := newTunnelSSHServer(t, "s3cret")
	writeKnownHosts(t, sshSrv)

	target := targetNode("dbhost", sshSrv.addr)
	target.Username = "user"
	target.Password = []byte("s3cret")

	d, err := NewTunnelDialer(context.Background(), sshBundle(target), echo.Addr().String())
	if err != nil {
		t.Fatalf("NewTunnelDialer: %v", err)
	}
	defer d.Close()

	conn, err := d.DialContext(context.Background(), "tcp", echo.Addr().String())
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	if _, err := io.WriteString(conn, "ping"); err != nil {
		t.Fatalf("write through tunnel: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read through tunnel: %v", err)
	}
	if string(buf) != "ping" {
		t.Fatalf("echo = %q, want ping", buf)
	}
	conn.Close()

	d.Close()
	if _, err := d.DialContext(context.Background(), "tcp", echo.Addr().String()); err == nil {
		t.Fatal("DialContext after Close: want error, got nil")
	}
	sshSrv.waitClosed(t)
}

// TestTunnelCloseClosesWholeChain verifies Close() tears down the jump
// client, the target client, and every channel built on them.
func TestTunnelCloseClosesWholeChain(t *testing.T) {
	echo := newEchoServer(t)
	jumpSrv := newTunnelSSHServer(t, "jump")
	targetSrv := newTunnelSSHServer(t, "target")
	writeKnownHosts(t, jumpSrv, targetSrv)

	jump := targetNode("jump", jumpSrv.addr)
	jump.Username = "user"
	jump.Password = []byte("jump")
	target := targetNode("target", targetSrv.addr)
	target.Username = "user"
	target.Password = []byte("target")

	d, err := NewTunnelDialer(context.Background(), sshBundle(target, jump), echo.Addr().String())
	if err != nil {
		t.Fatalf("NewTunnelDialer: %v", err)
	}

	conn, err := d.DialContext(context.Background(), "tcp", echo.Addr().String())
	if err != nil {
		t.Fatalf("DialContext through jump: %v", err)
	}
	if _, err := io.WriteString(conn, "hop"); err != nil {
		t.Fatalf("write through jump: %v", err)
	}
	buf := make([]byte, 3)
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "hop" {
		t.Fatalf("echo through jump = %q, err=%v", buf, err)
	}
	conn.Close()

	d.Close()
	jumpSrv.waitClosed(t)
	targetSrv.waitClosed(t)
}

// TestTunnelDialContextCanceled verifies a canceled context fails the dial
// without leaving connections behind.
func TestTunnelDialContextCanceled(t *testing.T) {
	sshSrv := newTunnelSSHServer(t, "s3cret")
	writeKnownHosts(t, sshSrv)

	target := targetNode("dbhost", sshSrv.addr)
	target.Username = "user"
	target.Password = []byte("s3cret")

	d, err := NewTunnelDialer(context.Background(), sshBundle(target), "127.0.0.1:3306")
	if err != nil {
		t.Fatalf("NewTunnelDialer: %v", err)
	}
	defer d.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := d.DialContext(ctx, "tcp", "127.0.0.1:3306"); !errors.Is(err, context.Canceled) {
		t.Fatalf("DialContext error = %v, want context.Canceled", err)
	}
}

// TestTunnelNoDeadlineRequirement documents that tunnel connections cannot
// honor deadlines (x/crypto returns "deadline not supported") and that this
// is safe: the mysql driver only sets deadlines when timeouts are configured,
// which RunQuery never does (cancellation is handled through contexts).
func TestTunnelNoDeadlineRequirement(t *testing.T) {
	echo := newEchoServer(t)
	sshSrv := newTunnelSSHServer(t, "s3cret")
	writeKnownHosts(t, sshSrv)

	target := targetNode("dbhost", sshSrv.addr)
	target.Username = "user"
	target.Password = []byte("s3cret")

	d, err := NewTunnelDialer(context.Background(), sshBundle(target), echo.Addr().String())
	if err != nil {
		t.Fatalf("NewTunnelDialer: %v", err)
	}
	defer d.Close()

	conn, err := d.DialContext(context.Background(), "tcp", echo.Addr().String())
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()

	// Data still flows even though deadlines are unsupported.
	if _, err := io.WriteString(conn, "x"); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 1)
	if _, err := io.ReadFull(conn, buf); err != nil || buf[0] != 'x' {
		t.Fatalf("read = %q, err=%v", buf, err)
	}
	if err := conn.SetDeadline(time.Time{}); err == nil {
		t.Fatal("SetDeadline: want unsupported error, got nil")
	}
}
