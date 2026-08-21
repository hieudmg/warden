package db

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh/knownhosts"

	"warden/internal/model"
)

func dbHostPort(addr string) (string, int) {
	host, portStr, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(portStr)
	return host, port
}

// directBundle builds a direct DBBundle pointing at addr.
func directBundle(addr, username, password string) model.DBBundle {
	host, port := dbHostPort(addr)
	return model.DBBundle{
		Host:     host,
		Port:     port,
		Username: username,
		Password: []byte(password),
		Database: "testdb",
	}
}

func TestRunQueryDirectOutput(t *testing.T) {
	srv := newFakeMySQLServer(t, []string{"id", "name"}, [][]string{{"1", "alice"}, {"2", "bob"}})

	var out bytes.Buffer
	err := RunQuery(context.Background(), directBundle(srv.addr, "dbuser", "dbpass"), "SELECT id, name FROM users", &out)
	if err != nil {
		t.Fatalf("RunQuery: %v", err)
	}

	want := "" +
		"+----+-------+\n" +
		"| id | name  |\n" +
		"+----+-------+\n" +
		"| 1  | alice |\n" +
		"| 2  | bob   |\n" +
		"+----+-------+\n"
	if out.String() != want {
		t.Fatalf("output = %q, want %q", out.String(), want)
	}
	if got := srv.queries(); len(got) != 1 || got[0] != "SELECT id, name FROM users" {
		t.Fatalf("server queries = %q, want the sent SQL", got)
	}
}

func TestRunQueryOKNoResultSet(t *testing.T) {
	srv := newFakeMySQLServer(t, nil, nil)

	var out bytes.Buffer
	err := RunQuery(context.Background(), directBundle(srv.addr, "dbuser", "dbpass"), "INSERT INTO t VALUES (1)", &out)
	if err != nil {
		t.Fatalf("RunQuery: %v", err)
	}
	if !strings.Contains(out.String(), "Query OK") {
		t.Fatalf("output = %q, want Query OK", out.String())
	}
}

func TestRunQueryDBError(t *testing.T) {
	srv := newFakeMySQLServer(t, nil, nil)
	srv.errMsg = "Table 'x' doesn't exist"

	var out bytes.Buffer
	err := RunQuery(context.Background(), directBundle(srv.addr, "dbuser", "p4ssword"), "SELECT * FROM x", &out)
	if err == nil {
		t.Fatal("RunQuery: want error, got nil")
	}
	if !strings.Contains(err.Error(), "Table 'x' doesn't exist") {
		t.Fatalf("error = %q, want server error message", err.Error())
	}
	if strings.Contains(err.Error(), "p3ssword") {
		t.Fatalf("error leaks password: %q", err.Error())
	}
}

func TestRunQueryEmptySQL(t *testing.T) {
	var out bytes.Buffer
	err := RunQuery(context.Background(), directBundle("127.0.0.1:3306", "u", "p"), "   ", &out)
	if err == nil {
		t.Fatal("RunQuery: want error for empty SQL, got nil")
	}
}

func TestRunQuerySQLTooLarge(t *testing.T) {
	srv := newFakeMySQLServer(t, nil, nil)
	big := strings.Repeat("x", maxSQLBytes+1)

	var out bytes.Buffer
	err := RunQuery(context.Background(), directBundle(srv.addr, "u", "p"), big, &out)
	if err == nil {
		t.Fatal("RunQuery: want error for oversized SQL, got nil")
	}
	if srv.connectionCount() != 0 {
		t.Fatalf("oversized SQL reached the server (%d connections)", srv.connectionCount())
	}
}

func TestRunQueryConnectionRefusedNoPasswordLeak(t *testing.T) {
	// Reserve and release a port so the address is guaranteed closed.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedAddr := ln.Addr().String()
	ln.Close()

	password := "s3cr;t!p4ssw0rd"
	var out bytes.Buffer
	err = RunQuery(context.Background(), directBundle(closedAddr, "dbuser", password), "SELECT 1", &out)
	if err == nil {
		t.Fatal("RunQuery: want dial error, got nil")
	}
	if strings.Contains(err.Error(), password) {
		t.Fatalf("error leaks password: %q", err.Error())
	}
}

func TestRunQueryContextCanceled(t *testing.T) {
	srv := newFakeMySQLServer(t, []string{"id"}, [][]string{{"1"}})
	srv.setBlock(true)
	defer srv.setBlock(false)

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		var out bytes.Buffer
		errCh <- RunQuery(ctx, directBundle(srv.addr, "dbuser", "dbpass"), "SELECT SLEEP(10)", &out)
	}()

	// Give the query time to reach the (blocking) server, then cancel.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if len(srv.queries()) > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()

	select {
	case err := <-errCh:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("RunQuery error = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("RunQuery did not return after context cancel")
	}
}

// TestRunQueryTunneled executes a query through an SSH tunnel: the MySQL
// wire traffic passes through the SSH server's direct-tcpip forwarding.
func TestRunQueryTunneled(t *testing.T) {
	mysqlSrv := newFakeMySQLServer(t, []string{"n"}, [][]string{{"42"}})
	sshSrv := newTunnelSSHServer(t, "s3cret")
	writeKnownHosts(t, sshSrv)

	target := targetNode("dbhost", sshSrv.addr)
	target.Username = "user"
	target.Password = []byte("s3cret")

	host, port := dbHostPort(mysqlSrv.addr)
	bundle := model.DBBundle{
		Host:     host,
		Port:     port,
		Username: "dbuser",
		Password: []byte("dbpass"),
		Database: "testdb",
		SSH:      &model.SSHBundle{Target: target},
	}

	var out bytes.Buffer
	err := RunQuery(context.Background(), bundle, "SELECT 42", &out)
	if err != nil {
		t.Fatalf("RunQuery tunneled: %v", err)
	}
	want := "" +
		"+----+\n" +
		"| n  |\n" +
		"+----+\n" +
		"| 42 |\n" +
		"+----+\n"
	if out.String() != want {
		t.Fatalf("output = %q, want %q", out.String(), want)
	}
	if got := mysqlSrv.queries(); len(got) != 1 || got[0] != "SELECT 42" {
		t.Fatalf("mysql queries = %q, want the sent SQL", got)
	}
	// The tunnel must be torn down after the query.
	sshSrv.waitClosed(t)
}

// writeKnownHosts writes known_hosts entries for the given SSH servers
// and points HOME at the directory so the tunnel's strict host-key check
// can verify them.
func writeKnownHosts(t *testing.T, srvs ...*tunnelSSHServer) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, srv := range srvs {
		lines = append(lines, knownhosts.Line([]string{srv.addr}, srv.hostKey))
	}
	if err := os.WriteFile(filepath.Join(dir, "known_hosts"), []byte(strings.Join(lines, "\n")+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
}

