package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
	"golang.org/x/term"

	"warden/internal/model"
)

func TestRunHelpCommandsSkipArgAndConfigValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		args      []string
		wantUsage string
	}{
		{
			name:      "ssh",
			args:      []string{"ssh", "--help"},
			wantUsage: "warden ssh <connection> <command>",
		},
		{
			name:      "db",
			args:      []string{"db", "--help"},
			wantUsage: "warden db <connection> <sql>",
		},
		{
			name:      "xssh",
			args:      []string{"xssh", "--help"},
			wantUsage: "warden xssh [connection]",
		},
		{
			name:      "config list",
			args:      []string{"config", "list", "--help"},
			wantUsage: "warden config list",
		},
		{
			name:      "config get",
			args:      []string{"config", "get", "--help"},
			wantUsage: "warden config get <connection>",
		},
	}

	lookupEnv := func(string) (string, bool) {
		return "not-a-duration", true
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var stdout bytes.Buffer
			var stderr bytes.Buffer
			exitCode := run(tc.args, &stdout, &stderr, lookupEnv)
			if exitCode != 0 {
				t.Fatalf("run(%v) exitCode = %d, want 0, stderr=%q", tc.args, exitCode, stderr.String())
			}
			if !strings.Contains(stdout.String(), tc.wantUsage) {
				t.Fatalf("run(%v) stdout = %q, want usage containing %q", tc.args, stdout.String(), tc.wantUsage)
			}
			if stderr.Len() != 0 {
				t.Fatalf("run(%v) stderr = %q, want empty", tc.args, stderr.String())
			}
		})
	}
}

func TestRunRejectsEmptyExplicitConfigFlag(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := run([]string{"--config=", "ssh", "prod", "uptime"}, &stdout, &stderr, emptyLookupEnv)
	if exitCode != 1 {
		t.Fatalf("run() exitCode = %d, want 1, stdout=%q stderr=%q", exitCode, stdout.String(), stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("run() stdout = %q, want empty", stdout.String())
	}
	if !strings.Contains(stderr.String(), "--config") {
		t.Fatalf("run() stderr = %q, want --config error", stderr.String())
	}
}

func emptyLookupEnv(string) (string, bool) {
	return "", false
}

// TestRunSSHEndToEnd exercises the full warden ssh path: redacted list via
// the API, transport bundle retrieval, local SSH execution, and exit status
// propagation.
func TestRunSSHEndToEnd(t *testing.T) {
	srv := newCLITestSSHServer(t, "s3cret")

	home := t.TempDir()
	t.Setenv("HOME", home)
	knownHostsDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(knownHostsDir, 0700); err != nil {
		t.Fatal(err)
	}
	knownHosts := filepath.Join(knownHostsDir, "known_hosts")
	line := knownhosts.Line([]string{srv.addr}, srv.hostKey)
	if err := os.WriteFile(knownHosts, []byte(line+"\n"), 0600); err != nil {
		t.Fatal(err)
	}

	host, portStr, _ := net.SplitHostPort(srv.addr)
	port, _ := strconv.Atoi(portStr)

	apiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/ssh-connections":
			io.WriteString(w, fmt.Sprintf(`[{"id":1,"name":"prod","host":%q,"port":%d,"username":"user","has_password":true,"has_private_key":false,"has_private_key_passphrase":false,"proxy_host":"","proxy_port":0,"proxy_username":"","has_proxy_password":false,"jump_connection_ids":"[]"}]`, host, port))
		case "/api/v1/transport/ssh/1":
			w.Header().Set("Cache-Control", "no-store")
			io.WriteString(w, fmt.Sprintf(`{"target":{"id":1,"name":"prod","host":%q,"port":%d,"username":"user","password":%q},"jumps":[]}`, host, port, base64.StdEncoding.EncodeToString([]byte("s3cret"))))
		default:
			http.NotFound(w, r)
		}
	}))
	defer apiSrv.Close()

	lookupEnv := func(key string) (string, bool) {
		switch key {
		case "WARDEN_CLIENT_API_BASE_URL":
			return apiSrv.URL, true
		case "WARDEN_CLIENT_TIMEOUT":
			return "10s", true
		}
		return "", false
	}

	var stdout, stderr bytes.Buffer
	exitCode := run([]string{"ssh", "prod", "echo remote-out"}, &stdout, &stderr, lookupEnv)
	if exitCode != 0 {
		t.Fatalf("run() exitCode = %d, stderr = %q", exitCode, stderr.String())
	}
	if !strings.Contains(stdout.String(), "remote-out") {
		t.Fatalf("stdout = %q, want remote output", stdout.String())
	}
}

// TestRunSSHPropagatesRemoteExitStatus verifies the CLI returns the remote
// command's exit status as its own process status.
func TestRunSSHPropagatesRemoteExitStatus(t *testing.T) {
	srv := newCLITestSSHServer(t, "s3cret")

	home := t.TempDir()
	t.Setenv("HOME", home)
	knownHosts := filepath.Join(home, ".ssh", "known_hosts")
	if err := os.MkdirAll(filepath.Dir(knownHosts), 0700); err != nil {
		t.Fatal(err)
	}
	line := knownhosts.Line([]string{srv.addr}, srv.hostKey)
	if err := os.WriteFile(knownHosts, []byte(line+"\n"), 0600); err != nil {
		t.Fatal(err)
	}

	host, portStr, _ := net.SplitHostPort(srv.addr)
	port, _ := strconv.Atoi(portStr)
	apiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/ssh-connections":
			io.WriteString(w, fmt.Sprintf(`[{"id":1,"name":"prod","host":%q,"port":%d,"username":"user","has_password":true,"has_private_key":false,"has_private_key_passphrase":false,"proxy_host":"","proxy_port":0,"proxy_username":"","has_proxy_password":false,"jump_connection_ids":"[]"}]`, host, port))
		case "/api/v1/transport/ssh/1":
			io.WriteString(w, fmt.Sprintf(`{"target":{"id":1,"name":"prod","host":%q,"port":%d,"username":"user","password":%q},"jumps":[]}`, host, port, base64.StdEncoding.EncodeToString([]byte("s3cret"))))
		default:
			http.NotFound(w, r)
		}
	}))
	defer apiSrv.Close()

	lookupEnv := func(key string) (string, bool) {
		switch key {
		case "WARDEN_CLIENT_API_BASE_URL":
			return apiSrv.URL, true
		case "WARDEN_CLIENT_TIMEOUT":
			return "10s", true
		}
		return "", false
	}

	var stdout, stderr bytes.Buffer
	exitCode := run([]string{"ssh", "prod", "exit 3"}, &stdout, &stderr, lookupEnv)
	if exitCode != 3 {
		t.Fatalf("run() exitCode = %d, want 3, stderr = %q", exitCode, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
}

// TestRunSSHUnknownConnection verifies a missing connection name fails
// cleanly before any transport is attempted.
func TestRunSSHUnknownConnection(t *testing.T) {
	apiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/ssh-connections" {
			io.WriteString(w, `[]`)
			return
		}
		http.NotFound(w, r)
	}))
	defer apiSrv.Close()

	lookupEnv := func(key string) (string, bool) {
		switch key {
		case "HOME":
			return t.TempDir(), true
		case "WARDEN_CLIENT_API_BASE_URL":
			return apiSrv.URL, true
		case "WARDEN_CLIENT_TIMEOUT":
			return "10s", true
		}
		return "", false
	}

	var stdout, stderr bytes.Buffer
	exitCode := run([]string{"ssh", "nope", "uptime"}, &stdout, &stderr, lookupEnv)
	if exitCode != 1 {
		t.Fatalf("run() exitCode = %d, want 1", exitCode)
	}
	if !strings.Contains(stderr.String(), "not found") {
		t.Fatalf("stderr = %q, want not-found message", stderr.String())
	}
}

// TestRunDBUnknownConnection verifies a missing DB connection name fails
// cleanly before any transport is attempted.
func TestRunDBUnknownConnection(t *testing.T) {
	apiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/db-connections" {
			io.WriteString(w, `[]`)
			return
		}
		http.NotFound(w, r)
	}))
	defer apiSrv.Close()

	lookupEnv := func(key string) (string, bool) {
		switch key {
		case "HOME":
			return t.TempDir(), true
		case "WARDEN_CLIENT_API_BASE_URL":
			return apiSrv.URL, true
		case "WARDEN_CLIENT_TIMEOUT":
			return "10s", true
		}
		return "", false
	}

	var stdout, stderr bytes.Buffer
	exitCode := run([]string{"db", "nope", "SELECT 1"}, &stdout, &stderr, lookupEnv)
	if exitCode != 1 {
		t.Fatalf("run() exitCode = %d, want 1", exitCode)
	}
	if !strings.Contains(stderr.String(), "not found") {
		t.Fatalf("stderr = %q, want not-found message", stderr.String())
	}
}

// TestPickConnectionSelectsByNumber verifies the built-in picker accepts
// a list number and prints the connection list (no fzf dependency).
func TestPickConnectionSelectsByNumber(t *testing.T) {
	conns := []model.SSHConnection{
		{ID: 1, Name: "prod-web", Host: "10.0.0.1", Port: 22, Username: "deploy"},
		{ID: 2, Name: "prod-db", Host: "10.0.0.2", Port: 22, Username: "dba"},
		{ID: 3, Name: "bastion", Host: "bastion.corp", Port: 2222, Username: "ops"},
	}
	var stdout bytes.Buffer
	got, err := pickConnection(strings.NewReader("2\n"), &stdout, conns)
	if err != nil {
		t.Fatalf("pickConnection() err = %v", err)
	}
	if got.ID != 2 || got.Name != "prod-db" {
		t.Fatalf("picked %+v, want prod-db", got)
	}
	if !strings.Contains(stdout.String(), "prod-web") || !strings.Contains(stdout.String(), "bastion.corp") {
		t.Fatalf("stdout = %q, want connection list", stdout.String())
	}
}

// TestPickConnectionExactName verifies an exact name selects directly.
func TestPickConnectionExactName(t *testing.T) {
	conns := []model.SSHConnection{
		{ID: 1, Name: "prod-web", Host: "10.0.0.1"},
		{ID: 2, Name: "prod-db", Host: "10.0.0.2"},
	}
	got, err := pickConnection(strings.NewReader("prod-db\n"), io.Discard, conns)
	if err != nil {
		t.Fatalf("pickConnection() err = %v", err)
	}
	if got.ID != 2 {
		t.Fatalf("picked ID %d, want 2", got.ID)
	}
}

// TestPickConnectionFilterNarrowsAndSelects verifies a substring filter
// narrows the list and a follow-up number selects from the filtered set.
func TestPickConnectionFilterNarrowsAndSelects(t *testing.T) {
	conns := []model.SSHConnection{
		{ID: 1, Name: "prod-web", Host: "10.0.0.1"},
		{ID: 2, Name: "prod-db", Host: "10.0.0.2"},
		{ID: 3, Name: "dev-db", Host: "10.0.1.2"},
	}
	var stdout bytes.Buffer
	got, err := pickConnection(strings.NewReader("db\n1\n"), &stdout, conns)
	if err != nil {
		t.Fatalf("pickConnection() err = %v", err)
	}
	if got.ID != 2 || got.Name != "prod-db" {
		t.Fatalf("picked %+v, want prod-db (first of filtered [prod-db, dev-db])", got)
	}
}

// TestPickConnectionAbort verifies q quits without selecting.
func TestPickConnectionAbort(t *testing.T) {
	conns := []model.SSHConnection{{ID: 1, Name: "prod"}}
	if _, err := pickConnection(strings.NewReader("q\n"), io.Discard, conns); err == nil {
		t.Fatal("pickConnection() err = nil, want abort error")
	}
}

// TestPickConnectionEmptyList verifies an empty list fails fast.
func TestPickConnectionEmptyList(t *testing.T) {
	if _, err := pickConnection(strings.NewReader("1\n"), io.Discard, nil); err == nil {
		t.Fatal("pickConnection() err = nil, want error for empty list")
	}
}

// TestRunXSSHUnknownConnection verifies a missing connection name fails
// cleanly before any transport or terminal setup.
func TestRunXSSHUnknownConnection(t *testing.T) {
	apiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/ssh-connections" {
			io.WriteString(w, `[]`)
			return
		}
		http.NotFound(w, r)
	}))
	defer apiSrv.Close()

	lookupEnv := func(key string) (string, bool) {
		switch key {
		case "HOME":
			return t.TempDir(), true
		case "WARDEN_CLIENT_API_BASE_URL":
			return apiSrv.URL, true
		case "WARDEN_CLIENT_TIMEOUT":
			return "10s", true
		}
		return "", false
	}

	var stdout, stderr bytes.Buffer
	exitCode := run([]string{"xssh", "nope"}, &stdout, &stderr, lookupEnv)
	if exitCode != 1 {
		t.Fatalf("run() exitCode = %d, want 1", exitCode)
	}
	if !strings.Contains(stderr.String(), "not found") {
		t.Fatalf("stderr = %q, want not-found message", stderr.String())
	}
}

// TestRunXSSHRequiresInteractiveTerminal verifies xssh fails cleanly when
// stdin is not a terminal: it must never fall back to line-buffered
// interactive mode.
func TestRunXSSHRequiresInteractiveTerminal(t *testing.T) {
	if term.IsTerminal(int(os.Stdin.Fd())) {
		t.Skip("stdin is a terminal; non-terminal requirement not exercisable")
	}
	apiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/ssh-connections":
			io.WriteString(w, `[{"id":1,"name":"prod","host":"127.0.0.1","port":22,"username":"user","has_password":true,"has_private_key":false,"has_private_key_passphrase":false,"proxy_host":"","proxy_port":0,"proxy_username":"","has_proxy_password":false,"jump_connection_ids":"[]"}]`)
		case "/api/v1/transport/ssh/1":
			io.WriteString(w, `{"target":{"id":1,"name":"prod","host":"127.0.0.1","port":22,"username":"user","password":"c2VjcmV0"},"jumps":[]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer apiSrv.Close()

	lookupEnv := func(key string) (string, bool) {
		switch key {
		case "HOME":
			return t.TempDir(), true
		case "WARDEN_CLIENT_API_BASE_URL":
			return apiSrv.URL, true
		case "WARDEN_CLIENT_TIMEOUT":
			return "10s", true
		}
		return "", false
	}

	var stdout, stderr bytes.Buffer
	exitCode := run([]string{"xssh", "prod"}, &stdout, &stderr, lookupEnv)
	if exitCode != 1 {
		t.Fatalf("run() exitCode = %d, want 1, stderr=%q", exitCode, stderr.String())
	}
	if !strings.Contains(stderr.String(), "not a terminal") {
		t.Fatalf("stderr = %q, want interactive-terminal error", stderr.String())
	}
}

// cliTestSSHServer is a minimal in-process SSH server for CLI tests.
type cliTestSSHServer struct {
	addr    string
	hostKey ssh.PublicKey
}

func newCLITestSSHServer(t *testing.T, password string) *cliTestSSHServer {
	t.Helper()

	cfg := &ssh.ServerConfig{
		PasswordCallback: func(conn ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if subtle.ConstantTimeCompare(pass, []byte(password)) == 1 {
				return nil, nil
			}
			return nil, fmt.Errorf("bad password")
		},
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	cfg.AddHostKey(signer)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &cliTestSSHServer{addr: ln.Addr().String(), hostKey: signer.PublicKey()}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleCLITestConn(conn, cfg)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return s
}

func handleCLITestConn(conn net.Conn, cfg *ssh.ServerConfig) {
	sconn, chans, reqs, err := ssh.NewServerConn(conn, cfg)
	if err != nil {
		conn.Close()
		return
	}
	defer sconn.Close()
	go ssh.DiscardRequests(reqs)
	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			newCh.Reject(ssh.UnknownChannelType, "unsupported")
			continue
		}
		ch, reqs, err := newCh.Accept()
		if err != nil {
			continue
		}
		go func(ch ssh.Channel, reqs <-chan *ssh.Request) {
			defer ch.Close()
			for req := range reqs {
				if req.Type != "exec" {
					req.Reply(false, nil)
					continue
				}
				var payload struct {
					Command string
				}
				if err := ssh.Unmarshal(req.Payload, &payload); err != nil {
					req.Reply(false, nil)
					continue
				}
				req.Reply(true, nil)

				cmd := exec.Command("sh", "-c", payload.Command)
				cmd.Stdout = ch
				cmd.Stderr = ch.Stderr()
				cmd.Stdin = ch
				status := uint32(0)
				if err := cmd.Run(); err != nil {
					if ee, ok := err.(*exec.ExitError); ok {
						status = uint32(ee.ExitCode())
					} else {
						status = 1
					}
				}
				ch.SendRequest("exit-status", false, ssh.Marshal(struct {
					Status uint32
				}{Status: status}))
				return
			}
		}(ch, reqs)
	}
}

func TestRunReportCreateRequiresAllFlags(t *testing.T) {
	lookupEnv := func(string) (string, bool) { return "", false }

	cases := [][]string{
		{"report", "create", "demo", "--title", "t", "--summary", "s"},
		{"report", "create", "demo", "--title", "t", "--agent-model", "a"},
		{"report", "create", "demo", "--summary", "s", "--agent-model", "a"},
		{"report", "create", "", "--title", "t", "--summary", "s", "--agent-model", "a"},
	}
	for _, args := range cases {
		var stdout, stderr bytes.Buffer
		exitCode := run(args, &stdout, &stderr, lookupEnv)
		if exitCode != 2 {
			t.Errorf("run(%v) exitCode = %d, want 2", args, exitCode)
		}
		if !strings.Contains(stderr.String(), "report create requires") {
			t.Errorf("run(%v) stderr = %q, want missing-flags message", args, stderr.String())
		}
	}
}

func TestRunReportCreateAPIError(t *testing.T) {
	apiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, `{"code":"validation_error","message":"title must be 1-200 bytes"}`)
	}))
	defer apiSrv.Close()

	lookupEnv := func(key string) (string, bool) {
		switch key {
		case "WARDEN_CLIENT_API_BASE_URL":
			return apiSrv.URL, true
		case "WARDEN_CLIENT_TIMEOUT":
			return "10s", true
		}
		return "", false
	}

	var stdout, stderr bytes.Buffer
	exitCode := run([]string{"report", "create", "demo", "--title", "t", "--summary", "s", "--agent-model", "a"},
		&stdout, &stderr, lookupEnv)
	if exitCode != 1 {
		t.Fatalf("run() exitCode = %d, want 1, stderr=%q", exitCode, stderr.String())
	}
	if !strings.Contains(stderr.String(), "validation_error") {
		t.Fatalf("stderr = %q, want validation_error surfaced", stderr.String())
	}
	if strings.Contains(stderr.String(), "title must be 1-200 bytes") == false {
		t.Fatalf("stderr = %q, want server message", stderr.String())
	}
}

func TestRunReportCreateSuccess(t *testing.T) {
	apiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/reports" || r.Method != http.MethodPost {
			t.Errorf("got %s %s, want POST /api/v1/reports", r.Method, r.URL.Path)
		}
		w.WriteHeader(http.StatusCreated)
		io.WriteString(w, `{"id":11,"project":"demo","title":"t","summary":"s","agent_model":"a","created_at":"2026-08-21T10:00:00Z"}`)
	}))
	defer apiSrv.Close()

	lookupEnv := func(key string) (string, bool) {
		switch key {
		case "WARDEN_CLIENT_API_BASE_URL":
			return apiSrv.URL, true
		case "WARDEN_CLIENT_TIMEOUT":
			return "10s", true
		}
		return "", false
	}

	var stdout, stderr bytes.Buffer
	exitCode := run([]string{"report", "create", "demo", "--title", "t", "--summary", "s", "--agent-model", "a"},
		&stdout, &stderr, lookupEnv)
	if exitCode != 0 {
		t.Fatalf("run() exitCode = %d, want 0, stderr=%q", exitCode, stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "11") || !strings.Contains(out, "2026-08-21T10:00:00Z") {
		t.Fatalf("stdout = %q, want confirmation with report id and created_at", out)
	}
	if strings.Contains(out, `"summary"`) || strings.Contains(out, `"title"`) {
		t.Fatalf("stdout = %q, must not echo report body", out)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestRunReportCreateUnknownCommand(t *testing.T) {
	lookupEnv := func(string) (string, bool) { return "", false }

	var stdout, stderr bytes.Buffer
	exitCode := run([]string{"report", "list"}, &stdout, &stderr, lookupEnv)
	if exitCode != 2 {
		t.Fatalf("run() exitCode = %d, want 2", exitCode)
	}
	if !strings.Contains(stderr.String(), "unknown report command") {
		t.Fatalf("stderr = %q, want unknown-command message", stderr.String())
	}
}
