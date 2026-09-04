package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
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
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
	"golang.org/x/term"

	pkgsftp "github.com/pkg/sftp"

	clientagent "warden/internal/client/agent"
	clientssh "warden/internal/client/ssh"
	"warden/internal/model"
)

func TestParseDBReference(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		input       string
		wantProfile string
		wantDB      string
		wantErr     bool
	}{
		{name: "profile only", input: "prod", wantProfile: "prod"},
		{name: "named database", input: "prod/audit", wantProfile: "prod", wantDB: "audit"},
		{name: "empty profile", input: "", wantErr: true},
		{name: "empty database", input: "prod/", wantErr: true},
		{name: "multiple separators", input: "prod/audit/extra", wantErr: true},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			profile, database, err := parseDBReference(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parseDBReference(%q) error = nil, want error", tc.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseDBReference(%q): %v", tc.input, err)
			}
			if profile != tc.wantProfile || database != tc.wantDB {
				t.Fatalf("parseDBReference(%q) = (%q, %q), want (%q, %q)", tc.input, profile, database, tc.wantProfile, tc.wantDB)
			}
		})
	}
}

func TestRunDBSelectsNamedDatabase(t *testing.T) {
	apiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/db-connections":
			io.WriteString(w, `[{"id":10,"name":"reporting","host":"db.example","port":3306,"username":"reader","database":"main","databases":[{"name":"main","is_default":true},{"name":"audit","is_default":false}]}]`)
		case "/api/v1/transport/db/10":
			if got := r.URL.Query().Get("database"); got != "audit" {
				t.Errorf("database query = %q, want audit", got)
			}
			io.WriteString(w, `{"host":"db.example","port":3306,"username":"reader","password":"c2VjcmV0","database":"audit"}`)
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

	var gotBundle model.DBBundle
	oldRunDirectDB := runDirectDB
	defer func() { runDirectDB = oldRunDirectDB }()
	runDirectDB = func(_ context.Context, bundle model.DBBundle, _ string, _ io.Writer) error {
		gotBundle = bundle
		return nil
	}

	var stdout, stderr bytes.Buffer
	if exitCode := run([]string{"db", "reporting/audit", "SELECT 1"}, &stdout, &stderr, lookupEnv); exitCode != 0 {
		t.Fatalf("run() exitCode = %d, stderr=%q", exitCode, stderr.String())
	}
	if gotBundle.Database != "audit" {
		t.Fatalf("database = %q, want audit", gotBundle.Database)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

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
			name:      "config search",
			args:      []string{"config", "search", "--help"},
			wantUsage: "warden config search <query>",
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

func TestRunSSHUsesAgent(t *testing.T) {
	apiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/ssh-connections":
			io.WriteString(w, `[{"id":7,"name":"prod","host":"ssh.example","port":22,"username":"user"}]`)
		case "/api/v1/transport/ssh/7":
			io.WriteString(w, `{"target":{"id":7,"name":"prod","host":"ssh.example","port":22,"username":"user","password":"c2VjcmV0"},"jumps":[]}`)
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
	var gotBundle model.SSHBundle
	var gotCommand string
	var gotStreams clientssh.Streams
	var calls int
	oldRunAgentSSH := runAgentSSH
	defer func() { runAgentSSH = oldRunAgentSSH }()
	runAgentSSH = func(_ context.Context, bundle model.SSHBundle, command string, streams clientssh.Streams) error {
		calls++
		gotBundle = bundle
		gotCommand = command
		gotStreams = streams
		return nil
	}

	exitCode := run([]string{"ssh", "prod", "printf exact"}, &stdout, &stderr, lookupEnv)
	if exitCode != 0 {
		t.Fatalf("run() exitCode = %d, want 0, stderr=%q", exitCode, stderr.String())
	}
	if calls != 1 {
		t.Fatalf("agent calls = %d, want 1", calls)
	}
	if gotBundle.Target.ID != 7 || gotBundle.Target.Host != "ssh.example" || string(gotBundle.Target.Password) != "secret" {
		t.Fatalf("agent bundle = %+v, want resolved connection bundle", gotBundle)
	}
	if gotCommand != "printf exact" {
		t.Fatalf("agent command = %q, want exact command", gotCommand)
	}
	if gotStreams.Stdin != os.Stdin || gotStreams.Stdout != &stdout || gotStreams.Stderr != &stderr {
		t.Fatalf("agent streams = %#v, want CLI streams", gotStreams)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestRunCPUsesAgent(t *testing.T) {
	apiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/ssh-connections":
			io.WriteString(w, `[
				{"id":1,"name":"source","host":"source.example","port":22,"username":"user"},
				{"id":2,"name":"destination","host":"destination.example","port":22,"username":"user"}
			]`)
		case "/api/v1/transport/ssh/1":
			io.WriteString(w, `{"target":{"id":1,"name":"source","host":"source.example","port":22,"username":"user","password":"c291cmNl"},"jumps":[]}`)
		case "/api/v1/transport/ssh/2":
			io.WriteString(w, `{"target":{"id":2,"name":"destination","host":"destination.example","port":22,"username":"user","password":"ZGVzdGluYXRpb24="},"jumps":[]}`)
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

	var requests []clientagent.CopyRequest
	oldRunAgentCopy := runAgentCopy
	defer func() { runAgentCopy = oldRunAgentCopy }()
	runAgentCopy = func(_ context.Context, requestOrSource interface{}, destination ...clientagent.CopyEndpoint) error {
		if len(destination) != 0 {
			t.Fatalf("agent copy destination operands = %#v, want request form", destination)
		}
		request, ok := requestOrSource.(clientagent.CopyRequest)
		if !ok {
			t.Fatalf("agent copy request = %T, want clientagent.CopyRequest", requestOrSource)
		}
		requests = append(requests, request)
		return nil
	}

	var stdout, stderr bytes.Buffer
	exitCode := run([]string{"cp", "relative-source", "destination:/remote/path"}, &stdout, &stderr, lookupEnv)
	if exitCode != 0 {
		t.Fatalf("local-to-remote exitCode = %d, stderr=%q", exitCode, stderr.String())
	}
	if len(requests) != 1 {
		t.Fatalf("copy requests = %d, want 1", len(requests))
	}
	request := requests[0]
	if !filepath.IsAbs(request.Source.Path) {
		t.Fatalf("local source path = %q, want absolute", request.Source.Path)
	}
	if request.Source.Bundle != nil {
		t.Fatalf("local source bundle = %#v, want nil", request.Source.Bundle)
	}
	if request.Destination.Path != "/remote/path" || request.Destination.Bundle == nil || request.Destination.Bundle.Target.ID != 2 {
		t.Fatalf("copy destination = %#v, want remote path and destination bundle", request.Destination)
	}

	exitCode = run([]string{"cp", "source:/remote/source", "destination:/remote/destination"}, &stdout, &stderr, lookupEnv)
	if exitCode != 0 {
		t.Fatalf("remote-to-remote exitCode = %d, stderr=%q", exitCode, stderr.String())
	}
	if len(requests) != 2 {
		t.Fatalf("copy requests = %d, want 2", len(requests))
	}
	request = requests[1]
	if request.Source.Path != "/remote/source" || request.Destination.Path != "/remote/destination" {
		t.Fatalf("remote paths = %q, %q, want exact paths", request.Source.Path, request.Destination.Path)
	}
	if request.Source.Bundle == nil || request.Source.Bundle.Target.ID != 1 || request.Destination.Bundle == nil || request.Destination.Bundle.Target.ID != 2 {
		t.Fatalf("remote bundles = %#v, %#v, want source and destination bundles", request.Source.Bundle, request.Destination.Bundle)
	}

	exitCode = run([]string{"cp", "source:/remote/source", "relative-destination"}, &stdout, &stderr, lookupEnv)
	if exitCode != 0 {
		t.Fatalf("remote-to-local exitCode = %d, stderr=%q", exitCode, stderr.String())
	}
	if len(requests) != 3 || !filepath.IsAbs(requests[2].Destination.Path) {
		t.Fatalf("local destination path = %q, want absolute", requests[2].Destination.Path)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestRunDBRoutesTunnel(t *testing.T) {
	apiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/db-connections":
			io.WriteString(w, `[
				{"id":10,"name":"direct","host":"db.example","port":3306,"username":"user","database":"main"},
				{"id":20,"name":"tunneled","host":"db.internal","port":3306,"username":"user","database":"main","ssh_connection_id":7}
			]`)
		case "/api/v1/transport/db/10":
			io.WriteString(w, `{"host":"db.example","port":3306,"username":"user","password":"ZGlyZWN0","database":"main"}`)
		case "/api/v1/transport/db/20":
			io.WriteString(w, `{"host":"db.internal","port":3306,"username":"user","password":"dHVubmVsZWQ=","database":"main","ssh":{"target":{"id":7,"name":"bastion","host":"ssh.example","port":22,"username":"user","password":"c2VjcmV0"},"jumps":[]}}`)
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

	var directCalls, tunneledCalls int
	var gotBundle model.DBBundle
	var gotSQL string
	var gotWriter io.Writer
	oldRunDirectDB := runDirectDB
	oldRunAgentDB := runAgentDB
	defer func() {
		runDirectDB = oldRunDirectDB
		runAgentDB = oldRunAgentDB
	}()
	runDirectDB = func(_ context.Context, bundle model.DBBundle, sqlText string, out io.Writer) error {
		directCalls++
		if bundle.SSH != nil {
			t.Errorf("direct bundle SSH = %#v, want nil", bundle.SSH)
		}
		gotSQL = sqlText
		gotWriter = out
		return nil
	}
	runAgentDB = func(_ context.Context, bundle model.DBBundle, sqlText string, out io.Writer) error {
		tunneledCalls++
		if bundle.SSH == nil {
			t.Errorf("tunneled bundle SSH = nil, want resolved SSH bundle")
		}
		gotBundle = bundle
		gotSQL = sqlText
		gotWriter = out
		return nil
	}

	var stdout, stderr bytes.Buffer
	if exitCode := run([]string{"db", "direct", "SELECT 1"}, &stdout, &stderr, lookupEnv); exitCode != 0 {
		t.Fatalf("direct DB exitCode = %d, stderr=%q", exitCode, stderr.String())
	}
	if directCalls != 1 || tunneledCalls != 0 {
		t.Fatalf("after direct DB direct=%d tunneled=%d, want 1/0", directCalls, tunneledCalls)
	}
	if exitCode := run([]string{"db", "tunneled", "SELECT 2"}, &stdout, &stderr, lookupEnv); exitCode != 0 {
		t.Fatalf("tunneled DB exitCode = %d, stderr=%q", exitCode, stderr.String())
	}
	if directCalls != 1 || tunneledCalls != 1 {
		t.Fatalf("after tunneled DB direct=%d tunneled=%d, want 1/1", directCalls, tunneledCalls)
	}
	if gotBundle.Host != "db.internal" || gotBundle.SSH == nil || gotBundle.SSH.Target.ID != 7 {
		t.Fatalf("tunneled bundle = %+v, want SSH-backed DB bundle", gotBundle)
	}
	if gotSQL != "SELECT 2" || gotWriter != &stdout {
		t.Fatalf("tunneled query = %q writer=%#v, want exact query and stdout", gotSQL, gotWriter)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestAgentServeHidden(t *testing.T) {
	cacheDir := t.TempDir()
	t.Setenv("HOME", cacheDir)
	t.Setenv("XDG_CACHE_HOME", cacheDir)

	var calls int
	oldRunAgentServe := runAgentServe
	defer func() { runAgentServe = oldRunAgentServe }()
	runAgentServe = func(_ context.Context, listener net.Listener, token []byte, pool *clientagent.Pool) error {
		calls++
		if listener == nil || len(token) != clientagent.TokenBytes || pool == nil {
			t.Errorf("agent serve arguments = listener:%v token:%d pool:%v, want initialized values", listener, len(token), pool)
		}
		return nil
	}

	var stdout, stderr bytes.Buffer
	exitCode := run([]string{"agent", "serve"}, &stdout, &stderr, func(key string) (string, bool) {
		if key == "WARDEN_CLIENT_TIMEOUT" {
			return "not-a-duration", true
		}
		return "", false
	})
	if exitCode != 0 {
		t.Fatalf("run() exitCode = %d, want 0, stderr=%q", exitCode, stderr.String())
	}
	if calls != 1 {
		t.Fatalf("agent serve calls = %d, want 1", calls)
	}
	var usage bytes.Buffer
	printUsage(&usage)
	if strings.Contains(usage.String(), "warden agent") {
		t.Fatalf("printUsage = %q, must not advertise agent command", usage.String())
	}
	if stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatalf("agent serve output stdout=%q stderr=%q, want empty", stdout.String(), stderr.String())
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

func TestRunConfigSearch(t *testing.T) {
	apiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/ssh-connections":
			io.WriteString(w, `[
				{"id":10,"name":"prod-web","host":"edge.internal","port":22,"username":"private-ssh-user"},
				{"id":11,"name":"bastion","host":"prod-gateway.internal","port":22,"username":"private-bastion-user"},
				{"id":12,"name":"dev-web","host":"dev.internal","port":22,"username":"private-dev-user"}
			]`)
		case "/api/v1/db-connections":
			io.WriteString(w, `[
				{"id":20,"name":"reporting","host":"prod-db.internal","port":3306,"username":"private-db-user","database":"analytics","ssh_connection_id":10},
				{"id":21,"name":"prod-name","host":"mysql.internal","port":3306,"username":"private-mysql-user","database":"app"},
				{"id":22,"name":"dev-db","host":"dev-db.internal","port":3306,"username":"private-dev-db-user","database":"dev"}
			]`)
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
	exitCode := run([]string{"config", "search", "PrOd"}, &stdout, &stderr, lookupEnv)
	if exitCode != 0 {
		t.Fatalf("run() exitCode = %d, want 0, stderr=%q", exitCode, stderr.String())
	}
	const want = "SSH\n├── prod-web — edge.internal\n└── bastion — prod-gateway.internal\n\nDB\n├── reporting — prod-db.internal — SSH: prod-web\n└── prod-name — mysql.internal\n"
	if stdout.String() != want {
		t.Errorf("stdout = %q, want %q", stdout.String(), want)
	}
	if stderr.Len() != 0 {
		t.Errorf("stderr = %q, want empty", stderr.String())
	}
	if strings.Contains(stdout.String(), "private-ssh-user") || strings.Contains(stdout.String(), "private-db-user") || strings.Contains(stdout.String(), "private-mysql-user") {
		t.Errorf("stdout = %q, must not include usernames", stdout.String())
	}
}

func TestWriteConfigSearchResultsMatchesConfiguredDatabaseNames(t *testing.T) {
	dbConns := []model.DBConnection{{
		Name: "warehouse", Host: "db.internal",
		Databases: []model.DatabaseInfo{
			{Name: "orders", IsDefault: true},
			{Name: "audit", IsDefault: false},
		},
	}}

	for _, query := range []string{"orders", "AUDIT"} {
		t.Run(query, func(t *testing.T) {
			var stdout bytes.Buffer
			writeConfigSearchResults(&stdout, query, nil, dbConns)

			const want = "DB\n└── warehouse — db.internal\n"
			if stdout.String() != want {
				t.Errorf("stdout = %q, want %q", stdout.String(), want)
			}
		})
	}
}

func TestWriteConfigSearchResultsIgnoresLegacyDatabaseField(t *testing.T) {
	var stdout bytes.Buffer
	writeConfigSearchResults(&stdout, "legacy", nil, []model.DBConnection{{
		Name: "warehouse", Host: "db.internal", Database: "legacy",
		Databases: []model.DatabaseInfo{{Name: "orders", IsDefault: true}},
	}})

	if stdout.String() != "No matching connections.\n" {
		t.Errorf("stdout = %q, want no-match message", stdout.String())
	}
}

func TestWriteConfigSearchResultsIgnoresLegacyDatabaseFieldWithoutCanonicalList(t *testing.T) {
	var stdout bytes.Buffer
	writeConfigSearchResults(&stdout, "legacy", nil, []model.DBConnection{{
		Name: "warehouse", Host: "db.internal", Database: "legacy",
	}})

	if stdout.String() != "No matching connections.\n" {
		t.Errorf("stdout = %q, want no-match message", stdout.String())
	}
}

func TestWriteConfigSearchResultsEscapesControlCharacters(t *testing.T) {
	var stdout bytes.Buffer
	writeConfigSearchResults(&stdout, "bad", []model.SSHConnection{{
		ID: 1, Name: "bad\nname", Host: "host\x1b[2J\b\u0085",
	}}, nil)

	const want = "SSH\n└── bad\\nname — host\\x1b[2J\\u0008\\u0085\n"
	if stdout.String() != want {
		t.Errorf("stdout = %q, want %q", stdout.String(), want)
	}
}

func TestRunConfigSearchNoMatches(t *testing.T) {
	apiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `[]`)
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
	exitCode := run([]string{"config", "search", "missing"}, &stdout, &stderr, lookupEnv)
	if exitCode != 0 {
		t.Fatalf("run() exitCode = %d, want 0, stderr=%q", exitCode, stderr.String())
	}
	if stdout.String() != "No matching connections.\n" {
		t.Errorf("stdout = %q, want no-match message", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Errorf("stderr = %q, want empty", stderr.String())
	}
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
	startCLITestAgent(t)

	host, portStr, _ := net.SplitHostPort(srv.addr)
	port, _ := strconv.Atoi(portStr)

	apiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/ssh-connections":
			io.WriteString(w, fmt.Sprintf(`[{"id":1,"name":"prod","host":%q,"port":%d,"username":"user","has_password":true,"key_pair_id":0,"proxy_host":"","proxy_port":0,"proxy_username":"","has_proxy_password":false,"jump_connection_ids":"[]"}]`, host, port))
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
	startCLITestAgent(t)

	host, portStr, _ := net.SplitHostPort(srv.addr)
	port, _ := strconv.Atoi(portStr)
	apiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/ssh-connections":
			io.WriteString(w, fmt.Sprintf(`[{"id":1,"name":"prod","host":%q,"port":%d,"username":"user","has_password":true,"key_pair_id":0,"proxy_host":"","proxy_port":0,"proxy_username":"","has_proxy_password":false,"jump_connection_ids":"[]"}]`, host, port))
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

// TestWriteInteractiveProgressUsesGreenOutput verifies progress is green.
func TestWriteInteractiveProgressUsesGreenOutput(t *testing.T) {
	var out bytes.Buffer
	clientssh.WriteProgress(&out, "Fetching credentials...")
	if got, want := out.String(), "\x1b[32mFetching credentials...\x1b[0m\r\n"; got != want {
		t.Fatalf("WriteProgress() = %q, want %q", got, want)
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
			io.WriteString(w, `[{"id":1,"name":"prod","host":"127.0.0.1","port":22,"username":"user","has_password":true,"key_pair_id":0,"proxy_host":"","proxy_port":0,"proxy_username":"","has_proxy_password":false,"jump_connection_ids":"[]"}]`)
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

// TestRunXSSHWithoutNameRequiresInteractiveTerminal verifies xssh without
// an explicit connection reports the picker terminal creation error when
// test stdin is not interactive, instead of falling back to buffered
// input.
func TestRunXSSHWithoutNameRequiresInteractiveTerminal(t *testing.T) {
	if term.IsTerminal(int(os.Stdin.Fd())) {
		t.Skip("stdin is a terminal; non-terminal requirement not exercisable")
	}
	apiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/ssh-connections":
			io.WriteString(w, `[{"id":1,"name":"prod","host":"127.0.0.1","port":22,"username":"user","has_password":true,"key_pair_id":0,"proxy_host":"","proxy_port":0,"proxy_username":"","has_proxy_password":false,"jump_connection_ids":"[]"}]`)
		case "/api/v1/transport/ssh/1":
			t.Errorf("transport bundle requested; picker must fail before bundle fetch")
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
	exitCode := run([]string{"xssh"}, &stdout, &stderr, lookupEnv)
	if exitCode != 1 || !strings.Contains(stderr.String(), "interactive mode requires one") {
		t.Fatalf("xssh picker error = %d, %q", exitCode, stderr.String())
	}
}

// startCLITestAgent injects a real local agent server so end-to-end CLI
// tests exercise the same IPC and pooled transport used by production. The
// runtime directory is isolated per test to avoid cross-test clients.
func startCLITestAgent(t *testing.T) func() {
	t.Helper()
	t.Setenv("XDG_CACHE_HOME", t.TempDir())

	runtime, err := clientagent.NewRuntime()
	if err != nil {
		t.Fatal(err)
	}
	listener, err := runtime.Listen()
	if err != nil {
		t.Fatal(err)
	}
	token, err := runtime.ReadToken()
	if err != nil {
		_ = runtime.Cleanup()
		t.Fatal(err)
	}
	pool := clientagent.NewDefaultPool(time.Now, time.Minute)
	ctx, cancel := context.WithCancel(context.Background())
	serveDone := make(chan error, 1)
	go func() {
		serveDone <- clientagent.Serve(ctx, listener, token, pool)
	}()

	var stopOnce sync.Once
	stop := func() {
		stopOnce.Do(func() {
			cancel()
			select {
			case err := <-serveDone:
				if err != nil && !errors.Is(err, context.Canceled) {
					t.Errorf("agent serve: %v", err)
				}
			case <-time.After(time.Second):
				_ = runtime.Cleanup()
				select {
				case err := <-serveDone:
					if err != nil && !errors.Is(err, context.Canceled) {
						t.Errorf("agent serve after cleanup: %v", err)
					}
				case <-time.After(time.Second):
					t.Errorf("agent server did not stop")
				}
			}
			_ = runtime.Cleanup()
		})
	}
	t.Cleanup(stop)
	return stop
}

// cliTestSSHServer is a minimal in-process SSH server for CLI tests. It
// serves exec requests (for ssh command tests) and the sftp subsystem
// rooted at root (for cp tests). conns counts accepted SSH connections and
// returns to zero only after every connection has fully closed.
type cliTestSSHServer struct {
	addr    string
	root    string
	hostKey ssh.PublicKey
	conns   atomic.Int64
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
	s := &cliTestSSHServer{addr: ln.Addr().String(), root: t.TempDir(), hostKey: signer.PublicKey()}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			s.conns.Add(1)
			go func() {
				defer s.conns.Add(-1)
				s.handleConn(conn, cfg)
			}()
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return s
}

// handleConn accepts one SSH connection and dispatches session channels to
// handleSession. The connection counter is decremented by the caller when
// the connection fully closes.
func (s *cliTestSSHServer) handleConn(conn net.Conn, cfg *ssh.ServerConfig) {
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
		go s.handleSession(ch, reqs)
	}
}

// handleSession answers exec requests by running the command via sh and
// reporting the exit status, and answers an sftp subsystem request by
// serving the server's root directory over the channel. The channel is
// closed by the caller of the exec path and by the SFTP server when the
// session ends.
func (s *cliTestSSHServer) handleSession(ch ssh.Channel, reqs <-chan *ssh.Request) {
	for req := range reqs {
		switch req.Type {
		case "exec":
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
			ch.Close()
			return
		case "subsystem":
			var payload struct{ Name string }
			if err := ssh.Unmarshal(req.Payload, &payload); err != nil || payload.Name != "sftp" {
				req.Reply(false, nil)
				continue
			}
			req.Reply(true, nil)
			server, err := pkgsftp.NewServer(ch, pkgsftp.WithServerWorkingDirectory(s.root))
			if err != nil {
				ch.Close()
				return
			}
			go func() {
				defer server.Close()
				_ = server.Serve()
			}()
			return
		default:
			req.Reply(false, nil)
		}
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

func TestRunCPHelp(t *testing.T) {
	var stdout, stderr bytes.Buffer
	exitCode := run([]string{"cp", "--help"}, &stdout, &stderr, emptyLookupEnv)
	if exitCode != 0 {
		t.Fatalf("run() exitCode = %d, want 0, stderr=%q", exitCode, stderr.String())
	}
	if !strings.Contains(stdout.String(), "warden cp <source> <destination>") {
		t.Fatalf("stdout = %q, want cp usage", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestRunCPRejectsWrongArgumentCount(t *testing.T) {
	lookupEnv := func(string) (string, bool) { return "", false }

	for _, args := range [][]string{
		{"cp"},
		{"cp", "a"},
		{"cp", "a", "b", "c"},
	} {
		var stdout, stderr bytes.Buffer
		exitCode := run(args, &stdout, &stderr, lookupEnv)
		if exitCode != 2 {
			t.Errorf("run(%v) exitCode = %d, want 2, stderr=%q", args, exitCode, stderr.String())
		}
	}
}

func TestRunCPRejectsLocalToLocal(t *testing.T) {
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
	exitCode := run([]string{"cp", "a", "b"}, &stdout, &stderr, lookupEnv)
	if exitCode != 2 {
		t.Fatalf("run() exitCode = %d, want 2, stderr=%q", exitCode, stderr.String())
	}
}

func TestRunCPRejectsLocalToLocalBeforeConfigOrAPICall(t *testing.T) {
	var apiCalls atomic.Int64
	apiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiCalls.Add(1)
		http.Error(w, "unexpected API request", http.StatusInternalServerError)
	}))
	defer apiSrv.Close()

	var configLookups atomic.Int64
	lookupEnv := func(key string) (string, bool) {
		configLookups.Add(1)
		switch key {
		case "WARDEN_CLIENT_API_BASE_URL":
			return apiSrv.URL, true
		case "WARDEN_CLIENT_TIMEOUT":
			return "not-a-duration", true
		default:
			return "", false
		}
	}

	var stdout, stderr bytes.Buffer
	exitCode := run([]string{"cp", "local-source", "local-destination"}, &stdout, &stderr, lookupEnv)
	if exitCode != 2 {
		t.Fatalf("run() exitCode = %d, want 2, stdout=%q stderr=%q", exitCode, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "local-to-local copies are not supported") {
		t.Fatalf("stderr = %q, want local-to-local usage error", stderr.String())
	}
	if got := configLookups.Load(); got != 0 {
		t.Fatalf("config lookups: got %d, want 0", got)
	}
	if got := apiCalls.Load(); got != 0 {
		t.Fatalf("API calls: got %d, want 0", got)
	}
}

func TestRunCPRejectsSameRemoteHostBeforeTransport(t *testing.T) {
	var bundleCalls atomic.Int64
	apiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/ssh-connections":
			io.WriteString(w, `[
				{"id":101,"name":"source","host":"HP-SERVER","port":22,"username":"user"},
				{"id":202,"name":"destination","host":"hp-server","port":22,"username":"user"}
			]`)
		case "/api/v1/transport/ssh/101", "/api/v1/transport/ssh/202":
			bundleCalls.Add(1)
			http.Error(w, "transport must not be requested for same-host copies", http.StatusInternalServerError)
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
	exitCode := run([]string{"cp", "source:/tmp/source", "destination:/tmp/destination"}, &stdout, &stderr, lookupEnv)
	if exitCode != 1 {
		t.Fatalf("run() exitCode = %d, want 1, stdout=%q stderr=%q", exitCode, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "same host") {
		t.Fatalf("stderr = %q, want same-host rejection", stderr.String())
	}
	if got := bundleCalls.Load(); got != 0 {
		t.Fatalf("transport bundle calls: got %d, want 0", got)
	}
}

func TestParseCPEndpointRecognizesWindowsVolume(t *testing.T) {
	ep, err := parseCPEndpoint(`C:\tmp\file`, nil)
	if err != nil {
		t.Fatalf("parseCPEndpoint() error = %v", err)
	}
	if ep.connection != nil {
		t.Fatalf("parseCPEndpoint() connection = %v, want nil (local)", ep.connection)
	}
	if ep.path != `C:\tmp\file` {
		t.Fatalf("parseCPEndpoint() path = %q, want %q", ep.path, `C:\tmp\file`)
	}
}

func TestRunCPRejectsUnknownConnection(t *testing.T) {
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
	exitCode := run([]string{"cp", "missing:/tmp/file", "local"}, &stdout, &stderr, lookupEnv)
	if exitCode != 1 {
		t.Fatalf("run() exitCode = %d, want 1", exitCode)
	}
	if !strings.Contains(stderr.String(), `cp: connection "missing" not found`) {
		t.Fatalf("stderr = %q, want not-found message", stderr.String())
	}
}

// TestRunCPEndToEnd exercises the full warden cp path against a real
// in-process SSH/SFTP server: profile resolution via the API, transport
// bundle retrieval, local->remote, remote->local, and remote->remote
// transfers, recursive placement, destination overwrite, mode bits, silent
// stdout, and connection closure.
func TestRunCPEndToEnd(t *testing.T) {
	srcSrv := newCLITestSSHServer(t, "s3cret")
	dstSrv := newCLITestSSHServer(t, "s3cret")

	home := t.TempDir()
	t.Setenv("HOME", home)
	knownHosts := filepath.Join(home, ".ssh", "known_hosts")
	if err := os.MkdirAll(filepath.Dir(knownHosts), 0o700); err != nil {
		t.Fatal(err)
	}
	var hosts strings.Builder
	for _, srv := range []*cliTestSSHServer{srcSrv, dstSrv} {
		hosts.WriteString(knownhosts.Line([]string{srv.addr}, srv.hostKey))
		hosts.WriteString("\n")
	}
	if err := os.WriteFile(knownHosts, []byte(hosts.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	stopAgent := startCLITestAgent(t)

	srcHost, srcPortStr, _ := net.SplitHostPort(srcSrv.addr)
	srcPort, _ := strconv.Atoi(srcPortStr)
	dstHost, dstPortStr, _ := net.SplitHostPort(dstSrv.addr)
	dstPort, _ := strconv.Atoi(dstPortStr)

	apiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/ssh-connections":
			io.WriteString(w, fmt.Sprintf(`[
				{"id":1,"name":"source","host":%q,"port":%d,"username":"user","has_password":true,"key_pair_id":0,"proxy_host":"","proxy_port":0,"proxy_username":"","has_proxy_password":false,"jump_connection_ids":"[]"},
				{"id":2,"name":"destination","host":%q,"port":%d,"username":"user","has_password":true,"key_pair_id":0,"proxy_host":"","proxy_port":0,"proxy_username":"","has_proxy_password":false,"jump_connection_ids":"[]"}
			]`, srcHost, srcPort, dstHost, dstPort))
		case "/api/v1/transport/ssh/1":
			w.Header().Set("Cache-Control", "no-store")
			io.WriteString(w, fmt.Sprintf(`{"target":{"id":1,"name":"source","host":%q,"port":%d,"username":"user","password":%q},"jumps":[]}`, srcHost, srcPort, base64.StdEncoding.EncodeToString([]byte("s3cret"))))
		case "/api/v1/transport/ssh/2":
			w.Header().Set("Cache-Control", "no-store")
			io.WriteString(w, fmt.Sprintf(`{"target":{"id":2,"name":"destination","host":%q,"port":%d,"username":"user","password":%q},"jumps":[]}`, dstHost, dstPort, base64.StdEncoding.EncodeToString([]byte("s3cret"))))
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

	runCP := func(args ...string) (stdout, stderr string, exitCode int) {
		t.Helper()
		var out, errOut bytes.Buffer
		exitCode = run(args, &out, &errOut, lookupEnv)
		return out.String(), errOut.String(), exitCode
	}

	// Local -> remote: a missing destination becomes the copied root, and
	// the copy recurses into subdirectories preserving mode bits.
	localSrc := filepath.Join(t.TempDir(), "local-src")
	if err := os.MkdirAll(filepath.Join(localSrc, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(localSrc, "hello.txt"), []byte("hi"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(localSrc, "sub", "deep.txt"), []byte("deep"), 0o644); err != nil {
		t.Fatal(err)
	}

	stdout, stderr, exitCode := runCP("cp", localSrc, "source:dest")
	if exitCode != 0 {
		t.Fatalf("local->remote exitCode = %d, stderr = %q", exitCode, stderr)
	}
	if stdout != "" {
		t.Fatalf("local->remote stdout = %q, want empty", stdout)
	}
	assertCLIRemoteFile(t, srcSrv.root, "dest/hello.txt", "hi", 0o600)
	assertCLIRemoteFile(t, srcSrv.root, "dest/sub/deep.txt", "deep", 0o644)

	// A source directory is placed beneath an existing destination
	// directory, preserving pre-existing entries.
	if err := os.MkdirAll(filepath.Join(srcSrv.root, "dest2"), 0o755); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(srcSrv.root, "dest2", "marker.txt")
	if err := os.WriteFile(marker, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	stdout, stderr, exitCode = runCP("cp", localSrc, "source:dest2")
	if exitCode != 0 {
		t.Fatalf("local->remote existing-dir exitCode = %d, stderr = %q", exitCode, stderr)
	}
	if stdout != "" {
		t.Fatalf("local->remote existing-dir stdout = %q, want empty", stdout)
	}
	assertCLIRemoteFile(t, srcSrv.root, "dest2/local-src/hello.txt", "hi", 0o600)
	assertCLIRemoteFile(t, srcSrv.root, "dest2/local-src/sub/deep.txt", "deep", 0o644)
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("pre-existing destination entries must be preserved: %v", err)
	}

	// A regular file source is also placed beneath an existing destination
	// directory using its basename.
	fileSrc := filepath.Join(t.TempDir(), "single-local.txt")
	if err := os.WriteFile(fileSrc, []byte("file placement"), 0o640); err != nil {
		t.Fatal(err)
	}
	fileDestDir := filepath.Join(srcSrv.root, "file-dest")
	if err := os.MkdirAll(fileDestDir, 0o755); err != nil {
		t.Fatal(err)
	}
	stdout, stderr, exitCode = runCP("cp", fileSrc, "source:file-dest")
	if exitCode != 0 {
		t.Fatalf("file into existing dir exitCode = %d, stderr = %q", exitCode, stderr)
	}
	if stdout != "" {
		t.Fatalf("file into existing dir stdout = %q, want empty", stdout)
	}
	assertCLIRemoteFile(t, fileDestDir, "single-local.txt", "file placement", 0o640)

	// Destination overwrite: a file copy replaces an existing remote file
	// and its mode.
	single := filepath.Join(t.TempDir(), "single.txt")
	if err := os.WriteFile(single, []byte("new"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcSrv.root, "dest", "hello.txt"), []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	stdout, stderr, exitCode = runCP("cp", single, "source:dest/hello.txt")
	if exitCode != 0 {
		t.Fatalf("overwrite exitCode = %d, stderr = %q", exitCode, stderr)
	}
	if stdout != "" {
		t.Fatalf("overwrite stdout = %q, want empty", stdout)
	}
	assertCLIRemoteFile(t, srcSrv.root, "dest/hello.txt", "new", 0o640)

	// Remote -> local: bytes, placement, and modes survive the return trip.
	out := filepath.Join(t.TempDir(), "out")
	stdout, stderr, exitCode = runCP("cp", "source:dest", out)
	if exitCode != 0 {
		t.Fatalf("remote->local exitCode = %d, stderr = %q", exitCode, stderr)
	}
	if stdout != "" {
		t.Fatalf("remote->local stdout = %q, want empty", stdout)
	}
	assertCLILocalFile(t, filepath.Join(out, "hello.txt"), "new", 0o640)
	assertCLILocalFile(t, filepath.Join(out, "sub", "deep.txt"), "deep", 0o644)

	// Remote -> remote: bytes relay through the local client.
	stdout, stderr, exitCode = runCP("cp", "source:dest", "destination:import")
	if exitCode != 0 {
		t.Fatalf("remote->remote exitCode = %d, stderr = %q", exitCode, stderr)
	}
	if stdout != "" {
		t.Fatalf("remote->remote stdout = %q, want empty", stdout)
	}
	assertCLIRemoteFile(t, dstSrv.root, "import/hello.txt", "new", 0o640)
	assertCLIRemoteFile(t, dstSrv.root, "import/sub/deep.txt", "deep", 0o644)

	// Stop the intentionally injected agent before checking that its pooled
	// SSH graphs have closed.
	stopAgent()
	waitForCLIConnectionsClosed(t, srcSrv)
	waitForCLIConnectionsClosed(t, dstSrv)
}

// assertCLIRemoteFile verifies content and mode of a file served by the CLI
// test SSH server's SFTP root.
func assertCLIRemoteFile(t *testing.T, root, rel, want string, mode os.FileMode) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	info, err := os.Lstat(p)
	if err != nil {
		t.Fatalf("Lstat %s: %v", rel, err)
	}
	if got := info.Mode().Perm(); got != mode {
		t.Fatalf("mode of %s: got %v, want %v", rel, got, mode)
	}
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("ReadFile %s: %v", rel, err)
	}
	if string(data) != want {
		t.Fatalf("content of %s: got %q, want %q", rel, data, want)
	}
}

// assertCLILocalFile verifies content and mode of a local file.
func assertCLILocalFile(t *testing.T, path, want string, mode os.FileMode) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("Lstat %s: %v", path, err)
	}
	if got := info.Mode().Perm(); got != mode {
		t.Fatalf("mode of %s: got %v, want %v", path, got, mode)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile %s: %v", path, err)
	}
	if string(data) != want {
		t.Fatalf("content of %s: got %q, want %q", path, data, want)
	}
}

// waitForCLIConnectionsClosed waits until every accepted SSH connection on
// the server has fully closed, proving the CLI tore down its transports.
func waitForCLIConnectionsClosed(t *testing.T, srv *cliTestSSHServer) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if srv.conns.Load() == 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("SSH connections did not close; still %d open", srv.conns.Load())
}
