package main

import (
	"bytes"
	"strings"
	"testing"
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
