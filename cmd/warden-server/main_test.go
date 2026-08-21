package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRunServeRejectsEmptyExplicitConfigFlag(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := run([]string{"serve", "--config="}, &stdout, &stderr, emptyLookupEnv)
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
