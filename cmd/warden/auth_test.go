package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"warden/internal/client/agent"
)

func TestLoginLogoutStatusHelpAndNonInteractiveApproval(t *testing.T) {
	var out, errout bytes.Buffer
	if run([]string{"--help"}, &out, &errout, emptyLookupEnv) != 0 || !strings.Contains(out.String(), "warden login") || !strings.Contains(out.String(), "memory-only") {
		t.Fatal("root help omits enrollment and custody", out.String())
	}
	previous := agentAuthorization
	defer func() { agentAuthorization = previous }()
	calls := 0
	agentAuthorization = func(ctx context.Context, origin, ca string, timeout time.Duration, action, label string) (agent.Enrollment, error) {
		calls++
		return agent.Enrollment{ID: "public-id", Fingerprint: "public-fingerprint", ApprovalURL: "https://warden.example/?device=public-id", Label: "fixture", Status: "pending"}, nil
	}
	out.Reset()
	errout.Reset()
	started := time.Now()
	code := run([]string{"-n", "login"}, &out, &errout, func(key string) (string, bool) {
		if key == "WARDEN_CLIENT_API_BASE_URL" {
			return "https://warden.example", true
		}
		return "", false
	})
	if code != 1 || calls != 1 || time.Since(started) > time.Second || !strings.Contains(out.String(), "public-fingerprint") || !strings.Contains(errout.String(), "never waits") {
		t.Fatal("noninteractive approval blocked or omitted steps", code, out.String(), errout.String())
	}
}
