package api

import (
	"testing"
	"time"

	"warden/internal/client/agent"
)

func TestNewAgentPreservesOwnedIPCAndCommandTimeout(t *testing.T) {
	const origin = "https://warden.example"
	const ca = "/synthetic/public-ca.pem"
	client := NewAgent(origin, ca, 7*time.Second)
	transport, ok := client.http.Transport.(agent.Transport)
	if !ok || transport.Origin != origin || transport.CA != ca || transport.Timeout != 7*time.Second || client.http.Timeout != 7*time.Second || client.http.CheckRedirect == nil {
		t.Fatalf("owned IPC or configured command timeout lost: %#v", client.http)
	}
}
