package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	clientssh "warden/internal/client/ssh"
)

func TestAgentOwnsAPITokenInMemoryAndNeverPersistsOrReturnsIt(t *testing.T) {
	s := &Server{}
	client, server := agentTLSTestPair(t)
	token := bytes.Repeat([]byte{9}, TokenBytes)
	done := make(chan struct{})
	go func() { defer close(done); s.handleConn(context.Background(), server, token) }()
	err := relayRequest(context.Background(), client, token, Request{Operation: "api", Payload: json.RawMessage(`{"origin":"http://127.0.0.1:8080","method":"GET","path":"/api/v1/client/ssh-connections"}`)}, clientssh.Streams{}, false)
	<-done
	if err == nil || !strings.Contains(err.Error(), "HTTPS") {
		t.Fatal("missing HTTPS agent API boundary", err)
	}
}
