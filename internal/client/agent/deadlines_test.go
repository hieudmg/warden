package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"
)

func TestServerCancellationDoesNotWaitForTLSCloseNotify(t *testing.T) {
	client, peer := agentTLSTestPair(t)
	defer client.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server := &Server{}
	done := make(chan struct{})
	go func() { server.handleConn(ctx, peer, bytes.Repeat([]byte{1}, TokenBytes)); close(done) }()
	if err := client.(*tls.Conn).Handshake(); err != nil {
		t.Fatal(err)
	}
	// One byte of the frame prefix proves the server finished TLS and is now
	// blocked inside the initial token-frame read, not merely in Handshake.
	if _, err := client.Write([]byte{0}); err != nil {
		t.Fatal(err)
	}
	cancel() // Peer never reads close_notify or completes the token frame.
	select {
	case <-done:
	case <-time.After(300 * time.Millisecond):
		client.(*tls.Conn).NetConn().Close()
		<-done
		t.Fatal("cancel waited for TLS close_notify")
	}
}

func TestServerInitialAuthenticationDeadline(t *testing.T) {
	for _, phase := range []string{"handshake", "token frame", "wrong token stalled response"} {
		t.Run(phase, func(t *testing.T) {
			client, peer := agentTLSTestPair(t)
			defer client.Close()
			token := bytes.Repeat([]byte{1}, TokenBytes)
			done := make(chan struct{})
			go func() { (&Server{}).handleConn(context.Background(), peer, token); close(done) }()
			if phase != "handshake" {
				if err := client.(*tls.Conn).Handshake(); err != nil {
					t.Fatal(err)
				}
			}
			if phase == "wrong token stalled response" {
				if err := WriteFrame(client, Frame{Version: Version, Kind: FrameRequest, Token: bytes.Repeat([]byte{2}, TokenBytes), Request: &Request{Operation: operationDB}}); err != nil {
					t.Fatal(err)
				}
			}
			select {
			case <-done:
			case <-time.After(agentHandshakeTimeout + time.Second):
				client.(*tls.Conn).NetConn().Close()
				<-done
				t.Fatal("initial authentication exceeded bounded deadline")
			}
		})
	}
}

func TestServerRejectsPlaintextBeforeDispatch(t *testing.T) {
	client, peer := net.Pipe()
	defer client.Close()
	done := make(chan struct{})
	go func() { (&Server{}).handleConn(context.Background(), peer, make([]byte, TokenBytes)); close(done) }()
	if _, err := client.Write([]byte("plaintext")); err == nil {
		t.Fatal("plaintext was read")
	}
	<-done
	if _, err := io.Copy(io.Discard, client); err != nil {
		t.Fatal(err)
	}
}
