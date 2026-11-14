package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"net"
	"sync"
	"testing"
	"time"

	clientssh "warden/internal/client/ssh"
)

type capturedTLSConn struct {
	net.Conn
	mu   sync.Mutex
	wire bytes.Buffer
}

func (c *capturedTLSConn) Write(b []byte) (int, error) {
	n, e := c.Conn.Write(b)
	c.mu.Lock()
	c.wire.Write(b[:n])
	c.mu.Unlock()
	return n, e
}
func (c *capturedTLSConn) captured() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.wire.Bytes()...)
}

func TestAPIRequestAndSecretResponseAreCiphertextOnLocalIPC(t *testing.T) {
	rawClient, rawServer := net.Pipe()
	clientWire, serverWire := &capturedTLSConn{Conn: rawClient}, &capturedTLSConn{Conn: rawServer}
	defer rawClient.Close()
	defer rawServer.Close()
	cert := testAgentCertificate(t, agentTLSName, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	localToken := bytes.Repeat([]byte{44}, 32)
	remoteSecret := []byte("synthetic-returned-remote-password")
	peerDone := make(chan error, 1)
	go func() {
		secured := tls.Server(serverWire, agentServerTLS(cert))
		defer rawServer.Close()
		frame, e := ReadAuthenticatedFrame(secured, localToken)
		if e != nil {
			peerDone <- e
			return
		}
		if frame.Request == nil || frame.Request.Operation != operationAPI {
			peerDone <- ErrInvalidFrame
			return
		}
		body, _ := json.Marshal(apiResponse{Status: 200, Body: remoteSecret})
		if e = WriteFrame(secured, Frame{Version: Version, Kind: FrameStdout, Data: body}); e == nil {
			e = writeFinal(secured, Response{})
		}
		peerDone <- e
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	secured, e := authenticateAgent(ctx, clientWire, cert.Certificate[0])
	if e != nil {
		t.Fatal(e)
	}
	payload := json.RawMessage(`{"origin":"https://warden.example","method":"GET","path":"/api/v1/client/transport/ssh/1"}`)
	var out bytes.Buffer
	if e = relayRequest(ctx, secured, localToken, Request{Operation: operationAPI, Payload: payload}, clientssh.Streams{Stdout: &out}, false); e != nil {
		t.Fatal(e)
	}
	if e = <-peerDone; e != nil {
		t.Fatal(e)
	}
	var response apiResponse
	if e = json.Unmarshal(out.Bytes(), &response); e != nil || !bytes.Equal(response.Body, remoteSecret) {
		t.Fatal("endpoint lost response", e)
	}
	for _, wire := range [][]byte{clientWire.captured(), serverWire.captured()} {
		if len(wire) == 0 {
			t.Fatal("no captured TLS traffic")
		}
		for _, secret := range [][]byte{localToken, remoteSecret, payload, []byte(base64.StdEncoding.EncodeToString(remoteSecret)), []byte(base64.StdEncoding.EncodeToString(payload))} {
			if bytes.Contains(wire, secret) {
				t.Fatal("captured local IPC plaintext")
			}
		}
	}
}
