package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	clientssh "warden/internal/client/ssh"
)

func TestRelayRequestClosesRawTLSBeforeCloseNotifyOnEveryExit(t *testing.T) {
	for _, tc := range []struct {
		name       string
		request    Request
		cancelled  bool
		replyFinal bool
		wantErr    error
	}{
		{name: "cancelled at entry", cancelled: true, wantErr: context.Canceled},
		{name: "invalid local JSON", request: Request{Payload: json.RawMessage("{")}, wantErr: ErrInvalidFrame},
		{name: "oversized local frame", request: Request{Command: strings.Repeat("x", MaxFrameBytes)}, wantErr: ErrFrameTooLarge},
		{name: "final payload received", request: Request{Operation: operationDB}, replyFinal: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, peer := agentTLSTestPair(t)
			rawClient := client.(*tls.Conn).NetConn()
			rawPeer := peer.(*tls.Conn).NetConn()
			release := make(chan struct{})
			peerDone := make(chan struct{})
			handshaken := make(chan error, 1)
			peerResult := make(chan error, 1)
			token := bytes.Repeat([]byte{1}, TokenBytes)
			go func() {
				defer close(peerDone)
				defer rawPeer.Close()
				err := peer.(*tls.Conn).Handshake()
				handshaken <- err
				if err == nil && tc.replyFinal {
					_, err = ReadAuthenticatedFrame(peer, token)
					if err == nil {
						err = WriteFrame(peer, Frame{Version: Version, Kind: FrameStdout, Data: []byte("complete protected output")})
					}
					if err == nil {
						err = WriteFrame(peer, Frame{Version: Version, Kind: FrameFinal, Response: &Response{}})
					}
				}
				peerResult <- err
				// Deliberately do not read close_notify after the real handshake
				// (and, in the final case, a complete authenticated exchange).
				<-release
			}()
			t.Cleanup(func() {
				close(release)
				rawClient.Close()
				rawPeer.Close()
				select {
				case <-peerDone:
					if err := <-peerResult; err != nil && !t.Failed() {
						t.Error("TLS peer exchange failed", err)
					}
				case <-time.After(time.Second):
					t.Error("TLS fixture did not terminate")
				}
			})
			if err := client.(*tls.Conn).Handshake(); err != nil {
				t.Fatal(err)
			}
			if err := <-handshaken; err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tc.cancelled {
				cancel()
			}
			var stdout bytes.Buffer
			done := make(chan error, 1)
			go func() {
				done <- relayRequest(ctx, client, token, tc.request, clientssh.Streams{Stdout: &stdout}, false)
			}()
			select {
			case err := <-done:
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("relay error = %v; want %v", err, tc.wantErr)
				}
				if tc.replyFinal && stdout.String() != "complete protected output" {
					t.Fatal("relay lost completed output before final response")
				}
				if _, err := rawClient.Write(nil); err == nil {
					t.Fatal("relay returned without closing its raw transport")
				}
			case <-time.After(300 * time.Millisecond):
				// Release the real blocked TLS write and join before reporting RED.
				rawClient.Close()
				select {
				case <-done:
				case <-time.After(time.Second):
					t.Fatal("relay did not terminate even after raw close")
				}
				t.Fatal("relay waited for TLS close_notify on a nonreading peer")
			}
		})
	}
}
