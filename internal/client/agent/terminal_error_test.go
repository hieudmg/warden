package agent

import (
	"bytes"
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	clientssh "warden/internal/client/ssh"
	"warden/internal/client/terminal"
)

func TestAgentRelayTerminalBoundaryPreservesStreamsAndClassification(t *testing.T) {
	for _, typed := range []bool{false, true} {
		name := "diagnostic"
		if typed {
			name = "exit-status"
		}
		t.Run(name, func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			client.SetDeadline(time.Now().Add(3 * time.Second))
			server.SetDeadline(time.Now().Add(3 * time.Second))
			token := bytes.Repeat([]byte{0x42}, TokenBytes)
			raw := []byte{0, 0xff, 0x1b, ']', '5', '2', ';', 7, '\r', '\n', 0xc2, 0x9b}
			var out, errout bytes.Buffer
			done := make(chan error, 1)
			go func() {
				if _, err := ReadAuthenticatedFrame(server, token); err != nil {
					done <- err
					return
				}
				for _, kind := range []FrameKind{FrameStdout, FrameStderr} {
					if err := WriteFrame(server, Frame{Version: Version, Kind: kind, Data: raw}); err != nil {
						done <- err
						return
					}
				}
				response := Response{Error: "relay\x1b]52;c;synthetic\a\r\n\u009b"}
				if typed {
					status := 23
					response.ExitStatus = &status
				}
				done <- WriteFrame(server, Frame{Version: Version, Kind: FrameFinal, Response: &response})
			}()
			err := relayRequest(context.Background(), client, token, Request{Operation: operationSSH}, clientssh.Streams{Stdout: &out, Stderr: &errout}, false)
			if peerErr := <-done; peerErr != nil {
				t.Fatal(peerErr)
			}
			if !bytes.Equal(out.Bytes(), raw) || !bytes.Equal(errout.Bytes(), raw) {
				t.Fatal("relay byte streams filtered")
			}
			if typed {
				var status *clientssh.ExitStatusError
				if !errors.As(err, &status) || status.Status != 23 {
					t.Fatalf("classification lost: %v", err)
				}
			} else {
				if err == nil || !strings.Contains(err.Error(), "\x1b") {
					t.Fatal("test did not receive raw relay diagnostic")
				}
				if terminal.ErrorText(err) != `relay\x1b]52;c;synthetic\u0007\r\n\u009b` {
					t.Fatalf("terminal boundary unsafe: %q", terminal.ErrorText(err))
				}
			}
		})
	}
}
