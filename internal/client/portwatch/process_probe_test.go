package portwatch

import (
	"context"
	"io"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	golangssh "golang.org/x/crypto/ssh"

	clientssh "warden/internal/client/ssh"
	"warden/internal/model"
)

func TestRunListenerProcessCommandCanRetryAfterSSHFailure(t *testing.T) {
	const output = "LISTEN 0 128 *:3000 *:* users:((\"node\",pid=1,fd=1))\n"
	var calls atomic.Int32
	peer := newWatchBundlePeer(t, watchKnownHosts(t), func(_ int, incoming golangssh.NewChannel, _ chan struct{}) {
		channel, requests, err := incoming.Accept()
		if err != nil {
			return
		}
		defer channel.Close()
		req := <-requests
		var payload struct{ Command string }
		if req == nil || req.Type != "exec" || golangssh.Unmarshal(req.Payload, &payload) != nil || payload.Command != "ss -H -ltnp" {
			t.Errorf("unexpected process lookup exec request: %v", req)
			return
		}
		attempt := calls.Add(1)
		if attempt == 1 {
			_ = req.Reply(false, nil)
			return
		}
		_ = req.Reply(true, nil)
		_, _ = io.WriteString(channel, output)
		if attempt == 3 {
			_, _ = io.WriteString(channel, strings.Repeat("x", maxProcessProbeOutput))
		}
		status := uint32(0)
		if attempt == 2 {
			status = 1
		}
		_, _ = channel.SendRequest("exit-status", false, golangssh.Marshal(struct{ Status uint32 }{status}))
	}, false)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	graph, err := clientssh.DialGraph(ctx, model.SSHBundle{Target: peer.node}, clientssh.DialOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer closeProcessGraph(graph)

	for attempt := 1; attempt <= 4; attempt++ {
		result := make(chan struct {
			output string
			err    error
		}, 1)
		go func() {
			out, err := runListenerProcessCommand(graph.Target())
			result <- struct {
				output string
				err    error
			}{out, err}
		}()
		select {
		case got := <-result:
			wantErr, wantOutput := attempt < 3, output
			if wantErr || attempt == 3 {
				wantOutput = ""
			}
			if (got.err != nil) != wantErr || got.output != wantOutput {
				t.Fatalf("attempt %d got %q, %v; want %q, error=%v", attempt, got.output, got.err, wantOutput, wantErr)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("attempt %d did not complete", attempt)
		}
	}
}

type quitPortWatchSession struct {
	viewSession
	quit <-chan struct{}
}

func (s *quitPortWatchSession) StdinReadyWithin(time.Duration) (bool, error) {
	select {
	case <-s.quit:
		return true, nil
	default:
		return false, nil
	}
}

func (*quitPortWatchSession) Stdin() io.Reader { return strings.NewReader("q") }
