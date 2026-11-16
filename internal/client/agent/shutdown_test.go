package agent

import (
	"bytes"
	"context"
	"errors"
	"net"
	"path/filepath"
	"testing"
	"time"

	golangssh "golang.org/x/crypto/ssh"
	clientssh "warden/internal/client/ssh"
	"warden/internal/model"
)

func TestServerExternalCancellationClosesActiveGraphs(t *testing.T) {
	for _, retired := range []bool{false, true} {
		name := "cached"
		if retired {
			name = "retired"
		}
		t.Run(name, func(t *testing.T) {
			remote := newAgentSSHTestServer(t, "secret")
			bundle := remote.bundle("secret")
			var graph *clientssh.Graph
			pool := NewPool(func(ctx context.Context, bundle model.SSHBundle) (*clientssh.Graph, error) {
				var err error
				graph, err = clientssh.DialGraph(ctx, bundle, clientssh.DialOptions{HostKeyCallback: func(_ string, _ net.Addr, key golangssh.PublicKey) error {
					if !bytes.Equal(key.Marshal(), remote.key.Marshal()) {
						return errors.New("wrong fixture key")
					}
					return nil
				}})
				return graph, err
			}, time.Now, 10*time.Minute)
			entered := make(chan struct{})
			original := runCommandOnClient
			defer func() { runCommandOnClient = original }()
			runCommandOnClient = func(_ context.Context, client *golangssh.Client, _ string, _ clientssh.Streams) error {
				close(entered)
				// A blocked channel/session subsystem may not react to the request ctx.
				// Termination must close the pool-owned graph, not wait on the borrower.
				return client.Wait()
			}
			runtime, _ := NewRuntimeAt(filepath.Join(t.TempDir(), "a"))
			server, err := NewRuntimeServer(runtime, pool)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			serveDone := make(chan error, 1)
			go func() { serveDone <- server.Serve(ctx) }()
			requestDone := make(chan error, 1)
			go func() {
				conn, token, err := tryRuntime(context.Background(), runtime)
				if err == nil {
					err = relayRequest(context.Background(), conn, token, Request{Operation: operationSSH, SSHBundle: mustJSON(bundle)}, clientssh.Streams{}, false)
				}
				requestDone <- err
			}()
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("operation not admitted")
			}
			if retired {
				pool.Retire(bundle)
			}
			cancel()
			select {
			case err := <-serveDone:
				if !errors.Is(err, context.Canceled) {
					t.Fatal(err)
				}
			case <-time.After(300 * time.Millisecond):
				_ = graph.Close()
				<-serveDone
				<-requestDone
				t.Fatal("external cancellation waited for active graph borrower")
			}
			<-requestDone
			if _, err := pool.Acquire(context.Background(), bundle); !errors.Is(err, ErrPoolClosed) {
				t.Fatal("pool survived daemon termination", err)
			}
		})
	}
}
