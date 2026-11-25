package agent

import (
	"bytes"
	"context"
	"errors"
	"net"
	"runtime"
	"testing"
	"time"

	golangssh "golang.org/x/crypto/ssh"

	clientssh "warden/internal/client/ssh"
	"warden/internal/model"
)

func TestCopyRsyncCancelStalledJumpReleasesExclusiveGraph(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("pooled command fixture needs sh")
	}
	for _, tc := range []struct {
		name      string
		proxyHost string
		proxyPort int
		wantPort  uint32
	}{
		{name: "direct", wantPort: 22001},
		{name: "through HTTP proxy", proxyHost: "127.0.0.1", proxyPort: 22002, wantPort: 22002},
	} {
		t.Run(tc.name, func(t *testing.T) {
			type forward struct {
				conn   net.Conn
				closed <-chan struct{}
				host   string
				port   uint32
			}
			forwarding := make(chan forward, 1)
			jump := newAgentSSHTestServer(t, "secret", func(s *agentSSHTestServer) {
				s.stallForwarding = func(channel golangssh.NewChannel, conn net.Conn, closed <-chan struct{}) {
					var payload struct {
						Host       string
						Port       uint32
						OriginHost string
						OriginPort uint32
					}
					_ = golangssh.Unmarshal(channel.ExtraData(), &payload)
					forwarding <- forward{conn: conn, closed: closed, host: payload.Host, port: payload.Port}
					// No reply; the request must be interrupted by the copy owner.
				}
			})
			clock := &poolClock{now: time.Unix(100, 0)}
			pool := NewPool(func(ctx context.Context, bundle model.SSHBundle) (*clientssh.Graph, error) {
				return clientssh.DialGraph(ctx, bundle, clientssh.DialOptions{HostKeyCallback: func(_ string, _ net.Addr, key golangssh.PublicKey) error {
					if !bytes.Equal(key.Marshal(), jump.key.Marshal()) {
						return errors.New("unexpected host key")
					}
					return nil
				}})
			}, clock.Now, time.Minute)
			defer pool.Close()
			ctx, stop := context.WithTimeout(t.Context(), 5*time.Second)
			defer stop()
			pooledBundle := jump.bundle("secret")
			acquireCtx, cancelAcquire := context.WithCancel(ctx)
			lease, err := pool.Acquire(acquireCtx, pooledBundle)
			cancelAcquire() // construction no longer owns the successful pooled graph
			if err != nil {
				t.Fatal(err)
			}
			defer lease.Release()
			checkCommand := func() {
				t.Helper()
				var stdout bytes.Buffer
				err := clientssh.RunCommandOnClient(ctx, lease.Target(), "cat", clientssh.Streams{Stdin: bytes.NewReader([]byte("pool-alive")), Stdout: &stdout})
				if err != nil || stdout.String() != "pool-alive" {
					t.Fatalf("existing pooled command = %q, %v", stdout.String(), err)
				}
			}
			checkCommand()
			bundle := model.SSHBundle{
				Jumps:  []model.SSHNode{pooledBundle.Target},
				Target: model.SSHNode{Name: "stalled", Host: "127.0.0.1", Port: 22001, ProxyHost: tc.proxyHost, ProxyPort: tc.proxyPort},
			}
			copyCtx, cancel := context.WithCancel(ctx)
			defer cancel()
			done := make(chan error, 1)
			req := CopyRequest{Source: CopyEndpoint{Path: t.TempDir()}, Destination: CopyEndpoint{Path: "untouched", Bundle: &bundle}}
			go func() { done <- copyRsyncRequest(copyCtx, pool, req) }()
			var pending forward
			select {
			case pending = <-forwarding:
				defer pending.conn.Close() // also release the deliberately stalled fixture on RED
			case err := <-done:
				t.Fatalf("exclusive dial returned before forwarding: %v", err)
			case <-ctx.Done():
				t.Fatal("jump did not receive forwarding request")
			}
			if pending.host != "127.0.0.1" || pending.port != tc.wantPort {
				t.Fatalf("jump forwarding destination = %s:%d, want 127.0.0.1:%d", pending.host, pending.port, tc.wantPort)
			}
			cancel()
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("exclusive copy returned %v; want canceled", err)
				}
			case <-time.After(time.Second):
				t.Fatal("cancel did not release the stalled exclusive graph construction")
			}
			select {
			case <-pending.closed:
			case <-time.After(time.Second):
				t.Fatal("partial jump socket remained open")
			}
			checkCommand()
			if got := jump.accepted.Load(); got != 2 {
				t.Fatalf("got %d jump sockets; want one pooled and one exclusive", got)
			}
			lease.Release()
			clock.Advance(time.Minute)
			pool.Expire()
			if !pool.Empty() {
				t.Fatal("canceled construction retained exclusive idle accounting")
			}
		})
	}
}
