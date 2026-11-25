package ssh

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"warden/internal/model"

	golangssh "golang.org/x/crypto/ssh"
)

func TestDialGraph(t *testing.T) {
	t.Parallel()

	jump := newTestSSHServer(t, "jump-pass", nil)
	target := newTestSSHServer(t, "targ-pass", nil)

	jumpNode := targetNode("jump", jump.addr)
	jumpNode.Username = "user"
	jumpNode.Password = []byte("jump-pass")

	targetNode := targetNode("target", target.addr)
	targetNode.Username = "user"
	targetNode.Password = []byte("targ-pass")

	graph, err := DialGraph(context.Background(), model.SSHBundle{
		Target: targetNode,
		Jumps:  []model.SSHNode{jumpNode},
	}, testOptions())
	if err != nil {
		t.Fatalf("DialGraph: %v", err)
	}
	if graph.Target() == nil {
		t.Fatal("DialGraph returned a nil target")
	}

	clients := append([]*golangssh.Client(nil), graph.chain...)
	var out bytes.Buffer
	if err := RunCommandOnClient(context.Background(), graph.Target(), "echo first", Streams{Stdout: &out}); err != nil {
		t.Fatalf("RunCommandOnClient first: %v", err)
	}
	if err := RunCommandOnClient(context.Background(), graph.Target(), "echo second", Streams{Stdout: &out}); err != nil {
		t.Fatalf("RunCommandOnClient second: %v", err)
	}
	if got, want := strings.TrimSpace(out.String()), "first\nsecond"; got != want {
		t.Fatalf("output = %q, want %q", got, want)
	}

	if err := graph.Close(); err != nil {
		t.Fatalf("Graph.Close: %v", err)
	}
	if err := graph.Close(); err != nil {
		t.Fatalf("second Graph.Close: %v", err)
	}
	for i, client := range clients {
		waitForClientClosed(t, i, client)
	}
}

func TestDialGraphCancelsStalledAgentAuthentication(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("requires a Unix-domain SSH agent socket")
	}
	dir, err := os.MkdirTemp("", "warden-agent-") // Keep the Unix socket path short.
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	t.Setenv("SSH_AUTH_SOCK", path)
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := golangssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	target := newTestSSHServer(t, "", signer.PublicKey())
	node := targetNode("target", target.addr)
	node.Username = "user"
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		graph, err := DialGraph(ctx, model.SSHBundle{Target: node}, testOptions())
		if graph != nil {
			_ = graph.Close()
		}
		done <- err
	}()
	_ = listener.SetDeadline(time.Now().Add(time.Second))
	conn, err := listener.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	var request [5]byte // Length prefix and SSH_AGENTC_REQUEST_IDENTITIES.
	if _, err := io.ReadFull(conn, request[:]); err != nil || request[4] != 11 {
		t.Fatalf("expected agent identity request; got %v, %v", request, err)
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("DialGraph got %v, want cancellation", err)
		}
	case <-time.After(time.Second):
		t.Fatal("DialGraph did not return while the local agent was stalled")
	}
}

func waitForClientClosed(t *testing.T, index int, client *golangssh.Client) {
	t.Helper()

	closed := make(chan struct{})
	go func() {
		client.Wait()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatalf("client %d remained connected after Graph.Close", index)
	}
}
