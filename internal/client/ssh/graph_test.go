package ssh

import (
	"bytes"
	"context"
	"net"
	"reflect"
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

type graphCloseRecorder struct {
	net.Conn
	name  string
	order *[]string
}

func (c *graphCloseRecorder) Close() error { *c.order = append(*c.order, c.name); return nil }

func TestGraphClosesAgentsAndTransportsReverseOrderExactlyOnce(t *testing.T) {
	var order []string
	root := &onceConn{Conn: &graphCloseRecorder{name: "root", order: &order}}
	var chain []*golangssh.Client
	for _, name := range []string{"root", "jump", "target"} {
		raw := root
		if name != "root" {
			raw = &onceConn{Conn: &graphCloseRecorder{name: name, order: &order}}
		}
		ag := &onceConn{Conn: &graphCloseRecorder{name: "agent-" + name, order: &order}}
		chain = append(chain, &golangssh.Client{Conn: &ownedClientConn{raw: raw, root: root, agentConn: ag}})
	}
	g := &Graph{target: chain[2], chain: chain}
	g.Close()
	g.Close()
	g.Abort()
	want := []string{"agent-target", "target", "agent-jump", "jump", "agent-root", "root"}
	if !reflect.DeepEqual(order, want) {
		t.Errorf("close order=%v; want %v", order, want)
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
