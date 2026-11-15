package db

import (
	"io"
	"net"
	"testing"
	"time"
)

func TestTunnelFixtureChannelEOFClosesUpstreamAndJoins(t *testing.T) {
	channel, peer := net.Pipe()
	upstream, target := net.Pipe()
	defer channel.Close()
	defer peer.Close()
	defer upstream.Close()
	defer target.Close()
	done := make(chan struct{})
	go func() { relayTunnelFixture(channel, upstream); close(done) }()
	// A target SSH server waits for the jump's TCP EOF. The remote client closing
	// its direct-tcpip channel must propagate that EOF even when the target has
	// not yet sent anything (or closed its own socket).
	peer.Close()
	target.SetReadDeadline(time.Now().Add(time.Second))
	var b [1]byte
	if _, err := target.Read(b[:]); err != io.EOF {
		t.Errorf("target did not receive EOF after channel close: %v", err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Error("relay did not join both copy workers")
	}
	// Failure cleanup must also join; neither a passing counter nor process exit
	// is evidence that the forwarding workers have drained.
	upstream.Close()
	target.Close()
	channel.Close()
	<-done
}
