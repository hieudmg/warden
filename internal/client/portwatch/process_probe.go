package portwatch

import (
	"context"
	"errors"
	"io"
	"strings"
	"time"

	golangssh "golang.org/x/crypto/ssh"

	clientssh "warden/internal/client/ssh"
	"warden/internal/model"
)

const (
	processProbeTimeout   = 500 * time.Millisecond
	maxProcessProbeOutput = 1 << 20
)

// The watch loop owns pending. A probe owns the optional graph until it sends
// its result; no other probe can touch the graph until that result is read.
type processProbe struct {
	bundle    model.SSHBundle
	pending   <-chan map[int]string
	attempted bool
	graph     *clientssh.Graph
	stopClose func() bool
}

func (p *processProbe) start(ctx context.Context) <-chan map[int]string {
	if p.pending != nil {
		select {
		case <-p.pending: // Discard results from older authoritative snapshots.
			p.pending = nil
		default:
			return nil
		}
	}
	if ctx.Err() != nil || (p.attempted && p.graph == nil) {
		return nil
	}
	result := make(chan map[int]string, 1)
	p.pending = result
	go func() { result <- p.lookup(ctx) }()
	return result
}

func (p *processProbe) lookup(watchCtx context.Context) map[int]string {
	ctx, cancel := context.WithTimeout(watchCtx, processProbeTimeout)
	defer cancel()
	if p.graph == nil {
		// Make only one optional connection attempt per watch. In particular,
		// a rejected authentication must not cause a background login loop.
		p.attempted = true
		graph, err := clientssh.DialGraph(ctx, p.bundle, clientssh.DialOptions{})
		if err != nil {
			return nil
		}
		p.graph = graph
		p.stopClose = context.AfterFunc(watchCtx, func() { closeProcessGraph(graph) })
	}

	stopAbort := context.AfterFunc(ctx, p.graph.Abort)
	output, err := runListenerProcessCommand(p.graph.Target())
	var exitErr *golangssh.ExitError
	if !stopAbort() || ctx.Err() != nil || (err != nil && !errors.As(err, &exitErr)) {
		// Timeout or a channel/transport failure may leave a session open.
		// Close the optional graph rather than opening more sessions on it.
		p.stopClose()
		closeProcessGraph(p.graph)
		p.graph = nil
		return nil
	}
	if err != nil { // A normal nonzero exit has released the session.
		return nil
	}
	names, err := parseListeningPorts(output, true)
	if err != nil || ctx.Err() != nil {
		return nil
	}
	return names
}

func closeProcessGraph(graph *clientssh.Graph) {
	graph.Abort() // Close from the outside in before closing any jump channels.
	_ = graph.Close()
}

func runListenerProcessCommand(client *golangssh.Client) (string, error) {
	session, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer session.Close()
	var output processOutput
	session.Stdout = &output
	session.Stderr = io.Discard
	if err := session.Run(remoteListenerProcessCommand); err != nil {
		return "", err
	}
	if output.overflow {
		return "", nil
	}
	return output.buf.String(), nil
}

// Drain excess stdout without allocating for it or wedging the SSH session.
type processOutput struct {
	buf      strings.Builder
	overflow bool
}

func (o *processOutput) Write(p []byte) (int, error) {
	n := len(p)
	if remaining := maxProcessProbeOutput - o.buf.Len(); n > remaining {
		o.overflow = true
		p = p[:remaining]
	}
	_, _ = o.buf.Write(p)
	return n, nil
}
