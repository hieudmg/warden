package agent

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"

	clientssh "warden/internal/client/ssh"
	"warden/internal/model"

	golangssh "golang.org/x/crypto/ssh"
)

func TestRelayRequestPreservesStreamsAndRemoteExitStatus(t *testing.T) {
	clientConn, agentConn := net.Pipe()
	defer clientConn.Close()
	defer agentConn.Close()

	token := bytes.Repeat([]byte{0x42}, TokenBytes)
	stdin := bytes.NewBufferString("input\x00bytes")
	var stdout, stderr bytes.Buffer
	agentDone := make(chan error, 1)
	go func() {
		frame, err := ReadAuthenticatedFrame(agentConn, token)
		if err != nil {
			agentDone <- err
			return
		}
		if frame.Request == nil || frame.Request.Operation != operationSSH {
			agentDone <- errors.New("unexpected SSH request")
			return
		}
		var received bytes.Buffer
		for {
			input, err := ReadFrame(agentConn)
			if err != nil {
				agentDone <- err
				return
			}
			if input.Kind == FrameEOF {
				break
			}
			if input.Kind != FrameStdin {
				agentDone <- errors.New("unexpected input frame")
				return
			}
			received.Write(input.Data)
		}
		if got, want := received.String(), "input\x00bytes"; got != want {
			agentDone <- errors.New("stdin bytes changed")
			return
		}
		if err := WriteFrame(agentConn, Frame{Version: Version, Kind: FrameStdout, Data: []byte("out\x00")}); err != nil {
			agentDone <- err
			return
		}
		if err := WriteFrame(agentConn, Frame{Version: Version, Kind: FrameStderr, Data: []byte("err\n")}); err != nil {
			agentDone <- err
			return
		}
		status := 23
		agentDone <- WriteFrame(agentConn, Frame{Version: Version, Kind: FrameFinal, Response: &Response{ExitStatus: &status}})
	}()

	err := relayRequest(context.Background(), clientConn, token, Request{Operation: operationSSH}, clientssh.Streams{
		Stdin:  stdin,
		Stdout: &stdout,
		Stderr: &stderr,
	}, true)
	var exitErr *clientssh.ExitStatusError
	if !errors.As(err, &exitErr) || exitErr.Status != 23 {
		t.Fatalf("relayRequest error = %v, want ExitStatusError(23)", err)
	}
	if got, want := stdout.String(), "out\x00"; got != want {
		t.Fatalf("stdout = %q, want %q", got, want)
	}
	if got, want := stderr.String(), "err\n"; got != want {
		t.Fatalf("stderr = %q, want %q", got, want)
	}
	if err := <-agentDone; err != nil {
		t.Fatalf("agent: %v", err)
	}
}

func TestRelayRequestReturnsSanitizedFinalError(t *testing.T) {
	clientConn, agentConn := net.Pipe()
	defer clientConn.Close()
	defer agentConn.Close()
	token := bytes.Repeat([]byte{0x42}, TokenBytes)
	agentDone := make(chan error, 1)
	go func() {
		if _, err := ReadAuthenticatedFrame(agentConn, token); err != nil {
			agentDone <- err
			return
		}
		agentDone <- WriteFrame(agentConn, Frame{Version: Version, Kind: FrameFinal, Response: &Response{Error: "safe error"}})
	}()

	err := relayRequest(context.Background(), clientConn, token, Request{Operation: operationDB}, clientssh.Streams{}, false)
	if err == nil || err.Error() != "safe error" {
		t.Fatalf("relayRequest error = %v, want safe error", err)
	}
	if err := <-agentDone; err != nil {
		t.Fatalf("agent: %v", err)
	}
}

func TestNormalizeCopyRequestMakesLocalPathsAbsolute(t *testing.T) {
	request := normalizeCopyRequest(CopyRequest{
		Source:      CopyEndpoint{Path: "relative/source"},
		Destination: CopyEndpoint{Path: "relative/destination"},
	})
	if !filepath.IsAbs(request.Source.Path) || !filepath.IsAbs(request.Destination.Path) {
		t.Fatalf("request paths = %q, %q, want absolute", request.Source.Path, request.Destination.Path)
	}
}

func TestConnectOrStartUsesExistingRuntimeWithoutLaunching(t *testing.T) {
	runtime, err := NewRuntimeAt(filepath.Join(t.TempDir(), "agent"))
	if err != nil {
		t.Fatal(err)
	}
	listener, err := runtime.Listen()
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Cleanup()

	accepted := make(chan net.Conn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- conn
	}()

	oldStart := startAgentServer
	defer func() { startAgentServer = oldStart }()
	var starts sync.Mutex
	startCalls := 0
	startAgentServer = func() error {
		starts.Lock()
		startCalls++
		starts.Unlock()
		return errors.New("must not start")
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, token, err := connectOrStart(ctx, runtime)
	if err != nil {
		t.Fatalf("connectOrStart: %v", err)
	}
	conn.Close()
	select {
	case acceptedConn := <-accepted:
		acceptedConn.Close()
	case err := <-acceptErr:
		t.Fatalf("Accept: %v", err)
	case <-time.After(time.Second):
		t.Fatal("timed out accepting runtime connection")
	}
	if len(token) != TokenBytes {
		t.Fatalf("token length = %d, want %d", len(token), TokenBytes)
	}
	starts.Lock()
	defer starts.Unlock()
	if startCalls != 0 {
		t.Fatalf("start calls = %d, want 0", startCalls)
	}
}

func TestSendStdinFramesSendsEOFForNilReader(t *testing.T) {
	var frames []Frame
	var mu sync.Mutex
	writeFrame := func(frame Frame) error {
		mu.Lock()
		frames = append(frames, frame)
		mu.Unlock()
		return nil
	}
	sendStdinFrames(context.Background(), io.Discard, writeFrame, nil)
	if len(frames) != 1 || frames[0].Kind != FrameEOF {
		t.Fatalf("frames = %#v, want one EOF", frames)
	}
}

func TestRunSSHUsesRuntimeServerAndReusesGraph(t *testing.T) {
	sshServer := newAgentSSHTestServer(t, "secret")
	bundle := sshServer.bundle("secret")
	pool := NewPool(func(ctx context.Context, bundle model.SSHBundle) (*clientssh.Graph, error) {
		return clientssh.DialGraph(ctx, bundle, clientssh.DialOptions{HostKeyCallback: func(_ string, _ net.Addr, key golangssh.PublicKey) error {
			if !bytes.Equal(key.Marshal(), sshServer.key.Marshal()) {
				return errors.New("unexpected host key")
			}
			return nil
		}})
	}, time.Now, time.Minute)
	runtime, err := NewRuntimeAt(filepath.Join(t.TempDir(), "runtime"))
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewRuntimeServer(runtime, pool)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(ctx) }()

	oldFactory := runtimeFactory
	defer func() { runtimeFactory = oldFactory }()
	runtimeFactory = func() (*Runtime, error) { return runtime, nil }
	var out bytes.Buffer
	if err := RunSSH(ctx, bundle, "printf first", clientssh.Streams{Stdout: &out}); err != nil {
		t.Fatalf("first RunSSH: %v", err)
	}
	if err := RunSSH(ctx, bundle, "printf second", clientssh.Streams{Stdout: &out}); err != nil {
		t.Fatalf("second RunSSH: %v", err)
	}
	if got, want := out.String(), "firstsecond"; got != want {
		t.Fatalf("output = %q, want %q", got, want)
	}
	if got := sshServer.accepted.Load(); got != 1 {
		t.Fatalf("accepted SSH connections = %d, want 1", got)
	}
	cancel()
	select {
	case <-serveDone:
	case <-time.After(time.Second):
		t.Fatal("server did not stop after cancellation")
	}
}
