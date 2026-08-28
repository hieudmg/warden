package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os/exec"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	clientssh "warden/internal/client/ssh"
	"warden/internal/model"

	golangssh "golang.org/x/crypto/ssh"
)

func TestServerWrongTokenReturnsFinalWithoutDialing(t *testing.T) {
	var dials sync.Mutex
	dialCalls := 0
	pool := NewPool(func(context.Context, model.SSHBundle) (*clientssh.Graph, error) {
		dials.Lock()
		dialCalls++
		dials.Unlock()
		return &clientssh.Graph{}, nil
	}, time.Now, time.Minute)
	server := &Server{Pool: pool, Token: bytes.Repeat([]byte{0x22}, TokenBytes)}

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	go server.handleConn(context.Background(), serverConn, server.Token)

	wrong := bytes.Repeat([]byte{0x11}, TokenBytes)
	request := Request{Operation: operationSSH, Command: "must not run"}
	frame := Frame{Version: Version, Kind: FrameRequest, Token: wrong, Request: &request}
	if err := WriteFrame(clientConn, frame); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	response, err := ReadFrame(clientConn)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if response.Kind != FrameFinal || response.Response == nil || response.Response.Error != "authentication failed" {
		t.Fatalf("response = %#v, want authentication final", response)
	}
	dials.Lock()
	defer dials.Unlock()
	if dialCalls != 0 {
		t.Fatalf("dial calls = %d, want 0", dialCalls)
	}
}

func TestServerMalformedFramesCloseRequestWithoutPanic(t *testing.T) {
	tests := []struct {
		name  string
		frame []byte
	}{
		{
			name: "oversized",
			frame: func() []byte {
				var size [4]byte
				binary.BigEndian.PutUint32(size[:], MaxFrameBytes+1)
				return size[:]
			}(),
		},
		{
			name: "unknown version",
			frame: func() []byte {
				body, _ := json.Marshal(Frame{Version: Version + 1, Kind: FrameRequest})
				var size [4]byte
				binary.BigEndian.PutUint32(size[:], uint32(len(body)))
				return append(size[:], body...)
			}(),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pool := NewPool(func(context.Context, model.SSHBundle) (*clientssh.Graph, error) {
				return &clientssh.Graph{}, nil
			}, time.Now, time.Minute)
			server := &Server{Pool: pool, Token: bytes.Repeat([]byte{0x22}, TokenBytes)}
			clientConn, serverConn := net.Pipe()
			defer clientConn.Close()
			go server.handleConn(context.Background(), serverConn, server.Token)
			if _, err := clientConn.Write(test.frame); err != nil {
				t.Fatalf("write malformed frame: %v", err)
			}
			_ = clientConn.SetReadDeadline(time.Now().Add(time.Second))
			if _, err := ReadFrame(clientConn); err == nil {
				t.Fatal("malformed request received a response")
			}
		})
	}
}

func TestFrameWriterSerializesConcurrentStreams(t *testing.T) {
	var wire bytes.Buffer
	writer := &frameWriter{w: &wire}
	const perStream = 20
	var wg sync.WaitGroup
	for i := 0; i < perStream; i++ {
		wg.Add(2)
		go func(i int) {
			defer wg.Done()
			_, _ = writer.stream(FrameStdout).Write([]byte{byte(i)})
		}(i)
		go func(i int) {
			defer wg.Done()
			_, _ = writer.stream(FrameStderr).Write([]byte{byte(i)})
		}(i)
	}
	wg.Wait()

	reader := bytes.NewReader(wire.Bytes())
	seen := map[FrameKind][]byte{FrameStdout: {}, FrameStderr: {}}
	for reader.Len() > 0 {
		frame, err := ReadFrame(reader)
		if err != nil {
			t.Fatalf("ReadFrame: %v", err)
		}
		seen[frame.Kind] = append(seen[frame.Kind], frame.Data...)
	}
	if len(seen[FrameStdout]) != perStream || len(seen[FrameStderr]) != perStream {
		t.Fatalf("stream lengths = %d/%d, want %d/%d", len(seen[FrameStdout]), len(seen[FrameStderr]), perStream, perStream)
	}
}

func TestOperationResponseCarriesRemoteStatusSeparately(t *testing.T) {
	response := operationResponse(&clientssh.ExitStatusError{Status: 17})
	if response.Error != "" {
		t.Fatalf("Error = %q, want empty", response.Error)
	}
	if response.ExitStatus == nil || *response.ExitStatus != 17 {
		t.Fatalf("ExitStatus = %#v, want 17", response.ExitStatus)
	}
	if response.Status != 17 {
		t.Fatalf("Status = %d, want 17", response.Status)
	}
}

func TestSanitizeOperationErrorRemovesBundleSecrets(t *testing.T) {
	secret := []byte("do-not-leak")
	response := operationResponse(errors.New("failed with do-not-leak"), secret)
	if response.Error != "failed with ***" {
		t.Fatalf("Error = %q, want redacted", response.Error)
	}
}

func TestRequestCopyRoundTrip(t *testing.T) {
	bundle := testBundle("secret")
	payload, err := json.Marshal(CopyRequest{
		Source:      CopyEndpoint{Path: "/source", Bundle: &bundle},
		Destination: CopyEndpoint{Path: "/destination"},
	})
	if err != nil {
		t.Fatal(err)
	}
	request, err := requestCopy(Request{Payload: payload})
	if err != nil {
		t.Fatal(err)
	}
	if request.Source.Bundle == nil || request.Destination.Bundle != nil {
		t.Fatalf("request = %#v, want one remote endpoint", request)
	}
}

func TestReadSSHInputForwardsExactBytes(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()
	inputReader, inputWriter := io.Pipe()
	defer inputReader.Close()
	defer inputWriter.Close()

	done := make(chan struct{})
	go func() {
		readSSHInput(context.Background(), serverConn, inputWriter)
		close(done)
	}()
	want := []byte("stdin\x00bytes")
	writeDone := make(chan error, 1)
	go func() {
		if err := WriteFrame(clientConn, Frame{Version: Version, Kind: FrameStdin, Data: want}); err != nil {
			writeDone <- err
			return
		}
		writeDone <- WriteFrame(clientConn, Frame{Version: Version, Kind: FrameEOF})
	}()
	got, err := io.ReadAll(inputReader)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("input = %q, want %q", got, want)
	}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("stdin reader did not finish")
	}
}

// pipeListener adapts net.Pipe to net.Listener for Serve lifecycle tests.
type pipeListener struct {
	conns  chan net.Conn
	closed chan struct{}
	once   sync.Once
}

func newPipeListener() *pipeListener {
	return &pipeListener{conns: make(chan net.Conn), closed: make(chan struct{})}
}

func (l *pipeListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.conns:
		return conn, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *pipeListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *pipeListener) Addr() net.Addr { return pipeAddr("agent-test") }

type pipeAddr string

func (a pipeAddr) Network() string { return "pipe" }
func (a pipeAddr) String() string  { return string(a) }

func TestServerStopsWhenPoolBecomesEmpty(t *testing.T) {
	clock := &poolClock{now: time.Unix(500, 0)}
	pool := NewPool(func(context.Context, model.SSHBundle) (*clientssh.Graph, error) {
		return &clientssh.Graph{}, nil
	}, clock.Now, time.Minute)
	lease, err := pool.Acquire(context.Background(), testBundle("secret"))
	if err != nil {
		t.Fatal(err)
	}
	lease.Release()

	listener := newPipeListener()
	server := NewServer(listener, bytes.Repeat([]byte{0x22}, TokenBytes), pool)
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(context.Background()) }()
	clock.Advance(time.Minute)
	pool.Expire()
	select {
	case err := <-serveDone:
		if err != nil {
			t.Fatalf("Serve: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Serve did not stop after the pool became empty")
	}
}

type agentSSHTestServer struct {
	listener net.Listener
	addr     string
	key      golangssh.PublicKey
	accepted atomic.Int64
}

func newAgentSSHTestServer(t *testing.T, password string) *agentSSHTestServer {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := golangssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	config := &golangssh.ServerConfig{PasswordCallback: func(_ golangssh.ConnMetadata, pass []byte) (*golangssh.Permissions, error) {
		if subtle.ConstantTimeCompare(pass, []byte(password)) != 1 {
			return nil, errors.New("authentication failed")
		}
		return nil, nil
	}}
	config.AddHostKey(signer)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &agentSSHTestServer{listener: listener, addr: listener.Addr().String(), key: signer.PublicKey()}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			server.accepted.Add(1)
			go server.handle(conn, config)
		}
	}()
	t.Cleanup(func() { listener.Close() })
	return server
}

func (s *agentSSHTestServer) handle(conn net.Conn, config *golangssh.ServerConfig) {
	session, channels, requests, err := golangssh.NewServerConn(conn, config)
	if err != nil {
		conn.Close()
		return
	}
	defer session.Close()
	go golangssh.DiscardRequests(requests)
	for newChannel := range channels {
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(golangssh.UnknownChannelType, "unsupported")
			continue
		}
		channel, requests, err := newChannel.Accept()
		if err != nil {
			continue
		}
		go s.handleSession(channel, requests)
	}
}

func (s *agentSSHTestServer) handleSession(channel golangssh.Channel, requests <-chan *golangssh.Request) {
	defer channel.Close()
	for request := range requests {
		if request.Type != "exec" {
			request.Reply(false, nil)
			continue
		}
		var payload struct{ Command string }
		if err := golangssh.Unmarshal(request.Payload, &payload); err != nil {
			request.Reply(false, nil)
			return
		}
		request.Reply(true, nil)
		command := exec.Command("sh", "-c", payload.Command)
		command.Stdin = channel
		command.Stdout = channel
		command.Stderr = channel.Stderr()
		status := uint32(0)
		if err := command.Run(); err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				status = uint32(exitErr.ExitCode())
			} else {
				status = 1
			}
		}
		_, _ = channel.SendRequest("exit-status", false, golangssh.Marshal(struct{ Status uint32 }{status}))
		return
	}
}

func (s *agentSSHTestServer) bundle(password string) model.SSHBundle {
	host, portText, _ := net.SplitHostPort(s.addr)
	port, _ := strconv.Atoi(portText)
	return model.SSHBundle{Target: model.SSHNode{Host: host, Port: port, Username: "user", Password: []byte(password)}}
}

func TestServerSequentialSSHRequestsReuseOneGraph(t *testing.T) {
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
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	token := bytes.Repeat([]byte{0x22}, TokenBytes)
	server := NewServer(listener, token, pool)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(ctx) }()

	run := func(command string, input []byte) (string, string, error) {
		conn, err := net.Dial("tcp", listener.Addr().String())
		if err != nil {
			return "", "", err
		}
		var stdout, stderr bytes.Buffer
		err = relayRequest(ctx, conn, token, Request{Operation: operationSSH, Command: command, SSHBundle: mustJSON(bundle)}, clientssh.Streams{Stdin: bytes.NewReader(input), Stdout: &stdout, Stderr: &stderr}, true)
		return stdout.String(), stderr.String(), err
	}
	stdout, stderr, err := run("printf out; printf err >&2", nil)
	if err != nil {
		t.Fatalf("first request: %v", err)
	}
	if stdout != "out" || stderr != "err" {
		t.Fatalf("first streams = %q/%q, want out/err", stdout, stderr)
	}
	stdout, _, err = run("cat", []byte("stdin\\x00bytes"))
	if err != nil {
		t.Fatalf("second request: %v", err)
	}
	if stdout != "stdin\\x00bytes" {
		t.Fatalf("second stdout = %q, want exact stdin", stdout)
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

func mustJSON(value any) json.RawMessage {
	data, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return data
}
