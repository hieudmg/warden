package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	clientdb "warden/internal/client/db"
	clientsftp "warden/internal/client/sftp"
	clientssh "warden/internal/client/ssh"
	"warden/internal/model"
)

const (
	operationSSH  = "ssh"
	operationCopy = "copy"
	operationCP   = "cp"
	operationDB   = "db"
)

var (
	// Operation runners are variables so server tests can inject a bounded
	// fake while production uses the borrowed-resource implementations.
	runCommandOnClient      = clientssh.RunCommandOnClient
	openSFTP                = clientsftp.Open
	copySFTP                = clientsftp.Copy
	runQueryWithDialContext = clientdb.RunQueryWithDialContext
)

// CopyEndpoint is the serializable form of one cp operand. A nil Bundle marks
// a local filesystem path; a non-nil Bundle marks a remote SFTP path.
type CopyEndpoint struct {
	Path      string           `json:"path"`
	Bundle    *model.SSHBundle `json:"bundle,omitempty"`
	SSHBundle *model.SSHBundle `json:"ssh_bundle,omitempty"`
}

// CopyRequest describes one remote/local copy operation. SourceBundle and
// DestinationBundle are compatibility fields for callers that prefer a flat
// request; endpoint Bundle fields take precedence when both are supplied.
type CopyRequest struct {
	Source            CopyEndpoint     `json:"source"`
	Destination       CopyEndpoint     `json:"destination"`
	SourcePath        string           `json:"source_path,omitempty"`
	DestinationPath   string           `json:"destination_path,omitempty"`
	SourceBundle      *model.SSHBundle `json:"source_bundle,omitempty"`
	DestinationBundle *model.SSHBundle `json:"destination_bundle,omitempty"`
}

// Server owns one authenticated agent listener and dispatches operations to
// the graph pool. Listener and token are exported so the internal CLI and
// package integration tests can compose Server with Runtime; NewServer is the
// usual constructor.
type Server struct {
	Listener net.Listener
	Token    []byte
	Pool     *Pool
	Runtime  *Runtime

	// Lower-case aliases keep construction convenient for same-package tests
	// while the exported fields support the command package in a later task.
	listener net.Listener
	token    []byte
	pool     *Pool
	runtime  *Runtime

	closeOnce sync.Once
	stop      chan struct{}
}

// NewServer creates an authenticated server over listener. The server copies
// token before serving, so callers may safely reuse or clear their token slice
// after construction.
func NewServer(listener net.Listener, token []byte, pool *Pool) *Server {
	return &Server{
		Listener: listener,
		Token:    append([]byte(nil), token...),
		Pool:     pool,
	}
}

// NewRuntimeServer creates a server from a Runtime's existing listener and
// token. Runtime.Listen must have been called first.
func NewRuntimeServer(runtime *Runtime, pool *Pool) (*Server, error) {
	if runtime == nil {
		return nil, errors.New("agent runtime is nil")
	}
	listener, err := runtime.Listen()
	if err != nil {
		return nil, err
	}
	token, err := runtime.ReadToken()
	if err != nil {
		_ = listener.Close()
		return nil, err
	}
	server := NewServer(listener, token, pool)
	server.Runtime = runtime
	return server, nil
}

// Serve accepts authenticated local requests until ctx is canceled or the
// pool has become empty after TTL cleanup. The initial empty pool is kept
// alive so a freshly detached agent can accept its first client.
func (s *Server) Serve(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	listener := s.serverListener()
	pool := s.serverPool()
	token := s.serverToken()
	if listener == nil {
		return errors.New("agent server listener is nil")
	}
	if pool == nil {
		return errors.New("agent server pool is nil")
	}
	if len(token) != TokenBytes {
		return errors.New("agent server token has invalid length")
	}

	s.stop = make(chan struct{})
	var handlers sync.WaitGroup
	watchDone := make(chan struct{})
	watchStopped := make(chan struct{})
	go s.watchPool(ctx, listener, pool, watchDone, watchStopped)
	defer func() {
		close(watchDone)
		<-watchStopped
		s.closeListener(listener)
		handlers.Wait()
		_ = pool.Close()
		if runtime := s.serverRuntime(); runtime != nil {
			_ = runtime.Cleanup()
		}
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-s.stop:
				if ctx.Err() != nil {
					return ctx.Err()
				}
				return nil
			default:
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		handlers.Add(1)
		go func() {
			defer handlers.Done()
			s.handleConn(ctx, conn, token)
		}()
	}
}

// Serve is the package-level convenience wrapper used by a hidden agent
// command without requiring it to retain a Server value.
func Serve(ctx context.Context, listener net.Listener, token []byte, pool *Pool) error {
	return NewServer(listener, token, pool).Serve(ctx)
}

func (s *Server) serverListener() net.Listener {
	if s.Listener != nil {
		return s.Listener
	}
	return s.listener
}

func (s *Server) serverToken() []byte {
	if len(s.Token) != 0 {
		return s.Token
	}
	return s.token
}

func (s *Server) serverPool() *Pool {
	if s.Pool != nil {
		return s.Pool
	}
	return s.pool
}

func (s *Server) serverRuntime() *Runtime {
	if s.Runtime != nil {
		return s.Runtime
	}
	return s.runtime
}

func (s *Server) closeListener(listener net.Listener) {
	s.closeOnce.Do(func() {
		close(s.stop)
		_ = listener.Close()
	})
}

func (s *Server) watchPool(ctx context.Context, listener net.Listener, pool *Pool, done, stopped chan struct{}) {
	defer close(stopped)

	ttl := pool.TTL()
	interval := time.Second
	if ttl > 0 && ttl < interval {
		interval = ttl
	}
	if interval <= 0 {
		interval = 10 * time.Millisecond
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		if pool.Used() {
			signal := pool.EmptySignal()
			if pool.Empty() {
				s.closeListener(listener)
				return
			}
			select {
			case <-signal:
				if pool.Empty() {
					s.closeListener(listener)
					return
				}
			case <-ticker.C:
				pool.Expire()
			case <-ctx.Done():
				s.closeListener(listener)
				return
			case <-done:
				return
			}
			continue
		}
		select {
		case <-ticker.C:
			pool.Expire()
		case <-ctx.Done():
			s.closeListener(listener)
			return
		case <-done:
			return
		}
	}
}

func (s *Server) handleConn(ctx context.Context, conn net.Conn, token []byte) {
	if ctx == nil {
		ctx = context.Background()
	}
	if conn == nil {
		return
	}
	defer conn.Close()
	connectionDone := make(chan struct{})
	defer close(connectionDone)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-connectionDone:
		}
	}()

	frame, err := ReadAuthenticatedFrame(conn, token)
	if err != nil {
		// A token failure receives a stable, non-secret final frame. Framing
		// failures are deliberately closed without echoing a protocol error;
		// this also prevents a peer that sent only an oversized declaration
		// from keeping the handler blocked on a response write.
		if errors.Is(err, ErrTokenMismatch) {
			_ = writeFinal(conn, Response{Error: "authentication failed"})
		} else if errors.Is(err, ErrAuthenticationRequired) {
			_ = writeFinal(conn, Response{Error: "agent request authentication required"})
		}
		return
	}

	request, err := requestFromFrame(frame)
	if err != nil {
		_ = writeFinal(conn, Response{Error: "invalid agent request"})
		return
	}

	requestCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	switch request.Operation {
	case operationSSH:
		s.handleSSH(requestCtx, conn, request)
	case operationCopy, operationCP:
		disconnectCtx, stop := watchDisconnect(requestCtx, conn)
		defer stop()
		s.handleCopy(disconnectCtx, conn, request)
	case operationDB:
		disconnectCtx, stop := watchDisconnect(requestCtx, conn)
		defer stop()
		s.handleDB(disconnectCtx, conn, request)
	default:
		_ = writeFinal(conn, Response{Error: "unknown agent operation"})
	}
}

func (s *Server) handleSSH(ctx context.Context, conn net.Conn, request Request) {
	bundle, err := requestSSHBundle(request)
	if err != nil {
		_ = writeFinal(conn, Response{Error: "invalid SSH bundle"})
		return
	}

	pool := s.serverPool()
	lease, err := pool.Acquire(ctx, bundle)
	if err != nil {
		_ = writeFinal(conn, operationResponse(err, bundleSecrets(bundle)...))
		return
	}
	defer lease.Release()
	if lease.Target() == nil {
		lease.Retire()
		_ = writeFinal(conn, Response{Error: "agent graph target is unavailable"})
		return
	}

	var inputReader *io.PipeReader
	var inputWriter *io.PipeWriter
	inputDone := make(chan struct{})
	inputReader, inputWriter = io.Pipe()
	inputCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		defer close(inputDone)
		if err := readSSHInput(inputCtx, conn, inputWriter); err != nil {
			cancel()
		}
	}()

	writer := &frameWriter{w: conn}
	streams := clientssh.Streams{Stdin: inputReader, Stdout: writer.stream(FrameStdout), Stderr: writer.stream(FrameStderr)}
	err = runCommandOnClient(inputCtx, lease.Target(), request.Command, streams)
	if shouldRetireGraph(err) {
		lease.Retire()
	}
	_ = inputWriter.Close()
	response := operationResponse(err, bundleSecrets(bundle)...)
	if writeErr := writeFinal(conn, response); writeErr != nil && err == nil {
		err = writeErr
	}
	// Closing the request connection after the final frame unblocks a reader
	// that was waiting for a late stdin EOF. The client has already received
	// the terminal response by this point.
	_ = conn.SetDeadline(time.Now().Add(100 * time.Millisecond))
	select {
	case <-inputDone:
	case <-time.After(100 * time.Millisecond):
	}
}

func watchDisconnect(ctx context.Context, conn net.Conn) (context.Context, func()) {
	requestCtx, cancel := context.WithCancel(ctx)
	go func() {
		var one [1]byte
		if _, err := conn.Read(one[:]); err != nil {
			cancel()
		}
	}()
	return requestCtx, cancel
}

func readSSHInput(ctx context.Context, conn net.Conn, dst *io.PipeWriter) error {
	defer dst.Close()
	for {
		frame, err := ReadFrame(conn)
		if err != nil {
			_ = dst.CloseWithError(err)
			return err
		}
		switch frame.Kind {
		case FrameStdin:
			if _, err := dst.Write(frame.Data); err != nil {
				return err
			}
		case FrameEOF:
			return nil
		default:
			err := errors.New("invalid SSH input frame")
			_ = dst.CloseWithError(err)
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
	}
}

func (s *Server) handleCopy(ctx context.Context, conn net.Conn, request Request) {
	copyRequest, err := requestCopy(request)
	if err != nil {
		_ = writeFinal(conn, Response{Error: "invalid copy request"})
		return
	}
	pool := s.serverPool()

	leases := make(map[[32]byte]*Lease)
	var leaseOrder []*Lease
	defer func() {
		for i := len(leaseOrder) - 1; i >= 0; i-- {
			leaseOrder[i].Release()
		}
	}()

	acquire := func(endpoint CopyEndpoint) (*Lease, error) {
		bundle := endpointBundle(endpoint)
		if bundle == nil {
			return nil, nil
		}
		key := FingerprintBundle(*bundle)
		if lease := leases[key]; lease != nil {
			return lease, nil
		}
		lease, err := pool.Acquire(ctx, *bundle)
		if err != nil {
			return nil, err
		}
		leases[key] = lease
		leaseOrder = append(leaseOrder, lease)
		return lease, nil
	}

	sourceLease, err := acquire(copyRequest.Source)
	if err != nil {
		_ = writeFinal(conn, operationResponse(err, endpointSecrets(copyRequest.Source)...))
		return
	}
	destinationLease, err := acquire(copyRequest.Destination)
	if err != nil {
		_ = writeFinal(conn, operationResponse(err, endpointSecrets(copyRequest.Destination)...))
		return
	}

	source, sourceRemote, err := openCopyEndpoint(copyRequest.Source, sourceLease)
	if err != nil {
		if sourceLease != nil {
			sourceLease.Retire()
		}
		_ = writeFinal(conn, operationResponse(err, endpointSecrets(copyRequest.Source)...))
		return
	}
	if sourceRemote != nil {
		defer sourceRemote.Close()
	}
	destination, destinationRemote, err := openCopyEndpoint(copyRequest.Destination, destinationLease)
	if err != nil {
		if destinationLease != nil {
			destinationLease.Retire()
		}
		_ = writeFinal(conn, operationResponse(err, endpointSecrets(copyRequest.Destination)...))
		return
	}
	if destinationRemote != nil {
		defer destinationRemote.Close()
	}

	err = copySFTP(source, destination)
	secrets := append(endpointSecrets(copyRequest.Source), endpointSecrets(copyRequest.Destination)...)
	_ = writeFinal(conn, operationResponse(err, secrets...))
}

func (s *Server) handleDB(ctx context.Context, conn net.Conn, request Request) {
	bundle, err := requestDBBundle(request)
	if err != nil || bundle.SSH == nil {
		_ = writeFinal(conn, Response{Error: "invalid tunneled DB request"})
		return
	}

	pool := s.serverPool()
	lease, err := pool.Acquire(ctx, *bundle.SSH)
	if err != nil {
		secrets := append([][]byte{bundle.Password}, bundleSecrets(*bundle.SSH)...)
		_ = writeFinal(conn, operationResponse(err, secrets...))
		return
	}
	defer lease.Release()
	if lease.Target() == nil {
		lease.Retire()
		_ = writeFinal(conn, Response{Error: "agent graph target is unavailable"})
		return
	}

	dbAddr := net.JoinHostPort(bundle.Host, strconv.Itoa(bundle.Port))
	tunnel := clientdb.NewBorrowedTunnelDialer(lease.Target(), dbAddr)
	dbWriter := (&frameWriter{w: conn}).stream(FrameStdout)
	err = runQueryWithDialContext(ctx, bundle, request.SQL, dbWriter, tunnel.DialContext)
	if closeErr := tunnel.Close(); err == nil {
		err = closeErr
	}
	if shouldRetireGraph(err) {
		lease.Retire()
	}
	secrets := append([][]byte{bundle.Password}, bundleSecrets(*bundle.SSH)...)
	_ = writeFinal(conn, operationResponse(err, secrets...))
}

type frameWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (w *frameWriter) stream(kind FrameKind) io.Writer {
	return frameStream{parent: w, kind: kind}
}

type frameStream struct {
	parent *frameWriter
	kind   FrameKind
}

func (w frameStream) Write(data []byte) (int, error) {
	if w.parent == nil || w.parent.w == nil {
		return 0, io.ErrClosedPipe
	}
	if len(data) == 0 {
		return 0, nil
	}
	copyData := append([]byte(nil), data...)
	w.parent.mu.Lock()
	defer w.parent.mu.Unlock()
	if err := WriteFrame(w.parent.w, Frame{Version: Version, Kind: w.kind, Data: copyData}); err != nil {
		return 0, err
	}
	return len(data), nil
}

func requestFromFrame(frame Frame) (Request, error) {
	if frame.Request != nil {
		return *frame.Request, nil
	}
	raw := frame.Data
	if len(raw) == 0 {
		raw = frame.Payload
	}
	if len(raw) == 0 {
		return Request{}, errors.New("agent request payload is empty")
	}
	var request Request
	if err := json.Unmarshal(raw, &request); err != nil {
		return Request{}, err
	}
	return request, nil
}

func requestSSHBundle(request Request) (model.SSHBundle, error) {
	var bundle model.SSHBundle
	if len(request.SSHBundle) != 0 {
		if err := json.Unmarshal(request.SSHBundle, &bundle); err != nil {
			return bundle, err
		}
		return bundle, nil
	}
	if len(request.Payload) != 0 {
		if json.Unmarshal(request.Payload, &bundle) == nil && bundle.Target.Host != "" {
			return bundle, nil
		}
		var payload struct {
			Bundle    json.RawMessage `json:"bundle"`
			SSHBundle json.RawMessage `json:"ssh_bundle"`
		}
		if err := json.Unmarshal(request.Payload, &payload); err == nil {
			raw := payload.Bundle
			if len(raw) == 0 {
				raw = payload.SSHBundle
			}
			if len(raw) != 0 && json.Unmarshal(raw, &bundle) == nil {
				return bundle, nil
			}
		}
	}
	return bundle, errors.New("SSH bundle is missing")
}

func requestDBBundle(request Request) (model.DBBundle, error) {
	var bundle model.DBBundle
	if len(request.DBBundle) != 0 {
		if err := json.Unmarshal(request.DBBundle, &bundle); err != nil {
			return bundle, err
		}
		return bundle, nil
	}
	if len(request.Payload) != 0 {
		if json.Unmarshal(request.Payload, &bundle) == nil && bundle.Host != "" {
			return bundle, nil
		}
		var payload struct {
			Bundle   json.RawMessage `json:"bundle"`
			DBBundle json.RawMessage `json:"db_bundle"`
		}
		if err := json.Unmarshal(request.Payload, &payload); err == nil {
			raw := payload.Bundle
			if len(raw) == 0 {
				raw = payload.DBBundle
			}
			if len(raw) != 0 && json.Unmarshal(raw, &bundle) == nil {
				return bundle, nil
			}
		}
	}
	return bundle, errors.New("DB bundle is missing")
}

func requestCopy(request Request) (CopyRequest, error) {
	var copyRequest CopyRequest
	if len(request.Payload) == 0 {
		return copyRequest, errors.New("copy payload is missing")
	}
	if err := json.Unmarshal(request.Payload, &copyRequest); err != nil {
		// Accept the flat wire form as well: it is useful to callers that
		// already keep paths and bundles in separate fields.
		var flat struct {
			Source            string           `json:"source"`
			Destination       string           `json:"destination"`
			SourcePath        string           `json:"source_path"`
			DestinationPath   string           `json:"destination_path"`
			SourceBundle      *model.SSHBundle `json:"source_bundle"`
			DestinationBundle *model.SSHBundle `json:"destination_bundle"`
		}
		if flatErr := json.Unmarshal(request.Payload, &flat); flatErr != nil {
			return copyRequest, err
		}
		copyRequest.Source = CopyEndpoint{Path: flat.Source, Bundle: flat.SourceBundle}
		copyRequest.Destination = CopyEndpoint{Path: flat.Destination, Bundle: flat.DestinationBundle}
		copyRequest.SourcePath = flat.SourcePath
		copyRequest.DestinationPath = flat.DestinationPath
		if copyRequest.Source.Path == "" {
			copyRequest.Source.Path = flat.SourcePath
		}
		if copyRequest.Destination.Path == "" {
			copyRequest.Destination.Path = flat.DestinationPath
		}
	}
	if copyRequest.Source.Path == "" && copyRequest.SourcePath != "" {
		copyRequest.Source.Path = copyRequest.SourcePath
	}
	if copyRequest.Destination.Path == "" && copyRequest.DestinationPath != "" {
		copyRequest.Destination.Path = copyRequest.DestinationPath
	}
	if copyRequest.Source.Bundle == nil {
		copyRequest.Source.Bundle = copyRequest.Source.SSHBundle
	}
	if copyRequest.Destination.Bundle == nil {
		copyRequest.Destination.Bundle = copyRequest.Destination.SSHBundle
	}
	if copyRequest.Source.Bundle == nil {
		copyRequest.Source.Bundle = copyRequest.SourceBundle
	}
	if copyRequest.Destination.Bundle == nil {
		copyRequest.Destination.Bundle = copyRequest.DestinationBundle
	}
	if copyRequest.Source.Path == "" || copyRequest.Destination.Path == "" {
		return copyRequest, errors.New("copy path is missing")
	}
	return copyRequest, nil
}

func endpointBundle(endpoint CopyEndpoint) *model.SSHBundle {
	if endpoint.Bundle != nil {
		return endpoint.Bundle
	}
	return endpoint.SSHBundle
}

func endpointSecrets(endpoint CopyEndpoint) [][]byte {
	bundle := endpointBundle(endpoint)
	if bundle == nil {
		return nil
	}
	return bundleSecrets(*bundle)
}

func bundleSecrets(bundle model.SSHBundle) [][]byte {
	secrets := make([][]byte, 0, 4+len(bundle.Jumps)*4)
	appendNode := func(node model.SSHNode) {
		secrets = append(secrets, node.Password, node.PrivateKey, node.PrivateKeyPassphrase, node.ProxyPassword)
	}
	appendNode(bundle.Target)
	for _, jump := range bundle.Jumps {
		appendNode(jump)
	}
	return secrets
}

func openCopyEndpoint(endpoint CopyEndpoint, lease *Lease) (client clientsftp.Endpoint, remote *clientsftp.Remote, err error) {
	bundle := endpointBundle(endpoint)
	if bundle == nil {
		return clientsftp.Endpoint{FS: clientsftp.NewLocalFilesystem(), Path: endpoint.Path, Identity: "local"}, nil, nil
	}
	if lease == nil || lease.Target() == nil {
		return clientsftp.Endpoint{}, nil, errors.New("copy graph is unavailable")
	}
	remote, err = openSFTP(lease.Target(), *bundle)
	if err != nil {
		return clientsftp.Endpoint{}, nil, fmt.Errorf("open SFTP session: %w", err)
	}
	return remote.Endpoint(endpoint.Path), remote, nil
}

func writeFinal(w io.Writer, response Response) error {
	return WriteFrame(w, Frame{Version: Version, Kind: FrameFinal, Response: &response})
}

func operationResponse(err error, secrets ...[]byte) Response {
	if err == nil {
		return Response{}
	}
	message := sanitizeOperationError(err, secrets...)
	var exitErr *clientssh.ExitStatusError
	if errors.As(err, &exitErr) {
		status := exitErr.Status
		return Response{ExitStatus: &status, Status: status}
	}
	return Response{Error: message}
}

func sanitizeOperationError(err error, secrets ...[]byte) string {
	if err == nil {
		return ""
	}
	message := err.Error()
	for _, secret := range secrets {
		if len(secret) != 0 {
			message = strings.ReplaceAll(message, string(secret), "***")
		}
	}
	if message == "" {
		return "operation failed"
	}
	return message
}

func shouldRetireGraph(err error) bool {
	if err == nil {
		return false
	}
	var exitErr *clientssh.ExitStatusError
	if errors.As(err, &exitErr) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	message := err.Error()
	return strings.Contains(message, "open ssh session") ||
		strings.Contains(message, "start remote command") ||
		strings.Contains(message, "SFTP session") ||
		strings.Contains(message, "tunnel to ") ||
		strings.Contains(message, "connection reset") ||
		strings.Contains(message, "broken pipe")
}
