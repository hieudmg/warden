package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	clientssh "warden/internal/client/ssh"
	"warden/internal/model"
)

const (
	agentStartupTimeout = 5 * time.Second
	agentRetryInterval  = 10 * time.Millisecond
	stdinFrameBytes     = 32 * 1024
)

var (
	// These seams keep startup-race tests deterministic without changing the
	// production command or Runtime behavior.
	runtimeFactory   = NewRuntime
	startAgentServer = startDetachedAgent
)

// RunSSH executes command through the local authenticated agent, preserving
// the three SSH streams and remote exit status.
func RunSSH(ctx context.Context, bundle model.SSHBundle, command string, streams clientssh.Streams) error {
	payload, err := json.Marshal(bundle)
	if err != nil {
		return err
	}
	request := Request{
		Operation: operationSSH,
		Command:   command,
		SSHBundle: payload,
	}
	return runRequest(ctx, request, streams, true)
}

// RunCopy executes a local/remote or remote/remote copy through the agent.
// It accepts either a CopyRequest or two CopyEndpoint operands. Remote
// endpoints carry their complete resolved SSH bundle; local endpoints carry a
// nil Bundle and are evaluated by the agent's process filesystem.
func RunCopy(ctx context.Context, requestOrSource interface{}, destination ...CopyEndpoint) error {
	switch value := requestOrSource.(type) {
	case CopyRequest:
		if len(destination) != 0 {
			return errors.New("copy request cannot have a second operand")
		}
		return RunCopyRequest(ctx, value)
	case *CopyRequest:
		if value == nil {
			return errors.New("copy request is nil")
		}
		if len(destination) != 0 {
			return errors.New("copy request cannot have a second operand")
		}
		return RunCopyRequest(ctx, *value)
	case CopyEndpoint:
		if len(destination) != 1 {
			return errors.New("copy requires source and destination operands")
		}
		return RunCopyRequest(ctx, CopyRequest{Source: value, Destination: destination[0]})
	default:
		return errors.New("invalid copy request")
	}
}

// RunCopyRequest is the request-struct form of RunCopy.
func RunCopyRequest(ctx context.Context, copyRequest CopyRequest) error {
	copyRequest = normalizeCopyRequest(copyRequest)
	payload, err := json.Marshal(copyRequest)
	if err != nil {
		return err
	}
	return runRequest(ctx, Request{Operation: operationCopy, Payload: payload}, clientssh.Streams{}, false)
}

// RunTunneledDB executes one SQL statement through a pooled SSH graph and
// streams the formatted result to out. Direct DB bundles should continue to
// use db.RunQuery in the CLI.
func RunTunneledDB(ctx context.Context, bundle model.DBBundle, sqlText string, out io.Writer) error {
	payload, err := json.Marshal(bundle)
	if err != nil {
		return err
	}
	request := Request{
		Operation: operationDB,
		SQL:       sqlText,
		DBBundle:  payload,
	}
	return runRequest(ctx, request, clientssh.Streams{Stdout: out}, false)
}

func normalizeCopyRequest(copyRequest CopyRequest) CopyRequest {
	copyRequest.Source.Bundle = endpointBundle(copyRequest.Source)
	copyRequest.Destination.Bundle = endpointBundle(copyRequest.Destination)
	// Preserve an explicitly supplied SSHBundle alias when Bundle was nil.
	if copyRequest.Source.Bundle == nil {
		copyRequest.Source.Bundle = copyRequest.Source.SSHBundle
	}
	if copyRequest.Destination.Bundle == nil {
		copyRequest.Destination.Bundle = copyRequest.Destination.SSHBundle
	}
	if copyRequest.Source.Path == "" {
		copyRequest.Source.Path = copyRequest.SourcePath
	}
	if copyRequest.Destination.Path == "" {
		copyRequest.Destination.Path = copyRequest.DestinationPath
	}
	if copyRequest.Source.Bundle == nil {
		copyRequest.Source.Bundle = copyRequest.SourceBundle
	}
	if copyRequest.Destination.Bundle == nil {
		copyRequest.Destination.Bundle = copyRequest.DestinationBundle
	}
	// The detached agent may have a different working directory from the
	// caller. Make local paths stable before sending them over IPC.
	if copyRequest.Source.Bundle == nil && copyRequest.Source.Path != "" {
		if absolute, err := filepath.Abs(copyRequest.Source.Path); err == nil {
			copyRequest.Source.Path = absolute
		}
	}
	if copyRequest.Destination.Bundle == nil && copyRequest.Destination.Path != "" {
		if absolute, err := filepath.Abs(copyRequest.Destination.Path); err == nil {
			copyRequest.Destination.Path = absolute
		}
	}
	return copyRequest
}

func runRequest(ctx context.Context, request Request, streams clientssh.Streams, sendStdin bool) error {
	if ctx == nil {
		return errors.New("agent client context is nil")
	}
	runtime, err := runtimeFactory()
	if err != nil {
		return err
	}
	conn, token, err := connectOrStart(ctx, runtime)
	if err != nil {
		return err
	}
	return relayRequest(ctx, conn, token, request, streams, sendStdin)
}

func connectOrStart(ctx context.Context, runtime *Runtime) (io.ReadWriteCloser, []byte, error) {
	if runtime == nil {
		return nil, nil, errors.New("agent runtime is nil")
	}
	if ctx == nil {
		return nil, nil, errors.New("agent client context is nil")
	}

	// First attach to an already-running agent. A token may be present while
	// the listener is still coming up, so both reads and dials are retried.
	if conn, token, err := tryRuntime(ctx, runtime); err == nil {
		return conn, token, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	if err := startAgentServer(); err != nil {
		return nil, nil, err
	}

	deadline := time.Now().Add(agentStartupTimeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	for {
		if conn, token, err := tryRuntime(ctx, runtime); err == nil {
			return conn, token, nil
		}
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		if time.Now().After(deadline) {
			return nil, nil, errors.New("agent did not become ready within 5 seconds")
		}
		timer := time.NewTimer(agentRetryInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, nil, ctx.Err()
		case <-timer.C:
		}
	}
}

func tryRuntime(ctx context.Context, runtime *Runtime) (io.ReadWriteCloser, []byte, error) {
	token, err := runtime.ReadToken()
	if err != nil {
		return nil, nil, err
	}
	if len(token) != TokenBytes {
		return nil, nil, errors.New("agent token has invalid length")
	}
	conn, err := runtime.Dial(ctx)
	if err != nil {
		return nil, nil, err
	}
	return conn, token, nil
}

func startDetachedAgent() error {
	executable, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve agent executable: %w", err)
	}
	command := exec.Command(executable, "agent", "serve")
	command.Stdin = nil
	command.Stdout = nil
	command.Stderr = nil
	if err := command.Start(); err != nil {
		return fmt.Errorf("start agent: %w", err)
	}
	if err := command.Process.Release(); err != nil {
		return fmt.Errorf("detach agent: %w", err)
	}
	return nil
}

func relayRequest(ctx context.Context, conn io.ReadWriteCloser, token []byte, request Request, streams clientssh.Streams, sendStdin bool) error {
	if conn == nil {
		return errors.New("agent connection is nil")
	}
	defer conn.Close()
	request.Token = append([]byte(nil), token...)

	writeMu := sync.Mutex{}
	writeRequest := func(frame Frame) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		return WriteFrame(conn, frame)
	}
	if err := writeRequest(Frame{Version: Version, Kind: FrameRequest, Token: token, Request: &request}); err != nil {
		return err
	}

	var stdinErr <-chan error
	if sendStdin {
		stdinResults := make(chan error, 1)
		go func() {
			stdinResults <- sendStdinFrames(ctx, conn, writeRequest, streams.Stdin)
		}()
		stdinErr = stdinResults
	}

	frames := make(chan readFrameResult, 1)
	go func() {
		for {
			frame, err := ReadFrame(conn)
			if err != nil {
				frames <- readFrameResult{err: err}
				return
			}
			if frame.Kind == FrameFinal {
				frames <- readFrameResult{frame: frame}
				return
			}
			frames <- readFrameResult{frame: frame}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			_ = conn.Close()
			return ctx.Err()
		case err := <-stdinErr:
			stdinErr = nil
			if err != nil {
				_ = conn.Close()
				return err
			}
		case result := <-frames:
			if result.err != nil {
				return result.err
			}
			switch result.frame.Kind {
			case FrameStdout:
				if err := writeOutput(streams.Stdout, result.frame.Data); err != nil {
					return err
				}
			case FrameStderr:
				if err := writeOutput(streams.Stderr, result.frame.Data); err != nil {
					return err
				}
			case FrameFinal:
				return finalResponseError(result.frame)
			default:
				return errors.New("invalid agent response frame")
			}
			if result.frame.Kind == FrameFinal {
				return nil
			}
		}
	}
}

type readFrameResult struct {
	frame Frame
	err   error
}

func sendStdinFrames(ctx context.Context, conn io.Writer, writeFrame func(Frame) error, input io.Reader) error {
	if input == nil {
		return writeFrame(Frame{Version: Version, Kind: FrameEOF})
	}
	buffer := make([]byte, stdinFrameBytes)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, err := input.Read(buffer)
		if n > 0 {
			data := append([]byte(nil), buffer[:n]...)
			if writeErr := writeFrame(Frame{Version: Version, Kind: FrameStdin, Data: data}); writeErr != nil {
				return writeErr
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return writeFrame(Frame{Version: Version, Kind: FrameEOF})
			}
			return err
		}
	}
}

func writeOutput(w io.Writer, data []byte) error {
	if w == nil || len(data) == 0 {
		return nil
	}
	for len(data) > 0 {
		n, err := w.Write(data)
		if n > 0 {
			data = data[n:]
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

func finalResponseError(frame Frame) error {
	if frame.Response == nil {
		return nil
	}
	response := frame.Response
	if response.ExitStatus != nil {
		return &clientssh.ExitStatusError{Status: *response.ExitStatus}
	}
	if response.Status != 0 {
		return &clientssh.ExitStatusError{Status: response.Status}
	}
	if response.Error != "" {
		return errors.New(response.Error)
	}
	return nil
}
