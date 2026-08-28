// Package agent contains the private local transport used by the client-side
// connection agent. The transport is deliberately small: each message is a
// bounded, versioned JSON frame carried over one local connection.
package agent

import (
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const (
	// Version is the current wire-protocol version.
	Version uint8 = 1

	// MaxFrameBytes bounds the encoded JSON body of one frame. The size prefix
	// is not included in this limit.
	MaxFrameBytes = 1 << 20

	// TokenBytes is the size of a runtime authentication token.
	TokenBytes = 32

	maxFrameBytes = MaxFrameBytes
	tokenBytes    = TokenBytes
)

// FrameKind identifies the purpose of a frame on an agent connection.
type FrameKind string

const (
	FrameRequest FrameKind = "request"
	FrameStdin   FrameKind = "stdin"
	FrameStdout  FrameKind = "stdout"
	FrameStderr  FrameKind = "stderr"
	FrameEOF     FrameKind = "eof"
	FrameFinal   FrameKind = "final"

	// FrameStdinEOF is an expressive alias for the stdin end-of-stream frame.
	FrameStdinEOF = FrameEOF
)

// Frame is one versioned message. Data is an opaque byte payload and is
// encoded as base64 by encoding/json. Request and Response are optional
// structured payloads for callers that want to keep the envelope typed; the
// generic Data field remains available for stream bytes and future messages.
// Token is sent only on an authenticated request and is omitted from output
// frames.
type Frame struct {
	Version  uint8           `json:"version"`
	Kind     FrameKind       `json:"kind"`
	Token    []byte          `json:"token,omitempty"`
	Data     []byte          `json:"data,omitempty"`
	Payload  json.RawMessage `json:"payload,omitempty"`
	Request  *Request        `json:"request,omitempty"`
	Response *Response       `json:"response,omitempty"`
}

// Request is the structured operation envelope used by the agent. Fields not
// needed by a particular operation remain empty; operation-specific data may
// be carried in Payload or in the opaque bundle fields.
type Request struct {
	Token     []byte          `json:"token,omitempty"`
	Operation string          `json:"operation,omitempty"`
	Command   string          `json:"command,omitempty"`
	SQL       string          `json:"sql,omitempty"`
	Payload   json.RawMessage `json:"payload,omitempty"`
	SSHBundle json.RawMessage `json:"ssh_bundle,omitempty"`
	DBBundle  json.RawMessage `json:"db_bundle,omitempty"`
}

// Response is the structured terminal response used by the agent. Stream
// frames use Frame.Data; a final response can carry a sanitized Error and an
// optional remote exit status.
type Response struct {
	Data       []byte `json:"data,omitempty"`
	Error      string `json:"error,omitempty"`
	Status     int    `json:"status,omitempty"`
	ExitStatus *int   `json:"exit_status,omitempty"`
}

var (
	// ErrFrameTooLarge reports a frame body that exceeds MaxFrameBytes.
	ErrFrameTooLarge = errors.New("agent frame too large")
	// ErrVersionMismatch reports a frame from a different wire protocol.
	ErrVersionMismatch = errors.New("agent protocol version mismatch")
	// ErrTokenMismatch reports failed local-agent authentication.
	ErrTokenMismatch = errors.New("agent token mismatch")
	// ErrInvalidFrame reports a syntactically invalid or incomplete envelope.
	ErrInvalidFrame = errors.New("invalid agent frame")
)

// ReadFrame reads and validates one length-prefixed JSON frame. The version is
// checked before any structured request/response payload is decoded, so an
// unknown peer cannot reach operation dispatch through a newer envelope.
func ReadFrame(r io.Reader) (Frame, error) {
	if r == nil {
		return Frame{}, fmt.Errorf("%w: nil reader", ErrInvalidFrame)
	}

	var size [4]byte
	if _, err := io.ReadFull(r, size[:]); err != nil {
		return Frame{}, err
	}
	length := binary.BigEndian.Uint32(size[:])
	if length > MaxFrameBytes {
		return Frame{}, ErrFrameTooLarge
	}
	if length == 0 {
		return Frame{}, fmt.Errorf("%w: empty body", ErrInvalidFrame)
	}

	body := make([]byte, length)
	if _, err := io.ReadFull(r, body); err != nil {
		return Frame{}, err
	}

	// Decode just the version first. Unknown-version bodies are rejected even
	// if their operation-specific fields are not understood by this binary.
	var envelope struct {
		Version *uint8 `json:"version"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return Frame{}, fmt.Errorf("%w: %v", ErrInvalidFrame, err)
	}
	if envelope.Version == nil || *envelope.Version != Version {
		var got uint8
		if envelope.Version != nil {
			got = *envelope.Version
		}
		return Frame{}, fmt.Errorf("%w: got %d, want %d", ErrVersionMismatch, got, Version)
	}

	var frame Frame
	if err := json.Unmarshal(body, &frame); err != nil {
		return Frame{}, fmt.Errorf("%w: %v", ErrInvalidFrame, err)
	}
	return frame, nil
}

// WriteFrame validates and writes one length-prefixed JSON frame. A single
// frame is never written partially as a result of a short, nil-error writer.
func WriteFrame(w io.Writer, f Frame) error {
	if w == nil {
		return fmt.Errorf("%w: nil writer", ErrInvalidFrame)
	}
	if f.Version != Version {
		return fmt.Errorf("%w: got %d, want %d", ErrVersionMismatch, f.Version, Version)
	}
	body, err := json.Marshal(f)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidFrame, err)
	}
	if len(body) > MaxFrameBytes {
		return ErrFrameTooLarge
	}

	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(body)))
	if err := writeAll(w, size[:]); err != nil {
		return err
	}
	return writeAll(w, body)
}

// ValidateToken compares a frame's authentication token without exposing a
// timing distinction between matching and non-matching token prefixes. For a
// request that carries a typed Request payload, its token is accepted when the
// envelope Token is empty.
func (f Frame) ValidateToken(expected []byte) error {
	if f.Version != Version {
		return ErrVersionMismatch
	}
	actual := f.Token
	if len(actual) == 0 && f.Request != nil {
		actual = f.Request.Token
	}
	if len(actual) == 0 && f.Kind == FrameRequest && len(f.Data) != 0 {
		var request Request
		if err := json.Unmarshal(f.Data, &request); err == nil {
			actual = request.Token
		}
	}
	if len(actual) != TokenBytes || len(expected) != TokenBytes || subtle.ConstantTimeCompare(actual, expected) != 1 {
		return ErrTokenMismatch
	}
	return nil
}

// ValidateToken checks the authentication token on f. It is a convenience
// wrapper for callers that prefer a function over Frame.ValidateToken.
func ValidateToken(f Frame, expected []byte) error {
	return f.ValidateToken(expected)
}

// ReadAuthenticatedFrame reads one frame and validates its authentication
// token before returning it to an operation dispatcher.
func ReadAuthenticatedFrame(r io.Reader, expected []byte) (Frame, error) {
	frame, err := ReadFrame(r)
	if err != nil {
		return Frame{}, err
	}
	if err := frame.ValidateToken(expected); err != nil {
		return Frame{}, err
	}
	return frame, nil
}

func writeAll(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if n > 0 {
			p = p[n:]
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
