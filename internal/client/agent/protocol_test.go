package agent

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	frames := []Frame{
		{
			Version: Version,
			Kind:    FrameRequest,
			Token:   []byte("token"),
			Request: &Request{Operation: "ssh", Command: "printf request"},
		},
		{Version: Version, Kind: FrameStdout, Data: []byte("output\x00")},
		{
			Version:  Version,
			Kind:     FrameFinal,
			Response: &Response{Error: "remote command failed", Status: 7},
		},
	}

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	writeErr := make(chan error, 1)
	go func() {
		defer close(writeErr)
		for _, frame := range frames {
			if err := WriteFrame(client, frame); err != nil {
				writeErr <- err
				return
			}
		}
	}()

	for i, want := range frames {
		got, err := ReadFrame(server)
		if err != nil {
			t.Fatalf("ReadFrame(%d): %v", i, err)
		}
		if got.Version != want.Version || got.Kind != want.Kind || !bytes.Equal(got.Token, want.Token) || !bytes.Equal(got.Data, want.Data) {
			t.Fatalf("ReadFrame(%d) = %#v, want %#v", i, got, want)
		}
		if want.Request != nil && (got.Request == nil || got.Request.Operation != want.Request.Operation || got.Request.Command != want.Request.Command) {
			t.Fatalf("request frame = %#v, want %#v", got.Request, want.Request)
		}
		if want.Response != nil && (got.Response == nil || got.Response.Error != want.Response.Error || got.Response.Status != want.Response.Status) {
			t.Fatalf("response frame = %#v, want %#v", got.Response, want.Response)
		}
	}
	if err := <-writeErr; err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
}

func TestReadFrameRejectsOversizedDeclaration(t *testing.T) {
	var wire bytes.Buffer
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], maxFrameBytes+1)
	wire.Write(size[:])

	_, err := ReadFrame(&wire)
	if !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("ReadFrame() error = %v, want ErrFrameTooLarge", err)
	}
}

func TestReadFrameRejectsUnknownVersionBeforePayloadDispatch(t *testing.T) {
	var wire bytes.Buffer
	body, err := json.Marshal(Frame{Version: Version + 1, Kind: FrameRequest, Data: []byte("must not dispatch")})
	if err != nil {
		t.Fatal(err)
	}
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(body)))
	wire.Write(size[:])
	wire.Write(body)

	_, err = ReadFrame(&wire)
	if !errors.Is(err, ErrVersionMismatch) {
		t.Fatalf("ReadFrame() error = %v, want ErrVersionMismatch", err)
	}
}

func TestFrameRejectsTokenMismatch(t *testing.T) {
	frame := Frame{Version: Version, Kind: FrameRequest, Token: []byte("wrong")}
	if err := frame.ValidateToken([]byte("expected")); !errors.Is(err, ErrTokenMismatch) {
		t.Fatalf("ValidateToken() error = %v, want ErrTokenMismatch", err)
	}
}

func TestWriteFrameRejectsUnknownVersion(t *testing.T) {
	err := WriteFrame(io.Discard, Frame{Version: Version + 1, Kind: FrameStdout, Data: []byte("invalid")})
	if !errors.Is(err, ErrVersionMismatch) {
		t.Fatalf("WriteFrame() error = %v, want ErrVersionMismatch", err)
	}
}
