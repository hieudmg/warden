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
	token := bytes.Repeat([]byte{0x42}, TokenBytes)
	frames := []Frame{
		{
			Version: Version,
			Kind:    FrameRequest,
			Token:   token,
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
		var got Frame
		var err error
		if i == 0 {
			got, err = ReadAuthenticatedFrame(server, token)
		} else {
			got, err = ReadFrame(server)
		}
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
	if err := writeRawFrame(&wire, Frame{Version: Version + 1, Kind: FrameRequest, Data: []byte("must not dispatch")}); err != nil {
		t.Fatal(err)
	}

	_, err := ReadFrame(&wire)
	if !errors.Is(err, ErrVersionMismatch) {
		t.Fatalf("ReadFrame() error = %v, want ErrVersionMismatch", err)
	}
}

func TestReadFrameRejectsUnauthenticatedRequestDispatch(t *testing.T) {
	var wire bytes.Buffer
	payload, err := json.Marshal(Request{Operation: "ssh", Command: "must not run"})
	if err != nil {
		t.Fatal(err)
	}
	if err := writeRawFrame(&wire, Frame{Version: Version, Kind: FrameRequest, Data: payload}); err != nil {
		t.Fatal(err)
	}

	structuredDispatched := false
	structuredDispatch := func(frame Frame) {
		var request Request
		if json.Unmarshal(frame.Data, &request) == nil && request.Operation != "" {
			structuredDispatched = true
		}
	}
	frame, err := ReadFrame(&wire)
	if err == nil {
		structuredDispatch(frame)
	}
	if !errors.Is(err, ErrAuthenticationRequired) {
		t.Fatalf("ReadFrame() error = %v, want ErrAuthenticationRequired", err)
	}
	if structuredDispatched {
		t.Fatal("unauthenticated request reached structured dispatch")
	}
}

func TestReadAuthenticatedFrameRejectsTokenMismatch(t *testing.T) {
	var wire bytes.Buffer
	wrong := bytes.Repeat([]byte{0x11}, TokenBytes)
	expected := bytes.Repeat([]byte{0x22}, TokenBytes)
	if err := writeRawFrame(&wire, Frame{Version: Version, Kind: FrameRequest, Token: wrong}); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadAuthenticatedFrame(&wire, expected); !errors.Is(err, ErrTokenMismatch) {
		t.Fatalf("ReadAuthenticatedFrame() error = %v, want ErrTokenMismatch", err)
	}
}

func TestWriteFrameRejectsUnauthenticatedRequest(t *testing.T) {
	err := WriteFrame(io.Discard, Frame{Version: Version, Kind: FrameRequest, Data: []byte(`{"operation":"ssh"}`)})
	if !errors.Is(err, ErrAuthenticationRequired) {
		t.Fatalf("WriteFrame() error = %v, want ErrAuthenticationRequired", err)
	}
}

func TestWriteFrameRejectsUnknownVersion(t *testing.T) {
	err := WriteFrame(io.Discard, Frame{Version: Version + 1, Kind: FrameStdout, Data: []byte("invalid")})
	if !errors.Is(err, ErrVersionMismatch) {
		t.Fatalf("WriteFrame() error = %v, want ErrVersionMismatch", err)
	}
}

func writeRawFrame(w io.Writer, frame Frame) error {
	body, err := json.Marshal(frame)
	if err != nil {
		return err
	}
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(body)))
	if _, err := w.Write(size[:]); err != nil {
		return err
	}
	_, err = w.Write(body)
	return err
}
