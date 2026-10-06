package portwatch

import (
	"context"
	"errors"
	"io"
	"net"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestParsePortRanges(t *testing.T) {
	ranges, err := ParsePortRanges("3000,5000-6000,9999-12222")
	if err != nil {
		t.Fatalf("ParsePortRanges: %v", err)
	}
	for _, port := range []int{3000, 5000, 5500, 6000, 9999, 12222} {
		if !ranges.Contains(port) {
			t.Errorf("Contains(%d) = false, want true", port)
		}
	}
	for _, port := range []int{2999, 3001, 4999, 6001, 9998, 12223} {
		if ranges.Contains(port) {
			t.Errorf("Contains(%d) = true, want false", port)
		}
	}
}

func TestParsePortRangesRejectsInvalidInput(t *testing.T) {
	for _, input := range []string{"", "0", "65536", "6000-5000", "1-", "-2", "1,,2", "1-2-3", " 80", "80 "} {
		t.Run(input, func(t *testing.T) {
			if _, err := ParsePortRanges(input); err == nil {
				t.Fatalf("ParsePortRanges(%q) succeeded, want error", input)
			}
		})
	}
}

func TestParseListeningPorts(t *testing.T) {
	output := "LISTEN 0 128 127.0.0.1:3000 0.0.0.0:*\n" +
		"LISTEN 0 128 [::]:5000 [::]:*\n" +
		"LISTEN 0 128 0.0.0.0:8080 0.0.0.0:*\n" +
		"ESTAB 0 0 127.0.0.1:6000 127.0.0.1:80\n"
	got, err := parseListeningPorts(output)
	if err != nil {
		t.Fatalf("parseListeningPorts: %v", err)
	}
	if want := []int{3000, 5000, 8080}; !reflect.DeepEqual(got, want) {
		t.Fatalf("parseListeningPorts = %v, want %v", got, want)
	}
}

func TestParseListeningPortsRejectsMalformedListenRow(t *testing.T) {
	if _, err := parseListeningPorts("LISTEN 0 128 missing-port 0.0.0.0:*\n"); err == nil {
		t.Fatal("parseListeningPorts succeeded on malformed LISTEN row, want error")
	}
}

func TestPortForwardRelaysAndBindsLoopback(t *testing.T) {
	port := unusedLocalPort(t)
	forward, err := newPortForward(echoPortDialer{}, port)
	if err != nil {
		t.Fatalf("newPortForward: %v", err)
	}
	address := forward.listener.Addr().String()
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatalf("SplitHostPort(%q): %v", address, err)
	}
	if host != "127.0.0.1" {
		t.Fatalf("forward bound to %q, want 127.0.0.1", host)
	}

	conn, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatalf("connect to forwarded port: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	if _, err := conn.Write([]byte("echo")); err != nil {
		t.Fatalf("write to forwarded port: %v", err)
	}
	got := make([]byte, 4)
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read forwarded response: %v", err)
	}
	if string(got) != "echo" {
		t.Fatalf("forwarded response = %q, want echo", got)
	}
	if err := forward.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := net.DialTimeout("tcp", address, 100*time.Millisecond); err == nil {
		t.Fatalf("connection to %s succeeded after Close", address)
	}
}

func TestWatchPortsClosesForwardWhenRemotePortDisappears(t *testing.T) {
	port := unusedLocalPort(t)
	ranges, err := ParsePortRanges(strconv.Itoa(port))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	scans := 0
	scan := func(context.Context) ([]int, error) {
		scans++
		switch scans {
		case 1:
			return []int{port}, nil
		case 2:
			return nil, nil
		default:
			cancel()
			return nil, nil
		}
	}
	var stdout, stderr strings.Builder
	if err := watchPorts(ctx, scan, ranges, echoPortDialer{}, &stdout, &stderr, time.Millisecond); err != nil {
		t.Fatalf("watchPorts: %v", err)
	}
	if got := stdout.String(); !strings.Contains(got, "forwarding localhost:") || !strings.Contains(got, "closed localhost:") {
		t.Fatalf("stdout = %q, want forward-open and remote-close events", got)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	if _, err := net.DialTimeout("tcp", address, 100*time.Millisecond); err == nil {
		t.Fatalf("connection to %s succeeded after remote port disappeared", address)
	}
}

func TestWatchPortsStopsAndClosesForwardsWhenListenerScanFails(t *testing.T) {
	port := unusedLocalPort(t)
	ranges, err := ParsePortRanges(strconv.Itoa(port))
	if err != nil {
		t.Fatal(err)
	}
	cause := errors.New("remote command exited with status 127: ss: not found")
	scans := 0
	scan := func(context.Context) ([]int, error) {
		scans++
		if scans == 1 {
			return []int{port}, nil
		}
		return nil, cause
	}
	var stdout, stderr strings.Builder
	err = watchPorts(context.Background(), scan, ranges, echoPortDialer{}, &stdout, &stderr, time.Millisecond)
	if !errors.Is(err, cause) || !strings.Contains(err.Error(), "inspect remote TCP listeners") {
		t.Fatalf("watchPorts error = %v, want wrapped ss failure", err)
	}
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	if _, err := net.DialTimeout("tcp", address, 100*time.Millisecond); err == nil {
		t.Fatalf("connection to %s succeeded after listener scan failed", address)
	}
}

func TestPortForwardCloseDoesNotWaitForAnInFlightSSHForwardRequest(t *testing.T) {
	port := unusedLocalPort(t)
	dialer := &blockingPortDialer{started: make(chan struct{}), release: make(chan struct{})}
	forward, err := newPortForward(dialer, port)
	if err != nil {
		t.Fatalf("newPortForward: %v", err)
	}
	conn, err := net.DialTimeout("tcp", forward.listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatalf("connect to forwarded port: %v", err)
	}
	defer conn.Close()
	select {
	case <-dialer.started:
	case <-time.After(time.Second):
		t.Fatal("forwarder did not start SSH dial")
	}

	closed := make(chan struct{})
	go func() {
		_ = forward.Close()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(100 * time.Millisecond):
		close(dialer.release)
		<-closed
		t.Fatal("Close waited for the in-flight SSH forward request")
	}
	close(dialer.release)
}

func TestWatchPortsReportsLocalBindConflictAndKeepsWatching(t *testing.T) {
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	_, rawPort, err := net.SplitHostPort(occupied.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(rawPort)
	ranges, err := ParsePortRanges(rawPort)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	scans := 0
	scan := func(context.Context) ([]int, error) {
		scans++
		if scans > 1 {
			cancel()
		}
		return []int{port}, nil
	}
	var stdout, stderr strings.Builder
	if err := watchPorts(ctx, scan, ranges, echoPortDialer{}, &stdout, &stderr, time.Millisecond); err != nil {
		t.Fatalf("watchPorts: %v", err)
	}
	if scans < 2 {
		t.Fatalf("scan calls = %d, want watcher to continue after bind conflict", scans)
	}
	if got := stderr.String(); strings.Count(got, "cannot forward localhost:") != 1 {
		t.Fatalf("stderr = %q, want one local bind conflict warning", got)
	}
}

func unusedLocalPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	_, rawPort, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(rawPort)
	if err != nil {
		t.Fatal(err)
	}
	return port
}

type echoPortDialer struct{}

func (echoPortDialer) Dial(string, string) (net.Conn, error) {
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		_, _ = io.Copy(server, server)
	}()
	return client, nil
}

type blockingPortDialer struct {
	started chan struct{}
	release chan struct{}
}

func (d *blockingPortDialer) Dial(string, string) (net.Conn, error) {
	close(d.started)
	<-d.release
	return nil, net.ErrClosed
}
