package portwatch

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestWatchSnapshotReflectsOnlyCurrentListeners(t *testing.T) {
	port := unusedLocalPort(t)
	ranges, _ := ParsePortRanges("1-65535")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	scans := 0
	var snapshots [][]portRow
	scan := func(context.Context) ([]int, error) {
		scans++
		if scans == 1 {
			return []int{port, port}, nil
		}
		return nil, nil
	}
	err := watchPortsWithView(ctx, scan, ranges, echoPortDialer{}, io.Discard, io.Discard, time.Millisecond, func(rows []portRow) {
		snapshots = append(snapshots, rows)
		if len(snapshots) == 2 {
			cancel()
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshots) != 2 || len(snapshots[0]) != 1 || snapshots[0][0].port != port || snapshots[0][0].failure != "" || len(snapshots[1]) != 0 {
		t.Fatalf("snapshots = %#v", snapshots)
	}
}

func TestWatchSnapshotShowsBindFailureThenRecovers(t *testing.T) {
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	port := occupied.Addr().(*net.TCPAddr).Port
	ranges, _ := ParsePortRanges(strconv.Itoa(port))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var snapshots [][]portRow
	err = watchPortsWithView(ctx, func(context.Context) ([]int, error) { return []int{port}, nil }, ranges, echoPortDialer{}, io.Discard, io.Discard, time.Millisecond, func(rows []portRow) {
		snapshots = append(snapshots, rows)
		if len(snapshots) == 1 {
			_ = occupied.Close()
		} else {
			cancel()
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshots) != 2 || len(snapshots[0]) != 1 || snapshots[0][0].failure == "" || len(snapshots[1]) != 1 || snapshots[1][0].failure != "" {
		t.Fatalf("snapshots = %#v", snapshots)
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 100*time.Millisecond)
	if err == nil {
		conn.Close()
		t.Fatal("forward still open after cancellation")
	}
}

func TestRenderScreenViewportCanReachEveryPort(t *testing.T) {
	rows := make([]portRow, 50)
	for i := range rows {
		rows[i].port = 3000 + i
	}
	first := renderScreen("dev", "3000-3049", rows, 60, 10, 0)
	last := renderScreen("dev", "3000-3049", rows, 60, 10, len(rows))
	if !strings.Contains(first, "http://127.0.0.1:3000/") || strings.Contains(first, "http://127.0.0.1:3049/") {
		t.Fatalf("first page = %q", first)
	}
	if !strings.Contains(last, "http://127.0.0.1:3049/") || strings.Contains(last, "http://127.0.0.1:3000/") {
		t.Fatalf("last page = %q", last)
	}
	if len(strings.Split(first, "\r\n")) > 10 {
		t.Fatal("viewport overflow")
	}
}

func TestRedirectedOutputDoesNotSelectTerminal(t *testing.T) {
	if terminalOutput(&bytes.Buffer{}) {
		t.Fatal("buffer selected full-screen mode")
	}
}

func TestRenderScreenHasTitleHyperlinksAndRedFailures(t *testing.T) {
	got := renderScreen("dev\x1b[2J", "3000-6000", []portRow{{port: 3000}, {port: 5173, failure: "address already in use"}}, 100, 24, 0)
	for _, want := range []string{"Watching dev", "3000-6000", "REMOTE PORT", "LOCAL URL", "\x1b]8;;http://127.0.0.1:3000/\x1b\\", "\x1b[31m", "address already in use"} {
		if !strings.Contains(got, want) {
			t.Errorf("screen missing %q: %q", want, got)
		}
	}
	if strings.Contains(got, "dev\x1b[2J") {
		t.Fatal("unsanitized connection name")
	}
	if strings.Contains(got, "http://127.0.0.1:5173/") {
		t.Fatal("failed forward rendered as URL")
	}
	empty := renderScreen("dev", "3000", nil, 80, 24, 0)
	if !strings.Contains(empty, "No matching ports listening") || strings.Contains(empty, "http://") {
		t.Fatalf("empty screen = %q", empty)
	}
}

func TestFullScreenRefreshRemovesDisappearedPorts(t *testing.T) {
	var output bytes.Buffer
	cause := errors.New("scan stopped")
	err := runFullScreen(context.Background(), &viewSession{}, &output, "dev", "3000-4000", func(ctx context.Context, update func([]portRow)) error {
		update([]portRow{{port: 3000}, {port: 4000}})
		update([]portRow{{port: 4000}})
		return cause
	})
	if !errors.Is(err, cause) {
		t.Fatal(err)
	}
	frames := strings.Split(output.String(), "\x1b[H\x1b[2J")
	if len(frames) != 4 {
		t.Fatalf("frame count = %d, want initial plus two snapshots", len(frames)-1)
	}
	if !strings.Contains(frames[2], "http://127.0.0.1:3000/") {
		t.Fatal("first snapshot missing port")
	}
	if strings.Contains(frames[3], "http://127.0.0.1:3000/") || !strings.Contains(frames[3], "http://127.0.0.1:4000/") {
		t.Fatalf("stale final frame = %q", frames[3])
	}
}

func TestFullScreenRestoresTerminalOnErrorAndQuit(t *testing.T) {
	for _, quit := range []bool{false, true} {
		t.Run(map[bool]string{false: "error", true: "quit"}[quit], func(t *testing.T) {
			session := &viewSession{}
			if quit {
				session.input.WriteString("q")
			}
			var output bytes.Buffer
			cause := errors.New("scan failed")
			watch := func(ctx context.Context, update func([]portRow)) error {
				if !quit {
					return cause
				}
				update([]portRow{{port: 3000}})
				<-ctx.Done()
				return nil
			}
			err := runFullScreen(context.Background(), session, &output, "dev", "3000", watch)
			if !quit && !errors.Is(err, cause) {
				t.Fatalf("error = %v", err)
			}
			if quit && err != nil {
				t.Fatal(err)
			}
			if !session.restored || !session.raw {
				t.Fatalf("terminal lifecycle: %#v", session)
			}
			for _, escape := range []string{"\x1b[?1049h", "\x1b[?1049l", "\x1b[?25h"} {
				if !strings.Contains(output.String(), escape) {
					t.Errorf("missing %q", escape)
				}
			}
		})
	}
}

type viewSession struct {
	input         bytes.Buffer
	raw, restored bool
}

func (s *viewSession) EnterRaw() error                              { s.raw = true; return nil }
func (s *viewSession) Restore() error                               { s.restored = true; return nil }
func (s *viewSession) Size() (int, int)                             { return 80, 24 }
func (s *viewSession) ResizeEvents() <-chan struct{}                { return nil }
func (s *viewSession) Stdin() io.Reader                             { return &s.input }
func (s *viewSession) Stdout() io.Writer                            { return io.Discard }
func (s *viewSession) Stderr() io.Writer                            { return io.Discard }
func (s *viewSession) SupportsANSI() bool                           { return true }
func (s *viewSession) StdinReadyWithin(time.Duration) (bool, error) { return s.input.Len() > 0, nil }
