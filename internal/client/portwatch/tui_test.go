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

func TestWatchSnapshotRetainsClosedPorts(t *testing.T) {
	port := unusedLocalPort(t)
	ranges, _ := ParsePortRanges("1-65535")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	scans := 0
	var snapshots [][]portRow
	scan := func(context.Context) (map[int]string, error) {
		scans++
		switch scans {
		case 1:
			return map[int]string{port: "node", 9: "ssh", 100: "proxy"}, nil
		case 2:
			return nil, nil
		default:
			return map[int]string{port: "python"}, nil
		}
	}
	err := watchPortsWithView(ctx, scan, ranges, echoPortDialer{}, io.Discard, io.Discard, time.Millisecond, func(rows []portRow) {
		snapshots = append(snapshots, rows)
		if len(snapshots) == 3 {
			cancel()
		}
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, rows := range snapshots {
		if len(rows) != 3 || rows[0].port != 9 || rows[1].port != 100 || rows[2].port != port {
			t.Fatalf("rows are not unique and numerically sorted: %#v", rows)
		}
	}
	if got := snapshots[0][2]; got.process != "node" || got.closed || got.failure != "" {
		t.Fatalf("initial row = %#v", got)
	}
	if got := snapshots[1][2]; got.process != "node" || !got.closed || got.failure != "" {
		t.Fatalf("closed row = %#v", got)
	}
	if got := snapshots[2][2]; got.process != "python" || got.closed || got.failure != "" {
		t.Fatalf("reopened row = %#v", got)
	}
	if !snapshots[2][0].closed || !snapshots[2][1].closed {
		t.Fatalf("unrelated closed rows were lost: %#v", snapshots[2])
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
	err = watchPortsWithView(ctx, func(context.Context) (map[int]string, error) { return map[int]string{port: "node"}, nil }, ranges, echoPortDialer{}, io.Discard, io.Discard, time.Millisecond, func(rows []portRow) {
		snapshots = append(snapshots, rows)
		if len(snapshots) == 1 {
			_ = occupied.Close()
		} else {
			cancel()
		}
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshots) != 2 || len(snapshots[0]) != 1 || snapshots[0][0].failure == "" || !snapshots[0][0].conflict || len(snapshots[1]) != 1 || snapshots[1][0].failure != "" || snapshots[1][0].conflict {
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

func TestRenderScreenHasColumnsAndDistinctForwardStates(t *testing.T) {
	got := renderScreen("dev\x1b[2J", "3000-6000", []portRow{
		{port: 3000},
		{port: 4000, process: "old-node", closed: true},
		{port: 5173, process: "vite", failure: "address already in use", conflict: true},
		{port: 6000, process: "proxy", failure: "permission denied"},
	}, 100, 24, 0)
	for _, want := range []string{"Watching dev", "3000-6000", "Host process name", "Host port", "Client URL", "\x1b]8;;http://127.0.0.1:3000/\x1b\\"} {
		if !strings.Contains(got, want) {
			t.Errorf("screen missing %q: %q", want, got)
		}
	}
	if strings.Contains(got, "dev\x1b[2J") {
		t.Fatal("unsanitized connection name")
	}
	lines := strings.Split(got, "\r\n")
	for i, want := range []struct{ prefix, text string }{
		{"—", "http://127.0.0.1:3000/"},
		{"\x1b[90mold-node", "closed"},
		{"\x1b[33mvite", "address already in use"},
		{"\x1b[31mproxy", "permission denied"},
	} {
		line := lines[i+4]
		if !strings.HasPrefix(line, want.prefix) || !strings.Contains(line, want.text) || (i > 0 && strings.Contains(line, "http://")) {
			t.Errorf("row %d = %q, want prefix %q and text %q", i, line, want.prefix, want.text)
		}
	}
	empty := renderScreen("dev", "3000", nil, 80, 24, 0)
	if !strings.Contains(empty, "No matching ports listening") || strings.Contains(empty, "http://") {
		t.Fatalf("empty screen = %q", empty)
	}
}

func TestRenderScreenClipsAndPadsWideTextByTerminalCell(t *testing.T) {
	name := strings.Repeat("界", 20)
	rows := []portRow{{port: 5173, process: name}, {port: 6000, process: "中文"}}
	wide := strings.Split(renderScreen(name, "5173,6000", rows, 34, 24, 0), "\r\n")
	for i, prefix := range []string{
		strings.Repeat("界", 8) + "   5173       ",
		"中文" + strings.Repeat(" ", 15) + "6000       ",
	} {
		if !strings.HasPrefix(wide[i+4], prefix+"\x1b]8;;") || !strings.Contains(wide[i+4], "\x1b\\htt\x1b]8;;") {
			t.Errorf("row %d has misaligned columns or URL clipping: %q", i, wide[i+4])
		}
	}
	// A 12-column terminal has only 11 usable cells, including the title.
	narrow := strings.Split(renderScreen(name, "5173,6000", rows, 12, 24, 0), "\r\n")
	if want := "\x1b[H\x1b[2J\x1b[1mWatching 界\x1b[0m"; narrow[0] != want {
		t.Errorf("narrow title = %q, want %q", narrow[0], want)
	}
	if want := strings.Repeat("界", 5); narrow[4] != want {
		t.Errorf("narrow row = %q, want %q", narrow[4], want)
	}
}

func TestFullScreenRefreshRetainsDisappearedPortsAndUpdatesNames(t *testing.T) {
	var output bytes.Buffer
	cause := errors.New("scan stopped")
	err := runFullScreen(context.Background(), &viewSession{}, &output, "dev", "3000-4000", func(ctx context.Context, update func([]portRow)) error {
		update([]portRow{{port: 3000, process: "node"}, {port: 4000}})
		update([]portRow{{port: 3000, process: "node", closed: true}, {port: 4000}})
		update([]portRow{{port: 3000, process: "python"}, {port: 4000}})
		update([]portRow{{port: 3000, process: "ruby"}, {port: 4000}})
		update([]portRow{{port: 3000, process: "ruby"}, {port: 4000}})
		return cause
	})
	if !errors.Is(err, cause) {
		t.Fatal(err)
	}
	frames := strings.Split(output.String(), "\x1b[H\x1b[2J")
	if len(frames) != 6 {
		t.Fatalf("frame count = %d, want initial plus four changed snapshots", len(frames)-1)
	}
	if !strings.Contains(frames[2], "http://127.0.0.1:3000/") {
		t.Fatal("first snapshot missing port")
	}
	if strings.Contains(frames[3], "http://127.0.0.1:3000/") || !strings.Contains(frames[3], "\x1b[90mnode") || !strings.Contains(frames[3], "http://127.0.0.1:4000/") {
		t.Fatalf("closed frame = %q", frames[3])
	}
	if !strings.Contains(frames[4], "python") || !strings.Contains(frames[5], "ruby") {
		t.Fatalf("process name did not refresh: %q", frames[4:])
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
