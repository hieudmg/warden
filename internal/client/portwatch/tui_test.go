package portwatch

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"

	"warden/internal/client/terminal"
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

func renderScreen(name, ranges string, rows []portRow, width, height, offset int) string {
	m := newPortWatchModel(name, ranges, width, height)
	m.Update(watchRowsMsg(rows))
	m.body.SetYOffset(offset)
	return m.View().Content
}

func TestPortWatchViewportCanReachEveryPort(t *testing.T) {
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
	if len(strings.Split(first, "\n")) != 10 {
		t.Fatal("viewport does not fill available height")
	}
}

func TestPortWatchFooterAdvertisesArrows(t *testing.T) {
	for _, width := range []int{80, 45} {
		view := renderScreen("dev", "3000", nil, width, 8, 0)
		lines := strings.Split(view, "\n")
		footer := lines[len(lines)-1]
		if !strings.Contains(footer, "↑/↓ scroll") || !strings.Contains(footer, "←/→ top/end") ||
			!strings.Contains(footer, "quit") || strings.Contains(footer, "j/k") || strings.Contains(footer, "g/G") {
			t.Errorf("width %d: unexpected navigation footer %q", width, footer)
		}
	}
}

func TestRedirectedOutputDoesNotSelectTerminal(t *testing.T) {
	if terminalOutput(&bytes.Buffer{}) {
		t.Fatal("buffer selected full-screen mode")
	}
}

func TestPortWatchModelHasColumnsAndDistinctForwardStates(t *testing.T) {
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
	lines := strings.Split(got, "\n")
	for i, want := range []struct{ prefix, text string }{
		{"│ —", "http://127.0.0.1:3000/"},
		{"│\x1b[90m old-node", "closed"},
		{"│\x1b[33m vite", "address already in use"},
		{"│\x1b[31m proxy", "permission denied"},
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

func TestPortWatchModelClipsAndPadsWideTextByTerminalCell(t *testing.T) {
	name := strings.Repeat("界", 20)
	rows := []portRow{{port: 5173, process: name}, {port: 6000, process: "中文"}}
	wide := strings.Split(renderScreen(name, "5173,6000", rows, 34, 24, 0), "\n")
	for i, prefix := range []string{
		strings.Repeat("界", 8) + "   5173       ",
		"中文" + strings.Repeat(" ", 15) + "6000       ",
	} {
		if !strings.HasPrefix(wide[i+4], prefix+"\x1b]8;;") || !strings.Contains(wide[i+4], "\x1b\\htt\x1b]8;;") {
			t.Errorf("row %d has misaligned columns or URL clipping: %q", i, wide[i+4])
		}
	}
	// A 12-column terminal has only 11 usable cells, including the title.
	narrow := strings.Split(renderScreen(name, "5173,6000", rows, 12, 24, 0), "\n")
	if want := "\x1b[1mWatching 界\x1b[0m"; narrow[0] != want {
		t.Errorf("narrow title = %q, want %q", narrow[0], want)
	}
	if want := strings.Repeat("界", 5); strings.TrimRight(narrow[4], " ") != want {
		t.Errorf("narrow row = %q, want %q", narrow[4], want)
	}
}

func TestPortWatchModelGrowsProcessColumnWithSpareCells(t *testing.T) {
	name := strings.Repeat("界", 20)
	rows := watchRowsMsg{{port: 65535, process: name}, {port: 3000, process: "node"}}
	m := newPortWatchModel("dev", "3000,65535", 100, 8)
	m.Update(rows)
	const url = "http://127.0.0.1:65535/"
	const link = "\x1b]8;;" + url + "\x1b\\" + url + "\x1b]8;;\x1b\\"
	for _, size := range []struct{ width, height, nameCells int }{
		{100, 8, 40}, // Entire name fits; don't consume the remaining spare cells.
		{74, 8, 32},  // Only enough spare cells for 16 wide glyphs and the full URL.
		{100, 8, 40}, // Grow again on resize without a new snapshot.
	} {
		m.Update(tea.WindowSizeMsg{Width: size.width, Height: size.height})
		lines := strings.Split(m.View().Content, "\n")
		for i, prefix := range []string{
			"┌" + strings.Repeat("─", size.nameCells+2) + "┬───────────┬",
			"│ Host process name" + strings.Repeat(" ", size.nameCells-17) + " │ Host port │ Client URL",
			"├" + strings.Repeat("─", size.nameCells+2) + "┼───────────┼",
			"│ " + strings.Repeat("界", size.nameCells/2) + " │ 65535     │ " + url,
			"│ node" + strings.Repeat(" ", size.nameCells-4) + " │ 3000      │ http://127.0.0.1:3000/",
			"└" + strings.Repeat("─", size.nameCells+2) + "┴───────────┴",
		} {
			line := ansi.Strip(lines[i+1])
			if !strings.HasPrefix(line, prefix) || ansi.StringWidthWc(line) != size.width-1 {
				t.Errorf("width %d, line %d = %q; want prefix %q and %d cells", size.width, i+1, line, prefix, size.width-1)
			}
		}
		if !strings.Contains(lines[4], link) {
			t.Errorf("width %d: row missing complete OSC 8 link: %q", size.width, lines[4])
		}
	}

	m.Update(tea.WindowSizeMsg{Width: 100, Height: 5})
	lines := strings.Split(m.View().Content, "\n")
	if lines[1] != "Host process name  Host port  Client URL" ||
		ansi.Strip(lines[2]) != strings.Repeat("界", 8)+"   65535      "+url {
		t.Errorf("short layout changed: %q", lines)
	}

	m.Update(tea.WindowSizeMsg{Width: 100, Height: 8})
	m.Update(watchRowsMsg{rows[1]})
	if heading := strings.Split(m.View().Content, "\n")[2]; strings.HasPrefix(heading, "│ Host process name"+strings.Repeat(" ", 24)) {
		t.Errorf("heading did not shrink after row update: %q", heading)
	}
}

func TestPortWatchModelWidensProcessColumnWithShortNames(t *testing.T) {
	const url = "http://127.0.0.1:65535/"
	const narrow, wide = 64, 120
	m := newPortWatchModel("dev", "65531-65535", narrow, 24)
	rows := watchRowsMsg{
		{port: 65531, process: "node"}, {port: 65532, process: "sshd"},
		{port: 65533, process: "nginx"}, {port: 65534, process: "redis"},
		{port: 65535, process: "中文"},
	}
	m.Update(rows)
	var narrowDivider int
	for i, width := range []int{narrow, wide, narrow, wide} {
		m.Update(tea.WindowSizeMsg{Width: width, Height: 24})
		lines := strings.Split(m.View().Content, "\n")
		heading := strings.Split(lines[2], "│")
		if len(heading) != 5 {
			t.Fatalf("width %d: no bordered heading: %q", width, lines[2])
		}
		divider := ansi.StringWidthWc(heading[1]) + 1
		if i == 0 {
			narrowDivider = divider
		}
		if (width == narrow && divider != narrowDivider) || (width == wide && divider <= narrowDivider) {
			t.Errorf("width %d: process divider at cell %d, narrow position %d", width, divider, narrowDivider)
		}
		if got := ansi.StringWidthWc(heading[2]); got != len(" Host port ") {
			t.Errorf("width %d: port column has %d cells", width, got)
		}
		row := strings.Split(ansi.Strip(lines[8]), "│")
		if len(row) != 5 || strings.TrimSpace(row[1]) != "中文" || ansi.StringWidthWc(row[1])+1 != divider || strings.TrimSpace(row[2]) != "65535" || strings.TrimSpace(row[3]) != url {
			t.Errorf("width %d: wide name, port or complete URL misplaced: %q", width, lines[8])
		}
		if !strings.Contains(lines[8], "\x1b]8;;"+url+"\x1b\\"+url+"\x1b]8;;\x1b\\") {
			t.Errorf("width %d: missing complete hyperlink: %q", width, lines[8])
		}
	}
}

func TestPortWatchModelAlignsDividersThroughEmptyBodyRows(t *testing.T) {
	for _, tc := range []struct {
		name          string
		width, height int
		rows          []portRow
		message       string
	}{
		{name: "fillers", width: 120, height: 24, rows: []portRow{{port: 4000, process: "中文"}}},
		{name: "empty", width: 120, height: 24, message: "No matching ports listening"},
		{name: "empty minimum", width: minTableWidth + 1, height: 7, message: "No matching ports"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lines := strings.Split(renderScreen("dev", "4000", tc.rows, tc.width, tc.height, 0), "\n")
			if len(lines) != tc.height {
				t.Fatalf("got %d lines, want %d", len(lines), tc.height)
			}
			bottom := []rune(lines[len(lines)-2])
			if len(bottom) != tc.width-1 {
				t.Fatalf("unexpected bottom rule: %q", string(bottom))
			}
			for i := 4; i < len(lines)-2; i++ {
				line := ansi.Strip(lines[i])
				if ansi.StringWidthWc(line) != tc.width-1 {
					t.Errorf("line %d has wrong width: %q", i, line)
					continue
				}
				cells := strings.Split(line, "│")
				if len(cells) != 5 || cells[0] != "" || cells[4] != "" {
					t.Errorf("line %d missing table dividers: %q", i, line)
					continue
				}
				first := 1 + ansi.StringWidthWc(cells[1])
				second := first + 1 + ansi.StringWidthWc(cells[2])
				if bottom[first] != '┴' || bottom[second] != '┴' {
					t.Errorf("line %d dividers do not meet the bottom rule: %q", i, line)
				}
				if i == 4 && tc.message != "" && strings.TrimSpace(cells[1]) != tc.message {
					t.Errorf("empty state missing from first process cell: %q", line)
				}
			}
		})
	}
}

func TestPortWatchModelFitsTerminalAndKeepsNavigationOnResize(t *testing.T) {
	m := newPortWatchModel("dev", "3000-3005", 80, 8)
	rows := make([]portRow, 6)
	for i := range rows {
		rows[i] = portRow{port: 3000 + i, process: "中文"}
	}
	rows[0].process = "中文👋🏽" // The renderer measures emoji modifiers separately in wcwidth mode.
	m.Update(watchRowsMsg(rows))
	m.Update(watchKeyMsg{code: 'G', repeat: 1})
	if view := m.View().Content; !strings.Contains(view, ":3005/") || strings.Contains(view, ":3003/") {
		t.Fatalf("end view = %q", view)
	}
	m.Update(tea.WindowSizeMsg{Width: 80, Height: 20})
	if view := m.View().Content; !strings.Contains(view, ":3005/") || !strings.Contains(view, ":3000/") {
		t.Fatalf("grown view did not clamp offset = %q", view)
	}
	for _, size := range []tea.WindowSizeMsg{{Width: 80, Height: 20}, {Width: 60, Height: 7}, {Width: 17, Height: 8}, {Width: 12, Height: 3}, {Width: 1, Height: 1}} {
		m.Update(size)
		lines := strings.Split(m.View().Content, "\n")
		if len(lines) != size.Height {
			t.Errorf("%+v: got %d lines", size, len(lines))
		}
		for _, line := range lines {
			width := ansi.StringWidthWc(line)
			if width >= size.Width || (strings.ContainsAny(line, "┌│└├") && width != size.Width-1) {
				t.Errorf("%+v: unexpected width %d: %q", size, width, line)
			}
		}
	}
}

func TestPortWatchShortViewUsesAllAvailableBodyRows(t *testing.T) {
	for _, height := range []int{5, 6} {
		m := newPortWatchModel("dev", "3000-3003", 80, height)
		m.Update(watchRowsMsg{{port: 3000}, {port: 3001}, {port: 3002}, {port: 3003}})
		lines := strings.Split(m.View().Content, "\n")
		if len(lines) != height {
			t.Errorf("height %d: got %d lines, want %d", height, len(lines), height)
		}
		for i := 0; i < height-3; i++ {
			if !strings.Contains(m.View().Content, fmt.Sprintf(":%d/", 3000+i)) {
				t.Errorf("height %d: missing visible port %d", height, 3000+i)
			}
		}
	}
}

func TestFullScreenDrawsBorderedTableWithStyledLinks(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		var output watchFrameBuffer
		session := &viewSession{raw: true}
		done := make(chan error, 1)
		go func() {
			done <- runFullScreen(ctx, session, &output, "dev", "3000-6000", func(ctx context.Context, update func([]portRow)) error {
				update([]portRow{
					{port: 3000, process: "中文"},
					{port: 4000, process: "old-node", closed: true},
					{port: 5173, process: "vite", conflict: true},
					{port: 6000, process: "proxy", failure: "permission denied"},
				})
				<-ctx.Done()
				return nil
			})
		}()
		time.Sleep(25 * time.Millisecond)
		synctest.Wait()
		got := output.String()
		for _, want := range []string{"┌", "┬", "│", "┴", "┘", "Host process name", "Host port", "Client URL", "中文", "\x1b]8;;http://127.0.0.1:3000/", "\x1b[90m old-node", "\x1b[33m vite", "\x1b[31m proxy"} {
			if !strings.Contains(got, want) {
				t.Errorf("missing %q from terminal output %q", want, got)
			}
		}
		if !strings.Contains(got, "\x1b]8;;http://127.0.0.1:3000/\ahttp://127.0.0.1:3000/\x1b]8;;\a") {
			t.Error("renderer did not enclose the successful URL in an OSC 8 link")
		}
		if runtime.GOOS != "windows" && !strings.Contains(got, "\r\n┌") {
			t.Error("raw Unix output moved down without returning to column one")
		}
		for _, port := range []string{"4000", "5173", "6000"} {
			if strings.Contains(got, "\x1b]8;;http://127.0.0.1:"+port+"/") {
				t.Errorf("unexpected hyperlink for unsuccessful port %s", port)
			}
		}
		cancel()
		if err := <-done; err != nil || !session.restored {
			t.Fatalf("cancel: err = %v, restored = %v", err, session.restored)
		}
	})
}

func TestFullScreenRefreshRetainsDisappearedPortsAndUpdatesNames(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var output watchFrameBuffer
		cause := errors.New("scan stopped")
		session := &viewSession{raw: true}
		err := runFullScreen(t.Context(), session, &output, "dev", "3000-4000", func(ctx context.Context, update func([]portRow)) error {
			for _, step := range []struct {
				row  portRow
				want string
			}{
				{portRow{port: 3000, process: "node"}, "http://127.0.0.1:3000/"},
				{portRow{port: 3000, process: "node", closed: true}, "closed"},
				{portRow{port: 3000, process: "python"}, "python"},
				{portRow{port: 3000, process: "ruby"}, "ruby"},
			} {
				before := len(output.String())
				update([]portRow{step.row, {port: 4000}})
				time.Sleep(25 * time.Millisecond)
				if got := output.String()[before:]; !strings.Contains(got, step.want) {
					t.Errorf("redraw missing %q: %q", step.want, got)
				}
			}
			before := len(output.String())
			update([]portRow{{port: 3000, process: "ruby"}, {port: 4000}})
			time.Sleep(25 * time.Millisecond)
			if got := output.String()[before:]; got != "" {
				t.Errorf("duplicate snapshot changed output: %q", got)
			}
			return cause
		})
		if !errors.Is(err, cause) {
			t.Fatal(err)
		}
	})
}

func TestFullScreenRestoresTerminalOnErrorAndQuit(t *testing.T) {
	for _, quit := range []bool{false, true} {
		t.Run(map[bool]string{false: "error", true: "quit"}[quit], func(t *testing.T) {
			session := &viewSession{raw: true}
			if quit {
				session.input.WriteString("qk")
			}
			var output bytes.Buffer
			cause := errors.New("scan failed")
			watch := func(ctx context.Context, update func([]portRow)) error {
				if !quit {
					update([]portRow{{port: 3000}})
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
			if !session.restored || (quit && session.input.String() != "k") {
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

func TestFullScreenQuitsAndRestoresAtUnsupportedInitialSize(t *testing.T) {
	for _, tc := range []struct {
		name          string
		width, height int
	}{
		{"oversized dimension", 5000, 24},
		{"too many cells", 2048, 513},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), time.Second)
				defer cancel()
				session := &polledViewSession{width: tc.width, height: tc.height, keys: []polledWatchKey{{'q', 1}, {'k', 1}}}
				err := runFullScreen(ctx, session, io.Discard, "dev", "3000", func(ctx context.Context, _ func([]portRow)) error {
					<-ctx.Done()
					return nil
				})
				if ctx.Err() != nil || err != nil || !session.restored {
					t.Fatalf("buffered q did not exit and restore before deadline: context = %v, error = %v, restored = %v", ctx.Err(), err, session.restored)
				}
				if len(session.keys) != 1 || session.keys[0].key != 'k' {
					t.Fatalf("keys left for next owner = %v, want only k", session.keys)
				}
			})
		})
	}
}

func TestFullScreenJoinsWatcherAfterOutputError(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()
		cause := errors.New("output failed")
		watchExited := false
		session := &viewSession{raw: true}
		err := runFullScreen(ctx, session, watchOutputFunc(func([]byte) (int, error) { return 0, cause }), "dev", "3000", func(ctx context.Context, update func([]portRow)) error {
			<-ctx.Done()
			watchExited = true
			return nil
		})
		if !errors.Is(err, cause) || !session.restored || ctx.Err() != nil {
			t.Fatalf("output error = %v, restored = %v, deadline reached = %v", err, session.restored, ctx.Err())
		}
		if !watchExited {
			t.Fatal("watcher was not joined after output failed")
		}
	})
}

func TestFullScreenRedrawsAfterNonCharacterConsoleEvent(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		legacyRead := make(chan struct{})
		defer close(legacyRead) // Release the legacy read on a regression failure.
		var output watchFrameBuffer
		session := &polledViewSession{
			legacyRead: legacyRead,
			resize:     make(chan struct{}, 1),
			width:      80,
			height:     24,
			keys:       []polledWatchKey{{}}, // Queued console record, but no key.
		}
		publish := make(chan struct{})
		done := make(chan error, 1)
		go func() {
			done <- runFullScreen(ctx, session, &output, "dev", "3000", func(ctx context.Context, update func([]portRow)) error {
				select {
				case <-publish:
					update([]portRow{{port: 3000, process: "node"}})
				case <-ctx.Done():
				}
				<-ctx.Done()
				return nil
			})
		}()
		time.Sleep(25 * time.Millisecond)
		synctest.Wait()
		if !strings.Contains(output.String(), "No matching ports listening") {
			t.Fatal("initial frame was not drawn")
		}
		time.Sleep(50 * time.Millisecond) // Let the redraw loop observe console input.
		synctest.Wait()
		close(publish)
		time.Sleep(25 * time.Millisecond)
		synctest.Wait()
		if !strings.Contains(output.String(), "http://127.0.0.1:3000/") {
			t.Fatal("snapshot was not rendered after a non-character event with no keypress")
		}
		before := len(output.String())
		session.width = 12
		session.resize <- struct{}{}
		time.Sleep(25 * time.Millisecond)
		synctest.Wait()
		if redraw := output.String()[before:]; !strings.Contains(redraw, "q quit") || strings.Contains(redraw, "http://") {
			t.Fatalf("resize did not render a narrower view without a keypress: %q", redraw)
		}
		cancel()
		synctest.Wait()
		select {
		case err := <-done:
			if err != nil || !session.restored {
				t.Fatalf("cancel: err = %v, restored = %v", err, session.restored)
			}
		default:
			t.Fatal("cancel did not return without a keypress")
		}
	})
}

func TestRelayWatchTerminalDecodesSplitArrowsAndLeavesInputAfterQuit(t *testing.T) {
	for _, quit := range []byte{'q', 3} {
		t.Run(fmt.Sprintf("quit_%d", quit), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				session := &queuedWatchSession{input: make(chan byte, 32)}
				model := newPortWatchModel("dev", "3000-3005", 80, 7)
				model.Update(watchRowsMsg{{port: 3000}, {port: 3001}, {port: 3002}, {port: 3003}, {port: 3004}, {port: 3005}})
				done := make(chan error, 1)
				keys := make(chan tea.Msg, 32)
				events := 0
				go func() {
					done <- relayWatchTerminal(ctx, session, func(msg tea.Msg) { keys <- msg }, 80, 24)
				}()
				synctest.Wait()
				for _, step := range []struct {
					input          string
					offset, events int
				}{
					{"\x1b", 0, 0}, {"[", 0, 0}, {"", 0, 0}, {"B", 1, 1},
					{"\x1b[B\x1b[B", 3, 3}, {"\x1b[A", 2, 4},
					{"\x1bOC", 5, 5}, {"\x1b[D", 0, 6},
					{"\x1b[", 0, 6}, {string([]byte{quit, 'X'}), 0, 7},
				} {
					for i := range len(step.input) {
						session.input <- step.input[i]
					}
					time.Sleep(150 * time.Millisecond)
					synctest.Wait()
					for len(keys) > 0 {
						events++
						model.Update(<-keys)
					}
					if got := model.body.YOffset(); got != step.offset || events != step.events {
						t.Fatalf("after %q: offset = %d, events = %d; want %d, %d", step.input, got, events, step.offset, step.events)
					}
				}
				select {
				case err := <-done:
					if err != nil || len(session.input) != 1 || <-session.input != 'X' {
						t.Fatalf("quit: err = %v, queued byte was not preserved", err)
					}
				default:
					t.Fatal("relay did not stop at quit")
				}
			})
		})
	}
}

func TestRelayWatchTerminalDecodesSplitConsoleRecordsAndLeavesInputAfterQuit(t *testing.T) {
	for _, quit := range []rune{'q', 3} {
		t.Run(fmt.Sprintf("quit_%d", quit), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				session := &queuedConsoleWatchSession{records: make(chan polledWatchKey, 16)}
				done := make(chan error, 1)
				keys := make(chan tea.Msg, 16)
				go func() {
					done <- relayWatchTerminal(ctx, session, func(msg tea.Msg) { keys <- msg }, 80, 24)
				}()
				synctest.Wait()
				for _, step := range []struct {
					records []polledWatchKey
					want    watchKeyMsg
				}{
					{records: []polledWatchKey{{'\x1b', 1}}},
					{records: []polledWatchKey{{'[', 1}}},
					{}, // An idle poll must not discard the prefix.
					{[]polledWatchKey{{'B', 2}}, watchKeyMsg{terminal.KeyDown, 2}},
					{records: []polledWatchKey{{'\x1b', 1}}},
					{records: []polledWatchKey{{'O', 1}}},
					{[]polledWatchKey{{'A', 1}}, watchKeyMsg{terminal.KeyUp, 1}},
					{[]polledWatchKey{{'\x1b', 1}, {'[', 1}, {terminal.KeyLeft, 3}}, watchKeyMsg{terminal.KeyLeft, 3}},
					{[]polledWatchKey{{'B', 1}}, watchKeyMsg{'B', 1}}, // A native arrow clears a partial prefix.
					{records: []polledWatchKey{{'\x1b', 1}, {'[', 1}}},
					{[]polledWatchKey{{quit, 1}, {'X', 1}}, watchKeyMsg{quit, 1}},
				} {
					for _, record := range step.records {
						session.records <- record
					}
					time.Sleep(50 * time.Millisecond)
					synctest.Wait()
					var got tea.Msg
					select {
					case got = <-keys:
					default:
					}
					var want tea.Msg
					if step.want.repeat > 0 {
						want = step.want
					}
					if got != want || len(keys) != 0 {
						t.Fatalf("after records %+v: got %v (+%d queued), want %v", step.records, got, len(keys), want)
					}
				}
				select {
				case err := <-done:
					if err != nil || len(session.records) != 1 || <-session.records != (polledWatchKey{'X', 1}) {
						t.Fatalf("quit: err = %v, queued sentinel was not preserved", err)
					}
				default:
					t.Fatal("relay did not stop at quit")
				}
			})
		})
	}
}

type queuedConsoleWatchSession struct {
	viewSession
	records chan polledWatchKey
}

func (s *queuedConsoleWatchSession) PollKey() (rune, int, error) {
	select {
	case record := <-s.records:
		return record.key, record.repeat, nil
	default:
		return 0, 0, nil
	}
}

type queuedWatchSession struct {
	viewSession
	input chan byte
}

func (s *queuedWatchSession) Stdin() io.Reader { return s }
func (s *queuedWatchSession) StdinReadyWithin(time.Duration) (bool, error) {
	return len(s.input) > 0, nil
}
func (s *queuedWatchSession) Read(p []byte) (int, error) {
	p[0] = <-s.input
	return 1, nil
}

func TestFullScreenPollsBufferedNavigationAndQuitKeys(t *testing.T) {
	for _, tt := range []struct {
		name string
		quit byte
	}{{"q", 'q'}, {"Ctrl-C", 3}} {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				var output watchFrameBuffer
				session := &polledViewSession{width: 80, height: 7, keys: []polledWatchKey{
					{terminal.KeyDown, 2}, {terminal.KeyUp, 1}, {terminal.KeyRight, 1}, {terminal.KeyLeft, 1}, {rune(tt.quit), 1}, {'X', 1},
				}}
				done := make(chan error, 1)
				go func() {
					done <- runFullScreen(ctx, session, &output, "dev", "3000-3003", func(ctx context.Context, update func([]portRow)) error {
						update([]portRow{{port: 3000}, {port: 3001}, {port: 3002}, {port: 3003}})
						<-ctx.Done()
						return nil
					})
				}()
				synctest.Wait()
				time.Sleep(25 * time.Millisecond) // Inspect each delta after Tea's frame tick.
				for _, port := range []string{"3002", "3001", "3003", "3000"} {
					before := len(output.String())
					time.Sleep(50 * time.Millisecond)
					synctest.Wait()
					if redraw := output.String()[before:]; !strings.Contains(redraw, "http://127.0.0.1:"+port+"/") {
						t.Fatalf("buffered navigation did not show port %s: %q", port, redraw)
					}
				}
				time.Sleep(50 * time.Millisecond)
				synctest.Wait()
				select {
				case err := <-done:
					if err != nil || !session.restored {
						t.Fatalf("quit: err = %v, restored = %v", err, session.restored)
					}
				default:
					t.Fatal("buffered quit key was not handled")
				}
				if len(session.keys) != 1 || session.keys[0].key != 'X' {
					t.Fatalf("native input read ahead past quit: %+v", session.keys)
				}
			})
		})
	}
}

type watchFrameBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *watchFrameBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *watchFrameBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

type polledWatchKey struct {
	key    rune
	repeat int
}

type polledViewSession struct {
	viewSession
	legacyRead    chan struct{}
	resize        chan struct{}
	width, height int
	keys          []polledWatchKey
}

func (s *polledViewSession) PollKey() (rune, int, error) {
	if len(s.keys) == 0 {
		return 0, 0, nil
	}
	key := s.keys[0]
	s.keys = s.keys[1:]
	return key.key, key.repeat, nil
}

func (s *polledViewSession) Size() (int, int)              { return s.width, s.height }
func (s *polledViewSession) ResizeEvents() <-chan struct{} { return s.resize }
func (s *polledViewSession) StdinReadyWithin(time.Duration) (bool, error) {
	return s.legacyRead != nil, nil
}
func (s *polledViewSession) Stdin() io.Reader { return s }
func (s *polledViewSession) Read([]byte) (int, error) {
	<-s.legacyRead
	return 0, io.EOF
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
