package portwatch

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
	"unicode"

	"golang.org/x/term"
	"golang.org/x/text/width"

	"warden/internal/client/terminal"
)

type portRow struct {
	port     int
	process  string
	failure  string
	closed   bool
	conflict bool
}

func terminalOutput(w io.Writer) bool {
	f, ok := w.(interface{ Fd() uintptr })
	return ok && os.Getenv("TERM") != "dumb" && term.IsTerminal(int(f.Fd()))
}

// runFullScreen takes ownership of a raw session with ANSI enabled. The watcher
// sends immutable snapshots and is joined before the terminal is restored.
func runFullScreen(ctx context.Context, session terminal.Session, out io.Writer, name, ranges string, watch func(context.Context, func([]portRow)) error) (err error) {
	defer func() {
		if restoreErr := session.Restore(); err == nil {
			err = restoreErr
		}
	}()
	defer func() {
		_, restoreErr := io.WriteString(out, "\x1b[0m\x1b[?25h\x1b[?1049l")
		if err == nil {
			err = restoreErr
		}
	}()
	if _, err = io.WriteString(out, "\x1b[?1049h\x1b[?25l"); err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	updates := make(chan []portRow)
	done := make(chan error, 1)
	go func() {
		done <- watch(ctx, func(rows []portRow) {
			select {
			case updates <- rows:
			case <-ctx.Done():
			}
		})
	}()
	joined := false
	defer func() {
		cancel()
		if !joined {
			<-done
		}
	}()
	var rows []portRow
	offset := 0
	redraw := func() error {
		width, height := session.Size()
		offset = clampOffset(offset, len(rows), height)
		_, err := io.WriteString(out, renderScreen(name, ranges, rows, width, height, offset))
		return err
	}
	if err = redraw(); err != nil {
		return err
	}
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case err = <-done:
			joined = true
			return err
		case next := <-updates:
			if equalRows(rows, next) {
				continue
			}
			rows = next
		case <-session.ResizeEvents():
		case <-ticker.C:
			ready, readErr := session.StdinReadyWithin(0)
			if readErr != nil {
				return readErr
			}
			if !ready {
				continue
			}
			var key [1]byte
			if _, readErr = io.ReadFull(session.Stdin(), key[:]); readErr != nil {
				return readErr
			}
			switch key[0] {
			case 'q', 3, 4:
				return nil
			case 'j':
				offset++
			case 'k':
				offset--
			case 'g':
				offset = 0
			case 'G':
				offset = len(rows)
			default:
				continue
			}
		}
		if err = redraw(); err != nil {
			return err
		}
	}
}

func equalRows(a, b []portRow) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func visibleRows(height int) int {
	if height < 7 {
		return 1
	}
	return height - 6
}

func clampOffset(offset, count, height int) int {
	last := count - visibleRows(height)
	if last < 0 {
		last = 0
	}
	if offset > last {
		offset = last
	}
	if offset < 0 {
		offset = 0
	}
	return offset
}

func clipped(s string, limit int) string {
	text, _ := clipCells(s, limit)
	return text
}

// clipCells treats ambiguous characters as single-cell. Strip format and
// presentation modifiers to avoid common terminal-dependent width changes.
func clipCells(s string, limit int) (string, int) {
	if limit <= 0 {
		return "", 0
	}
	var text strings.Builder
	cells := 0
	for _, r := range s {
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf, unicode.Variation_Selector) || r == '\u20e3' {
			continue
		}
		if unicode.In(r, unicode.Mn, unicode.Me) {
			if cells > 0 {
				text.WriteRune(r)
			}
			continue
		}
		size := 1
		switch width.LookupRune(r).Kind() {
		case width.EastAsianFullwidth, width.EastAsianWide:
			size = 2
		}
		if cells+size > limit {
			break
		}
		text.WriteRune(r)
		cells += size
	}
	return text.String(), cells
}

func renderScreen(name, ranges string, rows []portRow, width, height, offset int) string {
	if width <= 0 {
		width = 80
	}
	if height <= 0 {
		height = 24
	}
	// Leave the last column unused to avoid automatic wrapping/scrolling.
	width--
	offset = clampOffset(offset, len(rows), height)
	const processWidth = len("Host process name")
	const portWidth = len("Host port")
	const prefixWidth = processWidth + portWidth + 4
	lines := []string{
		"\x1b[1m" + clipped("Watching "+name+" · ports "+ranges, width) + "\x1b[0m",
		"",
		clipped("Host process name  Host port  Client URL", width),
		"",
	}
	if len(rows) == 0 {
		lines = append(lines, clipped("No matching ports listening", width))
	} else {
		end := offset + visibleRows(height)
		if end > len(rows) {
			end = len(rows)
		}
		for _, row := range rows[offset:end] {
			process, cells := clipCells(row.process, processWidth)
			if process == "" {
				process, cells = "—", 1
			}
			prefix := fmt.Sprintf("%s%s  %-*d  ", process, strings.Repeat(" ", processWidth-cells), portWidth, row.port)
			line := clipped(prefix, width)
			remaining := width - prefixWidth
			switch {
			case row.closed:
				line = "\x1b[90m" + line + clipped("closed", remaining) + "\x1b[0m"
			case row.conflict:
				line = "\x1b[33m" + line + clipped("address already in use", remaining) + "\x1b[0m"
			case row.failure != "":
				line = "\x1b[31m" + line + clipped(row.failure, remaining) + "\x1b[0m"
			case remaining > 0:
				url := fmt.Sprintf("http://127.0.0.1:%d/", row.port)
				line += "\x1b]8;;" + url + "\x1b\\" + clipped(url, remaining) + "\x1b]8;;\x1b\\"
			}
			lines = append(lines, line)
		}
	}
	lines = append(lines, clipped(fmt.Sprintf("%d ports · j/k scroll · g/G top/end · q/Ctrl-C quit", len(rows)), width))
	if len(lines) > height {
		lines = lines[:height]
	}
	return "\x1b[H\x1b[2J" + strings.Join(lines, "\r\n")
}
