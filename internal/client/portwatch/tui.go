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

	"warden/internal/client/terminal"
)

type portRow struct {
	port    int
	failure string
}

func terminalOutput(w io.Writer) bool {
	f, ok := w.(interface{ Fd() uintptr })
	return ok && os.Getenv("TERM") != "dumb" && term.IsTerminal(int(f.Fd()))
}

// runFullScreen owns all terminal writes. The watcher sends immutable snapshots;
// cancellation joins it before restoring the terminal and closing SSH resources.
func runFullScreen(ctx context.Context, session terminal.Session, out io.Writer, name, ranges string, watch func(context.Context, func([]portRow)) error) (err error) {
	defer func() {
		if restoreErr := session.Restore(); err == nil {
			err = restoreErr
		}
	}()
	if err = session.EnterRaw(); err != nil {
		return err
	}
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

func cleanText(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
}

func clipped(s string, width int) string {
	if width <= 0 {
		return ""
	}
	runes := []rune(cleanText(s))
	if len(runes) > width {
		return string(runes[:width])
	}
	return string(runes)
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
	lines := []string{
		"\x1b[1m" + clipped("Watching "+cleanText(name)+" · ports "+ranges, width) + "\x1b[0m",
		"",
		clipped("REMOTE PORT   LOCAL URL", width),
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
			prefix := fmt.Sprintf("%-14d", row.port)
			if width <= len(prefix) {
				lines = append(lines, clipped(prefix, width))
				continue
			}
			if row.failure != "" {
				lines = append(lines, prefix+"\x1b[31m"+clipped(row.failure, width-len(prefix))+"\x1b[0m")
			} else {
				url := fmt.Sprintf("http://127.0.0.1:%d/", row.port)
				lines = append(lines, prefix+"\x1b]8;;"+url+"\x1b\\\x1b[36m"+clipped(url, width-len(prefix))+"\x1b[0m\x1b]8;;\x1b\\")
			}
		}
	}
	lines = append(lines, clipped(fmt.Sprintf("%d ports · j/k scroll · g/G top/end · q/Ctrl-C quit", len(rows)), width))
	if len(lines) > height {
		lines = lines[:height]
	}
	return "\x1b[H\x1b[2J" + strings.Join(lines, "\r\n")
}
