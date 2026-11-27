package portwatch

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"

	"charm.land/bubbles/v2/viewport"
	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/colorprofile"
	"github.com/charmbracelet/x/ansi"
	"golang.org/x/term"

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

// runFullScreen takes ownership after raw mode and full-screen output setup.
// Leave input and resize to the session alone: the Windows record poll
// preserves key repeats and never reads ahead or blocks on non-key records.
func runFullScreen(ctx context.Context, session terminal.Session, out io.Writer, name, ranges string, watch func(context.Context, func([]portRow)) error) (err error) {
	defer func() { err = errors.Join(err, session.Restore()) }()
	viewCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	width, height := watchWindowSize(session)
	initialWidth, initialHeight := width, height
	// Bubble Tea v2.1.3 drops sizes above 4096 per dimension or 1 Mi cells.
	// It must deliver the initial size to activate the terminal relay. Keep
	// the measured size as the relay baseline so a later resize still works.
	if width > 4096 || height > 4096 || width*height > 1<<20 {
		initialWidth, initialHeight = 80, 24
	}
	model := newPortWatchModel(name, ranges, initialWidth, initialHeight)
	ready := make(chan struct{})
	model.ready = ready
	output := &watchScreenOutput{Writer: out, cancel: cancel}
	program := tea.NewProgram(model,
		tea.WithContext(viewCtx), tea.WithInput(nil), tea.WithOutput(output),
		tea.WithWindowSize(initialWidth, initialHeight), tea.WithoutSignalHandler(), tea.WithColorProfile(colorprofile.ANSI),
	)

	var workers sync.WaitGroup
	var watchErr, inputErr error
	workers.Go(func() {
		watchErr = watch(viewCtx, func(rows []portRow) { program.Send(watchRowsMsg(rows)) })
		program.Send(tea.Quit())
	})
	workers.Go(func() {
		// Wait for Tea's initial WindowSizeMsg before relaying later sizes.
		select {
		case <-ready:
		case <-viewCtx.Done():
			return
		}
		inputErr = relayWatchTerminal(viewCtx, session, program.Send, width, height)
		if inputErr != nil {
			program.Send(tea.Quit())
		}
	})
	_, runErr := program.Run()
	cancel()
	workers.Wait()
	if output.err != nil {
		return output.err
	}
	if ctx.Err() != nil && errors.Is(runErr, tea.ErrProgramKilled) && errors.Is(runErr, ctx.Err()) {
		runErr = nil // An external interrupt is a normal exit from port-watch.
	}
	return errors.Join(runErr, inputErr, watchErr)
}

// Hide Fd from Tea so it does not configure output or start another resize
// listener. Cancel on a write failure rather than waiting for a key to make
// Tea return the renderer's recorded error.
type watchScreenOutput struct {
	io.Writer
	cancel context.CancelFunc
	once   sync.Once
	err    error
}

func (w *watchScreenOutput) Write(p []byte) (int, error) {
	frame := p
	if runtime.GOOS != "windows" && bytes.IndexByte(p, '\n') >= 0 {
		// With no TTY attached to Tea it expects cooked output to convert LF
		// to CRLF. The session is raw, so supply the missing carriage returns.
		frame = bytes.ReplaceAll(p, []byte("\n"), []byte("\r\n"))
	}
	n, err := w.Writer.Write(frame)
	if err == nil && n != len(frame) {
		err = io.ErrShortWrite
	}
	if err != nil {
		w.once.Do(func() {
			w.err = err
			w.cancel()
		})
		return min(n, len(p)), err
	}
	return len(p), nil
}

func watchWindowSize(session terminal.Session) (width, height int) {
	width, height = session.Size()
	if width <= 0 {
		width = 80
	}
	if height <= 0 {
		height = 24
	}
	return width, height
}

func relayWatchTerminal(ctx context.Context, session terminal.Session, send func(tea.Msg), width, height int) error {
	resize := session.ResizeEvents()
	var input watchKeyPoller
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for ctx.Err() == nil {
		var key watchKeyMsg
		select {
		case <-ctx.Done():
			return nil
		case _, ok := <-resize:
			if !ok {
				resize = nil
			}
		case <-ticker.C:
			var err error
			key.code, key.repeat, err = input.poll(session)
			if err != nil {
				return err
			}
		}
		// Also sample on the tick: raw terminal notifications can be coalesced.
		if w, h := watchWindowSize(session); w != width || h != height {
			width, height = w, h
			send(tea.WindowSizeMsg{Width: w, Height: h})
		}
		if key.repeat > 0 {
			send(key)
			if key.quits() {
				return nil // Leave queued bytes after quit for the next terminal owner.
			}
		}
	}
	return nil
}

type watchKeyPoller struct {
	prefix rune // ESC, '[' (CSI), or 'O' (SS3); zero between keys.
}

func (p *watchKeyPoller) poll(session terminal.Session) (key rune, repeat int, err error) {
	// Decode at most one key from up to three ready inputs. A split prefix
	// survives an idle tick without holding up resize, redraw, or cancellation.
	for range 3 {
		key, repeat, err := pollWatchInput(session)
		if err != nil || repeat == 0 {
			return 0, 0, err
		}
		if key == '\x1b' || (p.prefix == '\x1b' && (key == '[' || key == 'O')) {
			p.prefix = key
			continue
		}
		prefix := p.prefix
		p.prefix = 0
		if prefix == '[' || prefix == 'O' {
			switch key {
			case 'A':
				key = terminal.KeyUp
			case 'B':
				key = terminal.KeyDown
			case 'C':
				key = terminal.KeyRight
			case 'D':
				key = terminal.KeyLeft
			}
		}
		// Native key codes pass through, as do q and Ctrl-C after a partial prefix.
		return key, repeat, nil
	}
	return 0, 0, nil
}

func pollWatchInput(session terminal.Session) (rune, int, error) {
	// Windows may deliver native arrows or individual VT sequence characters
	// as records. Console readiness alone does not imply a readable character.
	if console, ok := session.(interface{ PollKey() (rune, int, error) }); ok {
		return console.PollKey()
	}
	ready, err := session.StdinReadyWithin(0)
	if err != nil || !ready {
		return 0, 0, err
	}
	var input [1]byte
	if _, err := io.ReadFull(session.Stdin(), input[:]); err != nil {
		return 0, 0, err
	}
	return rune(input[0]), 1, nil
}

type watchRowsMsg []portRow

type watchKeyMsg struct {
	code   rune
	repeat int
}

func (k watchKeyMsg) quits() bool { return k.code == 'q' || k.code == 3 || k.code == 4 }

type portWatchModel struct {
	name, ranges  string
	width, height int
	processWidth  int
	rows          []portRow
	body          viewport.Model
	ready         chan struct{}
}

func newPortWatchModel(name, ranges string, width, height int) *portWatchModel {
	m := &portWatchModel{name: name, ranges: ranges, body: viewport.New()}
	m.resize(width, height)
	return m
}

func (*portWatchModel) Init() tea.Cmd { return nil }

func (m *portWatchModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.resize(msg.Width, msg.Height)
		if m.ready != nil {
			close(m.ready)
			m.ready = nil
		}
	case watchRowsMsg:
		if !slices.Equal(m.rows, msg) {
			m.rows = msg
			m.setBody()
		}
	case watchKeyMsg:
		if msg.quits() {
			return m, tea.Quit
		}
		switch msg.code {
		case terminal.KeyDown, 'j':
			m.body.ScrollDown(msg.repeat)
		case terminal.KeyUp, 'k':
			m.body.ScrollUp(msg.repeat)
		case terminal.KeyLeft, 'g':
			m.body.GotoTop()
		case terminal.KeyRight, 'G':
			m.body.GotoBottom()
		}
	}
	return m, nil
}

const (
	processHeading         = "Host process name"
	portHeading            = "Host port"
	urlHeading             = "Client URL"
	minProcessWidth        = len(processHeading)
	portWidth              = len(portHeading)
	plainPrefix            = minProcessWidth + portWidth + 4
	borderedPrefixOverhead = portWidth + 7
	fullURLWidth           = len("http://127.0.0.1:65535/")
	minTableWidth          = minProcessWidth + borderedPrefixOverhead + fullURLWidth + 4
)

func (m *portWatchModel) bordered() bool { return m.width >= minTableWidth && m.height >= 7 }

func (m *portWatchModel) resize(width, height int) {
	m.width, m.height = max(0, width-1), height // Don't write in the wrapping column.
	bodyWidth, bodyHeight := m.width, max(1, height-6)
	if m.bordered() {
		bodyWidth -= 2
	} else if height >= 7 {
		bodyHeight++ // The plain layout has no bottom border.
	} else {
		bodyHeight = max(1, height-3) // Title, heading and quit help.
	}
	m.body.SetWidth(bodyWidth)
	m.body.SetHeight(bodyHeight)
	m.setBody()
}

func (m *portWatchModel) setBody() {
	m.processWidth = minProcessWidth
	if m.bordered() {
		// Split spare cells after reserving the full URL, but give longer names
		// more room when they need it.
		limit := m.body.Width() - borderedPrefixOverhead - fullURLWidth
		m.processWidth += (limit - minProcessWidth) / 2
		for _, row := range m.rows {
			m.processWidth = max(m.processWidth, ansi.StringWidthWc(clipped(row.process, limit)))
			if m.processWidth == limit {
				break
			}
		}
	}
	if len(m.rows) == 0 {
		message := "No matching ports listening"
		if m.bordered() {
			if len(message) > m.processWidth {
				message = "No matching ports"
			}
			message = m.borderedCells(message, "")
		}
		m.body.SetContent(clipped(message, m.body.Width()))
		return
	}
	lines := make([]string, len(m.rows))
	for i, row := range m.rows {
		lines[i] = m.row(row)
	}
	m.body.SetContentLines(lines)
}

func (m *portWatchModel) row(row portRow) string {
	process := clipped(row.process, m.processWidth)
	if process == "" {
		process = "—"
	}
	port := fmt.Sprint(row.port)
	var prefix string
	var remaining int
	if m.bordered() {
		prefix = m.borderedCells(process, port)
		remaining = m.urlWidth()
	} else {
		prefix = clipped(padCells(process, m.processWidth)+"  "+padCells(port, portWidth)+"  ", m.body.Width())
		remaining = m.body.Width() - plainPrefix
	}
	var status, sgr string
	switch {
	case row.closed:
		status, sgr = "closed", "\x1b[90m"
	case row.conflict:
		status, sgr = "address already in use", "\x1b[33m"
	case row.failure != "":
		status, sgr = row.failure, "\x1b[31m"
	default:
		if remaining > 0 {
			url := fmt.Sprintf("http://127.0.0.1:%d/", row.port)
			return prefix + "\x1b]8;;" + url + "\x1b\\" + clipped(url, remaining) + "\x1b]8;;\x1b\\"
		}
		return prefix
	}
	return sgr + prefix + clipped(status, remaining) + "\x1b[0m"
}

func (m *portWatchModel) View() tea.View {
	title := "\x1b[1m" + clipped("Watching "+m.name+" · ports "+m.ranges, m.width) + "\x1b[0m"
	footer := fmt.Sprintf("%d ports · ↑/↓ scroll · ←/→ top/end · q/Ctrl-C quit", len(m.rows))
	if m.width < ansi.StringWidthWc(footer) {
		footer = fmt.Sprintf("q quit · %d ports · ↑/↓ scroll · ←/→ top/end", len(m.rows))
	}
	footer = clipped(footer, m.width)
	bodyRows := strings.Split(m.body.View(), "\n")
	for i, row := range bodyRows {
		// The viewport pads using grapheme widths, but Tea's renderer uses
		// wcwidth without negotiation. Strip its padding before framing.
		bodyRows[i] = strings.TrimRight(row, " ")
	}
	var lines []string
	if m.bordered() {
		rule := func(left, join, right string) string {
			return left + strings.Repeat("─", m.processWidth+2) + join + strings.Repeat("─", portWidth+2) + join + strings.Repeat("─", m.urlWidth()+1) + right
		}
		frame := func(s string) string { return "│" + padCells(s, m.body.Width()) + "│" }
		lines = []string{title, rule("┌", "┬", "┐"), frame(m.borderedCells(processHeading, portHeading) + urlHeading), rule("├", "┼", "┤")}
		blank := frame(m.borderedCells("", ""))
		for _, row := range bodyRows {
			if row == "" {
				lines = append(lines, blank)
			} else {
				lines = append(lines, frame(row))
			}
		}
		lines = append(lines, rule("└", "┴", "┘"), footer)
	} else {
		body := strings.Join(bodyRows, "\n")
		heading := clipped(processHeading+"  "+portHeading+"  "+urlHeading, m.width)
		switch {
		case m.height >= 7:
			lines = []string{title, "", heading, "", body, footer}
		case m.height >= 4:
			lines = []string{title, heading, body, footer}
		case m.height == 3:
			lines = []string{title, body, footer}
		case m.height == 2:
			lines = []string{title, body}
		default:
			lines = []string{title}
		}
	}
	v := tea.NewView(strings.Join(lines, "\n"))
	v.AltScreen = true
	v.DisableBracketedPasteMode = true
	return v
}

func (m *portWatchModel) urlWidth() int {
	return m.body.Width() - m.processWidth - borderedPrefixOverhead
}

func (m *portWatchModel) borderedCells(process, port string) string {
	return " " + padCells(process, m.processWidth) + " │ " + padCells(port, portWidth) + " │ "
}

func padCells(s string, width int) string {
	return s + strings.Repeat(" ", max(0, width-ansi.StringWidthWc(s)))
}

func clipped(s string, limit int) string {
	if limit <= 0 {
		return ""
	}
	// Treat SSH metadata as text, not terminal commands. Keep combining marks
	// on their base character but omit unstable format/presentation modifiers.
	started := false
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf, unicode.Variation_Selector) || r == '\u20e3' {
			return -1
		}
		if !started && unicode.In(r, unicode.Mn, unicode.Me) {
			return -1
		}
		started = true
		return r
	}, s)
	return ansi.WcWidth.Truncate(s, limit, "")
}
