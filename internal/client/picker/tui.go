package picker

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"runtime"
	"sync/atomic"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/colorprofile"
	"github.com/charmbracelet/x/ansi"

	"warden/internal/client/terminal"
	"warden/internal/model"
)

// Select returns a connection only after Tea has stopped rendering and the
// terminal is restored. Tea never owns the input or changes terminal modes.
func Select(session terminal.Session, conns []model.SSHConnection) (conn model.SSHConnection, retErr error) {
	if len(conns) == 0 {
		return conn, errors.New("no ssh connections configured")
	}
	if err := session.EnterRaw(); err != nil {
		return conn, fmt.Errorf("enter picker raw mode: %w", err)
	}
	defer func() {
		if err := session.Restore(); err != nil {
			conn = model.SSHConnection{}
			retErr = errors.Join(retErr, fmt.Errorf("restore picker raw mode: %w", err))
		}
	}()
	if !session.SupportsANSI() {
		return conn, errors.New("terminal does not support ANSI rendering; use a modern terminal")
	}
	if err := terminal.EnableFullScreenOutput(session); err != nil {
		return conn, fmt.Errorf("terminal is incompatible with the full-screen picker: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out := &pickerOutput{writer: session.Stdout(), cancel: cancel}
	m := &pickerModel{
		state: NewState(conns), ctx: ctx, output: out,
		input: pickerInput{session: session},
	}
	w, h := pickerSize(session)
	m.resize(w, h)
	program := tea.NewProgram(m, tea.WithContext(ctx), tea.WithInput(nil), tea.WithOutput(out),
		tea.WithWindowSize(w, h), tea.WithColorProfile(colorprofile.ANSI),
	)
	_, err := program.Run()
	if m.err != nil {
		return conn, m.err
	}
	if out.err != nil {
		return conn, out.err
	}
	if err != nil {
		return conn, fmt.Errorf("run picker: %w", err)
	}
	if !m.confirmed {
		return conn, errors.New("selection aborted")
	}
	conn, _ = m.state.Selected()
	return conn, nil
}

// Hiding Fd prevents Tea from configuring output or subscribing to resize.
// With neither a tty nor input, Tea won't send terminal queries or drain replies.
type pickerOutput struct {
	writer io.Writer
	cancel context.CancelFunc
	ready  atomic.Bool
	err    error // Tea serializes writes and completes cleanup before Run returns.
}

func (o *pickerOutput) Write(p []byte) (int, error) {
	frame := p
	if runtime.GOOS != "windows" {
		// Tea assumes cooked output (LF to CRLF) when it doesn't own a TTY.
		frame = bytes.ReplaceAll(p, []byte("\n"), []byte("\r\n"))
	}
	n, err := o.writer.Write(frame)
	if err == nil && n != len(frame) {
		err = io.ErrShortWrite
	}
	if err != nil {
		if o.err == nil {
			action := "render picker"
			if bytes.Contains(p, []byte(ansi.ResetModeAltScreenSaveCursor)) {
				action = "leave alternate screen"
			}
			o.err = fmt.Errorf("%s: %w", action, err)
			o.cancel()
		}
		return min(n, len(p)), err
	}
	o.ready.Store(true)
	return len(p), nil
}

func pickerSize(session terminal.Session) (int, int) {
	w, h := session.Size()
	if w < 1 || h < 1 {
		return 80, 24
	}
	return w, h
}

const pickerInputInterval = 10 * time.Millisecond

type pollPickerInputMsg struct{}

func pollPickerInput() tea.Msg { return pollPickerInputMsg{} }

func pollPickerInputLater() tea.Cmd {
	return tea.Tick(pickerInputInterval, func(time.Time) tea.Msg { return pollPickerInputMsg{} })
}

type pickerModel struct {
	state         State
	input         pickerInput
	output        *pickerOutput
	ctx           context.Context
	width, height int
	content       string
	nextSizeCheck time.Time
	confirmed     bool
	err           error
}

func (*pickerModel) Init() tea.Cmd { return pollPickerInputLater() }

func (m *pickerModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.resize(msg.Width, msg.Height)
	case pollPickerInputMsg:
		if m.ctx.Err() != nil || m.confirmed || m.err != nil {
			return m, tea.Quit
		}
		if !m.output.ready.Load() {
			return m, pollPickerInputLater()
		}
		now := time.Now()
		if !now.Before(m.nextSizeCheck) {
			m.nextSizeCheck = now.Add(100 * time.Millisecond)
			if w, h := pickerSize(m.input.session); w != m.width || h != m.height {
				// Tea can reject a resize message without calling Update.
				resize := func() tea.Msg { return tea.WindowSizeMsg{Width: w, Height: h} }
				return m, tea.Sequence(resize, pollPickerInput)
			}
		}

		// Poll on the event loop, not in a Tea command or separate reader.
		// Apply the decoded key before asking for another record or byte.
		keys, repeat, progressed, err := m.input.poll(now)
		if err != nil {
			m.err = fmt.Errorf("read picker input: %w", err)
			return m, tea.Quit
		}
		changed := false
		for _, key := range keys {
			switch key.Kind {
			case KeyCancel:
				m.err = errors.New("selection aborted")
				return m, tea.Quit
			case KeyEnter:
				if _, ok := m.state.Selected(); ok {
					m.confirmed = true
					return m, tea.Quit
				}
			default:
				for range repeat {
					m.state = m.state.Apply(key)
				}
				changed = true
			}
		}
		if changed {
			m.content = pickerContent(m.state, m.width, m.height)
		}
		if progressed {
			return m, pollPickerInput
		}
		return m, pollPickerInputLater()
	}
	return m, nil
}

func (m *pickerModel) resize(w, h int) {
	m.width, m.height = w, h
	m.content = pickerContent(m.state, w, h)
}

func (m *pickerModel) View() tea.View {
	v := tea.NewView(m.content)
	v.AltScreen = true
	v.DisableBracketedPasteMode = true
	return v
}
