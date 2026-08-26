package picker

import (
	"io"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"warden/internal/model"
)

// ANSI SGR styles used by the renderer. All styling goes through these
// constants so the escape sequences stay in one place.
const (
	reset    = "\x1b[0m"
	cyan     = "\x1b[36m"
	yellow   = "\x1b[33m"
	blue     = "\x1b[34m"
	selected = "\x1b[7;36m"
)

// Field is one labeled value in the selected-connection preview.
type Field struct {
	Label string
	Value string
}

// FormatConnection renders every profile field with secrets redacted:
// Has* booleans become the exact markers [configured] / [not configured]
// and no secret value is ever emitted. Fields always appear in this order.
func FormatConnection(c model.SSHConnection) []Field {
	return []Field{
		{Label: "ID", Value: strconv.FormatInt(c.ID, 10)},
		{Label: "Name", Value: orNotSet(c.Name)},
		{Label: "Group", Value: groupValue(c)},
		{Label: "Host", Value: orNotSet(c.Host)},
		{Label: "Port", Value: orNotSetInt(c.Port)},
		{Label: "Username", Value: orNotSet(c.Username)},
		{Label: "Password", Value: configured(c.HasPassword)},
		{Label: "Key pair", Value: keyPairValue(c)},
		{Label: "Proxy host", Value: orNotSet(c.ProxyHost)},
		{Label: "Proxy port", Value: orNotSetInt(c.ProxyPort)},
		{Label: "Proxy username", Value: orNotSet(c.ProxyUsername)},
		{Label: "Proxy password", Value: configured(c.HasProxyPassword)},
		{Label: "Jump connection IDs", Value: orNotSet(c.JumpConnectionIDs)},
		{Label: "Default directory", Value: orNotSet(c.DefaultDir)},
		{Label: "Created at", Value: formatTime(c.CreatedAt)},
		{Label: "Updated at", Value: formatTime(c.UpdatedAt)},
	}
}

// Render draws the picker to w: a title, the search prompt, the filtered
// connection list, and the selected connection's redacted fields. At
// width >= 80 the list and fields sit side by side separated by a │
// column (always at the leftWidth column); below that the fields stack
// beneath the list. Every line is clamped to its pane width and model
// values pass through sanitize so a profile cannot inject terminal
// control sequences. The list viewport follows the selection so the
// selected row is always visible, and the detail viewport shows a window
// of the selected connection's fields starting at state.detailOffset so
// every field stays reachable by paging. A failed write is returned so
// Select never reports a successful selection on a broken terminal.
func Render(w io.Writer, state State, width, height int) error {
	if width < 1 || height < 1 {
		return nil
	}

	// Build every row as a separate line, then join them with CRLF so the
	// final viewport row never carries a trailing newline: when exactly
	// height rows are rendered a trailing CRLF would move the cursor past
	// the last row and scroll the alternate screen.
	var lines []string

	// Three fixed rows (title, search prompt, focus hint); the remaining
	// rows (bodyRows) are shared between the list and the preview so the
	// render never emits more rows than height and the query, list, and
	// preview all stay visible when the viewport has room. The focus hint
	// exposes the Tab control and names the pane that owns Up/Down; it is
	// omitted on a two-row terminal where the title and prompt already
	// fill the viewport.
	bodyRows := height - 3
	if height < 3 {
		bodyRows = 0
	}

	lines = append(lines, cyan+clamp("warden xssh — pick a connection", width)+reset)

	if height >= 2 {
		lines = append(lines, yellow+clamp("Search: "+sanitize(state.query), width)+reset)
	}

	filtered := state.Filtered()
	selectedConn, hasSelected := state.Selected()

	if width >= 80 {
		leftWidth := width * 45 / 100
		rightWidth := width - leftWidth - 1
		if rightWidth < 1 {
			rightWidth = 1
		}
		listStart := listWindowStart(state.selected, bodyRows, len(filtered))
		fields := []Field{}
		if hasSelected {
			fields = FormatConnection(selectedConn)
		}
		for i := 0; i < bodyRows; i++ {
			row := listLine(filtered, state.selected, listStart+i, leftWidth)
			// Pad the visible row to leftWidth so the │ separator always
			// sits at the same column no matter how short the name is.
			line := padVisible(row, leftWidth) + cyan + "│" + reset
			if idx := state.detailOffset + i; idx < len(fields) {
				line += fieldLine(fields[idx], rightWidth)
			}
			lines = append(lines, line)
		}
	} else {
		// Narrow layout: split the body rows between the list and the
		// preview so the preview cannot push the render past the
		// viewport. A single body row goes to the list.
		listRows := bodyRows / 2
		previewRows := bodyRows - listRows
		if bodyRows == 1 {
			listRows, previewRows = 1, 0
		}
		listStart := listWindowStart(state.selected, listRows, len(filtered))
		for i := 0; i < listRows; i++ {
			lines = append(lines, listLine(filtered, state.selected, listStart+i, width))
		}
		if hasSelected {
			fields := FormatConnection(selectedConn)
			for i := 0; i < previewRows; i++ {
				if idx := state.detailOffset + i; idx < len(fields) {
					lines = append(lines, fieldLine(fields[idx], width))
				}
			}
		}
	}

	if height >= 3 {
		lines = append(lines, yellow+clamp(focusHint(state.focus), width)+reset)
	}

	var b strings.Builder
	b.WriteString("\x1b[2J\x1b[H")
	b.WriteString(strings.Join(lines, "\r\n"))
	_, err := w.Write([]byte(b.String()))
	return err
}

// listWindowStart returns the first visible list row so the selected row
// stays on screen: the window scrolls down once the selection moves past
// the last visible row, and clamps at the end of the filtered list.
func listWindowStart(sel, rows, total int) int {
	if total <= rows {
		return 0
	}
	start := sel - rows + 1
	if start < 0 {
		start = 0
	}
	if start+rows > total {
		start = total - rows
	}
	return start
}

// focusHint names the pane that currently owns Up/Down navigation and the
// key that toggles it, so the Tab control is visible in the picker UI
// itself rather than only in the README.
func focusHint(f Focus) string {
	if f == FocusDetail {
		return "detail focused — Tab switches to list"
	}
	return "list focused — Tab switches to detail"
}

// padVisible appends spaces so the line occupies exactly width visible
// columns, counting only non-ANSI runes. It keeps the wide layout's │
// separator anchored at the reserved column no matter how short a list
// row is.
func padVisible(line string, width int) string {
	if fill := width - visibleWidth(line); fill > 0 {
		return line + strings.Repeat(" ", fill)
	}
	return line
}

// visibleWidth counts the visible runes in a line, ignoring ANSI escape
// sequences.
func visibleWidth(line string) int {
	n := 0
	for i := 0; i < len(line); {
		if line[i] == 0x1b {
			i++
			for i < len(line) && line[i] != 'm' {
				i++
			}
			i++
			continue
		}
		_, size := utf8.DecodeRuneInString(line[i:])
		n++
		i += size
	}
	return n
}

// listLine renders one connection row, highlighting the selected row.
// rowIdx is the index into filtered; the row is only rendered when it
// falls inside the visible window.
func listLine(filtered []model.SSHConnection, selIdx, rowIdx, width int) string {
	if rowIdx < 0 || rowIdx >= len(filtered) {
		return ""
	}
	name := sanitize(filtered[rowIdx].Name)
	if rowIdx == selIdx {
		return selected + "> " + clamp(name, width-2) + reset
	}
	return "  " + clamp(name, width-2)
}

// fieldLine renders "Label: Value" with the label in blue, clamped to max
// runes so the value always has room.
func fieldLine(f Field, max int) string {
	if max < 1 {
		return ""
	}
	label := sanitize(f.Label)
	value := sanitize(f.Value)
	labelMax := max / 2
	if labelMax < 1 {
		labelMax = 1
	}
	label = clamp(label, labelMax)
	valueMax := max - utf8.RuneCountInString(label) - 2
	if valueMax < 1 {
		valueMax = 1
	}
	return blue + label + reset + ": " + clamp(value, valueMax)
}

// sanitize converts terminal control characters into visible escaped text
// so untrusted profile fields cannot inject escape sequences into the
// picker output.
func sanitize(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '\x1b':
			b.WriteString(`\x1b`)
		case '\r':
			b.WriteString(`\r`)
		case '\n':
			b.WriteString(`\n`)
		case '\t':
			b.WriteString(`\t`)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// clamp truncates s to at most max runes.
func clamp(s string, max int) string {
	if max < 1 {
		return ""
	}
	if utf8.RuneCountInString(s) <= max {
		return s
	}
	return string([]rune(s)[:max])
}

// keyPairValue renders the connection's stored key-pair reference without
// disclosing any key material: the pair name when present, a visible
// missing-reference marker for a nonzero id without a name, and the
// [not configured] marker when no pair is selected.
func keyPairValue(c model.SSHConnection) string {
	if c.KeyPairName != "" {
		return c.KeyPairName
	}
	if c.KeyPairID != 0 {
		return "Missing key pair #" + strconv.FormatInt(c.KeyPairID, 10)
	}
	return "[not configured]"
}

func configured(has bool) string {
	if has {
		return "[configured]"
	}
	return "[not configured]"
}

// groupValue renders the connection's group for the detail pane: the group
// name when joined, the ungrouped marker for group_id 0, and a visible
// missing-reference marker when an externally corrupted row carries a
// nonzero id without a name.
func groupValue(c model.SSHConnection) string {
	if c.GroupName != "" {
		return c.GroupName
	}
	if c.GroupID == 0 {
		return "(not set)"
	}
	return "Missing group #" + strconv.FormatInt(c.GroupID, 10)
}

func orNotSet(s string) string {
	if s == "" {
		return "(not set)"
	}
	return s
}

func orNotSetInt(n int) string {
	if n == 0 {
		return "(not set)"
	}
	return strconv.Itoa(n)
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return "(not set)"
	}
	return t.Format(time.RFC3339)
}
