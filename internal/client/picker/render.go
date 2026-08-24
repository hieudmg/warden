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
		{Label: "Host", Value: orNotSet(c.Host)},
		{Label: "Port", Value: orNotSetInt(c.Port)},
		{Label: "Username", Value: orNotSet(c.Username)},
		{Label: "Password", Value: configured(c.HasPassword)},
		{Label: "Private key", Value: configured(c.HasPrivateKey)},
		{Label: "Private-key passphrase", Value: configured(c.HasPrivateKeyPassphrase)},
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
// column; below that the fields stack beneath the list. Every line is
// clamped to its pane width and model values pass through sanitize so a
// profile cannot inject terminal control sequences.
func Render(w io.Writer, state State, width, height int) {
	if width < 1 || height < 1 {
		return
	}
	var b strings.Builder
	b.WriteString("\x1b[2J\x1b[H")

	// Two fixed header rows (title, search prompt); the remaining rows
	// (bodyRows) are shared between the list and the preview so the
	// render never emits more rows than height and the query, list, and
	// preview all stay visible when the viewport has room.
	bodyRows := height - 2
	if bodyRows < 0 {
		bodyRows = 0
	}

	b.WriteString(cyan)
	b.WriteString(clamp("warden xssh — pick a connection", width))
	b.WriteString(reset)
	b.WriteString("\r\n")

	if height >= 2 {
		b.WriteString(yellow)
		b.WriteString(clamp("Search: "+sanitize(state.query), width))
		b.WriteString(reset)
		b.WriteString("\r\n")
	}

	filtered := state.Filtered()
	selectedConn, hasSelected := state.Selected()

	if width >= 80 {
		leftWidth := width * 45 / 100
		rightWidth := width - leftWidth - 1
		if rightWidth < 1 {
			rightWidth = 1
		}
		var fields []Field
		if hasSelected {
			fields = FormatConnection(selectedConn)
		}
		for i := 0; i < bodyRows; i++ {
			b.WriteString(listLine(filtered, state.selected, i, leftWidth))
			b.WriteString(cyan)
			b.WriteString("│")
			b.WriteString(reset)
			if i < len(fields) {
				b.WriteString(fieldLine(fields[i], rightWidth))
			}
			b.WriteString("\r\n")
		}
	} else {
		// Narrow layout: split the body rows between the list and the
		// preview (up to 16 fields) so the preview cannot push the render
		// past the viewport. A single body row goes to the list.
		listRows := bodyRows / 2
		previewRows := bodyRows - listRows
		if bodyRows == 1 {
			listRows, previewRows = 1, 0
		}
		for i := 0; i < listRows; i++ {
			b.WriteString(listLine(filtered, state.selected, i, width))
			b.WriteString("\r\n")
		}
		if hasSelected {
			fields := FormatConnection(selectedConn)
			for i := 0; i < previewRows && i < len(fields); i++ {
				b.WriteString(fieldLine(fields[i], width))
				b.WriteString("\r\n")
			}
		}
	}

	w.Write([]byte(b.String()))
}

// listLine renders one connection row, highlighting the selected row.
func listLine(filtered []model.SSHConnection, selIdx, i, width int) string {
	if i >= len(filtered) {
		return ""
	}
	name := sanitize(filtered[i].Name)
	if i == selIdx {
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

func configured(has bool) string {
	if has {
		return "[configured]"
	}
	return "[not configured]"
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
