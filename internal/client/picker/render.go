package picker

import (
	"strconv"
	"strings"
	"time"

	"charm.land/bubbles/v2/viewport"
	"github.com/charmbracelet/x/ansi"

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
		{Label: "Note", Value: orNotSet(c.Note)},
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

// pickerContent keeps the grouped list and selected connection preview in
// independent Bubbles viewports. Group headings aren't selectable. On a
// narrow terminal the preview stacks below the list.
func pickerContent(state State, width, height int) string {
	if width < 1 || height < 1 {
		return ""
	}

	columns := width - 1 // Leave the wrapping column unused.
	lines := []string{cyan + clamp("warden xssh — pick a connection", columns) + reset}
	if height >= 2 {
		lines = append(lines, yellow+clamp("Search: "+sanitize(state.query), columns)+reset)
	}
	if height < 3 {
		return strings.Join(lines, "\n")
	}
	body := height - 3
	if body > 0 {
		filtered := state.Filtered()
		rows := buildListRows(filtered)
		if width >= 80 {
			leftWidth := width * 45 / 100
			rightWidth := columns - leftWidth - 1
			list := pickerList(filtered, rows, state.selected, leftWidth, body)
			detail := pickerDetail(state, rightWidth, body)
			for i, row := range list {
				lines = append(lines, padVisible(row, leftWidth)+cyan+"│"+reset+detail[i])
			}
		} else {
			listHeight := body / 2
			if body == 1 {
				listHeight = 1
			}
			if len(rows) > len(filtered) && listHeight < body {
				listHeight++
			}
			lines = append(lines, pickerList(filtered, rows, state.selected, columns, listHeight)...)
			lines = append(lines, pickerDetail(state, columns, body-listHeight)...)
		}
	}
	lines = append(lines, yellow+clamp(focusHint(state.focus), columns)+reset)
	return strings.Join(lines, "\n")
}

func pickerList(filtered []model.SSHConnection, rows []listRow, selected, width, height int) []string {
	if height == 0 {
		return nil
	}
	lines := make([]string, len(rows))
	selectedRow := 0
	for i, row := range rows {
		if row.header {
			lines[i] = clamp("  "+sanitize(row.group), width)
		} else {
			lines[i] = listLine(filtered, selected, row.connection, width)
			if row.connection == selected {
				selectedRow = i
			}
		}
	}
	return pickerPane(lines, width, height, max(0, selectedRow-height+1))
}

func pickerDetail(state State, width, height int) []string {
	if height == 0 {
		return nil
	}
	var lines []string
	if c, ok := state.Selected(); ok {
		fields := FormatConnection(c)
		// Allow even the final field to be the first row in the pane.
		lines = make([]string, len(fields)+height-1)
		for i, f := range fields {
			lines[i] = fieldLine(f, width)
		}
	}
	return pickerPane(lines, width, height, state.detailOffset)
}

func pickerPane(lines []string, width, height, offset int) []string {
	if width == 0 {
		return make([]string, height)
	}
	pane := viewport.New(viewport.WithWidth(width), viewport.WithHeight(height))
	pane.SetContentLines(lines)
	pane.SetYOffset(offset)
	rows := strings.Split(pane.View(), "\n")
	for i, row := range rows {
		// Bubbles pads by grapheme width; Tea uses wcwidth without input
		// negotiation. Frame by the renderer's cell widths instead.
		rows[i] = strings.TrimRight(row, " ")
	}
	return rows
}

type listRow struct {
	group      string
	connection int
	header     bool
}

func buildListRows(filtered []model.SSHConnection) []listRow {
	rows := make([]listRow, 0, len(filtered)+1)
	previousGroup := ""
	for i, c := range filtered {
		group := c.GroupName
		if i == 0 || group != previousGroup {
			label := group
			if label == "" {
				label = "(Ungrouped)"
			}
			rows = append(rows, listRow{group: label, header: true})
			previousGroup = group
		}
		rows = append(rows, listRow{connection: i})
	}
	return rows
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

func padVisible(line string, width int) string {
	return line + strings.Repeat(" ", max(0, width-ansi.StringWidthWc(line)))
}

func listLine(filtered []model.SSHConnection, selectedIndex, rowIndex, width int) string {
	name := sanitize(filtered[rowIndex].Name)
	if rowIndex == selectedIndex {
		return selected + clamp(">   "+name, width) + reset
	}
	return clamp("    "+name, width)
}

// fieldLine reserves room for the value when the label is wide.
func fieldLine(f Field, width int) string {
	label := clamp(sanitize(f.Label), max(1, width/2))
	return clamp(blue+label+reset+": "+sanitize(f.Value), width)
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

func clamp(s string, width int) string {
	if width < 1 {
		return ""
	}
	return ansi.TruncateWc(s, width, "")
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
