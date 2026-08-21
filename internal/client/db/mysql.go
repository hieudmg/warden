package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"

	"github.com/go-sql-driver/mysql"

	"warden/internal/model"
)

// maxSQLBytes bounds a single SQL statement sent to the database.
const maxSQLBytes = 1 << 20 // 1 MiB

// RunQuery connects to the bundle's database locally and executes one SQL
// statement, streaming the result to out in a stable tabular format.
// Profiles with an SSH graph are tunneled through it. The password never
// appears in returned errors or output.
func RunQuery(ctx context.Context, bundle model.DBBundle, sqlText string, out io.Writer) error {
	if strings.TrimSpace(sqlText) == "" {
		return errors.New("empty SQL query")
	}
	if len(sqlText) > maxSQLBytes {
		return fmt.Errorf("SQL query exceeds %d bytes", maxSQLBytes)
	}

	cfg := mysql.Config{
		User:                 bundle.Username,
		Passwd:               string(bundle.Password),
		Net:                  "tcp",
		Addr:                 net.JoinHostPort(bundle.Host, strconv.Itoa(bundle.Port)),
		DBName:               bundle.Database,
		MaxAllowedPacket:     1 << 20,
		AllowNativePasswords: true,
	}

	if bundle.SSH != nil {
		d, err := NewTunnelDialer(ctx, *bundle.SSH, cfg.Addr)
		if err != nil {
			return sanitize(err, bundle)
		}
		defer d.Close()
		cfg.DialFunc = d.DialContext
	}

	connector, err := mysql.NewConnector(&cfg)
	if err != nil {
		return sanitize(err, bundle)
	}
	db := sql.OpenDB(connector)
	defer db.Close()

	rows, err := db.QueryContext(ctx, sqlText)
	if err != nil {
		return sanitize(err, bundle)
	}
	defer rows.Close()

	cols, err := rows.Columns()
	if err != nil {
		return sanitize(err, bundle)
	}
	if len(cols) == 0 {
		// The server answered with an OK packet: the statement produced
		// no result set (e.g. INSERT/UPDATE).
		fmt.Fprintln(out, "Query OK")
		return nil
	}

	var values [][]string
	for rows.Next() {
		raw := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range raw {
			ptrs[i] = &raw[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return sanitize(err, bundle)
		}
		values = append(values, formatRow(raw))
	}
	if err := rows.Err(); err != nil {
		return sanitize(err, bundle)
	}
	return writeTable(out, cols, values)
}

// sanitize removes the bundle's password from an error message. Errors
// that contain no password are returned unchanged so error wrapping and
// errors.Is keep working.
func sanitize(err error, bundle model.DBBundle) error {
	if err == nil {
		return nil
	}
	secret := string(bundle.Password)
	if secret == "" {
		return err
	}
	msg := strings.ReplaceAll(err.Error(), secret, "***")
	if msg == err.Error() {
		return err
	}
	return fmt.Errorf("%s", msg)
}

// formatRow converts scanned database values to printable strings. nil
// becomes NULL; byte slices (MySQL text columns) become strings.
func formatRow(raw []any) []string {
	row := make([]string, len(raw))
	for i, v := range raw {
		switch t := v.(type) {
		case nil:
			row[i] = "NULL"
		case []byte:
			row[i] = sanitizeCell(string(t))
		default:
			row[i] = sanitizeCell(fmt.Sprint(t))
		}
	}
	return row
}

// sanitizeCell replaces control characters that would break tabular output.
func sanitizeCell(s string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case '\n', '\r', '\t':
			return ' '
		}
		return r
	}, s)
}

// writeTable renders columns and rows as a fixed ASCII table.
func writeTable(out io.Writer, cols []string, rows [][]string) error {
	widths := make([]int, len(cols))
	for i, c := range cols {
		widths[i] = len(c)
	}
	for _, r := range rows {
		for i := range cols {
			if len(r[i]) > widths[i] {
				widths[i] = len(r[i])
			}
		}
	}

	var b strings.Builder
	b.WriteString(border(widths) + "\n")
	writeTableRow(&b, widths, cols)
	b.WriteString(border(widths) + "\n")
	for _, r := range rows {
		writeTableRow(&b, widths, r)
	}
	b.WriteString(border(widths) + "\n")
	_, err := io.WriteString(out, b.String())
	return err
}

func border(widths []int) string {
	var b strings.Builder
	for _, w := range widths {
		b.WriteByte('+')
		b.WriteString(strings.Repeat("-", w+2))
	}
	b.WriteByte('+')
	return b.String()
}

func writeTableRow(b *strings.Builder, widths []int, cells []string) {
	for i, w := range widths {
		b.WriteString("| ")
		b.WriteString(cells[i])
		if pad := w - len(cells[i]); pad > 0 {
			b.WriteString(strings.Repeat(" ", pad))
		}
		b.WriteByte(' ')
	}
	b.WriteByte('|')
	b.WriteByte('\n')
}
