package db

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestDBHeadersSanitizedInTableAndTSV(t *testing.T) {
	// These names are sent in the producer's actual ColumnDefinition41 `name`
	// field, then decoded by go-sql-driver/mysql and database/sql.Rows.Columns.
	const hostile = "名\x1b]52;c;payload\a\x00\b\t\r\n\x7f\u0085\u009b"
	const safe = "名 ]52;c;payload         "
	for _, tsv := range []bool{false, true} {
		name := "table"
		if tsv {
			name = "tsv"
		}
		t.Run(name, func(t *testing.T) {
			srv := newFakeMySQLServer(t, []string{hostile, "héllo世界"}, [][]string{{"ok", "値"}})
			var out bytes.Buffer
			err := RunQueryWithOptions(context.Background(), directBundle(srv.addr, "user", "pass"), "SELECT synthetic", &out, QueryOptions{NonInteractive: tsv})
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(out.String(), safe) || !strings.Contains(out.String(), "héllo世界") || strings.ContainsAny(out.String(), "\x1b\a\x00\b\r\x7f\u0085\u009b") {
				t.Fatalf("unsafe headers: %q", out.String())
			}
			if tsv && out.String() != safe+"\théllo世界\nok\t値\n" {
				t.Fatalf("TSV structure changed: %q", out.String())
			}
			if !tsv && (strings.Count(out.String(), "\n") != 5 || strings.Contains(out.String(), "\t")) {
				t.Fatalf("table structure changed: %q", out.String())
			}
		})
	}
}
