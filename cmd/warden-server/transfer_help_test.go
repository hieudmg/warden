package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestServerHelpDocumentsOldExportFreshImportAndRollback(t *testing.T) {
	for _, args := range [][]string{{"--help"}, {"init", "--help"}, {"serve", "--help"}} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			var out, errOut bytes.Buffer
			if code := run(args, &out, &errOut, emptyLookupEnv); code != 0 {
				t.Fatal(code, errOut.String())
			}
			for _, want := range []string{"old release", "warden-data version 1", "fresh storage", "authenticate and unlock", "import", "verify", "rollback", "DB/WAL/SHM", "plaintext", "docs/migration.md"} {
				if !strings.Contains(out.String(), want) {
					t.Errorf("help missing %q", want)
				}
			}
			if strings.Contains(out.String(), "serve remains disabled") {
				t.Error("stale initialization-only checkpoint guidance")
			}
		})
	}
}
