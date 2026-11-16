package upgrade

import (
	"os"
	"strings"
	"testing"
)

func TestInstallerDownloaderSourceLineEndings(t *testing.T) {
	script, err := os.ReadFile("../../scripts/install-client.ps1")
	if err != nil {
		t.Fatal(err)
	}
	lf := strings.ReplaceAll(string(script), "\r\n", "\n")
	// Independently select the complete C# lines from the real script. The
	// expectation includes every line, not just a class-name substring.
	lines := strings.Split(lf, "\n")
	first, last := -1, -1
	for i, line := range lines {
		if line == "using System;" {
			first = i
		}
		if line == "'@" {
			last = i
			break
		}
	}
	if first < 0 || last <= first || lines[last-1] != "}" {
		t.Fatal("actual installer C# lines not found")
	}
	want := strings.Join(lines[first:last], "\n")
	for name, fixture := range map[string]string{
		"LF": lf, "CRLF": strings.ReplaceAll(lf, "\n", "\r\n"),
	} {
		t.Run(name, func(t *testing.T) {
			got, err := installerDownloaderSource([]byte(fixture))
			if err != nil {
				t.Fatal(err)
			}
			if got != want {
				t.Fatal("extraction changed actual C# bytes or included installer entry-point")
			}
		})
	}
}

func TestInstallerDownloaderSourceBoundaries(t *testing.T) {
	for name, script := range map[string]string{
		"missing start": "using System;\n'@\n",
		"wrong start":   "-OtherDefinition @'\nusing System;\n'@\n",
		"missing end":   "-TypeDefinition @'\nusing System;\n",
		"wrong end":     "-TypeDefinition @'\nusing System;\n'@wrong\n",
		"empty":         "-TypeDefinition @'\n\n'@\n",
	} {
		t.Run(name, func(t *testing.T) {
			if source, err := installerDownloaderSource([]byte(script)); err == nil || source != "" {
				t.Fatalf("invalid boundaries accepted: source=%q err=%v", source, err)
			}
		})
	}
}
