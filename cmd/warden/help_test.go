package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

// TestHelpConsoleProcess runs only as an isolated subprocess, with either a real
// PTY or a pipe attached to stdout. No configuration or environment lookup is allowed.
func TestHelpConsoleProcess(t *testing.T) {
	raw, ok := os.LookupEnv("WARDEN_HELP_TEST_ARGS")
	if !ok {
		return
	}
	var args []string
	if err := json.Unmarshal([]byte(raw), &args); err != nil {
		t.Fatal(err)
	}
	wantTTY := os.Getenv("WARDEN_HELP_TEST_TTY") == "true"
	if writerIsTerminal(os.Stdout) != wantTTY {
		t.Fatal("unexpected output terminal detection")
	}
	var stderr bytes.Buffer
	code := run(args, os.Stdout, &stderr, func(string) (string, bool) {
		t.Error("help accessed configuration/environment")
		return "invalid", true
	})
	if code != 0 || stderr.Len() != 0 {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
}

func TestHelpAudiencesUseOutputConsole(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("real PTY coverage uses Linux util-linux script; portable offline help tests still run")
	}
	script, err := exec.LookPath("script")
	if err != nil {
		t.Skip("real PTY coverage requires the local script utility")
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	sharedContracts := map[string][]string{
		"":              {"Commands:", "config search", "http METHOD", "ssh <connection>", "db <connection>", "xssh [connection]", "cp <source>", "report create", "port-watch", "upgrade", "permissions or SSH host-key verification", "does not make xssh headless", "not a remote command or SQL execution deadline", "Exit status:"},
		"ssh":           {"one quoted argument", "stdout and stderr stream", "remote command's exit status", "host-key verification"},
		"db":            {"tab-separated", "column header", "not JSON", "not a", "lossless data export", "SQL can modify data", "does not make a query read-only"},
		"xssh":          {"terminal is required even with -n", "host keys prompt", "headless command runner"},
		"http":          {"network interception", "HTTPS certificates are verified", "Redirects are not followed", "1 MiB", "2 MiB", "15s", "unchanged to stdout", "non-2xx", "exit status 1", "Usage errors return 2"},
		"config":        {"masked hosts/origins", "not credentials", "Archived profiles are excluded", "not JSON", "No matching connections.", "db.*"},
		"config search": {"masked hosts/origins", "not credentials", "Archived profiles are excluded", "not JSON", "No matching connections.", "db.*"},
		"cp":            {"SFTP", "local-to-local", "same host", "may be overwritten"},
		"report":        {"project before the flags", "not the report body", "--agent-model"},
		"report create": {"project before the flags", "not the report body", "--agent-model"},
		"port-watch":    {"Linux", "ss utility", "Up/Down", "Left/Right", "Ctrl-C", "not a one-shot command"},
		"upgrade":       {"verifies it", "replaces this executable", "left untouched"},
	}
	topics := [][]string{nil, {"ssh"}, {"db"}, {"xssh"}, {"http"}, {"config"}, {"config", "search"}, {"cp"}, {"report"}, {"report", "create"}, {"port-watch"}, {"upgrade"}}
	for _, tty := range []bool{false, true} {
		for _, topic := range topics {
			for _, mode := range []string{"", "-n", "-i", "--non-interactive", "--interactive"} {
				aliases := []string{"-h", "--help"}
				if len(topic) == 0 {
					aliases = append(aliases, "", "help")
				}
				for _, alias := range aliases {
					args := []string{"--config", "/nonexistent/help-only.json"}
					if len(topic) == 0 && mode == "" {
						args = nil // Exercise root's direct no-args/help-alias path too.
					}
					if mode != "" {
						args = append(args, mode)
					}
					args = append(args, topic...)
					if alias != "" {
						args = append(args, alias)
					}
					t.Run(strings.Join(args, " ")+"/tty="+fmt.Sprint(tty), func(t *testing.T) {
						command := exec.Command(executable, "-test.run=^TestHelpConsoleProcess$")
						if tty {
							quoted := "'" + strings.ReplaceAll(executable, "'", "'\\''") + "'"
							command = exec.Command(script, "-q", "-e", "-c", quoted+" -test.run=^TestHelpConsoleProcess$", "/dev/null")
						}
						raw, _ := json.Marshal(args)
						command.Env = append(os.Environ(), "SHELL=/bin/sh", "WARDEN_HELP_TEST_ARGS="+string(raw), "WARDEN_HELP_TEST_TTY="+fmt.Sprint(tty))
						out, err := command.CombinedOutput()
						if err != nil {
							t.Fatalf("console helper: %v\n%s", err, out)
						}
						text := strings.ReplaceAll(string(out), "\r\n", "\n")
						for _, contract := range sharedContracts[strings.Join(topic, " ")] {
							if !strings.Contains(text, contract) {
								t.Errorf("shared safety/usage contract missing %q:\n%s", contract, text)
							}
						}
						if !tty && len(topic) != 0 {
							for _, contract := range []string{"Exit status:", "not a JSON envelope", "Global flags precede", "quote arguments", "exact", "config search"} {
								if !strings.Contains(text, contract) {
									t.Errorf("agent guidance missing %q", contract)
								}
							}
						}
						want, unwanted := "For agents and scripts:", "For terminal users:"
						if tty {
							want, unwanted = unwanted, want
						}
						if !strings.Contains(text, want) || strings.Contains(text, unwanted) {
							t.Fatalf("wrong help audience:\n%s", text)
						}
						if len(topic) == 0 {
							for _, setup := range []string{"Configuration:", "Environment overrides:", "WARDEN_CLIENT_TIMEOUT", "WARDEN_CLIENT_CONFIG"} {
								if strings.Contains(text, setup) != tty {
									t.Errorf("setup detail %q visibility should match tty=%v", setup, tty)
								}
							}
						}
					})
				}
			}
		}
	}
}

// Help must be usable offline, even when the configured API or config is invalid.
func TestClientHelpGuidesConsumers(t *testing.T) {
	tests := []struct {
		command []string
		want    []string
	}{
		{nil, []string{"Commands:", "Global flags (before the command):", "For agents and scripts:", `warden -n config search "production"`, "do not guess", "Exit status:", "warden <command> --help"}},
		{[]string{"ssh"}, []string{"Run one remote command", "exact configured SSH connection name", `warden -n ssh prod "uname -a"`, "one quoted argument", "remote command's exit status"}},
		{[]string{"db"}, []string{"MySQL/MariaDB", "<connection>/<database>", "default database", "multiple databases", `warden -n db prod/app "SELECT 1"`, "tab-separated", "column header", "not JSON", "NULL", "control characters", "no output"}},
		{[]string{"xssh"}, []string{"interactive SSH shell", "terminal", "picker", "Use ssh", "warden xssh prod"}},
		{[]string{"config"}, []string{"Discover", "config search", `warden -n config search "production"`}},
		{[]string{"config", "search"}, []string{"Discover", "names, hosts, and database names", "not credentials", "not JSON", "No matching connections.", `warden -n config search "production"`}},
		{[]string{"cp"}, []string{"SFTP", "<connection>:<path>", "recursively", "local-to-local", "same host", "warden cp ./release.tar prod:/srv/releases/", "warden cp prod:/var/log/app.log ./app.log"}},
		{[]string{"report"}, []string{"Create a report", "--title", "--summary", "--agent-model", `warden report create my-project --title "Check complete"`}},
		{[]string{"report", "create"}, []string{"Create a report", "required", "project before", `warden report create my-project --title "Check complete"`, "confirmation"}},
		{[]string{"port-watch"}, []string{"Linux", "ss utility", "comma-separated", "Ctrl-C", "warden port-watch prod 3000,5000-5010"}},
		{[]string{"upgrade"}, []string{"replaces this executable", "WARDEN_REPO", "WARDEN_RELEASE_BASE_URL", "warden upgrade"}},
	}
	for _, tc := range tests {
		for _, flag := range []string{"-h", "--help"} {
			args := append(append([]string(nil), tc.command...), flag)
			t.Run(strings.Join(args, " "), func(t *testing.T) {
				var stdout, stderr bytes.Buffer
				code := run(args, &stdout, &stderr, func(string) (string, bool) {
					t.Error("help must not load configuration")
					return "invalid", true
				})
				if code != 0 || stderr.Len() != 0 {
					t.Fatalf("help returned %d, stderr=%q", code, stderr.String())
				}
				for _, want := range tc.want {
					if !strings.Contains(stdout.String(), want) {
						t.Errorf("help missing %q; output:\n%s", want, stdout.String())
					}
				}
			})
		}
	}
}
