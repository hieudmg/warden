package main

import (
	"bytes"
	"strings"
	"testing"
)

// Help must be usable offline, even when the configured API or config is invalid.
func TestClientHelpGuidesConsumers(t *testing.T) {
	tests := []struct {
		command []string
		want    []string
	}{
		{nil, []string{"Commands:", "Global flags (before the command):", "For agents and scripts:", `warden -n config search "production"`, "do not guess", "Exit status:", "WARDEN_CLIENT_TIMEOUT", "30s", "warden <command> --help"}},
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
