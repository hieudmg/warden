# CLI guide

The client talks to the configured Warden server. Transport work runs locally
after the client fetches a resolved bundle from the server.

## Commands

```text
warden [-n|--non-interactive|-i|--interactive] ssh <connection> <command>
warden [-n|--non-interactive|-i|--interactive] db <connection> <sql>
warden [-n|--non-interactive|-i|--interactive] db <connection>/<database> <sql>
warden [-n|--non-interactive|-i|--interactive] config search <query>
warden report create <project> --title <title> --summary <summary> --agent-model <model>
warden [-n|--non-interactive|-i|--interactive] xssh [--accept-new] [connection]
warden [-n|--non-interactive|-i|--interactive] cp <source> <destination>
```

Output mode is detected automatically from stdout: terminal output uses the
interactive presentation, while redirected or piped output uses the
non-interactive presentation. Use `-n`/`--non-interactive` or
`-i`/`--interactive` to override detection. The two modes cannot be combined.

Exit status mirrors the remote command or query. SSH-backed operations reuse a
local connection agent; cached connections close ten minutes after their last
operation. Interactive `xssh` and direct database connections bypass the
cache.

In non-interactive database mode, query results are written as TSV with a
header row. Values are written one record per line without table borders or
padding; statements without a result set produce no output. In interactive
mode, results retain the fixed-width CLI table and `Query OK` status.

## Configuration search

`warden config search` searches redacted SSH and database profiles by words in
name and host. Database profiles also search configured database names.
Matching tolerates bounded typos, retains partial matches, and ranks SSH and
DB sections independently.

## Database targets

Use `<connection>` for its default database. Use
`<connection>/<database>` to select a configured database explicitly. The
search output shows usable targets and host/database metadata without secrets.

## Interactive SSH picker

When no connection is provided, `xssh` opens a native picker. Connections are
grouped and sorted by group name, then connection name. Type to filter profile
names, hostnames, and group names. Group headers are not selectable.

- Up/Down moves between connections.
- Tab switches between connection list and profile preview.
- Enter connects.
- Esc or Ctrl-C cancels.

The preview never shows passwords, private keys, passphrases, or proxy
passwords; it shows whether each is configured. Terminals under 80 columns use
a stacked layout.

## File copy

`cp` recursively transfers files/directories and overwrites destinations by
default. A source beneath an existing destination directory is placed using
its basename. Host-to-host copies relay bytes through the local client; the
hosts do not connect directly. Local-to-local copies are rejected.

## Reports

Reports are immutable records with project, title, summary, agent model, and
server timestamp. Summaries are stored as Markdown and rendered by the web UI.
