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
warden [-n|--non-interactive|-i|--interactive] xssh [connection]
warden [-n|--non-interactive|-i|--interactive] cp <source> <destination>
warden [--config path] port-watch <ssh-connection> <port-range-list>
warden upgrade
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
DB sections independently. Interactive output uses a tree; non-interactive
output keeps the `SSH` and `DB` sections and renders each result as a bullet
list.

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

## SSH host keys

On the first interactive `xssh` connection to an unknown host, Warden displays
an OpenSSH-style host authenticity prompt with the key fingerprint. Enter `yes`
or the displayed fingerprint to add the key to `known_hosts`; any other answer
refuses it. Changed keys are always rejected. Non-interactive SSH-backed
commands remain strict and do not prompt; use interactive `xssh` to verify and
trust a new host first.

## Port watch

`warden port-watch` watches TCP listeners on a saved SSH connection and
forwards matching ports to the same port on `127.0.0.1`:

```text
warden port-watch prod 3000,5000-6000,9999-12222
```

The comma-separated port/range list is required; ranges are inclusive and ports
must be between 1 and 65535. The target is assumed to be Linux and must provide
the `ss` utility for listener discovery; if `ss` is unavailable or fails, the
watcher exits with an error. Warden polls it every two seconds, creates forwards
when a matching listener appears, and closes forwards when it disappears. Local
forwards bind only to `127.0.0.1`; if a local port is already occupied, that
forward is skipped and retried on the next poll. The foreground watcher exits
on Ctrl-C and closes all of its forwards.

## File copy

`cp` recursively transfers files/directories and overwrites destinations by
default. A source beneath an existing destination directory is placed using
its basename. Host-to-host copies relay bytes through the local client; the
hosts do not connect directly. Local-to-local copies are rejected.

## Reports

Reports are immutable records with project, title, summary, agent model, and
server timestamp. Summaries are stored as Markdown and rendered by the web UI.

## Upgrade

`warden upgrade` replaces the client executable with the latest released
client binary:

```bash
warden upgrade
```

The command downloads the published asset for the current platform, verifies
its SHA-256 digest against the release `SHA256SUMS` file, and replaces only the
executable. It accepts no arguments, prompts for nothing, and never reads or
writes `client.json` or cached transport credentials. Only the targets
published in the latest release are supported; any other OS/architecture fails
before the installed executable is touched.

On Windows a running executable cannot be replaced in place, so the command
reports that replacement is scheduled and the verified download is applied
after the process exits. On Linux the executable is replaced atomically before
the command returns.

Set `WARDEN_REPO` or `WARDEN_RELEASE_BASE_URL` to upgrade from a release source
other than the default `hieudmg/warden` GitHub releases. The server has its own
`warden-server upgrade` command; see [Deployment](deployment.md).
