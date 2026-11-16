# CLI guide

The client talks to the configured Warden server. The existing per-user agent makes authenticated HTTPS API requests on behalf of
the CLI over pinned private IPC. Transport work still runs locally after the CLI
obtains the resolved remote bundle; the API credential never enters the CLI process.

## Commands

```text
warden [-n|--non-interactive|-i|--interactive] login
warden logout
warden status
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
cache. Graph eviction never exits the daemon: it remains alive until external
termination, including when the pool is empty. Local-agent connections use pinned
TLS1.3 before request/token bytes; see the [IPC runtime runbook](agent-ipc.md) for
private discovery, old-agent handling and the pending native Windows checks.
T4 adds web-approved API credentials through this same daemon; native Windows
execution and genuine-authenticator PRF acceptance remain pending.

## Login, logout and status

Configure an **HTTPS origin** (not a management path), then run `warden login`.
The agent creates a random API secret and submits only its SHA-256 commitment.
Open the displayed configured-origin URL, log in with a passkey, compare the
complete request/device fingerprint with the CLI and approve that exact pending
request using a **fresh** passkey assertion. The server supplies a distinct
polling secret directly to the agent over HTTPS; neither secret is shown in the
browser, terminal, argv, environment, URLs or IPC discovery files.

Interactive login waits at most five minutes. `warden -n login`, redirected login,
and first-use data commands print actionable approval steps and fail promptly
while approval is pending; approve in the browser, then run login/the command
again. Concurrent CLI processes share the same origin's agent-owned enrollment,
not separate CLI-owned secrets. Two devices have independent commitments.

`warden status` checks the current authorization without unlocking the vault.
An unavailable server is reported as unavailable, without discarding the approved
credential or stopping the daemon. `warden logout` attempts server revocation,
then clears local authorization **even offline**; it does not terminate the
agent or globally lock the vault. Offline logout cannot guarantee server
revocation: use the web device list to revoke any remaining verifier.

The browser's **CLI devices** section lists pending requests and active/revoked
credentials and supports fresh-passkey approval, denial and revocation, even
while the vault is locked. Refresh it to observe newly pending devices. Recovery
replacement invalidates all client verifiers through the durable authorization
generation. Revocation affects future API retrieval, not remote credentials
already returned or established SSH/DB sessions.

API and polling secrets exist only in agent memory. Server verifier/revocation
state survives restart, but the vault starts locked and requires manual web
unlock. Agent exit/restart loses its copy and requires new approval; it does not
revoke an exfiltrated copy. There is intentionally no client-token expiry,
automatic rotation or refresh credential. A stolen token remains usable until
server revocation or recovery invalidation. Private disk discovery holds only
the separate local IPC token and public certificate (plus format version).

The client audience permits existing SSH/DB list/get/dependents/archive/transport,
project list/create and report list/create only. It cannot unlock or approve,
read key vaults directly, export/import, or administer authentication. All APIs
refuse redirects before another request can carry a bearer/body. System roots
are used by default; optional `ca_certificate` supplies a public private-CA PEM
path. There is no insecure-certificate option or persisted API credential.

In non-interactive database mode, query results are written as TSV with a
header row. Values are written one record per line without table borders or
padding; statements without a result set produce no output. In interactive
mode, results retain the fixed-width CLI table and `Query OK` status.
Column headers and cells replace control characters (including ESC, C0/C1,
DEL, tabs and newlines) with spaces in **both** tables and TSV. Printable Unicode
is retained; TSV's separator tabs and record newlines are unchanged. This is not
a lossless database export.

### Diagnostic text

CLI diagnostics visibly escape terminal controls and nonprintables, including
ESC/OSC initiators, C0/C1, DEL, CR/LF and invalid UTF-8. For example ESC becomes
`\x1b`, CR/LF become `\r`/`\n`, C1 CSI becomes `\u009b`, and invalid bytes become
`\ufffd`. Printable Unicode is preserved. Diagnostic text is truncated without a
suffix to **1,024 encoded UTF-8 bytes**, counting escape expansion but excluding
the CLI's fixed command prefix and final newline. Truncation never splits a
Unicode rune or a generated escape token. API error formatting includes its
`api: ...` prefix within that limit; parsed message fields retain their existing
1,024-byte limit, now without splitting UTF-8. Error codes/status and typed exit
classification remain available; formatting does not rewrite structured fields.

This applies in interactive and non-interactive modes. It is terminal-control
protection, **not secret redaction**. Interactive/exec SSH stdout and stderr,
stdin, and binary/file transfers remain byte-for-byte streams and are **not
filtered**. No JSON/CSV output format or whole-stream sanitizer was introduced.

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
forwards bind only to `127.0.0.1` and are printed as URLs, such as
`http://127.0.0.1:3000/`; if a local port is already occupied, that forward is
skipped and retried on the next poll. The foreground watcher exits
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

Archived SSH and database profiles remain available for management, but are omitted from `warden config search` and the interactive `warden xssh` picker. Attempts to connect to an archived profile (including an explicitly named `xssh` profile or an archived jump/tunnel host) are rejected by the server as `404 connection not found`.
