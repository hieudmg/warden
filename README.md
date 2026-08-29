# Warden

Warden is a personal central hub for LLM agents: a management server plus a
cross-platform CLI that stores SSH/MySQL/MariaDB connection profiles
(credentials encrypted at rest), resolves them into transport bundles, and
executes connections locally on the client. It also stores immutable agent
change reports (project, title, summary, agent_model, server timestamp).

Deployment is tailnet-only: the server has **no application
authentication**, and tailnet membership is the full trust boundary. Every
peer that can reach the API can manage profiles, retrieve credentials, and
run client operations.

## Components

- `warden-server` — Linux x86-64 service. Owns SQLite (project storage) and
  the master key. Serves the JSON API and the embedded management UI from
  one listener. Never executes commands.
- `warden` — Linux x86-64 and Windows x86-64 client. HTTP API wrapper; for
  transport commands it fetches the resolved bundle and executes locally
  (SSH via `golang.org/x/crypto/ssh`, MySQL via the Go driver, no native
  `ssh`, `sshpass`, `mysql`, or `fzf` dependencies).

## Quick start (development)

```bash
# 1. Build the server (compiles the frontend first) and the client.
make build

# 2. Generate the master key (32 raw random bytes, mode 0600, your uid).
openssl rand -out /tmp/warden-master.key 32
chmod 0600 /tmp/warden-master.key

# 3. Start the server on loopback with temporary state.
WARDEN_SERVER_LISTEN_ADDR=127.0.0.1:8080 \
WARDEN_SERVER_DB_PATH=/tmp/warden-e2e/warden.db \
WARDEN_SERVER_MASTER_KEY_PATH=/tmp/warden-master.key \
  ./warden-server serve

# 4. Point the client at the server.
export WARDEN_CLIENT_API_BASE_URL=http://127.0.0.1:8080

# 5. Manage profiles via the API (curl) or the web UI at http://127.0.0.1:8080/,
#    then use the CLI, e.g.:
./warden ssh my-host "uname -a"
./warden report create my-project --title "deployed" --summary "v2 shipped" --agent-model gpt-5.4
```

## Master key

- 32 random bytes in a standalone file (default `/etc/warden/master.key`),
  mode `0600`, owned by the service user.
- Generate with `openssl rand -out master.key 32` followed by
  `chmod 0600 master.key`. Do **not** pipe `head -c 32 /dev/urandom |
  base64` — that produces ASCII, and the server rejects any key that is not
  exactly 32 raw bytes.
- The server refuses to start if the key is missing, wrong length, wrong
  owner, or has any permission other than `0600` (including special bits).
- The key is a separate secret from the database: it decrypts every stored
  credential. Back it up separately (see below); losing it makes the
  database unreadable.

## Configuration

Server and client config stay separate.

### Server config

Default file: `/etc/warden/server.json`

```json
{
  "listen_addr": "127.0.0.1:8080",
  "db_path": "/var/lib/warden/warden.db",
  "master_key_path": "/etc/warden/master.key",
  "static_fs": ""
}
```

Environment overrides:
- `WARDEN_SERVER_CONFIG`
- `WARDEN_SERVER_LISTEN_ADDR`
- `WARDEN_SERVER_DB_PATH`
- `WARDEN_SERVER_MASTER_KEY_PATH`
- `WARDEN_SERVER_STATIC_FS`

`static_fs` overrides the embedded management UI for development. It must
point directly at a built Vite distribution directory — one containing
`index.html` and the generated `assets/` files, exactly the layout the
embedded `internal/web/dist/` uses. Missing files silently 404.

### Client config

Default file:
- Linux/macOS: `$XDG_CONFIG_HOME/warden/client.json` when `XDG_CONFIG_HOME`
  exists, otherwise `$HOME/.config/warden/client.json`
- Windows: `%AppData%\warden\client.json`

```json
{
  "api_base_url": "http://127.0.0.1:8080",
  "timeout": "30s"
}
```

Environment overrides:
- `WARDEN_CLIENT_CONFIG`
- `WARDEN_CLIENT_API_BASE_URL`
- `WARDEN_CLIENT_TIMEOUT`

Client config contains only API settings. It never reads server DB paths or
master-key material.

## Deployment (systemd)

See [`deploy/systemd/README.md`](deploy/systemd/README.md) for the full
guide: service user, master-key generation, environment file, unit
installation, tailnet-only exposure, and backup/restore.

Key points:

- The unit runs `warden-server serve` as the dedicated `warden` user with
  `StateDirectory=warden`, `UMask=0077`, `NoNewPrivileges=yes`,
  `ProtectSystem=strict`, and `Restart=on-failure`.
- Runtime settings live in `/etc/warden/warden-server.env` (non-secret
  paths only; never credentials).
- Bind loopback (plus `tailscale serve`) or the tailnet IP directly; never
  a public interface.
- Logs contain only startup/shutdown/audit-write warnings — never
  credentials, SQL text, or command payloads.

## Backup

Back up **two separate things**:

1. **SQLite database** — checkpoint WAL first and copy, or use the online
   backup: `sudo -u warden sqlite3 /var/lib/warden/warden.db ".backup
   /var/backups/warden/warden.db"`. Never copy only the main `.db` file
   while WAL mode is active without a checkpoint.
2. **Master key** — store in a different location/backup than the database.
   Without it the database is unreadable.

Restore both with the original owner (`warden`) and permissions (`0600` key).

## SSH host-key verification

- The client verifies against the platform-standard known-hosts file:
  `~/.ssh/known_hosts` on Linux and `%USERPROFILE%\.ssh\known_hosts` on
  Windows.
- Known keys are accepted. **Changed keys always fail** (potential MITM).
- Unknown keys fail closed by default. `--accept-new` (interactive `xssh`
  only) shows the SHA-256 fingerprint and requires an explicit `yes` before
  persisting the key; it never prompts in noninteractive mode.
- Malformed lines in `known_hosts` are skipped OpenSSH-style; one bad line
  never blocks all connections (a warning is printed to stderr).

## CLI examples

```text
# Run a command over SSH (target + optional jump chain, resolved server-side).
warden ssh <connection> "<command>"

# Run one SQL statement against the default database of a MySQL/MariaDB
# profile, locally or through an SSH tunnel; tabular output; no SQL or
# credentials in logs.
warden db <connection> "<sql>"

# Select a named database from a profile that exposes multiple databases.
warden db <connection>/<database> "<sql>"

# Record an agent change report. Immutable, append-only.
warden report create <project> --title <title> --summary <summary> --agent-model <name>

# Search redacted SSH and database connection profiles by name or host.
warden config search "production"

# Interactive shell (PTY). Omit the name for the built-in picker.
# --accept-new enables interactive host-key confirmation.
warden xssh [--accept-new] [connection]

# Copy files or directories between local paths and SSH hosts, or between
# two hosts. Host-to-host copies relay bytes through this client.
warden cp ./release.tar prod:/srv/releases/
warden cp prod:/var/log/app ./app-logs
warden cp source:/srv/export destination:/srv/import
```

When invoked without `<connection>`, `xssh` opens a colorized native
terminal picker. Connections are grouped and sorted by group name, then
connection name; `(Ungrouped)` appears last. Type to filter profile names,
hostnames, and group names. Use Up/Down to move between connections; group
headers are not selectable. Tab switches focus between the connection list
and the profile preview (the bottom line shows which pane is focused), Enter
to connect, and Esc or Ctrl-C to cancel. Green progress messages show
credential fetching and interactive connection stages. The right pane shows
the selected profile; password, private-key, passphrase, and
proxy-password values are never shown and instead display whether they are
configured. Terminals
narrower than 80 columns use a stacked layout. Use a modern
ANSI/VT-capable terminal on Windows.

`cp` recursively transfers directories and overwrites existing files by
default. Files and directories are placed beneath an existing destination
directory using the source basename (a missing destination becomes the
copied root). At least one configured host is required: local-to-local
copies are rejected.
Host-to-host copies relay bytes through the local Warden client; the two
hosts never talk to each other directly. Remote-to-remote copies between
profiles configured for the same host and port are rejected.

Exit status mirrors the remote command/query: 0 on success, nonzero on
failure (remote exit status is propagated for `ssh`).

Noninteractive `ssh`, remote `cp`, and SSH-backed `db` commands reuse each
user's cached SSH connections through a local connection agent. Each cached
connection closes ten minutes after its final operation; when the last cached
connection closes, the agent exits. The agent never persists credentials,
private keys, or transport bundles. Interactive `xssh` and direct (non-SSH)
`db` commands bypass the cache.

## Native Windows usage

Build the client:

```powershell
$env:GOOS = "windows"; $env:GOARCH = "amd64"
go build -o warden.exe ./cmd/warden
```

Run from PowerShell or cmd. Config file: `%AppData%\warden\client.json`
(created manually — see the client config section). Environment overrides
work the same as on Linux (`WARDEN_CLIENT_CONFIG`,
`WARDEN_CLIENT_API_BASE_URL`, `WARDEN_CLIENT_TIMEOUT`).

```powershell
$env:WARDEN_CLIENT_API_BASE_URL = "http://<tailnet-host>:8080"
.\warden.exe ssh my-host "ver"
.\warden.exe xssh
```

`xssh` uses native Windows console APIs (raw-mode input, resize, Ctrl-C
translation); no WSL, Cygwin, or native SSH is required. Host keys are
verified against `%USERPROFILE%\.ssh\known_hosts`. The picker needs
ANSI/VT rendering; interactive SSH retains the current console behavior.

## Build

The web UI is a React/Vite project in `web/`. Building the server requires
Node `^20.19.0 || >=22.12.0` and npm `>=10`; they are build-time-only
dependencies and are never required by a released server binary. Every
supported command that compiles the server package installs the locked
frontend dependencies and runs the production build first:

```bash
make build
make test
make test-race
make vet
bash scripts/test.sh                      # end-to-end: server + API + CLI on an ephemeral port
bash scripts/build-release.sh             # reproducible release artifacts into dist/
```

The generated frontend distribution (`internal/web/dist/`) is gitignored
and never committed. Raw `go build ./cmd/warden-server`, `go test ./...`,
`go test -race ./...`, and `go vet ./...` are unsupported from a clean
checkout because the embedded assets are intentionally absent.

The Windows client is a client-only build: it does not import the
embedded web package, so it can be built directly without the frontend
toolchain:

```bash
GOOS=windows GOARCH=amd64 go build ./cmd/warden
```

`make build-client-windows` produces the same `bin/warden.exe` client-only
build. For reproducible release artifacts (all three targets plus SHA-256
checksums into `dist/`) use `bash scripts/build-release.sh`.

## Tests

```bash
make test        # frontend tests + Go tests
make test-race   # frontend tests + Go race tests
make vet
bash scripts/test.sh   # end-to-end: server + API + CLI on an ephemeral port
```

## Security model (summary)

- Tailnet is the trust boundary; there is no application authentication.
- Secrets are encrypted at rest with AES-256-GCM (fresh nonce per value,
  AAD bound to `warden/<kind>/<id>/<field>`), keyed by the standalone
  `0600` master key the server alone reads.
- The API returns redacted metadata for normal reads; only transport
  endpoints return decrypted credentials, marked `Cache-Control: no-store`.
- The server never executes user commands; execution is local on the client.
- Audit events store operation/resource/source/result/timestamp — never
  credentials, SQL text, or commands.
