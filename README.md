# Warden

Warden is a cross-platform CLI and Linux server for personal development aid.
It keeps SSH, MySQL/MariaDB and HTTP connection profiles in one place, lets you
run development operations through them, and records agent change reports.

> **Vibe-coded software:** Warden is a personal aid while developing. Treat it
> as experimental software, review its behavior, and do not assume it is
> production-hardened.

Warden is designed for a private tailnet. The server has no application
authentication; anyone who can reach it can manage profiles and retrieve
transport credentials. Read [Security](docs/security.md) before exposing it.

## Install

Installers download and SHA-256-verify assets from the latest GitHub release.
They ask for configuration and can be rerun to update an existing installation.
Client timeout, server database, and master key are preserved on update; client
endpoint is updated from the prompt.

### Linux client

User-scope install; no `sudo` required:

```bash
curl -fsSL https://raw.githubusercontent.com/hieudmg/warden/main/scripts/install-client.sh \
  | bash
```

Prompts for server endpoint. Defaults:

- Binary: `~/.local/bin/warden`
- Config: `~/.config/warden/client.json`
- Endpoint: `http://127.0.0.1:8080`

### Windows client

User-scope install; no administrator rights required:

```powershell
Invoke-WebRequest `
  -Uri https://raw.githubusercontent.com/hieudmg/warden/main/scripts/install-client.ps1 `
  -OutFile "$env:TEMP\warden-install-client.ps1"
powershell -ExecutionPolicy Bypass -File "$env:TEMP\warden-install-client.ps1"
```

Prompts for server endpoint. Defaults:

- Binary: `%LOCALAPPDATA%\Warden\warden.exe`
- Config: `%APPDATA%\warden\client.json`
- Endpoint: `http://127.0.0.1:8080`

### Linux server

Run as target service user; no `sudo` required during installation:

```bash
curl -fsSL https://raw.githubusercontent.com/hieudmg/warden/main/scripts/install-server.sh \
  | bash
```

Prompts for listen host, port, and Warden directory. Defaults:

- Host: `127.0.0.1`
- Port: `8080`
- Directory: `~/.warden`

Server binary, config, database, master key, and generated systemd unit live
in the selected directory. Installer prints user-scope and system-scope
systemd setup/restart commands after every install or update.

### Upgrade

Both binaries upgrade themselves in place without prompts:

```bash
warden upgrade
warden-server upgrade
```

Each command downloads the latest released binary for the current platform,
verifies it against the release `SHA256SUMS`, and replaces only its own
executable. Client config, cached credentials, server config, the database,
the master key, and the service unit are left untouched.

`warden-server upgrade` does not restart the service. It prints the manual
user-scope and system-scope systemd restart commands, which are also listed in
[Deployment](docs/deployment.md).

## Configuration

Client only needs server endpoint:

```json
{
  "api_base_url": "http://127.0.0.1:8080",
  "timeout": "30s"
}
```

Server installer creates:

```text
~/.warden/
├── server.json
├── warden.db
├── master.key
├── warden-server
└── warden-server.service
```

See [Configuration](docs/configuration.md) for file paths, environment
variables, and complete server settings.

## Usage

```bash
# Run command over SSH.
warden ssh <connection> "uname -a"

# Run SQL against default or selected database.
warden db <connection> "SELECT 1"
warden db <connection>/<database> "SELECT 1"

# Force machine-readable output (auto-detected from stdout by default).
warden -n db <connection> "SELECT 1"
warden -i db <connection> "SELECT 1"

# Send an HTTP request through the server using stored credentials.
warden http GET service '/v1/items?limit=10'
warden http POST service /v1/items '{"name":"item"}'

# Search connection names, hosts/origins, and database names.
warden config search "production"

# Record an immutable development report.
warden report create <project> \
  --title "deployed" \
  --summary "v2 shipped" \
  --agent-model gpt-5.4

# Interactive SSH picker.
warden xssh

# Copy files through configured hosts.
warden cp ./release.tar prod:/srv/releases/

# Watch and forward remote listeners (Linux target with ss required).
warden port-watch prod 3000,5000-6000,9999-12222

# Upgrade a binary in place from the latest release.
warden upgrade
warden-server upgrade
```

`port-watch` opens a full-screen view on an ANSI-capable terminal, with **Host
process name**, **Host port**, and **Client URL** columns sorted by port number.
The process name is best effort: `—` means the remote `ss` did not provide a
usable name without elevated privileges. If multiple names are visible for a
port, the view shows the first in lexical order.

Successful local binds show a clickable HTTP URL. Closed ports stay gray in
the table until the session ends and reuse their row if they reopen. Local
address conflicts are yellow; other bind errors are red. Bind failures are
retried automatically and show no link. Both ends of the forward use IPv4
loopback, so a service listening only on a remote non-loopback address may be
listed but unreachable. Use the appropriate client for non-HTTP services.

Use Up/Down to scroll one row, Left/Right to jump to the top/end, and `q` or Ctrl-C to quit.
Redirected output keeps the plain-text forwarding/closure log without terminal
escape sequences.

### Copy backends

`warden cp` defaults to SFTP. Use `--backend=sftp` to select it explicitly.
`warden cp --backend=rsync ./assets prod:/srv/assets` opts into rsync for a
**directory** upload or download. If the source is a regular file, Warden uses
SFTP directly, including for an explicit destination filename. Rsync is not
available for remote-to-remote copies, and a failed rsync attempt is never
retried with SFTP.

Warden embeds the Go rsync client; no local `rsync` executable, WSL, or Cygwin
is required. The SSH host must provide stock `rsync` on `PATH`, a POSIX shell,
and SFTP metadata access to the same filesystem as the shell. Warden uses its
normal SSH host-key verification and gives each rsync-selected copy its own
SSH transport, so cancellation does not disconnect other operations.
Directory preflight rejects symlinks, special-file sources, and unsafe
paths. Uploads reject nested directory names that are not valid UTF-8, and
Windows downloads reject case-colliding sibling names and unsafe aliases.
Preflight does not protect against concurrent changes to either tree.

Opt-in rsync does not delete unrelated entries or write file data in place,
but it is not a directory-wide transaction. In particular:

- During a directory merge, a source subdirectory can replace an existing
  destination file, even without `--delete`. A directory source cannot use an
  existing file as its destination operand.
- An upload can report success even if rsync could not open and copy one of the
  source files. Verify the result when completeness matters.
- A download can fail while setting permissions **after** replacing an existing
  file. The old file is already gone; the replacement has complete, verified
  data but may have the wrong permissions.

Use SFTP when these differences are unacceptable.

### HTTP connections

Use the **HTTP** tab in Warden Hub (`/http`) to create, edit, group, annotate,
archive/restore or delete named profiles. Save an origin such as
`https://api.example.com:8443` (no path, query or trailing slash), then supply the
path/query separately with `warden http`. The web view manages profiles only;
it is not a request builder.

Choose Bearer, X-API-Key or Basic authentication. All HTTP credential fields,
including Basic username, are encrypted at rest and never returned by management
reads. Edit fields start blank; leave them blank to keep saved values when the
authentication mode is unchanged. Changing modes clears the old credentials.
Archived profiles remain manageable but cannot execute requests.

Requests run on the Warden server, not the client. Both HTTP and HTTPS and any
configured host (including private/loopback hosts) are allowed. **HTTP is
unencrypted and exposes credentials and data to interception or modification.**
HTTPS certificates are verified and redirects are not followed. This capability
does not add application authentication: every peer that can reach Warden is
trusted to configure destinations and use the stored credentials.

### Migrate data to another server

The Warden Hub web view exports and imports every managed record: SSH, database
and HTTP connections, groups, key pairs, projects, reports, and connection notes.

1. On the source server, open Warden Hub and choose **Export data**.
2. Transfer the downloaded `warden-data.json` file securely.
3. On the destination server, open Warden Hub and choose **Import data**, then
   select the file.

The export is unencrypted JSON containing plaintext credentials, including
passwords, private keys, passphrases and HTTP credentials (including Basic
usernames). Store it securely and delete it once
the migration is complete. Import only succeeds when the destination has no
managed data, so it never overwrites or merges existing records; a failed import
leaves the destination unchanged. The destination re-encrypts imported secrets
with its own master key, so the source and destination do not need the same key.
Legacy version-1 exports without HTTP records still import; new exports include
`http_connections` and may not be accepted by older strict-decoding servers.
Import reloads every web list, including HTTP profiles.

See [CLI guide](docs/cli.md) for advanced behavior, picker details, database
targets, copy semantics, and host-key handling.

## Development

```bash
make build
make test
make vet
bash scripts/test.sh
```

See [Development](docs/development.md) for build requirements, release
artifacts, Windows builds, and test details.

## Documentation

- [Configuration](docs/configuration.md)
- [CLI guide](docs/cli.md)
- [Deployment](docs/deployment.md)
- [Security](docs/security.md)
- [Development](docs/development.md)
- [Systemd deployment reference](deploy/systemd/README.md)

## License

[WTFPL](LICENSE)
