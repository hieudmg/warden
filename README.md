# Warden

Warden is a cross-platform CLI and Linux server for personal development aid.
It keeps SSH and MySQL/MariaDB connection profiles in one place, lets you
run development operations through them, and records agent change reports.

> **Vibe-coded software:** Warden is a personal aid while developing. Treat it
> as experimental software, review its behavior, and do not assume it is
> production-hardened.

The **0.23.0 security upgrade** requires HTTPS, passkey-authenticated management
and individually web-approved CLI credentials. A private tailnet is optional
defense in depth, not authentication. This is an unpublished local implementation
checkpoint, **not an accepted security release**: genuine authenticator PRF with
production certificate trust, native Windows, and hosted artifact/OIDC/signature
evidence remain required. See the [acceptance matrix](docs/superpowers/reports/2026-11-14-t17-integration.md)
and [Security](docs/security.md) before exposing it.

## Install

Use [explicit HTTPS initialization](docs/initialization.md) and verified-HTTPS
client enrollment. The instructions below describe the implemented upgrade;
they do not authorize or claim a release, installation or service cutover.

For old data, follow [old-release export → fresh init → v1 import](docs/migration.md).
Never reuse/delete the old encrypted database to make this branch start. Keep the
old binary/config/coherent DB+WAL/SHM/key for rollback and manually verify imported
data before cutover. Export files contain plaintext secrets.

Installers download and SHA-256-verify assets from the latest GitHub release.
This branch's installers enforce verified HTTPS on every release hop, bounded
streams (binary 256 MiB/checksums 1 MiB) and one 5-minute download budget. Linux
requires Python 3 and curl; Windows requires Windows PowerShell 5.1/.NET Framework
4.7.2+ (native Windows acceptance pending). Client timeout/trust settings and server config,
DB/WAL/SHM, legacy key and existing service unit are preserved on update; the
client HTTPS endpoint is updated from the prompt. These changes are not yet a
published/accepted security release. The bootstrap examples fetch `main` and
latest published assets, not this unpublished branch. Review the script at a
trusted revision before execution; release checksums do not independently
authenticate the bootstrap script.

### Linux client

User-scope install; no `sudo` required:

```bash
curl --disable --proto '=https' --proto-redir '=https' --connect-timeout 10 --max-time 300 \
  --max-filesize 1048576 -fsSL \
  https://raw.githubusercontent.com/hieudmg/warden/main/scripts/install-client.sh | bash
```

Prompts for the server's HTTPS origin (no guessed new-install endpoint):

- Binary: `~/.local/bin/warden`
- Config: `~/.config/warden/client.json`
- Endpoint: existing configured origin, or explicit entry on a fresh install.

### Windows client

User-scope install; no administrator rights required:

```powershell
# Retrieve/review scripts/install-client.ps1 over trusted HTTPS and save it
# in a private local directory. Then, in Windows PowerShell 5.1:
powershell.exe -NoProfile -File .\install-client.ps1
```

Prompts for the server's HTTPS origin (no guessed new-install endpoint):

- Binary: `%LOCALAPPDATA%\Warden\warden.exe`
- Config: `%APPDATA%\warden\client.json`
- Endpoint: existing configured origin, or explicit entry on a fresh install.

### Linux server

Run as target service user; no `sudo` required during installation:

```bash
curl --disable --proto '=https' --proto-redir '=https' --connect-timeout 10 --max-time 300 \
  --max-filesize 1048576 -fsSL \
  https://raw.githubusercontent.com/hieudmg/warden/main/scripts/install-server.sh | bash
```

Prompts only for the Warden directory (default `~/.warden`). It installs the
binary and an absent hardened systemd unit, **not** a key/config/database. Run
`~/.warden/warden-server init --config ~/.warden/server.json` manually from an
interactive terminal for fresh storage; init owns HTTPS/RP/TLS/storage prompts
and recovery confirmation. Only after init succeeds, choose the printed manual
user- or system-scope service setup. Existing initialized storage needs no re-init;
legacy storage needs retained old artifacts, old-release export and separate
fresh initialization/import/verification before manual cutover. Nothing is
automatically started/restarted or reset. See [deployment](docs/deployment.md).

### Upgrade

Both binaries upgrade themselves in place without prompts:

```bash
warden upgrade
warden-server upgrade
```

Each command downloads the latest released binary for the current platform,
verifies it against the release `SHA256SUMS`, and replaces only its own
executable. Client config, private IPC discovery material, server config, the
database, any retained legacy `master.key`, and the service unit are left untouched.

`warden-server upgrade` does not restart the service. It prints the manual
user-scope and system-scope systemd restart commands, which are also listed in
[Deployment](docs/deployment.md).

## Configuration

On the security-hardening branch the client requires a verified HTTPS origin:

```json
{
  "api_base_url": "https://warden.example",
  "timeout": "30s"
}
```

Run `warden login`, compare its fingerprint in the web **CLI devices** view,
and approve with a fresh passkey assertion. The existing agent owns the API
credential only in memory; restart requires reapproval, while server restart
preserves authorization and starts locked. Use `warden logout` for attempted
revocation and unconditional local clearing. Private CA trust is configurable;
see [configuration](docs/configuration.md) and [CLI enrollment](docs/cli.md).
Native Windows and genuine PRF/browser acceptance remain pending; this is not a
completed security release.

The server installer creates only `warden-server` and an absent
`warden-server.service` under `~/.warden/`. Later explicit init creates private
`server.json` and a fresh initialized `warden.db`; runtime may create WAL/SHM
sidecars. **No plaintext vault key is created or loaded.** Existing legacy keys
remain untouched only for old-release rollback. See [initialization](docs/initialization.md).

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

# Search connection names, hosts, and database names.
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

`port-watch` opens a full-screen view on an ANSI-capable terminal, showing the
connection, watched ranges, and currently listening ports. Successful forwards
have clickable local HTTP URLs; forwarding failures appear in red in the LOCAL
URL column and are retried automatically. Use `j`/`k` to scroll, `g`/`G` for the
top/end, and `q` or Ctrl-C to quit. URLs assume HTTP; use the forwarded port with
the appropriate client for non-HTTP services. Redirected output keeps the
plain-text forwarding/closure log without terminal escape sequences.

### Migrate data to another server

The Warden Hub web view exports and imports every managed record: SSH and
database connections, groups, key pairs, projects, reports, and connection notes.

1. On the source server, open Warden Hub and choose **Export data**.
2. Transfer the downloaded `warden-data.json` file securely.
3. On the destination server, open Warden Hub and choose **Import data**, then
   select the file.

The export is unencrypted JSON containing plaintext credentials, including
passwords, private keys, and passphrases. Store it securely and delete it once
the migration is complete. Import only succeeds when the destination has no
managed data, so it never overwrites or merges existing records; a failed import
leaves the destination unchanged. The destination re-encrypts imported secrets
with its own random vault DEK, wrapped by its passkeys and offline recovery
material. Source and destination do not need the same key or authentication
identity. Authenticate and unlock the destination, then authorize that exact
import with a fresh assertion. Auth/session/client records never travel in exports.

See [CLI guide](docs/cli.md) for advanced behavior, picker details, database
targets, copy semantics, and host-key handling.

## Development

Source builds require **Go 1.26.11 or newer**, enforced by `go.mod`. To use the
validated patch without changing the host default, set
`GOTOOLCHAIN=go1.26.11` for build/test commands. Installed Warden binaries do not
require Go on runtime hosts. Release builds select the exact patch in `go.mod`.

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
