# Warden

Warden is a cross-platform CLI and Linux server for personal development aid.
It keeps SSH and MySQL/MariaDB connection profiles in one place, lets you
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
```

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
