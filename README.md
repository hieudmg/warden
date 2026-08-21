# Warden

Task 1 bootstrap for Warden Hub.

Current scope:
- Go module with separate `warden-server` and `warden` entrypoints.
- Strict JSON config loading with defaults and environment overrides.
- Build targets for Linux server/client and Windows client cross-build.

Not in Task 1:
- SQLite, crypto, HTTP API, SSH, DB, UI, reports, or PTY support.

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

`static_fs` overrides the embedded management UI for development. The directory layout must mirror `internal/web/static/` and contain exactly `index.html`, `app.js`, and `styles.css`; missing files silently 404.

### Client config

Default file:
- Linux/macOS: `$XDG_CONFIG_HOME/warden/client.json` when `XDG_CONFIG_HOME` exists, otherwise `$HOME/.config/warden/client.json`
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

Client config contains only API settings. It does not read server DB paths or master-key material.

## Commands

```text
warden-server serve
warden ssh <connection> "<command>"
warden db <connection> "<SQL>"
warden xssh [connection]
warden report create <project> --title <title> --summary <summary> --agent-model <name>
warden config list
warden config get <connection>
```

Task 1 command handlers are bootstrap stubs: they parse usage and validate config, then exit without implementing transport or API behavior.

## Build

```bash
go build ./cmd/warden-server
go build ./cmd/warden
GOOS=windows GOARCH=amd64 go build ./cmd/warden
```

Or use `make build`, `make build-client-windows`, `make test`, and `make vet`.

## Validation status

Windows client cross-build is wired, but native Windows runtime and PTY behavior are not claimed until native tests exist.
