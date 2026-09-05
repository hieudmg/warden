# Configuration

Warden has separate server and client configuration. Configuration files are
strict JSON: unknown fields and trailing data are rejected.

## Client

Default config path:

- Linux/macOS: `$XDG_CONFIG_HOME/warden/client.json`, or
  `$HOME/.config/warden/client.json`
- Windows: `%APPDATA%\warden\client.json`

```json
{
  "api_base_url": "http://127.0.0.1:8080",
  "timeout": "30s"
}
```

`api_base_url` accepts only `http` or `https` URLs without query strings or
fragments. `timeout` uses Go duration syntax and must be positive.

Environment overrides:

- `WARDEN_CLIENT_CONFIG`
- `WARDEN_CLIENT_API_BASE_URL`
- `WARDEN_CLIENT_TIMEOUT`

Client config contains no credentials and never reads server database or
master-key paths.

## Server

Manual/default config path: `/etc/warden/server.json`.
The release installer uses `<warden-dir>/server.json`, with `~/.warden` as its
default directory.

```json
{
  "listen_addr": "127.0.0.1:8080",
  "db_path": "/var/lib/warden/warden.db",
  "master_key_path": "/etc/warden/master.key",
  "static_fs": ""
}
```

Fields:

- `listen_addr` — `host:port`; host must be `localhost`, loopback, or a
  Tailscale address (`100.64.0.0/10` or Tailscale IPv6 range).
- `db_path` — SQLite database path.
- `master_key_path` — path to exactly 32 raw random bytes with mode `0600`.
- `static_fs` — optional external frontend directory for development; empty
  uses the embedded UI.

Environment overrides:

- `WARDEN_SERVER_CONFIG`
- `WARDEN_SERVER_LISTEN_ADDR`
- `WARDEN_SERVER_DB_PATH`
- `WARDEN_SERVER_MASTER_KEY_PATH`
- `WARDEN_SERVER_STATIC_FS`

Environment values override file values. `WARDEN_SERVER_CONFIG` and the
`--config` flag select a different JSON file.

## Installer layout

Server installer defaults:

```text
~/.warden/
├── server.json
├── warden.db
├── master.key
├── warden-server
└── warden-server.service
```

It preserves `warden.db` and `master.key` when rerun. The client installer
preserves its existing timeout and changes only the endpoint selected at the
prompt.

## Master key

Generate a key as raw bytes, never base64 text:

```bash
openssl rand -out master.key 32
chmod 0600 master.key
```

The key is separate from the database and decrypts every stored credential.
Back it up separately. Losing it makes the database unreadable.
