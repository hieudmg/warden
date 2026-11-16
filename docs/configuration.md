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
  "api_base_url": "https://warden.example",
  "timeout": "30s"
}
```

`api_base_url` must be an HTTPS origin, with no userinfo, management path, query
or fragment. This also applies to loopback; direct client HTTP is refused. The
built-in default is `https://127.0.0.1:8080` and requires a matching trusted
certificate. `timeout` uses Go duration syntax and must be positive.

Optional `ca_certificate` is a **public** PEM certificate path for private-CA
trust, in addition to system roots. Relative paths are resolved in the invoking
CLI's working directory before IPC, not in the long-lived agent's directory. Certificate/hostname verification
cannot be disabled. No API or polling secret belongs in configuration or env;
run `warden login` for fresh web approval, and `warden logout` to clear memory
and attempt revocation. See [CLI enrollment](cli.md#login-logout-and-status).

Environment overrides:

- `WARDEN_CLIENT_CONFIG`
- `WARDEN_CLIENT_API_BASE_URL`
- `WARDEN_CLIENT_TIMEOUT`

Client config contains no credentials and never reads server database or
master-key paths.

## Server

Fresh server defaults are `~/.warden/server.json` and `~/.warden/warden.db`
(`~` is the current user's home directory). Direct TLS setup defaults to
`~/.warden/tls/fullchain.pem` and `~/.warden/tls/private.key`; init does not
create certificates. Explicit custom config/database/TLS paths remain supported.

`serve` discovers `/etc/warden/server.json` **only when** the new default config
is absent. It never copies or migrates that file, and retains the old omitted DB
default `/var/lib/warden/warden.db` for that legacy config path. An existing but
invalid/incomplete new default causes refusal, not fallback to an old installation.
Explicit `--config` or `WARDEN_SERVER_CONFIG` wins over discovery. Init uses the
explicit flag/environment path or prompts with the fresh home-directory default;
it never silently edits a discovered legacy deployment.

```json
{
  "listen_addr": "127.0.0.1:8080",
  "db_path": "/home/you/.warden/warden.db",
  "static_fs": "",
  "security": {
    "public_origin": "https://warden.example",
    "rp_id": "warden.example",
    "mode": "tls",
    "tls_certificate": "/home/you/.warden/tls/fullchain.pem",
    "tls_key": "/home/you/.warden/tls/private.key"
  }
}
```

Fields:

- `listen_addr` — `host:port`. Proxy mode requires a literal loopback IP and
  matching backend authority; public/direct TLS binds are an explicit exposure
  choice. See [initialization](initialization.md) for HTTPS and RP constraints.
- `db_path` — fresh SQLite storage for init; existing initialized storage for serve.
- `security` — public HTTPS origin, RP ID and `tls` or `proxy` transport settings.
  It is immutable once storage is initialized. Proxy mode uses
  `backend_authority` instead of TLS file settings.
- `static_fs` — optional external frontend directory for development; empty
  uses the embedded UI. Init preserves this and other recognized non-prompted settings.
- `initialization_draft` — init-owned marker for editable, unfinished answers.
  Serve refuses drafts even if their current answers validate. Init removes the
  marker after validation and storage checks, **before** starting setup; existing
  storage then prevents further init config edits. Do not toggle it manually.
- `master_key_path` — retained legacy field only, not a disk-key fallback in the
  authenticated runtime. New init files never emit it.

Environment overrides:

- `WARDEN_SERVER_CONFIG`
- `WARDEN_SERVER_LISTEN_ADDR`
- `WARDEN_SERVER_DB_PATH`
- `WARDEN_SERVER_MASTER_KEY_PATH`
- `WARDEN_SERVER_STATIC_FS`

Environment values override runtime file values. `WARDEN_SERVER_CONFIG` and the
`--config` flag select a different JSON file for init/serve (the flag wins).
Other runtime overrides are not imported into saved init answers. JSON paths are
literal paths; `~` in examples must be expanded by the shell or replaced with an
absolute home path, not written literally inside JSON.

## Installer layout

Server installer defaults:

```text
~/.warden/
├── server.json
├── warden.db
├── warden-server
└── warden-server.service
```

The server installer installs the executable and creates a service unit only
when absent; it does not create config, DB or TLS files. Manual init creates
non-secret configuration and, after successful registration, fresh storage.
Reruns preserve existing config, DB/WAL/SHM, legacy keys and service units.
The client installer preserves its existing timeout and changes only the endpoint
selected at the prompt.

## Resuming initialization and retaining legacy keys

Every submitted non-secret answer is saved immediately as private JSON, including
invalid answers and incomplete drafts. Rerun init with the same config path to
reprompt applicable fields with saved defaults. Fix validation errors or choose
fresh storage without discarding the other answers. No password, recovery key,
vault key, PRF output or authentication credential belongs in this JSON.

Keep an old `master.key` together with its old binary/config/DB/WAL/SHM for legacy
export and rollback. Do not generate a new key or overwrite existing storage to
make startup work. Follow [migration](migration.md) for manual export/import.
