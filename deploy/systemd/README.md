# Deploying warden-server as a systemd service

`warden-server` is the Linux-only management API + embedded web UI. It runs
as a dedicated non-root user and binds loopback or a tailnet address. The
cross-platform `warden` client never runs as a service.

## 1. Build and install the binary

```bash
go build -o /usr/local/bin/warden-server ./cmd/warden-server
```

## 2. Create the service user and directories

```bash
sudo useradd --system --home-dir /var/lib/warden --shell /usr/sbin/nologin warden
sudo install -d -o warden -g warden -m 0750 /var/lib/warden /etc/warden
```

`/var/lib/warden` holds the SQLite database (WAL mode). `/etc/warden` holds
the master key and the environment file. The systemd unit also declares
`StateDirectory=warden` and `ConfigurationDirectory=warden`, so systemd
creates and owns those directories if the manual `install` is skipped.

## 3. Generate the master key

The key is a 32-byte random file, mode `0600`, owned by `warden`. The
server refuses to start if the key is missing, not exactly 32 bytes, owned
by the wrong uid, or has any permission other than `0600`.

```bash
# Correct: raw 32 random bytes.
sudo openssl rand -out /etc/warden/master.key 32
sudo chown warden:warden /etc/warden/master.key
sudo chmod 0600 /etc/warden/master.key
```

Do **not** use `head -c 32 /dev/urandom | base64`: that produces ASCII, not
32 raw bytes, and the server rejects it.

The key is a separate secret from the database: losing it makes every
stored credential undecryptable. Keep an offline copy in a vault or
encrypted backup (see the backup section).

## 4. Environment file (non-secret settings only)

Create `/etc/warden/warden-server.env` (mode `0600`, owned by `warden`):

```ini
# Loopback binding. To expose the API over tailnet directly, replace
# 127.0.0.1 with the tailnet IP (e.g. 100.64.0.3:8080) instead of using
# tailscale serve. Never use 0.0.0.0 or a public-interface address.
WARDEN_SERVER_LISTEN_ADDR=127.0.0.1:8080
WARDEN_SERVER_DB_PATH=/var/lib/warden/warden.db
WARDEN_SERVER_MASTER_KEY_PATH=/etc/warden/master.key
# Optional: override the embedded UI with a local copy of the static
# layout (static/index.html, static/app.js, static/styles.css).
# WARDEN_SERVER_STATIC_FS=/srv/warden-ui
```

This file must never contain credentials (passwords, keys, tokens). The
unit loads it with `EnvironmentFile=-`, so the service starts with
compiled-in defaults when the file is absent.

## 5. Install and start the unit

```bash
sudo install -o root -g root -m 0644 deploy/systemd/warden-server.service \
  /usr/local/lib/systemd/system/warden-server.service
sudo systemctl daemon-reload
sudo systemctl enable --now warden-server
```

Check status and logs:

```bash
systemctl status warden-server
journalctl -u warden-server -f
journalctl -u warden-server --since "10 minutes ago" --no-pager
```

Logs contain only startup/shutdown/audit-write warnings — never
credentials, SQL text, or command payloads. If a credential string ever
appears in the journal, treat the deployment as compromised.

## 6. Tailnet-only exposure

The API has no application authentication. Tailnet membership is the full
trust boundary, so exposure must be restricted:

- **Preferred:** keep `WARDEN_SERVER_LISTEN_ADDR` on `127.0.0.1` and
  publish the UI/API through a tailnet proxy:
  `sudo tailscale serve --bg 8080` (Tailscale serves the port over the
  tailnet with per-node ACLs).
- **Alternative:** bind directly to the tailnet interface address
  (`WARDEN_SERVER_LISTEN_ADDR=100.64.0.3:8080`). Verify with
  `ss -ltnp | grep 8080` that no public-interface listener exists.
- Do not open firewall holes on the public interface for this port.
- Restrict tailnet peers with Tailscale ACLs. Every peer that can reach
  the API can read credentials and run client operations — that is the
  documented MVP trade-off.

## 7. Backup and restore

Back up two separate things:

1. **SQLite database** — the authoritative copy is the `-wal`-consistent
   database. Use the SQLite online backup so the WAL is checkpointed:

   ```bash
   sudo -u warden sqlite3 /var/lib/warden/warden.db ".backup '/var/backups/warden/warden.db'"
   ```

   Or with `sqlite3` installed: `sudo -u warden sqlite3 /var/lib/warden/warden.db
   "PRAGMA wal_checkpoint(TRUNCATE);"` then copy the file while the service
   is stopped. Do **not** copy only the main `.db` file while WAL mode is
   active without a checkpoint.

2. **Master key** — stored separately from the database (different
   location, different backup). Without it the database is unreadable.

Restore procedure: stop the service, restore the database file and the key
file with their original ownership (`warden:warden`) and permissions
(`0600` key), start the service. Never restore the key into the database
backup and vice versa.

## 8. Updates

Rebuild the binary, replace `/usr/local/bin/warden-server`, then
`sudo systemctl restart warden-server`. The SQLite schema migrates
automatically at startup; keep a database backup from before the update.
