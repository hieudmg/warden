# Deployment

Warden server is intended for a private tailnet. The release installer is the
simplest path; the detailed traditional systemd deployment reference is
[`deploy/systemd/README.md`](../deploy/systemd/README.md).

## Release installers

Installers download and SHA-256-verify assets from the latest GitHub release.
They prompt for settings and are safe to rerun:

- Linux client: `scripts/install-client.sh`
- Windows client: `scripts/install-client.ps1`
- Linux server: `scripts/install-server.sh`

Client installers run in user scope. Linux server installer runs as the target
service user and stores all server files under `~/.warden` by default:

```text
server.json
warden.db
master.key
warden-server
warden-server.service
```

The server installer creates the master key if absent, preserves the existing
key/database during upgrades, and refreshes the service unit.

## Generated systemd service

The server installer prints both setup paths after every install or update.
The generated unit has no `User=` field so it works as a user service. For a
system service, install it and add a drop-in assigning the target user.

User scope:

```bash
mkdir -p ~/.config/systemd/user
install -m 0644 ~/.warden/warden-server.service \
  ~/.config/systemd/user/warden-server.service
systemctl --user daemon-reload
systemctl --user enable --now warden-server
```

After an upgrade:

```bash
systemctl --user daemon-reload
systemctl --user restart warden-server
systemctl --user status warden-server
```

System scope:

```bash
sudo install -Dm644 ~/.warden/warden-server.service \
  /etc/systemd/system/warden-server.service
sudo mkdir -p /etc/systemd/system/warden-server.service.d
printf '[Service]\nUser=%s\nGroup=%s\n' "$USER" "$(id -gn)" \
  | sudo tee /etc/systemd/system/warden-server.service.d/user.conf
sudo systemctl daemon-reload
sudo systemctl enable --now warden-server
```

After an upgrade:

```bash
sudo systemctl daemon-reload
sudo systemctl restart warden-server
sudo systemctl status warden-server
```

Check logs with `journalctl -u warden-server -f`. Logs must never contain
credentials, SQL text, or command payloads.

## Exposure

Keep the listener on loopback and publish it through a tailnet proxy, or bind
directly to the machine's Tailscale address. Never bind a public interface.
Tailnet membership is the full trust boundary because the API has no
application authentication.

## Backup and restore

Back up both items separately:

1. SQLite database, using SQLite online backup or a WAL-safe checkpoint.
2. The standalone master key in a separate protected backup.

Restore with the service stopped and preserve key mode `0600`. Losing the key
makes the database unreadable.
