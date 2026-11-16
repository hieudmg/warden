# Deployment

Warden's security-hardening branch requires application authentication and a
configured HTTPS public origin; a private network is optional defense in depth,
not authentication or permission to trust additional hosts/origins. The installer
reference below describes this branch's T14 implementation, not a published or
accepted security release. Required genuine PRF/production trust, native Windows
and hosted artifact/OIDC/signature evidence is still pending; see the
[T17 acceptance matrix](superpowers/reports/2026-11-14-t17-integration.md).
The dedicated systemd reference is
[`deploy/systemd/README.md`](../deploy/systemd/README.md).

## Breaking-storage cutover on the security-hardening branch

Installers and executable-only self-upgrades are **not** an encrypted database
migration. Before replacing an old executable, retain its exact binary and export
with that old release. Follow
[the manual v1 transfer and rollback runbook](migration.md): export with the old
release, retain its binary/config/coherent DB+WAL/SHM/master key, initialize a
separate fresh destination, authenticate/unlock/import and verify before
operator-approved cutover. Never delete old storage, reuse its path or copy
legacy encrypted tables into the destination. Normal startup refuses it without
migration/WAL/chmod/key-loader fallback. No real deployment is exercised by the
synthetic T5 tests, and no automatic restart/deletion/cleanup is added.

## Release installers

Installers download and SHA-256-verify assets from the latest GitHub release.
Linux installers require Bash, Python 3 and curl; Windows uses Windows PowerShell
5.1 with .NET Framework 4.7.2+ (not PowerShell Core). Native Windows validation is
still required/pending. No installer skips certificate/hostname verification.
Missing Linux prerequisites (including Python 3) fail before downloads or binary/
unit publication; the installer does not install dependencies for you. Server
publication prepares both files first, retains private original-binary snapshots
until commit, and rolls back if absent-unit publication fails. A competing unit
is never replaced, including directory/symlink collisions. If rollback I/O fails,
the diagnostic identifies private recovery staging retained for manual recovery.
These are per-file atomic operations/error rollback, not a power-loss transaction.

They prompt for settings and can be rerun for executable updates:

- Linux client: `scripts/install-client.sh`
- Windows client: `scripts/install-client.ps1`
- Linux server: `scripts/install-server.sh`

Client installers run in user scope. Linux server installer runs as the target
service user and stores all server files under `~/.warden` by default:

```text
warden-server
warden-server.service
# Created ONLY by later explicit manual init/runtime:
server.json
warden.db (plus runtime WAL/SHM)
```

The server installer asks only for the directory. It never reads/generates a
`master.key`, writes/replaces server configuration, initializes a database, or
executes setup/service commands. Existing config, DB/WAL/SHM, legacy key and
service unit (including custom hardening) stay untouched; a hardened unit is
created only when absent. No passphrase or first-visitor fallback exists.

For a **fresh** installation, run explicitly from an interactive terminal:

```sh
~/.warden/warden-server init --config ~/.warden/server.json
# Defaults: ~/.warden/server.json, ~/.warden/warden.db, ~/.warden/tls/.
# Select fresh DB storage, HTTPS origin/RP and TLS or explicit loopback proxy.
# Each non-secret answer is saved immediately; rerun init to edit saved defaults.
# Complete passkey/PRF registration and save/re-enter recovery; init exits.
```

Only after successful init should you manually install/enable the service below.
An initialized installation does not need re-init. Legacy storage needs a separate
fresh destination and the manual export/import/verification/cutover workflow;
never overwrite a config, DB, key or identity marker to suppress refusal. See
[initialization](initialization.md) and [migration/rollback](migration.md).

## Self-upgrade

`warden-server upgrade` replaces the server executable in place without
prompts:

```bash
warden-server upgrade
```

It downloads the latest released server asset, verifies its SHA-256 digest
against exactly one matching filename in the release `SHA256SUMS` file, and
atomically replaces only the executable on Unix. Downloads require HTTPS at the
initial URL and **every** redirect; verified cross-host HTTPS CDN redirects are
allowed (unlike credential-bearing API redirects). Injected updater clients
cannot supply TLS dialers, hostname/ALPN delegates or unknown transports.

Updater and installer streams are bounded to **256 MiB binary / 1 MiB checksums**,
without trusting Content-Length. Connect/TLS/headers have 10-second phase bounds;
one **5-minute operation budget** covers both downloads, redirects and any
standard Go transport retry. Shell/PowerShell installers do not automatically
retry failed transfers: rerun explicitly; no attempt gets a fresh 5-minute
budget. Linux shell installers supervise real curl with a monotonic deadline and
stream counting, not only `--retry-max-time` or announced file sizes. Staging is
exclusive/private before bytes and cleaned on failure/interruption; destination
publication follows successful complete verification. Windows scheduled updater
replacement uses an encoded detached helper and reports **scheduled**, not a
completed replacement; native Windows ACL/helper/installer execution is pending. It
accepts no arguments and never modifies `server.json`, `warden.db`,
`master.key`, or `warden-server.service`. Only the target published in the
latest release is supported; any other OS/architecture fails before the
installed executable is touched.

The command does not restart the service. After it succeeds, run the manual
restart steps for the scope in use, shown under
[Generated systemd service](#generated-systemd-service).

Set `WARDEN_REPO` or `WARDEN_RELEASE_BASE_URL` to upgrade from a release source
other than the default `hieudmg/warden` GitHub releases. Overrides must still be
HTTPS; there is no insecure/file/local-HTTP production bypass. For private CAs,
configure platform trust (curl fixtures may use `CURL_CA_BUNDLE`, never `-k`).
Checksums delivered by the same release are integrity checks, not independent
authenticity/provenance or anti-rollback proof. Intentional mutable same-version
releases are unchanged. The client upgrades
itself with `warden upgrade`; see the [CLI guide](cli.md).

## Generated systemd service

The server installer prints both setup paths after every install or update,
explicitly gated on successful manual initialization. It runs none of them.
The generated unit retains `UMask=0077`, `NoNewPrivileges=yes`,
`ProtectSystem=strict` and `ReadWritePaths` for the selected storage directory.
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

## HTTPS exposure and request budgets (security-hardening branch)

Choose direct TLS with a trusted certificate for the configured public origin,
or **explicit proxy mode**, with the HTTP backend bound to a **literal loopback**
address, such as `127.0.0.1:8080`. Setup and serve use the same configured public
origin/RP ID; changing request headers cannot change them. Configure the backend
authority explicitly. Accept only the configured public authority (including its
port) or that one backend authority in proxy mode. A DNS alias, private/tailnet
address, alternate port, `Forwarded`, or `X-Forwarded-*` header never adds trust.
Do not expose the plaintext backend to a LAN, tailnet, container bridge or public
interface. Same-host processes are inside this proxy trust boundary. Use the
[initialization runbook](initialization.md) for actual branch configuration.

Setup and runtime use header **5 s**, whole-request read **120 s**, response write
**120 s**, keepalive idle **60 s**, and **16 KiB** headers. Ordinary JSON bodies
remain **1 MiB**, auth/setup have smaller limits, and the transfer API retains
**50 MiB import** and full-size export (not the smaller CLI/agent response cap).
Timeouts are not extended by request traffic; setup expires absolutely **15
minutes after listener readiness**. Failed TLS writes abort the unusable raw
stream rather than starting a new five-second close-notify wait. The server
continues to serve HTTP/1.x only; do not enable server HTTP/2 without separately
proving its response-lease/lock contract.

Import/export share **two** non-waiting slots. Expensive key operations and
assertion/registration finishes share **four** separate slots. Saturation returns
`429` with `Retry-After: 1` and `Cache-Control: no-store`, before reading a transfer
body or consuming its fresh grant. Retry only while the exact grant is still
valid; a failed admitted attempt consumes it. Slots cover response delivery and
release on error, cancellation and panic. Status, ordinary CRUD, lock and logout
are not serialized behind transfers. The existing setup eight-request and runtime
auth/client sixteen-request limits remain. These are per-process bounds, not
protection against arbitrary public traffic or a live-host memory guarantee.

### Same-host NGINX example

Example for `https://warden.example`, RP ID `warden.example`, configured backend
`127.0.0.1:8080`. Replace the name/certificate paths consistently; never use
`$http_host` to select a trusted backend/public origin. Put this in NGINX's `http`
context. No listener on port 80 is required (do not forward plaintext API bodies).

```nginx
server {
    listen 443 ssl;
    server_name warden.example;
    ssl_certificate     /etc/warden/tls/fullchain.pem;
    ssl_certificate_key /etc/warden/tls/private.key;
    ssl_protocols TLSv1.3;

    # Exact public authority, not merely a matching DNS suffix/server_name.
    if ($http_host != "warden.example") { return 403; }

    client_max_body_size 50m;
    client_header_timeout 5s;
    client_body_timeout 120s;
    send_timeout 120s;
    keepalive_timeout 60s;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Host warden.example;
        proxy_set_header Connection "";
        proxy_set_header Forwarded "";
        proxy_set_header X-Forwarded-Host "";
        proxy_set_header X-Forwarded-Proto "";
        proxy_set_header X-Forwarded-For "";
        # Preserve the real Origin/CSRF headers; never forge a trusted Origin.
        proxy_connect_timeout 5s;
        proxy_send_timeout 120s;
        proxy_read_timeout 120s;
        proxy_request_buffering off;
        proxy_buffering off;
        proxy_cache off;
    }
}
```

NGINX body/send/proxy timeouts are **inactivity intervals**, not an absolute
whole-request budget; Warden's unchanged read/write deadlines remain authoritative.
The example streams HTTP/1.1 uploads without proxy request/response temp-file
buffering/caching. Do not add a proxy cache for authenticated data/errors or strip
Warden's no-store headers. Keep immutable nonsecret assets functional. Verify the
installed NGINX version with `nginx -t` and trusted HTTPS socket tests before use;
this example was checked against official directive documentation, not deployed
or run through NGINX in T6.

The bounded synthetic acceptance uses **52,196,291 bytes**, 4,096 encrypted SSH
profiles plus ~12 KiB notes each, at a paced **16 MiB/s** link, direct verified TLS
and a same-host verified-HTTPS proxy. It finishes within both the 120 s server
budget and the existing fresh-grant 60 s lifetime. This is a documented tested
link/workload, not a minimum-link-speed promise or WAN benchmark. Start a fresh
authorization if upload/processing would outlive the grant. The test runs once per
mode, stops on a 120 s client deadline or 2 GiB cumulative allocation delta, and
logs allocation/heap measurements; it is not an endless stress benchmark. See
[the T6 evidence](superpowers/reports/2026-11-14-t6-backend-boundaries.md).

This HTTPS policy covers Warden setup/web/client APIs and its loopback proxy hop
only. Existing external DB and HTTP CONNECT proxy transport behavior is unchanged;
plaintext external legs remain scope-excluded risks, not end-to-end TLS claims.

## Backup and restore

For this branch, protect the initialized database (including auth metadata and
wrapped keys), coherent WAL/SHM when present, nonsecret HTTPS config/TLS material,
and **offline recovery key**. No standalone plaintext vault master key is created
or loaded. Keep recovery separately protected; losing all usable passkeys and
recovery has no administrative bypass. Restore only a coherent matching set with
the service stopped; restart remains locked and requires manual authentication
and unlock. Do not manipulate database markers to force a restore/upgrade.

For **legacy rollback**, separately retain the exact old binary/config/coherent
DB/WAL/SHM/master key with original permissions. Never start the old release on
the new initialized DB or the new release on the old DB. Follow
[the retention and rollback runbook](migration.md), not automatic deletion or an
in-place migration. No real service or storage operations were run for T14.
