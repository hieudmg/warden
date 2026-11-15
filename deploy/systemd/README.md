# Deploying initialized warden-server with systemd

This is manual guidance for the security-hardening branch, **not a deployment
performed by tests or a published/accepted security release**. Server startup
requires explicit initialization, stable trusted HTTPS origin/RP configuration,
and registered passkeys. It starts locked on every restart. Network restrictions
are defense in depth; tailnet membership does not authenticate management.

The client is not a system service. The Linux installer refuses root, installs
only the verified server executable plus an absent hardened unit, and prints
manual instructions. It never initializes storage or runs systemd, sudo,
sysctl or Tailscale commands. Existing server config, DB/WAL/SHM, legacy key,
identity and unit remain untouched. See [deployment](../../docs/deployment.md).

## Fresh initialization comes before service startup

Choose a non-root service account, fresh private storage, trusted TLS certificate
or an explicitly configured **same-host loopback** HTTPS reverse proxy. Do not
invent a public origin from the listener address. Run `init` from an actual
interactive controlling terminal as that account; init prompts for configuration:

```sh
/path/to/warden-server init --config /path/to/fresh/server.json
```

Select a **new** DB path and complete required passkey/PRF registration plus
save/hide/re-enter recovery. Init exits after atomic identity publication. It
does not start normal management or create a master key. Only then install/start
a unit pointing at that exact config. See [initialization](../../docs/initialization.md)
for direct TLS, RP/origin, proxy trust, certificate permissions and setup details.
The temporary setup password is terminal-only; put no secrets in argv, environment
files or service units. Required PRF unsupported means failure, not fallback.

For the static dedicated-user unit in this directory, arrange paths consistently:

- executable: `/usr/local/bin/warden-server`;
- nonsecret config: `/etc/warden/server.json`;
- fresh DB: `/var/lib/warden/warden.db`;
- TLS certificate/key paths accessible to the service account, not embedded in
  the unit/environment. No plaintext vault key exists here.

The static unit has `User=warden` / `Group=warden`, `StateDirectory=warden`,
`ConfigurationDirectory=warden`, explicit config argv, `ReadOnlyPaths=/etc/warden`,
`ReadWritePaths=/var/lib/warden`, and the existing UMask/NoNewPrivileges/
ProtectSystem/PrivateTmp/ProtectHome/kernel/control-group safeguards. Provision
initialization directories and ownership manually **before init**, not by starting
an uninitialized service. Init may create private nonsecret config; the running
service need not be able to rewrite it. Optional `warden-server.env` contains only
nonsecret, intentional overrides; missing config/identity fails closed.

## User and system scopes

The installer-generated unit uses the selected directory and has no `User=` field
so it also works as a user unit. It retains `UMask=0077`, `NoNewPrivileges=yes`,
`ProtectSystem=strict`, and `ReadWritePaths` for that directory. Existing units are
preserved on repeated installs; review any custom unit manually, do not expect the
installer to replace it silently.

**After successful manual init**, user scope:

```sh
mkdir -p ~/.config/systemd/user
install -m 0644 ~/.warden/warden-server.service ~/.config/systemd/user/warden-server.service
systemctl --user daemon-reload
systemctl --user enable --now warden-server
```

For a system-scope generated unit, install it under `/etc/systemd/system`, add a
`[Service]` drop-in with the intended non-root `User=` and `Group=`, then manually
reload/enable it. Alternatively, after provisioning the matching dedicated
account/paths and completing init, install this directory's static unit:

```sh
sudo install -m 0644 deploy/systemd/warden-server.service /usr/local/lib/systemd/system/warden-server.service
sudo systemctl daemon-reload
sudo systemctl enable --now warden-server
```

These commands are operator instructions only. Verify the installed systemd
version and unit offline before actual use. Normal service login works while
locked; manual fresh PRF unlock is separate. Restart never resumes the vault key.

## Updates, legacy cutover and rollback

`warden-server upgrade` intentionally remains available for service-managed
installations. It verifies the release and replaces **only the executable**;
there is no forced stop/restart or automatic cutover. Manually restart the scope
in use when ready:

```sh
systemctl --user restart warden-server
# OR, for a system unit:
sudo systemctl restart warden-server
```

Before crossing the breaking storage boundary, retain the **old executable** and
export with that old release. Retain its exact config, coherent DB/WAL/SHM and
legacy master key with original permissions. Initialize separate fresh storage,
import documented version 1, verify usable secrets/metadata and restart-locked
behavior, then choose a manual cutover. Never overwrite/delete config, keys,
markers or DB files to make an upgrade start. See
[manual migration and rollback](../../docs/migration.md). Same-version mutable
releases and manual restart semantics are intentionally unchanged, not a claim of
immutable distribution or anti-rollback.

For current backups retain the initialized DB/auth wrappers, coherent sidecars,
HTTPS config/TLS material and separately protected offline recovery. No disk vault
master key is generated. Restore coherent matching artifacts with the service
stopped, then authenticate/unlock manually. Legacy rollback requires its matching
old binary/config/DB/key set, not starting an old executable on the new DB. Logs
must not contain secrets, SQL or command payloads.
