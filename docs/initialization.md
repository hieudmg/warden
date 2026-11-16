# Explicit HTTPS initialization, unlock and recovery

Initialization remains a separate setup-only process. After it exits, normal
`warden-server serve --config /your/fresh/private-directory/server.json` now
starts the authenticated HTTPS runtime **locked**, without loading a disk key.
Log in with the registered passkey, then use a new required-UV assertion and PRF
unwrap to unlock management. Logout revokes only that browser session; Lock vault
cancels/drains global key access. Key reveal/mutation and documented v1
export/import now require a new passkey assertion bound to the exact request.
Legacy management transport remains blocked; CLI retrieval uses the separately
approved `/api/v1/client/` audience through the local agent. Security controls
add/revoke passkeys (never the last active one),
rotate recovery with saved re-entry, and offer restricted offline-key recovery.
Recovery MUST verify a new PRF passkey before atomically replacing ALL old
passkeys/wrappers, revoking sessions/client authorizations, and returning locked
to ordinary passkey login. Abort leaves the old identity intact. Recovery alone
never permits management/read/export and does not rotate the recovery root.
See the [T3 implementation/evidence report](superpowers/reports/2026-11-14-t3-passkeys-recovery.md)
for protocol evidence and [CLI enrollment](cli.md#login-logout-and-status) for
pairing. Genuine PRF-positive HTTPS/browser with production trust and native
Windows acceptance remain pending. Real Chromium CSP/network checks use a
synthetic signed authenticator/injected PRF and test-only certificate exception;
this is not verified M1 or a release-ready security upgrade.

## Build and run against fresh disposable storage

```sh
NODE_ENV=production npm --prefix web run build
GOTOOLCHAIN=go1.26.11 TMPDIR=/var/tmp go build -o /var/tmp/warden-server-check ./cmd/warden-server
/var/tmp/warden-server-check init --config /your/fresh/private-directory/server.json
```

Run from an interactive controlling terminal. `--config` wins over
`WARDEN_SERVER_CONFIG`; without either, init prompts for the config path with
`~/.warden/server.json` as its default. The fresh DB default is
`~/.warden/warden.db`. It asks for public HTTPS origin, RP ID, `tls` or `proxy`
mode, and listen address. TLS mode asks for certificate and private-key paths
(defaults `~/.warden/tls/fullchain.pem` and `~/.warden/tls/private.key`); proxy mode
asks for the explicit loopback backend authority. Init does not generate TLS files.
All file paths can be customized. Saved paths are literal, not shell-expanded.

Each non-secret answer is saved **before the next prompt**, even if invalid or
if validation, storage checks, certificate loading or later setup fails. Rerun
with the same config path to edit applicable fields with saved defaults; blank
input keeps the displayed default. Switching transport clears incompatible
transport fields. Other recognized settings such as `static_fs` are preserved.
Draft files carry `initialization_draft: true`; serve rejects them rather than
accepting incomplete or invalid answers. After validation and fresh-storage
checks, init removes the marker before starting the temporary setup plane.
This ordering protects config even if setup commits but its completion response
is lost. Never manually toggle the marker to bypass refusal.

New files and atomic sibling-temp replacements use POSIX mode 0600, with newly
created directories using 0700. Configuration contains paths, not TLS private-key
contents, vault keys, passwords or authentication secrets. Malformed/unknown-field
JSON, legacy config without security settings, config symlinks, and config already
pointing to initialized/occupied storage are not silently overwritten. An editable
draft's refused storage answer can be corrected without opening that storage.
Native Windows ACL/privacy behavior is not verified here.

Normal serve prefers the same home config default. Only when absent does it
still discover `/etc/warden/server.json`, without copying/migrating old settings;
explicit flag/environment selection wins. An invalid new default never falls
back to a different installation. Existing passkey installations are unchanged.

An origin has no path (not even `/`), userinfo, query or fragment. Use a canonical
lowercase DNS hostname, omit the default HTTPS port 443, and use an explicit port
only when non-default. RP ID is the origin's DNS name or an eligible parent DNS
domain, never a public suffix or an IP address. For example:

```json
{
  "listen_addr": "127.0.0.1:8080",
  "db_path": "/your/fresh/private-directory/warden.db",
  "security": {
    "public_origin": "https://warden.example",
    "rp_id": "warden.example",
    "mode": "proxy",
    "backend_authority": "127.0.0.1:8080"
  }
}
```

In direct TLS mode use `mode: "tls"`, `tls_certificate` and `tls_key`, and omit
`backend_authority`. The temporary listener requires TLS 1.3. Use a browser-trusted
certificate, including installing your private CA when appropriate; there is no
skip-verification mode.

Proxy mode is only for a **same-host** HTTPS reverse proxy. The HTTP backend must
bind a literal loopback IP, not `localhost`, wildcard or a remote address. The
proxy must enforce HTTPS, reject unexpected public hosts, remove untrusted
forwarded headers, and preserve the configured public Host or explicitly use the
configured backend authority. Warden does not trust forwarded headers to infer
HTTPS, RP ID or public origin. Other processes on that host are inside this trust
boundary. This does not alter external database or HTTP CONNECT proxy transport.

The eight-character setup password is printed **only to the controlling
terminal**, never stdout/stderr, URLs or logs. The global 15-minute lifetime starts
after successful bind/readiness, cannot be renewed, and permits at most 20 wrong
password attempts, rate limited to one/second with burst five. Only setup HTML,
its emitted dependencies, and `/api/v1/setup/*` are mounted. Normal management,
CLI, profile, report, transport, export/import and normal UI routes are absent.

## Complete setup

1. Open the configured public HTTPS origin and enter the terminal password.
2. Register the owner passkey with user verification. A separate assertion prompt
   is expected: registration may report PRF enabled without returning PRF results.
3. The browser requires a 32-byte WebAuthn PRF result, independently submits the
   signed assertion for server verification, generates a random DEK, wraps it via
   WebCrypto HKDF-SHA-256/AES-256-GCM, and tests the passkey wrapper roundtrip.
   PRF output is not identity proof and is never serialized to the server.
4. Save the displayed `warden-recovery-v1:...` key **offline and privately**. It is
   a plaintext secret; avoid shared/synced folders. Hide the displayed key and
   manually re-enter it from your saved copy. A checkbox cannot complete setup.
   The browser must unwrap recovery and derive its separate authentication subkey.
   Only the derived proof and recovered DEK are submitted over authenticated
   HTTPS, checked against the pending verifier/key-check. The raw recovery key
   never leaves the browser.
5. Finalization atomically publishes the complete identity and wrappers, closes
   the temporary listener and exits. Persisted state has no raw DEK, PRF output,
   recovery key, or recovery-auth subkey. Any restart remains locked; there is no
   persisted unlock token or master-key fallback. Start normal serve explicitly
   with the same configuration; it offers login/status while locked, never the
   old unauthenticated management plane.

Unsupported PRF, failed/canceled ceremonies, bad saved recovery proof, expiry,
process interruption or commit failure cannot create a partially initialized
identity. After a precommit interruption, a nonsecret config and OS-lock sidecars
may remain; rerun explicit init with that config/fresh DB path. A config
`*.setup.lock` lease covers prompts through setup; the independent DB `*.init.lock`
reservation still exclusively protects identity publication. Other initializers
cannot edit config during setup. File snapshots reject conflicting external
changes, but concurrent non-Warden edits of config/lock/storage are unsupported.
The kernel releases reservations on process exit; lock files are deliberately
not unlinked.
A crash can also leave a private `.warden-init-*.db` staging file. Init never loads
it as a fallback or deletes old artifacts automatically. After publication, rerun
init refuses the installation. A failed HTTP response around commit is ambiguous:
do not reset storage; retain it and inspect with the authenticated runtime.

## Recovery, replacement and rotation

1. At the HTTPS login view fill **Offline recovery key** and choose
   **Recover and replace all passkeys**. Re-enter the saved
   `warden-recovery-v1:...` key privately. The browser derives a separate
   authentication proof; the server verifies it before returning a recovery
   wrapper or accepting key delivery. The raw recovery key never goes to the
   server. Treat this proof as password-equivalent, not phishing-resistant.
2. After recovery unlock, the session is **restricted**: no managed reads,
   exports or general administration. Register a new passkey, complete its
   independent signed user-verifying assertion and PRF unwrap/rewrap check.
   Unsupported PRF fails explicitly; software passkeys are acceptable when
   they support the standard. There is no plaintext/key-only fallback.
3. Only a verified new wrapper preserving the same DEK permits the atomic swap:
   **all prior passkeys/wrappers are replaced**, all browser sessions and CLI
   authorizations invalidated, and the vault locked. Log in normally with the
   replacement passkey and unlock again. Reapprove CLI agents explicitly.
   Cancel/abort before commit preserves the old identity. A lost completion
   response is ambiguous: try ordinary login with the verified replacement;
   never delete storage or identity markers to retry.
4. Replacement keeps the recovery root. To rotate it separately while normally
   authenticated and unlocked, use Security's recovery-key rotation, freshly
   verify, save the new key, hide/re-enter it and confirm its local round-trip.
   The old key then fails against current state, **not against old backups**.

Keep at least one usable PRF-capable passkey and a separately protected saved
recovery key. Last-passkey removal is refused; loss of all usable passkeys AND
recovery means loss of vault access. There is no administrator bypass. Logout
ends only that browser session; Lock vault is global and drains new secret
emission before acknowledgement. Previously delivered bytes/proxy buffers or
retrieved remote credentials cannot be recalled. Every server restart is locked.

## Existing storage and limitations

Never point init at an old, unknown, corrupt or initialized database. It refuses
existing DB paths and sidecars without opening/migrating/chmodding them. Retain
the old binary, config, DB plus coherent WAL/SHM backup and master key. With the
old release, export the documented `warden-data` version 1; initialize **fresh
storage**, authenticate/unlock and follow the [manual import/verify/cutover and
rollback runbook](migration.md). T5 proof uses synthetic disposable data only;
no real migration is performed by this checkpoint. Export version 1 and external
transport behavior are unchanged.

Tests include real ECDSA-signed fixtures through the maintained verifier,
production init/serve/CLI executables over private-CA-verified HTTPS, explicit
proxy restart tests, and WebCrypto/shared vectors. The composed journey in
`scripts/test.sh` uses a real controlling PTY and synthetic signed credentials
and PRF material; no verifier bypass. Some older setup unit fixtures use an
explicit test-only ceremony seam. **A genuine PRF-capable authenticator's
positive HTTPS/browser ceremony with production trust remains pending.**
Mocks/vectors and the separately run synthetic Chromium CSP journey do not prove
provider/browser/authenticator PRF support. Native Windows execution is not
established by cross-compilation; jsdom alone cannot establish browser CSP.
Clearing Go/JS buffers is best effort; same-origin malicious JS or a compromised
live host/browser can steal live material.
