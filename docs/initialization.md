# Explicit initialization and authenticated runtime (T1–T3 checkpoint)

Initialization remains a separate setup-only process. After it exits, normal
`warden-server serve --config /your/fresh/private-directory/server.json` now
starts the authenticated HTTPS runtime **locked**, without loading a disk key.
Log in with the registered passkey, then use a new required-UV assertion and PRF
unwrap to unlock management. Logout revokes only that browser session; Lock vault
cancels/drains global key access. Key reveal/mutation and documented v1
export/import now require a new passkey assertion bound to the exact request.
Legacy management transport remains blocked; the future client audience is not
implemented. Security controls add/revoke passkeys (never the last active one),
rotate recovery with saved re-entry, and offer restricted offline-key recovery.
Recovery MUST verify a new PRF passkey before atomically replacing ALL old
passkeys/wrappers, revoking sessions/client authorizations, and returning locked
to ordinary passkey login. Abort leaves the old identity intact. Recovery alone
never permits management/read/export and does not rotate the recovery root.
See the [T3 implementation/evidence report](superpowers/reports/2026-11-14-t3-passkeys-recovery.md)
for disposable journeys and the T4 generation contract. Genuine PRF-positive
HTTPS/browser, native Windows and production-browser CSP acceptance are pending;
this is not verified M1 or a release-ready security upgrade.

## Build and run against fresh disposable storage

```sh
npm --prefix web run build
go build -o /tmp/warden-server-t2 ./cmd/warden-server
/tmp/warden-server-t2 init --config /your/fresh/private-directory/server.json
```

Run from an interactive controlling terminal. Without `--config`, init also
prompts for the config path. It asks for a **fresh DB path**, public HTTPS origin,
RP ID, `tls` or `proxy` mode, and listen address. TLS mode asks for certificate and
private-key paths; proxy mode asks for the explicit loopback backend authority.
Configuration contains no vault key or authentication secrets and new files use
POSIX mode 0600. Native Windows ACL/privacy behavior is not verified here.

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
identity. After a precommit interruption, a nonsecret config and OS-lock sidecar
may remain; rerun explicit init with that config/fresh DB path. The kernel releases
the reservation on process exit; the lock file is deliberately not unlinked.
A crash can also leave a private `.warden-init-*.db` staging file. Init never loads
it as a fallback or deletes old artifacts automatically. After publication, rerun
init refuses the installation. A failed HTTP response around commit is ambiguous:
do not reset storage; retain it and inspect with the authenticated runtime.

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
setup HTTPS tests with a test-only ceremony seam, normal-runtime subprocess
TLS/proxy restart tests using the real verifier, and WebCrypto/shared vectors. **A genuine PRF-capable authenticator's
positive HTTPS/browser ceremony remains external acceptance pending.** Mocks and
vectors do not prove provider/browser/authenticator PRF behavior. Native Windows
execution and full browser CSP enforcement are also not established by Linux
cross-compilation/jsdom. Clearing Go/JS buffers is best effort; same-origin
malicious JS or a compromised live host/browser can steal live material.
