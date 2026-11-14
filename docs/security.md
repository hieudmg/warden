# Security model

Warden is a personal development aid, not a production security boundary.
Review code and deployment choices before using it with sensitive systems.

## Current local-agent boundary (T10)

The security-hardening branch authenticates and encrypts private local IPC with
TLS1.3 and a per-runtime exact certificate pin before any token/request/stream
bytes. Native filesystem ownership/mode or Windows owner/DACL validation protects
the public pin plus separate IPC token; TLS private keys stay in agent memory.
Pinning does not protect a compromised same-user account or administrator.
See the [IPC runbook](agent-ipc.md) and
[T10 report](superpowers/reports/2026-11-14-t10-agent-ipc.md). Native Windows
adversarial pipe/ACL execution is required and remains pending, not established by
a Windows cross-build. The daemon no longer exits when SSH graphs expire.

## Current client enrollment boundary (T4)

The same agent now owns memory-only API and polling secrets and performs HTTPS
requests for every current CLI data command. First use submits only a commitment;
the owner compares the displayed fingerprint in the web CLI-device view and
approves that exact pending commitment with a fresh passkey assertion. The
explicit `/api/v1/client/` capability allowlist cannot administer authentication,
unlock, export/import or read key vaults directly. Browser cookies and API bearers
are distinct audiences. Durable server hashes/revocation and recovery generation
are checked per request, again after acquiring a managed-data lease.

Credentials survive server restart (the vault remains locked), not agent exit.
Logout attempts revocation and clears agent memory even offline, without stopping
the daemon; offline failure does not establish remote revocation. No API secret
is persisted in config/keychain/IPC discovery or returned to CLI processes.
There is deliberately no token expiry, refresh credential or rotation: a stolen
copy remains usable until explicit revocation/recovery invalidation, including
after the legitimate agent exits. Already retrieved remote credentials/sessions
cannot be recalled. Go/JS reference clearing is best effort, not zeroization.

See [CLI enrollment](cli.md#login-logout-and-status) and the
[T4 report](superpowers/reports/2026-11-14-t4-client-enrollment.md). Synthetic signed
fixtures and TLS subprocess tests are not genuine PRF-positive/browser or native
Windows acceptance. T11/T12 file-transfer/SSH forwarding and broader cancellation
remediation remain separate; external DB/proxy behavior is unchanged. In-flight
context-insensitive SSH dialing can still delay shutdown until T12; no all-states
bounded-shutdown claim is made.

## Legacy transfer and rollback (T5)

Only [old-release v1 export → fresh init → manual import](migration.md) is
supported; no in-place legacy encrypted-DB compatibility or automatic deletion.
Export plaintext already contains the source values, so import needs only the
destination's freshly unlocked DEK, never a source master key. All managed data
is transactionally restored with original IDs/timestamps/references/notes/archive
flags and destination row/field AEAD. A failed import preserves managed state and
identity; a nonempty managed destination is refused. Initialized auth/session/
client/audit rows do not block import and never travel in the bundle. Approved
client verifiers remain bound to their existing destination generation.

Retain the old executable/config/coherent DB+WAL/SHM/key for rollback; verify full
data before cutover. Exports are plaintext offline secrets, and retained old
snapshots/keys/wrappers remain decryptable after current credential or recovery
rotation. Do not place exports in logs/shared/synced folders or infer disposal
from a successful import. Tests use only synthetic data/disposable SQLite; this
is not live-account, native Windows, browser PRF/CSP or release acceptance.
Existing external DB/proxy transport risks are unchanged.

## Historical pre-0.23 server notes

The server/master-key notes below describe the previous release, **not** the
breaking branch's current authenticated initialization/vault implementation or a
new security acceptance claim. For the current server workflow and remaining
acceptance limitations, use [initialization](initialization.md) and the
[approved design](superpowers/specs/2026-11-14-security-hardening-design.md).

### Previous trust boundary

The server has no application authentication. Tailnet membership is the trust
boundary: every peer that can reach the API can manage profiles, retrieve
credentials through transport endpoints, and run client operations.

Bind loopback and use a tailnet proxy, or bind directly to a Tailscale address.
Do not expose the API on a public interface. Runtime configuration accepts only
`localhost`, loopback, or Tailscale addresses.

## Credential handling

- Credentials are encrypted at rest with AES-256-GCM.
- Each value uses a fresh nonce and resource-bound additional authenticated
  data.
- The standalone 32-byte master key must have mode `0600`.
- The server owns the database and master key; it never executes commands.
- Normal API reads return redacted metadata.
- Decrypted transport responses use `Cache-Control: no-store`.
- Audit records contain operation/resource/source/result/timestamp, never
  credentials, SQL text, or command payloads.

Protect the master key separately from the database. Losing it makes all
stored credentials unreadable.

## SSH host keys

The client verifies host keys against:

- Linux: `~/.ssh/known_hosts`
- Windows: `%USERPROFILE%\.ssh\known_hosts`

Known keys are accepted. Changed keys fail as a possible man-in-the-middle
attack. Interactive `xssh` shows an OpenSSH-style fingerprint prompt for unknown
keys and persists only explicit confirmation. Non-interactive SSH-backed
commands fail closed and never prompt for unknown keys.

Malformed `known_hosts` lines are skipped OpenSSH-style, with a warning.

## Logging and secrets

Do not put credentials in server environment files, service units, command
arguments, reports, or logs. Server logs contain only lifecycle and audit-write
warnings.
