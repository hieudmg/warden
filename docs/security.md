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

This is not API-token enrollment: T4's memory-only API credentials and client
route audience remain planned. T11/T12 file-transfer/SSH forwarding and broader
cancellation remediation remain separate; external DB/proxy behavior is unchanged.

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
