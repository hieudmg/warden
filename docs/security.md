# Security model

Warden is a personal development aid, not a production security boundary.
Review code and deployment choices before using it with sensitive systems.

## Trust boundary

The server has no application authentication. Tailnet membership is the trust
boundary: every peer that can reach the API can manage profiles, retrieve
credentials through transport endpoints, run client operations, and invoke
server-side HTTP requests with stored credentials. No login, session or vault-lock
mechanism is introduced by HTTP profiles.

Bind loopback and use a tailnet proxy, or bind directly to a Tailscale address.
Do not expose the API on a public interface. Runtime configuration accepts only
`localhost`, loopback, or Tailscale addresses.

## Credential handling

- Credentials are encrypted at rest with AES-256-GCM.
- Each value uses a fresh nonce and resource-bound additional authenticated
  data.
- The standalone 32-byte master key must have mode `0600`.
- The server owns the database and master key; it does not execute SSH commands
  or SQL, but does send HTTP requests with stored credentials.
- HTTP management reads (list, individual GET and write responses) return only
  metadata/presence flags. Even Basic username is encrypted and never returned.
  There is no HTTP saved-secret download or transport endpoint.
- SSH/database metadata reads are redacted. Existing transport endpoints and
  individual key-pair vault reads intentionally disclose credentials/key material.
- Decrypted transport responses use `Cache-Control: no-store`.
- Audit records contain operation/resource/source/result/timestamp, never
  credentials, SQL text, or command payloads.

Protect the master key separately from the database. Losing it makes all
stored credentials unreadable.

## HTTP destinations and transport

An HTTP profile fixes the origin (`scheme://host[:port]`); callers supply only an
origin-relative request path/query. Absolute URLs, scheme-relative URLs,
fragments and origin credentials are rejected. Only Bearer, X-API-Key or Basic
authentication is injected, not incoming cookies, Authorization or Host headers.
Redirects are never followed, HTTPS uses normal certificate verification, and
upstream headers (including Set-Cookie and Location) are not returned. The proxy
does not use ambient proxy settings, a cookie jar or reusable connections.

**Plain HTTP is explicitly allowed and is not confidential or integrity-protected.**
Credentials, paths, bodies and responses can be intercepted or modified. Prefer
HTTPS. Any configured host is allowed, including server loopback, private and
internal destinations. Network-trusted management callers may create/change
origins and use stored credentials: this is not an SSRF isolation boundary or an
application-authenticated credential vault. Restrict server egress externally
where appropriate.

Request bodies are bounded to 1 MiB, responses to 2 MiB and operations to 15
seconds. Cancellation propagates upstream. Proxy responses use `Cache-Control:
no-store`; transport failures are generic and do not disclose raw URLs, TLS
errors or credentials. Audits omit request paths, bodies and credential fields.
Upstream bodies are returned unchanged, even on non-2xx, and are not secret
sanitizers: a destination may echo credentials or return untrusted terminal data.

Full-data export is the intentional plaintext migration exception. It includes
all HTTP secrets as well as existing passwords and key material, with
`Cache-Control: no-store`. Protect/delete downloaded files after migration.
Import re-encrypts using the destination master key and requires an empty managed
dataset. Encryption at rest does not protect against a caller who can reach the
network-trusted management API or a host compromise exposing the master key.

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
