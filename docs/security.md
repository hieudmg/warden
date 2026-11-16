# Security model

Warden is a personal development aid, not certified production-hardened software.
The 0.24.0 implementation nevertheless makes **mandatory application
authentication** a security boundary, independent of network membership. Normal
management requires an account or passkey session and unlocked vault; CLI retrieval requires
an individually web-approved credential. Setup, web and client APIs require
configured HTTPS. A private tailnet is optional defense in depth, never an auth
bypass. Review deployment choices before using sensitive systems.

## Vault custody, recovery and release gates

Explicit `warden-server init` is the only bootstrap: an eight-character CSPRNG
terminal-only password, absolute 15-minute ready-time lifetime, bounded guesses,
setup-only routes and a terminal-selected authentication method. Account is the
new-init default; legacy missing mode means passkey. A passkey installation uses
signed WebAuthn UV registration/assertion and required PRF. An account installation
creates one username/password credential, not a synthetic WebAuthn credential.
There is no first-visitor initialization, unauthenticated mode, TOTP, dual
account/passkey enrollment or mode conversion. A random DEK encrypts fields with
AES-256-GCM and row/field AAD. Passkey PRF/HKDF/AES-GCM and high-entropy recovery
wrappers protect that DEK; no disk plaintext vault key or fallback is loaded.
Account passwords are submitted over configured HTTPS and wrap the DEK using
server-side Argon2id (x/crypto v0.56.0, RFC 9106 low-memory recommendation:
64 MiB, time=3, lanes=4, 32-byte output), random 32-byte salt and AES-256-GCM with
fresh nonce and version/purpose/vault/credential binding. Stored KDF parameters
must exactly match version 1 before allocation; there is no decrypt-capable
password verifier separate from the envelope. Username is exact UTF-8, 1–64
bytes, without surrounding whitespace or controls; password is exact UTF-8,
12–1024 bytes, with no trimming/normalization or composition rules. Wrong username
still performs password derivation before the same generic failure. Four bounded
runtime crypto slots (up to 256 MiB Argon2 working memory) and two setup slots
bound work before body reading; rate limits still apply. Slow KDF work runs
outside the publication mutex, then rechecks identity generation, session,
recovery reservation, vault epoch and cancellation before publishing access.

Account login authenticates **and unlocks**. After lock, re-unlock requires a new
password submission. Sensitive operations prompt for the password again in an
in-app modal, issuing the same short-lived, exact-request/session/credential/
vault-epoch-bound single-use grants. The browser never caches a password for a
future action. Account recovery uses the offline key, wraps the **same DEK** with
a new password/random credential ID, verifies the wrapper round-trip and commits
via identity CAS with all-session/client revocation; abort/failure preserves the
old identity. Recovery-key rotation uses fresh password verification too.

PRF output is key material, **not a signed identity proof**. Software passkeys
are supported by standards, not a vendor allowlist; unsupported PRF explicitly
fails without downgrade. Login can work locked without PRF, unlock cannot.

Restart is always locked. Logout revokes only that session, not the global key;
global lock is separate and cancels/drains secret response emission. Checked
writes and HTTP/1 flush remain inside the delivery lease, with joined cancellation
and current authentication/recovery revalidation after acquisition. The guarantee
is server emission into the network stack, not client receipt, proxy-buffer
revocation, future HTTP/2 proof or erasure of already retrieved credentials.

Save/re-enter recovery at setup and rotation. Verified recovery is restricted to
unlock and credential replacement, not management/export. In passkey mode, only
a new signed PRF-capable passkey and same-DEK wrapper round-trip permit one atomic
commit replacing **all** old passkeys/wrappers and revoking sessions/clients.
Account mode instead replaces the password credential as described above. Abort
preserves identity; success returns to ordinary login. Rotation is separate.
No last-passkey deletion or administrator/recovery-without-key bypass exists.
See [initialization/recovery](initialization.md) and [migration/rollback](migration.md).

Live compromise of browser/provider/OS, same-origin JS, unlocked server, service
account or trusted terminating proxy can steal live material; this is not zero
knowledge. Clearing Go/JS references is best effort, not guaranteed GC/string/
crypto-copy zeroization. Protect process memory/core dumps/swap and backups.
Metadata is not all encrypted. Old backup wrappers/recovery material remain
usable after current revocation/rotation; remote credentials already retrieved
must be rotated at the remote system after exposure. Losing the account password
(or every usable passkey) and saved recovery key means losing vault access.

The [T17 acceptance matrix](superpowers/reports/2026-11-14-t17-integration.md)
distinguishes local PASS from remaining **UNRUN** genuine authenticator PRF with
production trust, native Windows and hosted artifact/OIDC/signature checks.
Synthetic signed fixtures/injected PRF/test-only certificate exceptions are not
those proofs. This is not release readiness. Source scans retain eight Go
module-only findings; stripped release-binary scans conservatively exit 3, not
zero. The owner accepted only the identified enabled Undici trusted-service/
terminating-proxy risks and Sigstore DSSE/PAE type-binding limitation in the
[T16 risk report](superpowers/reports/2026-11-14-t16-action-runtime-risk.md), not
all action audit findings or downstream verification. Retain exact byte/source/
run/type guards and direct official attester; await official fixes. Mutable
same-version force/clobber and executable-only/manual-restart policy are
intentional, not immutability/anti-rollback guarantees.

Warden-owned HTTPS does **not** add verified TLS to existing external database
or HTTP CONNECT proxy legs. Basic credentials/data can traverse plaintext directly
or onward beyond an SSH endpoint. These owner-scope-excluded risks remain, not
end-to-end confidentiality claims. No DB/proxy profile or v1 export format change.

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
approves that exact pending commitment with fresh password verification (account)
or a passkey assertion. The
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
Windows acceptance. T11 transfer boundaries and T12 SSH lifecycle evidence are
recorded separately; external DB/proxy behavior is unchanged. The T12 boundary
below replaces the previously context-insensitive network establishment path;
it is not a preemption guarantee for arbitrary callbacks or console readers.

## API redirects and diagnostic output (T13)

The existing T4 owned HTTPS transports refuse **all** API redirects before a
second request, including same-origin redirects and 301/302/303/307/308 POST
rewrites/replays. Caller-injected network clients are copied, use owned guarded
standard transports, retain ordinary TCP routing/trusted roots and cannot replace
origin verification with arbitrary RoundTrippers or TLS protocol delegates.
The explicit agent IPC constructor remains separate. T13 adds verified two-peer
HTTPS characterizations, not a new post-response URL check or a transport-policy
change. Actual agent-produced bearer/body requests reach the trusted origin;
redirect targets receive zero requests, authorization bytes and body bytes.

API `Error()` and CLI diagnostic rendering now visibly escape terminal controls,
nonprintables and invalid UTF-8, preserving printable Unicode, with a **1,024
encoded UTF-8 byte** limit including escape expansion and safe truncation. The
CLI's fixed command prefix/newline is additional. Structured API fields keep
their data meaning and normal JSON encoding; this is not secret redaction or
an audit-policy change. Table column headers now use the existing DB cell
sanitizer, like TSV headers already did: control characters become spaces and
TSV delimiters remain intact. No arbitrary header-length truncation was added.
SSH interactive/exec byte streams and binary/file transfers are not filtered.
See [CLI diagnostic details](cli.md#diagnostic-text) and the
[T13 implementation report](superpowers/reports/2026-11-14-t13-client-output.md).
Native execution and overall acceptance remain separate; distribution and
dependency evidence are recorded in T14–T17, not inferred from redirect tests.

## SSH authentication and graph lifecycle (T12)

SSH_AUTH_SOCK can authenticate a connection, but never implicitly enables agent
forwarding. Exec, interactive and reused graph sessions send no forwarding
request. Each graph owns its raw transports and authentication sockets, closes
logical clients in reverse order and closes sockets once. Authentication uses
the pinned agent library's synchronous RPC path, not an idle pipeline reader.

Node network establishment is bounded by 15 seconds or the earlier caller context.
TCP dial, SSH handshake, second-hop direct-tcpip opens, raw/through-hop CONNECT
and DB channel opens have context-driven owned-transport abort protection even
when SetDeadline returns unsupported/error. Successful negotiation stops and
joins its cancellation callback before clearing a supported deadline and
publishing a reusable connection. Reset failure rejects the transport. DB Close
joins pending opens. Cancellation can abort the root socket before reverse
logical teardown because an SSH channel Close itself may block on a write.

An unconfirmed SSH OpenChannel has no per-request cancellation handle in pinned
x/crypto v0.56.0. A borrowed DB dialer therefore holds an explicit pool owner,
not just a target pointer. Canceling such an open invalidates and aborts **that
same graph**, including concurrent leases on that connection; it is removed from
reuse with reason `SSH channel open canceled; connection-level abort required`.
Independent healthy pool graphs remain usable, and later acquisition can create
a replacement. Healthy completed opens/ordinary borrowed Close do not force
invalidation. Ordinary operation failures still use lease-safe retirement.

Pool entries own cancelable dial contexts before they have Graph values.
External termination cancels those owners, aborts acquired graphs and joins IPC
handlers; canceled/shutdown publication reclaims late graphs without leases.
Graph TTL remains independent of the permanent-until-external-stop daemon and
approved memory-only API-token custody. No token expiry/timer/rotation or auth
policy change was added. Arbitrary injected dialers/host-key callbacks that do
not return, and blocked local console readers, are not made preemptible.

The previously intermittent DB whole-chain test was reproduced and traced to an
actual upstream TCP/worker leak in its test relay, not assumed counter timing.
A deterministic EOF regression, endpoint closure before joining, balanced
accepted/completed counters and joined drains fix that fixture while retaining
the 5-second whole-chain bound and checking graph Close errors. This is separate
from the production cancellation fixes.

See the [T12 evidence report](superpowers/reports/2026-11-14-t12-ssh-lifecycle.md)
for exact RED/GREEN, real handler/drain completion and the historical PTY
failure chronology. Native PTY evidence later demonstrated why immediate
SIGINT/EOT sequencing is not a valid fixture assumption; the fixture now waits
for a later private shell prompt before its single EOT, retaining the 10-second
bound and joins. That does not establish the parent's exact failed syscall
ordering or a production input-pump defect. T15 additionally fixed independently
attributed SSH relay fixture leaks and upgraded x/crypto to v0.56.0. Fresh T17
checks are in its matrix; historical passing reruns alone are not the fixes.
Native Windows and overall acceptance remain pending. External DB and
CONNECT proxy transport is unchanged: Basic credentials and onward traffic may
still traverse plaintext beyond SSH's encrypted segment. No end-to-end external
TLS, genuine PRF or production-browser trust claim follows from these tests.

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

## Transport graph validation and budget (T7)

A complete SSH or DB transport resolution permits **1,024 expanded profile
occurrences**, not 1,024 distinct IDs or edges. Charge the root as occurrence 1,
then each followed reference **before lookup and recursive descent**, even when
that ID appeared earlier. A tunneled DB root, its SSH target, and every expanded
SSH hop share one budget. A direct DB consumes one occurrence. Key-pair presence
checks/loads do not add profile occurrences; each is bounded by an already
charged SSH occurrence. Existing depth **32 SSH nodes per path**, including the
SSH target, remains independent; a DB root does not add SSH depth.

Examples (letters stand for synthetic profile IDs, not credentials):

- SSH `R -> [L repeated 1,023 times]`, with no jumps on `L`, uses 1,024
  occurrences and succeeds. One more `L` is rejected before its lookup.
- DB `D -> R -> [L repeated 1,022 times]` uses the same 1,024 occurrences;
  one more `L` fails. The SSH sub-resolution cannot reset the budget.
- If `R -> [B,A,B]` and `B -> [A]`, the six-occurrence SSH resolution returns
  jumps `[A,B,A,A,B]`, then the separate target `R`. Nothing is deduplicated.

Validation reads metadata only: all reachable routes, missing/archived targets
and hops, cycles, depth/budget, and selected key-pair existence/private-key
presence. Only a fully valid graph can load passwords, proxy passwords or key
material. Stored route arrays are parsed incrementally, without first allocating
an unbounded edge slice. Failure returns no partial bundle. Initial missing
profiles and any archived profile retain generic `404 not_found`; malformed,
cyclic, missing-hop, missing/cleared-key, depth and budget failures use
`422 invalid_graph`. New graph errors contain fixed text/numeric IDs/limits,
never raw stored JSON. The separate T8 audit boundary below handles raw
audit-value cleanup.

Both phases use **one SQLite read transaction**. Its first metadata read fixes
which rows are validated and later decrypted; concurrent profile/archive/key
updates cannot replace the graph or selected secrets between the phases.
Updates can commit under WAL, and later resolutions see them. This is snapshot
consistency, not retroactive cancellation of an already admitted resolution
when a profile is subsequently archived. The transaction is closed on every
exit and exposes no write operations. The existing runtime vault/response lease
still independently protects key access and response emission through lock.

Cancellation is checked before opening a snapshot, before each profile lookup
and recursive descent, during edge traversal/key-presence validation, and before
secret loads and successful return. SQLite reads use the request context.
Cancellation rejects without a partial bundle; cancellation during metadata
validation triggers zero decrypt callbacks. Already started, bounded field-codec
calls are synchronous, not individually interruptible. This is an operation-count
bound, not a wall-clock guarantee for arbitrary storage or a new transport/SSH
network cancellation claim. At most 1,024 profile metadata lookups occur; at most
one key-presence query per SSH occurrence follows. After validation, each profile
occurrence loads once and each selected pair at most once per SSH occurrence
(duplicates preserved), bounding total row queries by 4,096 and field decrypt
callbacks by 5,120, with fewer when fields/key selections are absent.

See the [T7 evidence report](superpowers/reports/2026-11-14-t7-graph-budget.md).
Archive persistence, dangling soft-reference import, the `warden-data` v1
transfer format and exports are unchanged. No external DB/proxy TLS was added.
Independent review and genuine PRF/browser/CSP/native Windows acceptance remain
separate pending requirements.

## Audit classifications and metadata boundary (T8)

New profile/report and runtime security audit events retain server-owned operation
and resource-type names, result, server timestamp, positive numeric resource IDs
when available, and the socket peer's canonical numeric IP/address-port. Project
names, report labels/agent models and raw request paths/queries are not audit IDs.
`Forwarded`, `X-Forwarded-*` and caller identity headers cannot supply source or
actor identity. Missing/invalid/overlong peer addresses are omitted, not truncated
into another address.

The audit `error` field is empty for success or one of these fixed classifications:
`validation`, `invalid_json`, `invalid_graph`, `unauthorized`, `locked`,
`rate_limited`, `storage`, `internal`, `not_found`, `conflict`, `payload_too_large`,
`cancelled`, `timeout`. Known sentinels are classified without their messages;
unknown errors become `internal`. No raw `err.Error()` fallback or truncation of
validation values is permitted. Runtime security events classify HTTP outcomes
and include numeric `status`; generic 5xx outcomes are `internal`. This is an
audit boundary, not a change to existing validation-response envelopes.

Allowed metadata is deliberately small:

- `archived`: a boolean; `groups`, `key_pairs`, `ssh_connections`, `db_connections`,
  `projects`, `reports`, `connection_notes`: nonnegative built-in integer counts.
- `status`: a built-in integer HTTP status (100–599).
- `credential_id`: the validated authenticator's public credential ID (at most
  1,366 base64url-alphabet bytes, corresponding to the existing 1,024-byte ID cap).
  `client_credential_id`: a validated nonsecret durable client ID (at most 128
  base64url-alphabet bytes). HTTP recorder actors come from server-authenticated
  request context, never caller metadata or headers. Anonymous/restricted-recovery
  requests have no fabricated credential actor. Sessions currently have only a
  token hash, not a separately safe session ID: **that hash is not recorded**.
- `user_agent`: an explicitly permitted untrusted header, capped at **512 bytes**
  before UTF-8/control filtering. A split final UTF-8 sequence and controls are
  dropped. The stored value can therefore be shorter (e.g. 510 bytes for a split
  three-byte character). This field is not a secret detector: callers must not
  place secrets in User-Agent; the allowance does not extend to error messages.

Metadata is at most **4,096 encoded JSON bytes**, including keys, punctuation and
escaping, not 4,096 runes. Only fixed known fields with exact built-in primitive
types are considered. Unknown fields, nested/cyclic containers, channels,
custom Stringers/JSON marshalers and oversized ID values are omitted without
walking/marshaling their contents. Counts and actors are prioritized; UA is
omitted if its escaped encoding would exceed the total cap. Caller maps are not
mutated. No names, model/device labels, report contents, SQL, passwords, raw
bearer/session/poll/action tokens, full token verifiers, recovery proofs/roots,
PRF output or DEKs are allowed in these fields.

Runtime security events cover the exact existing login/fresh, lock/unlock/logout,
passkey, recovery/rotation, CLI pairing/poll/status/logout and web client-management
routes on success/failure. They preserve the original response status and existing
response-controller/lease/abort protections. Setup/auth verifier packages had no
audit recorder or slog producers; setup has no durable store before finalization
and does not log raw setup passwords/proofs/errors. Existing profile/report events
remain enabled. Audit insertion failure returns only `audit persistence failed`
and emits a generic `audit write failed` warning classified `storage`, never the
original driver error or SQL parameters. Existing best-effort event-write handling
is retained; this is not a new transactional fail-closed mutation policy.

The SQLite schema and managed `warden-data` v1 transfer contract are unchanged.
There is no audit-list API/UI consumer in the current source. These limits apply
to **new recorder events**, not historical rows: previously stored plaintext audit
values are not automatically rewritten or deleted. Audit/auth/session/client state
is still excluded from export/import. Protect retained databases/backups and do
not infer that this change removes earlier exposure. The low-level store append
method persists already-vetted events; all current production producers use the
recorder. See the [T8 evidence report](superpowers/reports/2026-11-14-t8-audit-boundaries.md).
Independent review and genuine PRF/browser/CSP/native Windows acceptance remain
pending; this is not a security-release acceptance claim.

## File-transfer path and staging contract (T11 — revised owner decision)

Recursive entries and source basenames appended to an existing destination
directory now use a portable single-component contract, checked **before either
source or destination join**:

| Rejected components | Reason |
| --- | --- |
| Empty, `.` or `..`; `/` or `\` anywhere | Parent, rooted/UNC or separator traversal |
| `:` anywhere | Windows drive-qualified/relative names and alternate data streams |
| Invalid UTF-8, ASCII controls below U+0020, `< > " ? *` or U+007C (vertical bar) | Unsupported native Windows names or ambiguous encoding |
| Trailing dot or space | Windows component aliases |
| Case-insensitive `CON`, `PRN`, `AUX`, `NUL`, `CONIN$`, `CONOUT$`, `COM1`–`COM9`, `LPT1`–`LPT9` (including superscript ¹/²/³ variants), also before an extension | Reserved Windows devices; trailing spaces in the stem are ignored for this check |

Ordinary Unicode, internal spaces, `.hidden`, `..child`, `COM0` and `COM10.txt`
remain supported. This intentionally rejects some legal POSIX **entry names**,
including colon names in recursive copies or basenames appended to directories.
It does not reinterpret caller-supplied full POSIX paths as Windows paths:
explicit `source:literal` to explicit `target:literal` remains supported on POSIX.
An explicit caller directory source `.` or filesystem root retains the existing
“copy contents into this directory” behavior: the destination root is used
directly, with no dot/root component joined. Untrusted directory entries never
use this exception; dot/parent entries are still rejected.

Original operands are checked component-by-component with Lstat **before**
lexical normalization, rejecting existing symlink components even before `..` or
behind a trailing slash/dot. Source metadata and reads retain the caller's
operational spelling: `/work/link/../file` is rejected, never silently replaced
by `/work/file`. Missing/non-directory source components cannot be erased to
select another file; a missing destination component followed by `..` also fails
before writing. Local comparison paths use native `filepath.Abs`; remote paths
stay in the independent POSIX `path` namespace, without Windows volumes or case
folding. Each derived destination child must have native/adapter Rel equal to
its validated name. Local relative-source to absolute-descendant self-copy and
source-ancestor aliases into real descendants are rejected before creating the
target. Source symlink/special-file denial and same-host/self-copy safeguards
remain; existing destination symlink components are rejected for single files
as well as directories. These lexical/Lstat checks are not race-proof rooting
against concurrent replacement of writable ancestors, nor a case-normalization
or native Windows execution claim.

The owner's revised contract retains local exclusive private sibling staging
**at creation**, including native owner/DACL privacy on Windows rather than
POSIX-mode claims. Remote staging is explicitly permitted to use exclusive OPEN
followed by **handle-based chmod0600 before any Write**. Failed/unsupported chmod
must close and clean only the newly owned stage, with no content writes. File
and symlink collisions must not be truncated or removed. Copy/close/final-mode/
rename failures must preserve the old target; no delete-target rename fallback.

**Owner-accepted remote residual risk:** OPEN cannot send creation permissions
through this pinned public client API. The new empty file may initially be
public. Another user can open it before chmod and retain a descriptor to read
later contents, or write if initial permissions allow; chmod does not revoke
that descriptor. This is not private-at-creation or full satisfaction of the
original T11 staging guarantee. No fork, new SFTP library, dependency update,
custom frames or rsync implementation is authorized. A possible future
cp-to-rsync replacement is outside this PR.

The revised flow is implemented without dependency changes: POSIX local stages
use O_EXCL/0600, Windows stages request and validate a native protected owner-only
DACL at CREATE_NEW, and remote stages use exclusive OPEN plus handle FSETSTAT0600.
Real in-process SFTP tests observe initial mode0644, then0600 before any WRITE;
that initial public mode is the accepted gap, not a failed attempt to meet the
old guarantee. Unsupported/denied chmod tests observe zero writes, one close and
owned-stage removal. File/symlink collisions remain intact. Only after content
and both successful closes does the copy apply source mode and atomically rename;
there is no delete-old-target fallback. Cleanup failures are returned, not hidden.
Directory copies are not whole-tree transactions and may leave a partial tree.
Native Windows ACL/path/replacement tests are supplied and cross-compiled, but
not executed; Windows behavior remains an external acceptance requirement.

See the [T11 measured implementation and historical API blocker](superpowers/reports/2026-11-14-t11-sftp-boundaries.md).
The historical API blocker applies to the original stronger contract; the owner
has now authorized the limited flow above without changing dependencies. Native
Windows traversal/ACL/replacement tests remain required and unverified. This
section records authority and remaining evidence, not release acceptance.

## Legacy keys are rollback-only

Pre-0.23 releases used a standalone plaintext master key and lacked application
authentication. Retain that exact old key with coherent old artifacts only for
the [manual old-release export/rollback workflow](migration.md). Never copy it
to the new runtime as a fallback or start the old release on the new database.
Current storage uses wrapped custody above. Normal reads redact secret fields;
auth/data/error responses are no-store. Audit limits apply to new events, not
old rows or a guarantee against caller-supplied secrets in allowed User-Agent.

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
