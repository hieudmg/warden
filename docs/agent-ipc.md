# Local agent IPC (security-hardening branch)

This describes the **implemented T10 IPC boundary**, preserved by T4's
same-agent API enrollment/transport. It is not OS-service packaging or a completed
security release. See [CLI enrollment](cli.md#login-logout-and-status), the
[T4 report](superpowers/reports/2026-11-14-t4-client-enrollment.md), the
[T10 evidence report](superpowers/reports/2026-11-14-t10-agent-ipc.md) and
[security plan](superpowers/plans/2026-11-14-security-hardening.md).
Native Windows execution remains required and **pending**.

## Runtime and trust

Login and all CLI API retrieval (including interactive SSH/direct DB commands)
start the existing client executable as `warden agent serve` when necessary.
This remains an internal command, not a new service or public configuration
surface. Interactive SSH/console and direct DB execution remain local. Commands never use a plaintext local-agent fallback.

The runtime lives under `os.UserCacheDir()/warden/agent`:

- Linux: `$XDG_CACHE_HOME/warden/agent`, or `$HOME/.cache/warden/agent`.
- Windows: `%LocalAppData%\warden\agent`.
- The Unix endpoint is `agent.sock`; the Windows named-pipe name is derived from
  the runtime directory. Predictability is **not** the authentication mechanism.
- `credentials-v2.json` has exactly a protocol version, a random 32-byte **IPC**
  token, and the runtime's public DER certificate (JSON byte fields are base64).
- `runtime.lock` is a persistent private lock file. Its *OS lock*, not its
  existence, denotes ownership. Do not delete a lock file to break a live lock.

Every new runtime generates an independent ECDSA P-256 self-signed certificate
and private key. The key stays in agent memory and is never serialized. The
client reads the public pin and IPC token together from one validated file,
trusts only that certificate using a dedicated trust pool, and checks the fixed
`warden-agent` name, validity and exact certificate. TLS is restricted to1.3;
no system-root acceptance, skip-verification, plaintext mode, session tickets,
client resumption cache, or early application data is enabled. The certificate
has a one-minute NotBefore clock allowance and a year9999 NotAfter: identity is
replaced at runtime restart, not by a timer or persisted-key renewal mechanism.
Go still checks validity; adversarial expired/future/name certificates must fail.

Dial plus handshake is bounded to2seconds; initial server handshake/token-frame
receipt and rejected-token response share a2second deadline. Overall client
attach/start/retry is bounded to5seconds (or the caller's earlier cancellation).
Only after successful TLS does a client send the existing bounded, token-checked
version2 request/stream frames. Frame bodies remain capped at1MiB. A pipe/socket
squatter sees TLS, not the IPC token, bundle, SQL, command or stdin. A transparent
relay can forward ciphertext, but cannot decode the protected application bytes.
Client relay teardown closes the raw transport before TLS Close on every exit,
including an already-cancelled caller, local frame-encoding failure, and a fully
received final response. Completed output/final frames remain authoritative;
TLS close-notify delivery to a nonreading peer is not a completion dependency.
Cancellation callbacks are stopped or joined before returning.

**The certificate pin is trustworthy only while native filesystem protections
hold.** Unix requires current effective-user ownership, private directory/socket/
file modes, no unsafe path symlinks, and descriptor-based file reads. Windows
creates protected current-user-only DACLs and validates owner/DACL, file type,
reparse state and link count on opened handles; POSIX mode bits are not proof on
Windows. Listener creation uses explicit current-user pipe ACLs and exclusive
first-instance semantics. Other-user ACL grants and unsupported ACL forms fail
closed, rather than being silently repaired. Same-user, administrator, kernel or
live-process compromise is not solved by TLS or pinning.

## Startup, crash and stale state

A starter acquires the lifetime OS lock, validates existing discovery state,
generates fresh in-memory identity, and owns the listener **before** publishing
credentials. A private exclusive staging file is completely written and synced,
then hard-linked exclusively into place. Readers cannot consume a partial JSON
publication. Readiness requires successful removal of the staging name, leaving
one credential link. An unlink error fails startup, releases its listener/lock,
and preserves both ambiguous names without retrying removal or repairing them.
Windows readers deliberately omit `FILE_SHARE_DELETE`; a read handle can prevent
that unlink. This sharing-race fixture still requires native Windows execution.
Unsupported private creation/publication fails closed. A short startup race may
require a bounded retry; there is no separate token file that can get out of sync
with the certificate.

A losing starter/client does not own cleanup rights. Only the runtime owning the
OS lock and listener can remove its discovery file. After a crash, the OS lock
is released; a later owner may replace a **validated** stale credential record
only after it also wins the listener. A Unix socket is removed only after an
ownership/mode/type check, a definitive connection-refused probe, and a second
same-inode check. Timeout, permission and other inconclusive probe errors never
justify deleting an endpoint. Windows does not join another pipe owner's
listener. Malformed, incompatible, broadly accessible, linked or substituted
credential paths are refused, not automatically overwritten. A crash between
hard-link publication and staging-name removal leaves two links; that
inconclusive state also fails closed for manual inspection rather than silently
trusting or deleting it. A normal post-Listen crash has a single-link record and
is covered by the automatic validated-stale restart test.

The private IPC format intentionally breaks compatibility with older agents.
Stop an identified old agent externally and retry using the new executable.
This also applies to an already-running T10 version2 agent that lacks T4 API
operations; upgrading the executable does not automatically replace its daemon.
An enrolled T4 agent restart loses authorization and requires web approval again.
Do not send requests to it in plaintext, delete live endpoint/lock files, or
chmod/chown an unknown credential/certificate path to make an error disappear.
If a startup error persists after **verified** process termination, inspect only
the private runtime directory and its native permissions/ownership; preserve
suspicious material privately for diagnosis. Manual replacement of corrupt state
must not affect server config, database, exports, SSH keys or recovery material.
Old unversioned `token` files are never used for version2 authentication. Crash
staging leftovers contain only IPC discovery material, never a TLS private key or
API token; their existence is not readiness or ownership.

## Daemon and graph lifetime

The daemon has **no timed or idle exit**, even with zero API credentials or an
empty SSH pool. Ten-minute idle eviction applies only to SSH graphs, after the
last lease releases; all graphs expiring does not end the daemon. External
context cancellation closes the listener/active IPC connections, closes owned
cached and retired-active graphs, joins handlers and cleans runtime discovery.
Ordinary pool retirement/Close still lets active leases finish; forced closure
is specific to daemon termination. Unix SIGTERM/interrupt is wired to that clean
cancellation path. This is **not an all-states bounded-shutdown guarantee**:
`Pool.shutdown` skips still-dialing entries, and chained `via.Dial` / SSH handshake
work does not promptly obey context cancellation in every state. Handler joins
and runtime-discovery cleanup can therefore wait on an in-progress graph dial.
Those known limitations remain T12 work; the acquired-graph shutdown tests do not
prove cancellation of graph acquisition. Forced process termination/crash may
leave stale files and is handled by the startup rules above, not a promise of
crash-time cleanup.

T4 now adds memory-only API/poll-secret ownership and tests logout, revocation,
outage, server restart and vault lock against this same daemon, including fake
clock advancement beyond graph TTL and then years. None is an exit condition.
Logout clears local authorization even offline but cannot establish remote
revocation while unreachable. Server restart retains verifiers but locks the
vault; agent exit loses its copy and requires approval again. A stolen token
remains valid until server revocation/recovery invalidation; previously retrieved
remote credentials/sessions cannot be recalled. Browser session lifetimes,
recovery policy, external DB/proxy transports, SFTP validation and SSH forwarding
behavior are unchanged by T4.

## Disposable checks (not against a running user agent)

```sh
go test ./internal/client/agent ./cmd/warden -count=1
go test -race ./internal/client/agent ./cmd/warden -count=1
go test -race ./internal/client/agent -run 'TestRuntimeCrashStartup|TestRuntimeConcurrentStartup|TestAuthAgentLives|TestSSHPoolIdle|TestServerExternalCancellation|TestRelayRequestClosesRawTLSBeforeCloseNotifyOnEveryExit|TestRuntimePublicationUnlinkFailureIsNotReady' -count=20
```

Tests use `NewRuntimeAt` private fixtures or subprocesses with isolated existing
OS cache/home configuration, never the default live user agent. Required native
Windows execution (run on Windows, capture OS/Go versions, all failures/skips):

```powershell
go test ./internal/client/agent -run 'TestPipeSquatter|TestRuntimeACL|TestRuntimeWindows|TestRuntimeCrashStartup|TestRuntimeConcurrentStartup|TestRuntimeBindBeforeDiscovery|TestRuntimeInterruptedPublication|TestRuntimePublicationUnlinkFailureIsNotReady|TestRelayRequestClosesRawTLSBeforeCloseNotifyOnEveryExit|TestAgentTLS|TestAgentAuthenticates|TestServerInitialAuthenticationDeadline|TestConnectOrStartOverallDeadline|TestAuthAgentLives|TestSSHPoolIdle|TestServerExternalCancellation|TestAgentOwnsAPIToken|TestAgentAPIMemoryLifetime|TestConcurrentLoginRequests|TestAPIRequestAndSecretResponse' -count=1 -v
```

Reparse/symlink privilege skips and wrong-owner fixture limitations must remain
visible. Cross-compilation only checks syntax/types/linking; it is not NTFS or
named-pipe security evidence.
