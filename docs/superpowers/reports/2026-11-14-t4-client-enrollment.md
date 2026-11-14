# T4 — web-approved client enrollment and same-agent API custody

## Scope and status

Bounded implementation/self-review on `hieudmg/security-hardening`, reviewed T10
and correction base **`852eed9`**. The owner authorized T4 after T10, not T5 or a
release. Existing T1–T3 identity/CAS/session/recovery/delivery and T10 TLS/native
IPC/lifetime contracts remain binding. No commits, staging, push, PR, worktrees,
children, deployment, live agent/data operations, dependency/version changes or
real database use. The protected unrelated `mise.toml` was not read or changed.
Tests use disposable SQLite, HTTPS/private-CA and synthetic remote fixtures.

**Implemented, not independently accepted; no M1/security-release claim.** Genuine
PRF-positive browser/authenticator, production-browser CSP/network and native
Windows execution remain REQUIRED/PENDING. Cross-compilation is not native proof.
T11/T12 transport remediation, broad T13 hardening, T5 transfer changes and
installer/publication work remain separate. The minimal no-redirect credential
policy is included here because new bearer delivery cannot safely defer it.

## Implemented boundaries

### Server verifier, enrollment and audience

- New `client_credentials` schema stores only commitment/verifier, public ID/label,
  authorization generation, creation time and revocation. Fresh runtime schema is
  v8. Only the exact reviewed initialized v7 schema can upgrade; strict unknown/
  dirty schema refusal remains. Identity, sessions, wrappers and counters survive
  this upgrade. Legacy encrypted releases are not made compatible.
- `POST /api/v1/client/pairing` accepts a locally computed commitment and printable
  1–80-byte device label. Server creates a random request ID and a **separate
  32-byte poll secret**, returning the latter only over HTTPS to the producer's
  agent consumer. Pending state stores its hash. API secret is generated and
  retained by the agent, never generated/delivered by a browser or CLI.
- Pending requests expire in five minutes, cap at 20, creation token bucket is
  1/s with burst 5, and authorized polling is coalesced/limited to 1/s per pending
  request. Invalid/unknown/wrong polling proofs get generic denials. Pending
  status authorizes no data. Finished states remain bounded by the same expiry.
- Browser approval/denial targets the exact ID and commitment. Fresh, single-use
  `client_approve`/`client_revoke` grants bind method/path/SHA-256 exact body,
  current session/credential and epoch as in T3. Approval holds the pending lock
  and inserts through an identity-CAS writer transaction; recovery cannot rebind
  an old approval to a new generation. Replay, denial, expiry, concurrent
  approval and generation changes cannot create another usable credential.
- Active verifiers cap at 128. Approval prunes revoked/older-generation rows so
  recovery cannot permanently exhaust capacity. Only durable hashes are stored;
  export/import neither transfers authorization rows nor treats them as vault
  content. Revocation survives reopening the store.
- `/api/v1/client/` uses explicit registrations: SSH/DB list/get/dependents/archive
  and transport bundles, project list/create, report append/list. It does NOT alias
  management or expose groups, key-vault reads, authentication administration,
  unlock, export/import or approval. Client status/logout are separate control
  operations. Browser cookies alone never authenticate this audience; bearers
  never authenticate the management audience. Existing management URLs are still
  authenticated, not dead unauthenticated aliases.
- Every bearer request hashes its proof and checks current durable revocation and
  `identity.AuthorizationGeneration`. Managed dispatch repeats verification
  **after** lease acquisition, also rejecting restricted recovery, before any
  handler executes. Actual recovery replacement invalidates an enrolled client.
  Authenticated-but-locked managed data returns **423**, not an auth reset.
  Pair/poll/status/revoke metadata does not require a DEK; restricted recovery
  does not gain management enrollment/revoke authority.
- Managed responses use existing buffered checked-write/flush delivery with a
  lease held through handler, validation, write, flush and callback join. The
  client transport secret-response fixture covers a blocked final flush and
  write-before-read cancellation deadlines. `ErrAbortHandler` handling and T3
  recovery admission ordering are preserved.

### Agent, HTTPS and CLI

- Same existing daemon and pinned TLS1.3 IPC, wire version 2 and **1 MiB maximum
  frame**, not another daemon or credential store. Agent API operation has an
  explicit method/path capability allowlist, not an arbitrary URL proxy.
- API and pending poll secrets are memory-only, unexported fields; no keychain,
  disk/config/env/argv/URL/terminal/browser/IPC-discovery API credential or resume
  fallback. Discovery remains only format version, local IPC token and public
  certificate. Agent per-runtime TLS private key remains memory-only/immutable.
- Per-origin authorizations cap at eight. Concurrent CLI logins share one pending
  agent-owned request/poll proof; distinct devices have distinct requests. Public
  status always preserves request/URL/fingerprint while pending, including the
  one-second coalesced-poll path. Expiry clears pending memory/status promptly.
- API bodies stream through bounded existing IPC frames: **1 MiB HTTP request**,
  **4 MiB HTTP response**, **6 MiB serialized IPC result**. Every chunk remains
  below the original frame cap. No frame limit was raised and no request falls
  back to unauthenticated HTTP. Raw/token-byte echo checks are defense in depth,
  including 401 responses before dropping token references; they are not a claim
  to protect a credential from its authorized HTTPS server.
- Endpoint must be a verified **HTTPS origin**, including loopback. No path,
  userinfo, query or fragment. System roots and optional public private-CA PEM
  `ca_certificate`; relative paths are anchored in the invoking CLI before IPC,
  not an older detached daemon's cwd. No insecure bypass. Config defaults to
  `https://127.0.0.1:8080` and therefore needs a matching trusted certificate.
- Requests bind the exact configured origin, remove cookies and refuse every
  redirect before sending another bearer/body. Injected HTTP clients are cloned
  and guarded too; verification cannot be disabled by injected `*http.Transport`.
  Approval URL is constructed from configured origin plus validated public ID,
  never untrusted Host/server-returned URL. Same-host HTTP proxy remains a
  server-only deployment option, not a direct-client exception.
- Every current production CLI API constructor now uses `api.NewAgent`, including
  report/project/search/archive/transport helpers. The configured HTTP timeout is
  honored per request, not frozen at enrollment, while credential/trust/redirect
  state remains agent-owned. Presentation test fixtures use
  a clearly isolated verified-TLS constructor seam, not enrollment acceptance.
  Noninteractive graph commands still retrieve a fresh authorized bundle before
  pooled execution. Interactive xssh/portwatch use agent-mediated API retrieval
  while retaining local interactive SSH/console execution.
- `warden login`, `logout`, `status` and help explain custody/lifecycle. Interactive
  approval is bounded to five minutes. Noninteractive/redirected login and first
  use print actionable URL/request/device/fingerprint and fail promptly while
  pending; they never wait for a human indefinitely. Status distinguishes outage
  from approval. Logout attempts revocation, always clears local memory even
  when connection is refused, and leaves the daemon running.
- No token expiry, refresh credential or automatic rotation. Server restart
  preserves authentication but starts vault locked; agent exit loses its secret
  and requires approval again. A stolen copy remains usable until server revoke
  or recovery generation invalidation, even after legitimate agent exit. Web
  revoke blocks future retrieval; already retrieved remote credentials/sessions
  cannot be recalled. Reference clearing is NOT GC/string zeroization.
- No daemon idle/timed exit: logout, revoke, no auth, outage, server restart,
  vault lock, empty pools and graph expiry do not terminate it. Fake-clock
  fixtures advance beyond TTL and then years in each state. External cancellation
  drains operations and clears agent authorization. The T10 raw-close-first and
  publication-unlink corrections remain untouched. T12's context-insensitive
  SSH dial can still delay shutdown; no all-states bounded shutdown claim.

### Browser

`CLI devices` is mounted in the authenticated security view: refresh pending/
enrolled/revoked entries, show complete matching fingerprint/request/expiry,
approve, deny and revoke with fresh passkeys. Metadata is available while locked;
unlock remains separate. Public request query highlights the requested device.
Standards-based WebAuthn/ECMAScript only, no browser/provider gate or PRF downgrade.
Cancellation/lock/auth epochs clear pending UI and errors; repeated invalidation
re-arms the listener and ignores stale async completions. This is best-effort
state clearing, not memory erasure certification.

## Test-first chronology and self-review

Primary vertical slices had focused RED before minimal implementation: pairing/
client audience rejected or absent; missing verifier schema; unrecognized agent
API operation; redirects reached their destination; HTTP/non-origin endpoints
were accepted; device UI absent. These are not claims of native execution.

Subsequent focused behavior RED → fixes → GREEN:

1. Concurrent agent logins could encounter server poll rate failures; coalesce
   request ownership/polling and preserve public approval metadata for all callers.
2. Recovery-invalidated active rows exhausted future registration; prune only
   revoked/older-generation verifiers in the approval transaction.
3. Outage status falsely implied authorization, and expired pending status kept
   stale request/fingerprint. Distinguish unavailable and clear expired state.
4. Self-review reproduced a 401 body echo crossing IPC because the token reference
   was cleared before checking the response; inspect against the prior secret
   before clearing/rejecting. Regression now covers both success and 401 echoes.
5. Relative CA paths depended on detached-agent cwd; focused config test failed,
   then CLI config anchors paths before IPC.
6. Repeated security cancellation left a device-status error on screen; focused
   browser test failed, then re-arm invalidation listener and check async epochs.
7. Final integration review reproduced the enrollment caller's HTTP timeout being
   reused for a later request. A delayed-response test was RED; clone the guarded
   client per request and honor its configured timeout (no arbitrary new timeout
   ceiling). That new cancellation case exposed a synthetic-peer commitment
   string race under `-race`; use atomic fixture state. Focused repeats and the
   entire relevant race suite passed again after both corrections.

Supplemental audience matrices, durable revocation/no-export, no-expiry, actual
recovery invalidation, checked-flush, cipher-record capture and larger real report
fixtures were added as already-GREEN characterizations; do not relabel them as
new behavioral RED. CLI presentation/login command integration and final signed
subprocess acceptance supplement the primary agent/server test-first slices;
they do not constitute a separate preimplementation RED for every help branch.
Docs/report/plan/ledger use the documented documentation TDD exception.

Self-review covered all current CLI constructors/callers, explicit route tables,
credential flow (including producer/consumer poll-secret transfer), v7/v8 strict
schema, identity CAS, recovery/revocation post-acquisition races, flush/cancel
ordering, bounded streams, redirects/injected clients, browser epochs and T10
lifetime/publication/teardown invariants. No general proxy, raw-token IPC response,
credential persistence, managed API bypass or later outcome was added.

## Reproducible disposable journey / T5 handoff

From this checkout with its existing Go/npm dependencies (never a real DB):

```sh
npm --prefix web run build
go test ./internal/server/runtime \
  -run '^TestHTTPSClientEnrollmentTwoDevicesRestartAndRevoke$' -count=1 -v

go test ./internal/server/runtime \
  -run 'TestPairing|TestCredentialAudience|TestClientAdmission|TestClientTransport|TestClientToken|TestRecoveryCannotReadManagementData' \
  -count=1 -v
go test ./internal/client/agent ./internal/store ./cmd/warden -count=1
```

The first journey builds the actual CLI and production server, starts two distinct
same-user real agent runtimes, serves private-CA HTTPS, signs real WebAuthn
assertions over issued challenges, and drives simultaneous CLI first-use login
→ separate fingerprint/commitment match → fresh exact browser-API approval while
locked → authorized status/423 data → separate fresh unlock → helper API
capabilities and actual CLI search/report → production-server subprocess restart
(still-running agent retains auth, data locked) → unlock/preserved data → fresh
per-device web revoke (second device still works) → actual agent restart
(needs approval) → logout. All fixtures and environment/cache roots are isolated.
The helper exercises every current client capability via same-agent transport;
real report validation permits 16 KiB summaries, and 80 sanitized records make
an actual HTTPS/IPC report response exceed 1 MiB. Separate agent stream fixtures
exercise a sub-limit request and approximately 2 MiB response. The original
report claimed overlimit rejection coverage here without corresponding negative
fixtures; that claim is withdrawn. The bounded review-follow-up below records
new boundary coverage separately from original test-first evidence.

This uses **synthetic PRF output and signed standards fixtures**, not a genuine
PRF authenticator/browser. Browser tests use a JS DOM adapter. No real SSH host or
external DB is contacted, and the DB tunnel tests use local echo/SSH fixtures,
not a database. T5 must keep client auth outside export/import, retain v8 strict
schema and generation admission checks, and obtain separate authorization before
implementing its versioned transfer contract. No T5 implementation was started.

For native Windows, execute (not merely build) `go test ./internal/client/agent`
with T10's required native pipe/ACL/other-user/reparse/publication matrix and the
new portable API custody/concurrency/lifetime/wire fixtures. The Linux subprocess
journey explicitly skips Windows and is NOT a native two-device acceptance
fixture. Genuine PRF-positive setup/login/unlock/fresh approval/revoke and
production-CSP/network verification require the manual HTTPS browser journey in
the initialization/T3 runbooks, adding CLI device approval/fingerprint comparison
and restart/revoke here. Record platform/browser/authenticator and real results;
unsupported PRF must fail clearly, never be worked around.

## Original implementation checkpoint verification

The following records the original T4 checkpoint before the bounded review
follow-up below; it is historical evidence, not a claim these commands were all
rerun in the follow-up. Go 1.25.14 linux/amd64:

- `go test ./internal/client/agent ./internal/client/api ./internal/client/clienthttp ./internal/config ./internal/store ./internal/server/runtime ./cmd/warden -count=1 -timeout=180s` PASS.
- `go test -race ./cmd/warden ./cmd/warden-server ./internal/client/agent ./internal/client/api ./internal/client/clienthttp ./internal/client/report ./internal/client/ssh ./internal/client/db ./internal/config ./internal/crypto ./internal/store ./internal/server/... ./internal/web -count=1 -timeout=180s` PASS. Entire runtime `-race -count=1` repeated after strengthening the real >1 MiB report journey: PASS.
- Pairing commitment, post-acquire generation/revoke, client checked-flush boundaries `-race -count=25`: PASS. Agent concurrent login, long-lived state/streams and bidirectional IPC TLS-record capture `-race -count=20`: PASS.
- Correctly named two-device subprocess journey `-count=5`: PASS, repeated after the real report-size strengthening. An earlier mistyped `-run` selected zero tests; it is NOT counted as journey evidence.
- `NODE_ENV=test npm --prefix web test`: PASS **17 files / 252 Vitest tests**, plus **13** distribution verification tests. `npm --prefix web run build`: PASS; existing management chunk >500 kB warning remains.
- `go vet ./...`: PASS. Windows-amd64 agent test cross-compile and CLI/server cross-build: PASS, **not executed**. CLI/server are also compiled and run by the Linux journey.
- Full `go test ./... -count=1 -timeout=180s`: NOT GREEN. The latest final-source full run fails untouched `TestPosixRelMatchesFilepathRel` (`".."` vs `"../."`) AND intermittent `TestTunnelCloseClosesWholeChain` (target SSH fixture still has one connection after 5s). Earlier repeats failed only SFTP, but do not supersede this result; targeted DB `-count=25` and `-count=50` each reproduced one failure. Its entire reachable Warden production dependency subtree (DB, SSH, hostkey, terminal, model) and fixtures are unchanged; the T3 ledger already recorded this intermittent test. Race DB/SSH and subsequent full DB pass do not erase those failures. No unrelated transport/test fix or root-cause/acceptance claim.
- After the final timeout/fixture correction: broad relevant Go `-race -count=1`,
  repeated agent boundaries `-race -count=20`, correctly named two-device journey
  `-count=5`, `go vet ./...` and Windows cross-build/test compilation PASS again.
  The latest full Go failure includes **both** unchanged SFTP and intermittent
  DB failures, as recorded above; no clean repository-wide result is claimed.
- Final 52-task-file newline/whitespace/gofmt/local-Markdown-target checks PASS,
  including untracked files and the ledger, excluding the protected file.
  `git diff --check` PASS; no staged files or module/version/lockfile diff.

Relevant local logs: `/tmp/warden-t4-final-{focused,race,runtime-race,web,build,vet,full,full-repeat,boundary-repeat,agent-repeat}.log`,
`/tmp/warden-t4-final-source-{go,full,vet}.log`,
`/tmp/warden-t4-journey-repeat.log`, `/tmp/warden-t4-db-repeat{,50}.log`.
They are session artifacts, not durable acceptance records; rerun commands above.

## Pinned API/source evidence and changed seams

Before primary integration, consulted Context7 WebAuthn/SQLite/React references
and exact installed official `github.com/go-webauthn/webauthn@v0.17.4/webauthn/login.go`
and `modernc.org/sqlite@v1.57.0/tx.go`; reuse existing verified ceremonies and
`database/sql` transactions, never fabricate assertions in production. Existing
T3 exact-version API evidence remains applicable to fresh grants. React hooks
use the installed React 19.2.8 contract. Follow-up UI test preflight used Context7
Testing Library **16.3.2** (`ctx7:docs:460fb3979912e805929a11e2`) and Vitest
(`ctx7:docs:fd9fc3f4472b9a41dd6eeb0d`), with installed Vitest **4.1.11**.
Installed Go docs confirmed `Client.CheckRedirect` runs before the next request,
`ErrUseLastResponse`, `Transport.Clone`, `SystemCertPool`, and `tls.Config.Clone`.
No new dependencies or WebAuthn/SQLite API replacements.

Changed areas: `migrations/008_client_credentials.up.sql`; `internal/store/clients*`
and runtime schema; `internal/server/runtime/clients*`, audience/action wiring and
recovery regression; explicit profile/report registration; `internal/client/clienthttp`,
agent `api_*`/dispatch and API/report clients; client config; `cmd/warden/auth*`,
all CLI constructors and isolated fixtures; browser auth actions/client/device
view/security tests; README, CLI/config/security/agent-IPC docs and narrow spec/plan
status. The IPC runbook also calls out explicitly restarting an identified older
T10 daemon after executable upgrade; wire version2 does not add missing operations
to an already-running process, and no automatic restart policy was introduced.

**Next:** independent security review of this bounded uncommitted T4 checkpoint,
explicit disposition of observed unrelated test failures, and required external/
native acceptance. Do not infer T5, release/version, deployment or publication
authority from this report.

## Bounded review follow-up — P1 injected TLS / P2 boundary evidence

Same sole writer, branch and reviewed HEAD `852eed9`, preserving the uncommitted
T4 implementation. No staging/commit/push/deployment/worktree/protected-file
access, dependency/version change, T5 or unrelated outcome. Documentation and
chronological corrections use the documentation TDD exception.

### P1 — independently reproduced before production change

Exact installed official Go **1.25.14** `src/net/http/transport.go` was inspected
before implementation: lines 157–175 document that custom `DialTLSContext`/
`DialTLS` bypass `TLSClientConfig`; `Clone` lines 325–355 copy both hooks and clone
the TLS config; `addTLS` lines 1682–1690 uses the origin name only when `ServerName`
is empty; `dialConn` lines 1757–1785 directly accepts custom TLS dials (even a
plain `net.Conn`). `go doc net/http.Transport.DialTLSContext`, `DialTLS` and
`crypto/tls.Config.ServerName` confirm the installed contract. Only standard Go
APIs and existing IPC helpers are used; no third-party API/dependency change.

Added `internal/client/clienthttp/tls_test.go` before production edits:

```sh
go test ./internal/client/clienthttp -run '^TestInjected' -count=1 -v
```

Actual RED: **all five cases**—four plaintext/insecure custom TLS dial variants
(context and legacy) and trusted-certificate/wrong-origin `ServerName` override—reached the
HTTP handler with a synthetic bearer and POST body. The standard-root/TCP-dial
positive case also failed because the stale override was honored. An arbitrary
injected RoundTripper was invoked and accepted instead of failing closed.
Log: `/tmp/warden-t4-review-p1-red.log`.

Small fix in `clienthttp.Client`: clone standard transports, remove both custom
TLS dial hooks, clear `ServerName`, preserve roots and ordinary TCP dial hooks,
force normal TLS verification/minimum TLS1.3, and leave the caller's transport/
config unchanged. Unknown injected RoundTrippers fail closed rather than being
assumed to authenticate HTTPS. `api.NewAgent` explicitly installs its owned
origin/capability-checked IPC transport after constructing the guarded client;
this is not a general transport exception. The isolated decoder/body-close test
uses a private non-network fixture, not a public injection bypass. No agent API
custody, lifetime, verifier, generation, lease or recovery behavior changed.

GREEN: the same source-named TLS tests, API and report tests pass. The negative
TLS fixtures now reject before any HTTP handler runs; positive private roots/
ordinary TCP dialing work, and original hooks/config remain unchanged. The real
CLI/agent/HTTPS restart/revoke journey passes with the explicit agent constructor.
Log: `/tmp/warden-t4-review-p1-green.log`; final restored focused evidence below.

### P2 — correction and existing-guard characterizations

**Correction:** the original report and ledger claimed stream overlimit rejection
coverage that was not present. Original agent fixtures exercised only underlimit
requests and approximately 2 MiB responses. Those original claims do not
establish negative-boundary evidence; the ledger preserves them historically
with a chronological correction. No retroactive test-first claim is made.

New `internal/client/agent/api_bounds_test.go` exercises actual producer/consumer
boundaries with authenticated TLS IPC and, for HTTP bounds, a real verified
private-CA HTTPS protocol peer. Enrollment is covered separately, so these
fixtures deliberately seed approved memory-only custody; they do not bypass IPC
or HTTP TLS authentication. Covered:

- Local `Transport.RoundTrip` request **1 MiB + 1** rejects/closes the body before
  IPC attachment or HTTPS. The actual IPC consumer separately rejects that
  declared streamed size; the destination stays unchanged and HTTPS is not called.
  An exact **1 MiB** request still arrives intact over the complete transport.
- Actual HTTPS response **4 MiB + 1** produces terminal failure, not decoded
  success; exact **4 MiB** remains accepted. Failed requests retain approved
  custody and a subsequent small request succeeds in the same daemon.
- Consumer header bounds (negative/oversized declaration, forbidden inline body),
  short/overlong declared streams, unexpected stdout/final request frames,
  missing EOF and a truncated length-prefixed frame. Malformed inputs never
  dispatch HTTPS. Complete invalid streams receive an error final, not stdout;
  disconnected/truncated transports terminate with an error/EOF, not a fabricated
  deliverable terminal frame. Producer/consumer work is joined.
- A synthetic **authenticated IPC response producer** tests serialized **6 MiB + 1**
  output, truncated JSON, complete JSON without a terminal frame, unexpected
  response frames and terminal error after stdout. `callAPI` never decodes those
  into partial success; its sentinel destination remains unchanged. The 6 MiB
  case is deliberately not claimed to arise from the real 4 MiB-capped HTTP
  producer. Runtime cleanup/credential removal and worker completion are asserted.

Existing guards passed these characterizations without production changes.
The first harness run incorrectly treated expected explicit-stop
`context.Canceled` as cleanup failure; correcting only that assertion produced
GREEN, not a behavioral RED or a production fix.

**Mutation sensitivity, not test-first production work:** separately disabled
only the request declaration cap, HTTP response cap, serialized IPC cap, short
body-length check, and frame-kind check. Actual focused failures showed,
respectively: oversized request reached HTTPS/decoded success; oversized response
became status200; oversized IPC output decoded status200; short body and unexpected
stdout reached HTTPS. The initial frame-kind control waited for missing EOF;
adding explicit EOF strengthened it to prove dispatch, rather than relying on a
timeout. Each guard was restored before the next control; no mutation is retained.
`api_transport.go` before/after SHA-256 matches:
`d1e490ef824e5540cab180e750c6400e4969f8e24add2c9139c6bffd48dd04f6`.
Mutation logs: `/tmp/warden-t4-review-p2-mutation-{request,http-response,ipc-response,body-length,frame-kind}.log`.

### Fresh follow-up checks / scope

- Restored focused TLS/IPC boundary tests `-count=1`: PASS,
  `/tmp/warden-t4-review-restored-focused.log`.
- `go test ./cmd/warden ./cmd/warden-server ./internal/client/agent ./internal/client/api ./internal/client/clienthttp ./internal/client/report ./internal/client/ssh ./internal/client/db ./internal/config ./internal/crypto ./internal/store ./internal/server/... ./internal/web -count=1 -timeout=180s`: PASS, `/tmp/warden-t4-review-go.log`.
- Same complete relevant package set `-race -count=1 -timeout=180s`: PASS,
  `/tmp/warden-t4-review-race.log`.
- `go test -race ./internal/client/clienthttp ./internal/client/agent -run '^Test(Injected|APITransportRejects|AgentAPIRejects|APIConsumerRejects)' -count=25 -timeout=180s`: PASS,
  `/tmp/warden-t4-review-boundary-race25.log`.
- Correctly named `TestHTTPSClientEnrollmentTwoDevicesRestartAndRevoke`
  `-count=3`: PASS, `/tmp/warden-t4-review-journey.log`.
- `go vet ./...`: PASS, `/tmp/warden-t4-review-vet.log`. Agent/clienthttp Windows
  test binaries cross-compile, **not executed**. Formatting/diff/local-doc checks
  are recorded in the closing ledger entry.
- No frontend changes or new frontend test/build execution in this follow-up.
  Parent independently reports 252 + 13 checks passing; distinguish that from
  this writer's fresh Go commands. No new repository-wide full-Go result is
  claimed: recorded SFTP failure and transient DB failure remain unresolved;
  focused/race DB passes (including the parent's reported count20) do not fix them.
- `git status`/diff relative to `852eed9` shows no SSH/DB/hostkey/terminal/model
  source changes; this follow-up changes only shared HTTP policy, explicit agent
  construction, the isolated body-close fixture, two new regression files,
  report and ledger. This observation does not establish failure provenance or
  root cause. Agent integration remains the existing T4 change, not SSH/DB
  transport remediation.

Stop after bounded self-review. Genuine PRF/native Windows/CSP evidence and
T12 context-insensitive dial shutdown limitations remain pending; no acceptance,
publication or later-outcome authority is inferred.

## P1 residual rereview — inherited ALPN protocol delegation

**Correction to the preceding P1 checkpoint:** clearing TLS dial hooks/name and
rejecting unknown top-level RoundTrippers was only a partial injected-transport
fix. `Transport.Clone` still inherited `TLSNextProto` delegates. This does not
establish a normal CLI/default-agent token exploit; it violates the required
shared/injected HTTP-client contract. Same bounded T4 scope/sole writer/reviewed
HEAD `852eed9`; no other outcome, commit, deployment or protected-file access.

### Actual RED before the residual production fix

Added `internal/client/clienthttp/protocol_test.go` and ran:

```sh
go test ./internal/client/clienthttp \
  -run '^Test(InjectedTLSNextProto|OwnedStandardHTTP2|InjectedRegisteredHTTPS)' \
  -count=1 -v
```

Both `h2` and custom `warden-test-protocol` ALPN fixtures completed **trusted,
hostname-verified TLS**, then invoked the caller's inherited callback. Its
RoundTripper received the original request and forwarded the synthetic bearer
and POST body to a local **plaintext** attacker fixture. Both failed with
`verified TLS=true callbacks=1 plaintext deliveries=1`. No HTTP redirect was
involved; `CheckRedirect` could not protect this path. A separate positive
standard-HTTP/2 ownership test failed because `Transport.Clone` initialized the
caller's exported protocol state. The registered-HTTPS-protocol characterization
was already GREEN, not a newly reproduced defect.
Log: `/tmp/warden-t4-review-alpn-red.log`.

### Minimal owned transport and inspected hook surface

Before implementation, checked exact installed official Go **1.25.14** sources:
`net/http/transport.go` Clone 328–370 (initializes caller protocol state and copies
`TLSNextProto`), protocol setup 393–486, request delegation 691–694, ALPN callback
1933–1940, and scheme registrations 554–562 / 612–618 / 868–882. `Clone` does NOT
copy the private `altProto` registration map, but simply clearing fields on its
result would still initialize caller protocol state. `go doc` for
`Transport.TLSNextProto`, `Protocols`, `ForceAttemptHTTP2`, `HTTP2Config` and
`tls.Config.Clone` corroborates the installed APIs. No dependency/API upgrade.

Use fresh `http.Transport` state instead of `Transport.Clone`, copying the
supported ordinary TCP/proxy settings, limits/timeouts, public trust/TLS config
and HTTP2 tuning. Neither inherited TLS protocol callbacks nor private registered
scheme RoundTrippers/cached protocol state are copied. TLS dial hooks remain
absent; `ServerName` override remains cleared and verification/TLS1.3 enforced.
Clear owned `TLSClientConfig.NextProtos`, leave owned `Protocols`/`TLSNextProto`
unset and set `ForceAttemptHTTP2=true`: Go alone regenerates compatible standard
HTTP/1 + HTTPS HTTP/2 handlers/ALPN. No caller ALPN list or unencrypted-HTTP2
selection is reused. Caller configuration, handlers and registrations remain
unchanged. The previous explicit agent-IPC constructor and unknown-RoundTripper
rejection remain intact.

Audited other executable hooks as source inspection, not blanket exploit tests:
`Proxy`, TCP `Dial`/`DialContext`, CONNECT-header/response hooks are intentionally
supported routing/configuration; the owned TLS layer still authenticates the
request origin. Normal `VerifyPeerCertificate`/`VerifyConnection` run after Go's
default certificate/name verification with `InsecureSkipVerify=false`
(`crypto/tls/handshake_client.go` 1183–1229). ECH rejection has a special verification
callback, but TLS1.3 returns `ECHRejectionError` before marking handshake complete
(`handshake_client_tls13.go` 153–158), so it cannot delegate HTTP requests here.
HTTP2 `CountError` is a diagnostic string callback, not a request RoundTripper.
These are trusted configuration seams, not a sandbox against arbitrary malicious
in-process callback code. No new arbitrary URL or transport exception was added.

### GREEN and fresh verification

- Same focused command: PASS, `/tmp/warden-t4-review-alpn-green.log`. Zero caller
  callback/forwarder/plaintext deliveries; actual standard HTTP/2 reaches the
  authenticated origin. Caller ALPN/protocol state remains unchanged. The
  registered-HTTPS alternate is not inherited and still works on the original
  caller transport. This tests client protocol ownership, not managed HTTP/2
  response-lease acceptance.
- `go test ./cmd/warden ./cmd/warden-server ./internal/client/agent ./internal/client/api ./internal/client/clienthttp ./internal/client/report ./internal/config ./internal/crypto ./internal/store ./internal/server/... ./internal/web -count=1 -timeout=180s`: PASS,
  `/tmp/warden-t4-review-alpn-go.log`. Includes the actual signed two-device CLI/
  agent/production HTTPS server restart/revoke journey in the runtime package.
- Same complete relevant package set `-race -count=1 -timeout=180s`: PASS,
  `/tmp/warden-t4-review-alpn-race.log`.
- Entire `internal/client/clienthttp` suite `-race -count=25`: PASS,
  `/tmp/warden-t4-review-alpn-race25.log`.
- Existing P2 producer/consumer boundary tests `go test -race ./internal/client/agent -run '^Test(APITransportRejects|AgentAPIRejects|APIConsumerRejects)' -count=10 -timeout=180s`: PASS,
  `/tmp/warden-t4-review-alpn-p2-race.log`. No P2 guards or credential/lease/recovery
  behavior changed in this residual pass.
- `go vet ./...`: PASS, `/tmp/warden-t4-review-alpn-vet.log`; clienthttp Windows
  test cross-compilation PASS, **not native execution**. Closing formatting/diff
  and ownership-scope checks are in the ledger.

Only shared HTTP policy, its new protocol regressions, this report and ledger
changed in this residual pass. No frontend/full-repository Go rerun or new result
is claimed; recorded SFTP/DB failures remain unresolved, and PRF/browser CSP/native
Windows/T12 shutdown limitations remain pending. No claim of complete M1/security
release acceptance. Stop after bounded self-review for independent rereview.
