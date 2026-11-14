# T3 resumed implementation — passkeys, fresh actions and restricted recovery

Branch `hieudmg/security-hardening`, reviewed T2 base/unchanged HEAD `99bcbeb`.
Sole writer. **Bounded T3 is implemented; independent review and genuine
PRF-positive HTTPS/browser acceptance remain pending. This is not verified M1,
T4, or a completed security-hardening release.**

## Authority and distinction from the withdrawn attempt

The previous worker `01a1daf4` stopped on the disposition of existing passkeys
and restored ALL application/test edits to `99bcbeb`. Its source-only reference
patch `/tmp/warden-t3-partial-99bcbeb.patch` (1,403 lines, SHA-256
`6d7279d391aaabeb6ad25cd396a11e8db9ae9a7059b644345953144e99a9cab9`)
remains a **withdrawn, nonaccepted historical artifact**, not this deliverable.
The earlier attempt and its restored-baseline checks remain recorded in the
append-only execution ledger. No prior passing result is relabeled as fresh RED.

The owner now explicitly decided: **“remove all passkeys then. and force register
new passkey”**, with atomic sequencing clarified in this handoff. The binding
spec and T3 plan now require a verified new PRF-capable credential, its independent
required-UV assertion, same-DEK key check and local wrapper round-trip BEFORE
atomically replacing ALL old credentials/wrappers. Old identity survives abort
and failed commit. Completion revokes prior sessions/client authorizations and
requires ordinary login; replacement does not silently rotate recovery material.

Before production edits, this session inspected the partial patch as reference,
retained selected reference tests for reevaluation, and ran them against restored
current source. API-absence compile failures and actual 403/401 missing-behavior
failures below are this session's observations, not the old worker's evidence.
The reference implementation was not blindly applied. Its response boundary was
reviewed and extended to cover body reads as well as delivery; recovery, rotation,
browser UI/client integration, concurrency fixes and production-TLS journey were
implemented here. Documentation changes use the plan's explicit runtime-TDD
exception; link/diff/consistency checks replace a fabricated runtime RED.

## Delivered behavior

### Complete current identity, multiple passkeys and revocation

- New initialization writes `passkey_wrappers`. The unreleased singular
  `passkey_wrapper` T1/T2 checkpoint still reads non-destructively and evolves on
  the next metadata write, preserving DEK/check/recovery/credential. Conflicting
  representations, duplicate credentials/wrappers, missing wrapper pairs, wrong
  vault bindings and unknown fields are refused. No encrypted old-release DB
  compatibility, automatic reset, new SQLite schema or export version was added.
- Runtime sessions, assertions and changes read current durable identity, never
  cached `p.install`. That field is an immutable construction fixture, not an
  authorization source. Verified counters merge into the complete current record
  under one owner mutex and CAS transaction; library backup/zero-counter semantics
  remain. Counter, wrapper and recovery updates cannot overwrite stale snapshots.
- Up to32 active passkeys. Enrollment requires an authenticated unlocked owner and
  a fresh exact-request grant. Verify new registration and a separate signed UV
  assertion. A second fresh **old-owner** assertion binds HTTPS DEK delivery to
  that exact pending new credential. Browser wraps the same DEK with the new PRF
  material, locally unwraps/tests it, and submits the recovered DEK against the
  fixed key check. Credential and wrapper publish together, not partial records.
- Removal has its own request-bound fresh grant; removes credential+wrapper and
  revokes sessions/grants through that credential atomically. Last-active removal
  returns409. Removing the current browser credential returns to login; it is not
  an implicit global vault lock.

### Fresh sensitive management requests

`fresh/begin` accepts `{action,credential_id,method,path,digest}` for the explicit
allowlist; `digest` is canonical base64url SHA-256 of the EXACT UTF-8 body bytes
(empty bytes for normal sensitive GET/DELETE). After an independent signed UV
assertion, `fresh/finish` issues a single-use60s grant. Server checks session,
credential, action, method, request URI, exact body digest, expiry and vault
generation at consumption; rereads session and rechecks expiry/generation after
body reading. A generic fresh/age flag never authorizes an operation.

- Key-pair reveal/create/update/delete and v1 export/import now work through this
  gate. Redacted list/dependents remain normal authenticated unlocked metadata.
- Sensitive GET success/error paths are no-store and need a grant. Browser API
  helpers serialize before requesting authorization and send the same body and
  `X-Warden-Action` header; export Blob/file reads keep security-generation guards.
- Import accepts the existing documented `warden-data` version1 only, up to50MiB,
  into empty **managed** tables despite initialized auth/session/audit rows.
  Identity/auth state never transfers. Existing store transaction/validation and
  nonempty-destination refusal remain. A valid exactly50MiB body succeeds and
  limit+1 is rejected without managed writes. T5 still owns the wider old-release
  all-record fixture/migration/rollback matrix; T6 owns supported-link deadlines.
- Legacy management `/api/v1/transport/*` remains blocked; no private-key extraction
  bypass and no authenticated client audience were added.

### Restricted recovery and separate saved-confirmed rotation

- `POST recovery/begin {}` returns only nonce/context and public salt, never the
  wrapper. Context expires5min, state is capped128; starts are bounded by the
  existing global start limiter. `recovery/proof {id,proof}` consumes context and
  verifies SHA-256 of the separately HKDF-derived authentication subkey against
  current metadata before releasing the recovery wrapper. Proof submissions use
  a global1/10s bucket, burst5, generic429/Retry-After10. No per-IP map, logging of
  proof, stored authentication subkey or raw recovery root.
- Successful proof rotates to a separate Secure/HttpOnly/SameSite=Strict host-only
  recovery cookie and session-bound CSRF, expires5min, and returns a single-use60s
  recovery unlock grant. This is password-equivalent high-entropy proof over
  HTTPS, **not** a phishing-resistant assertion. Correct DEK alone authenticates
  nothing. Browser unwraps locally; server validates against the existing key
  check and generation before enabling its one runtime vault owner.
- Normal managed access is blocked while restricted recovery is active, including
  old ordinary browser sessions. Restricted context can ONLY unlock, enroll its
  replacement and abort; no list/read/export, ordinary grants, rotation or general
  session promotion. Status/logout/global lock for ordinary sessions retain their
  separate meanings. Abort/expiry drops runtime key access and leaves identity
  unchanged. Expiry is enforced on the next API request; restart is always locked.
- New replacement requires its own verified registration + signed UV assertion
  and working PRF in the browser. Its narrow DEK delivery/commit window is60s after
  that assertion. Browser local wrap/unwrap round-trip and same-DEK key check
  precede one CAS transaction replacing **all** old credentials/wrappers,
  deleting prior browser sessions and advancing durable authorization generation.
  Completion state is serialized with publication; abort wins before publication
  or observes completion, never falsely claims an already-published change aborted.
  Return locked, clear recovery cookie and require ordinary passkey login.
- Recovery replacement preserves the existing recovery wrapper/verifier. Explicit
  rotation instead requires fresh passkey verification while unlocked, freshly
  authorized HTTPS DEK delivery, random root32, local new-wrapper round-trip,
  immutable pending wrapper/verifier preparation, hiding the displayed root, and
  manual saved re-entry/local unwrap. Only matching proof + recovered same-DEK
  confirmation atomically replaces wrapper/verifier. Wrong re-entry sends no
  browser commit; server wrong proof/key, stale context/generation or failed
  transaction changes no current recovery material. Old root stops authenticating
  current state; historical backups retaining old wrappers remain decryptable.

### Reviewed T2 response lease retained and reused

All managed responses, enrollment DEK delivery and rotation DEK delivery share
`deliver`: whole-handler buffer; lease through checked Write +
`ResponseController.Flush`; abort sentinel on failed/short write/flush or failed
completed delivery. Existing middleware still propagates `http.ErrAbortHandler`.
Cancellation sets WRITE deadline first, then READ deadline; stop/join occurs
before release/return. The callback is installed BEFORE handler/body reading too,
so authorized slow uploads cannot hold a lease until the120s read deadline.
Buffered partial secrets are discarded; byte buffers/copies are cleared best
effort. No detached writer or saved DEK copy survives its lease by design.

Real HTTP/1 server-socket observers prove small DEK response emission occurs
before lock acknowledgement, not at later outer-handler finalization. Net.Pipe
exercises blocked DEK writes and incomplete authorized request bodies: lock
cancels promptly, joins cleanup and no DEK is emitted before/after ack in the
canceled case. Existing ordinary managed TLS/finalization/unread-body tests remain
passing. This establishes **server emission ordering, NOT network receipt**.
Already emitted bytes, TLS/TCP/proxy buffers and retrieved secrets cannot be
retracted. No h2 ALPN or protocol configuration changed; this is not an HTTP/2
emission guarantee.

### Browser UI

The auth gate now exposes masked offline recovery entry, restricted replacement/
abort, credential list/add/revoke and saved-confirmed recovery rotation. It warns
that recovery replaces ALL old credentials, current wrappers do not revoke old
backups, and offline roots/exports are plaintext secrets. Creation without PRF
results always proceeds to an independent get; missing PRF fails explicitly.
Generic client extension results remain empty; raw root/PRF/KEK never travels to
the server. Transient byte arrays clear in finally blocks, rotation retains only
its public wrapper/context, and lock/logout/cancel/unmount invalidate promises
and remove displayed/re-entry material. No browser persistent secret storage,
provider sniffing or weaker fallback was introduced.

## Actual resumed test-first chronology

| Focused command before corresponding production edit | Observed RED in this session | GREEN |
| --- | --- | --- |
| Runtime/crypto reference tests for collection/current identity/enrollment/key lease | Compile: absent `Passkeys`, `current`, `updateIdentity`, `KeyForLease` | PASS after bounded collection/current-CAS/lease implementation |
| `go test ./internal/server/runtime -run 'TestFreshActionGrantPurposeTargetSessionAndReplay\|TestSensitiveGETRequiresGrantAndIsNeverCached' -count=1` (API-absence tests temporarily isolated) | Every new action start403; old implementation supports only unlock | PASS after explicit request binding and gate integration |
| `go test ./internal/server/runtime -run TestRecovery -count=1` | Public recovery starts401, rotation key404 | PASS after restricted proof/unlock/replacement/rotation |
| Focused `src/auth/security.test.tsx` | Missing view import; isolated client tests then fail missing `grantFor`, `addPasskey`, `recover`, `rotateRecovery` functions | PASS after client and view implementation |
| Focused API test `sensitive GET mutation export and import carry grants` | Grant helper called zero times | PASS after actual fetch integration |
| `go test ./internal/server/runtime -run '^TestRecoveryActivationDoesNotExpireWhileDrainingOldLease$' -count=1` | An activating context was mistaken for expired; status blocked on a second Lock for1s | PASS after reserving a complete expiring context BEFORE draining leases |
| `go test ./internal/server/runtime -run '^TestOrdinarySessionCannotEnterRecoveryUnlockOrAllocateState$' -count=1` | Ordinary session allocated1 restricted map entry despite rejection | PASS after explicit restricted audience/phase check before any allocation |

Ephemeral RED logs: `/tmp/warden-t3-resume-red-{compile,actions,recovery,web,web-client,api,recovery-race}.log`.
The audience RED is also in the session tool transcript. Further signed lifecycle,
SQL rollback/CAS single-winner, concurrent metadata merge, full50MiB transfer,
HTTP lease/cancellation, production-TLS and late-response tests extend acceptance
as **already-green characterizations**, not invented additional RED cycles.

Two old fixtures depended on cached `p.install.Owner`: synced backup/counter
setup/assertions now use durable identity instead. No signature/counter check was
weakened. The initial near50MiB fixture used null collections, which documented
v1 validation correctly rejects; it now includes every required empty array.
The old auth-gate browser fixture now returns actual credential-list metadata,
and the PRF-negative fixture uses the new credential ID so it exercises missing
PRF rather than the preceding mismatched-ID rejection. An initial frontend type
check caught a zero-argument fetch mock's inferred tuple;
its mock is typed as `typeof fetch`. These were fixture/type corrections, not
production workarounds. A mistaken gofmt filename-list invocation was corrected
and final gofmt/validation rerun.

## Third-party/source evidence

Before production integration: Context7 WebAuthn
`ctx7:docs:7d90aaf2f9ed9ea24938c583`, official installed exact
`github.com/go-webauthn/webauthn@v0.17.4/webauthn/{login,registration}.go`:
owned credential options, owner/userHandle, expiry, required UV, actual signature
verification and independent registration/assertion API. Pinned
`modernc.org/sqlite@v1.57.0/tx.go` confirms transaction start, commit failure
rollback and cancellation. Existing T1 wrap/unwrap/recovery HKDF and standards
contract are reused unchanged, not custom cryptography. React Context7
`ctx7:docs:7eeb69f2ff36c502e1ee73a5` covers hook/unmount cleanup; Vitest mock
reference `ctx7:docs:eecab3203388a5db7060d40f` supplements installed test patterns.
No library/dependency/toolchain upgrade occurred. T1/T2 reports retain the exact
Go HTTP controller/deadline/abort and HTTP/2-source analysis; the same APIs and
HTTP/1 transport boundary are reused, not broadened.

## Final validation

Go `go1.25.14 linux/amd64`, Node `v26.12.1`, npm `11.20.0`.
Frontend build finishes before Go embedding checks; no concurrent dist rebuild.

| Check | Result |
| --- | --- |
| `NODE_ENV=test npm --prefix web test` | PASS17 files/246 tests +13 dist tests |
| `npm --prefix web run build` | PASS TypeScript/Vite/dist verification; existing >500kB management chunk warning |
| `go test ./cmd/warden-server ./internal/config ./internal/crypto ./internal/store ./internal/server/... ./internal/web -count=1` | PASS |
| Same package set with `go test -race ... -count=1` | PASS |
| `go test -race ./internal/server ./internal/server/runtime -run 'TestManagedResponse\|TestRuntimeKeyDelivery\|TestRecoveryActivation\|TestOrdinarySessionCannotEnterRecovery\|TestMiddlewarePropagatesAbortHandler\|TestResponseControllerFlushPreservesPanicStatus' -count=25` | PASS25 repetitions |
| `go vet ./...` | PASS |
| `go test ./... -count=1` first broad run | FAIL known SFTP mismatch and previously recorded intermittent DB `TestTunnelCloseClosesWholeChain` (one open connection after5s) |
| `go test ./internal/client/db -run '^TestTunnelCloseClosesWholeChain$' -count=5` | PASS; cause unverified, no client fix claimed |
| Full Go repeat, sequential after heavy checks | FAIL solely known unchanged SFTP `TestPosixRelMatchesFilepathRel`, `..` vs `../.` |

Logs `/tmp/warden-t3-final-{web,build,go,race,boundary-repeat,vet,full,db-repeat,full-repeat}.log`
are ephemeral; this table and ledger are durable facts. The final TLS journey and
final-source verification addendum below record checks added after this table.

## Runnable disposable M1 implementation journey / remaining acceptance

Automated synthetic evidence, no real DB or live credentials:

```sh
npm --prefix web run build
go test ./internal/server/runtime -run '^TestHTTPSRuntimeT3SecurityLifecycle$' -count=1 -v
go test ./internal/server/runtime -run 'TestTwoPasskeys|TestRecovery|TestFreshVaultCRUD|TestFreshImportBodyLimit|TestRuntimeKeyDelivery' -count=1
go test -race ./internal/store ./internal/server/runtime -count=1
```

`TestHTTPSRuntimeT3SecurityLifecycle` runs the PRODUCTION `Run`, real verifier,
embedded assets, real disposable SQLite and TLS1.3 with an explicitly trusted
private certificate (no skip-verification). It signs synthetic ECDSA credentials,
logs in locked/unlocks, adds another independently verified credential, logs in
with it, creates/reveals/exports a synthetic private key with fresh grants,
restarts locked with durable cookie, recovers with proof, denies recovery export,
atomically replaces both old passkeys, restarts, rejects both old logins, logs in
with replacement/unlocks/reads the preserved secret and rotates recovery,
rejecting the old root against the new salt. Separate tests exercise v1 import,
last-passkey/revocation, saved confirmation rollback, SQL failure/CAS contention,
request binding and real-socket cancellation. Synthetic PRF material and signed
fixtures are **not genuine PRF/provider/browser proof**.

Manual positive authenticator acceptance (PENDING, not executed here):

```sh
npm --prefix web run build
go build -o /tmp/warden-server-t3 ./cmd/warden-server
trial=$(mktemp -d)
/tmp/warden-server-t3 init --config "$trial/server.json"
# Use only "$trial/vault.db", a trusted HTTPS origin/RP and configured TLS
# certificate/key or same-host loopback proxy. Complete actual PRF registration
# and offline recovery save/hide/re-entry; init exits.
/tmp/warden-server-t3 serve --config "$trial/server.json"
```

In the production UI: login locked -> PRF unlock -> create synthetic data -> add
second passkey (old-owner fresh assertion, new create + get/PRF, bound old-owner
key-delivery assertion) -> separately login/unlock each -> revoke a nonlast
credential -> fresh reveal/mutation/export -> import documented v1 into a SECOND
fresh initialized empty destination, never into real storage -> restart locked ->
ordinary login without implicit global unlock -> explicit unlock -> compare logout
to global lock -> offline recovery proof/unlock -> confirm management denied ->
register/verify replacement -> ordinary new-passkey login/unlock -> verify old
passkeys fail -> restart/login/unlock -> explicit recovery rotation/save/hide/
re-enter -> verify old root fails current state. Abort recovery/rotation trials
must preserve current identity/recovery. Reentry/commit must finish inside60s;
restart a fresh authorization if it expires. Protect exports/roots offline and
retain deliberately protected rollback artifacts; never delete/reuse an old DB.

No accessible genuine authenticator/browser or native Windows acceptance was
established in this session. Genuine PRF-positive HTTPS/browser, native Windows
and actual production-browser CSP/network validation remain pending, not replaced
by mocks/vectors/signed fixtures/cross-compilation. No provider compatibility
claim, network-receipt guarantee, GC zeroization proof, HTTP/2 proof or completed
M1/security-release claim is made. T5–T17 and external DB/proxy plaintext residual
risks remain as documented, without any external TLS feature/schema work.

## Final-source verification addendum

After adding the production-TLS lifecycle and reviewing the actual tracked diff
and new production files, reran the complete relevant Go package set and its
race variant above with `-count=1`: both PASS, including the final old-passkey
rejection checks in the TLS journey. `go vet ./...` PASS. A final sequential
`go test ./... -count=1` fails ONLY the known unchanged SFTP mismatch; DB tests
pass. Additionally `go test -race ./internal/server/runtime -run
'^TestHTTPSRuntimeT3SecurityLifecycle$' -count=5` PASS and
`go build -o /tmp/warden-server-t3 ./cmd/warden-server` PASS. Logs:
`/tmp/warden-t3-final-source-{go,race,vet,full}.log`,
`/tmp/warden-t3-final-tls-repeat.log`. This is Linux execution, not native Windows.
The prior reference patch SHA-256 was independently rechecked unchanged.

Tracked diff whitespace, new-file/local-ledger whitespace/newline checks,
gofmt and local documentation links were checked; protected `mise.toml` was
excluded without reading it. No files staged; branch/HEAD remain the assigned
`hieudmg/security-hardening`/`99bcbeb`.

## T4 integration contract — not implemented here

- `Installation.AuthorizationGeneration` defaults0 for existing checkpoints and
  persists with complete identity. Recovery replacement increments it IN THE SAME
  CAS transaction as credential/wrapper replacement and session deletion. T4 must
  bind each durable client verifier to the generation at approval and compare
  CURRENT generation on EVERY authenticated request (including pooled retrieval
  and after server restart). A mismatch is revoked; never automatically rebind
  or reactivate an old verifier. T4 may alternatively delete client rows inside
  that transaction, but may not weaken the durable generation barrier.
- No client credential table, token, pairing route, transport alias or speculative
  client store was added. Reuse exact-request fresh grant issuance/consumption
  for T4's explicit approval/revoke actions; add only its explicit client-route
  allowlist, never bearer acceptance on management/security routes.
- Future policy is unchanged: per-user agent owns a memory-only API token and API
  requests; durable server verifier survives server restart, no token expiry/
  rotation/refresh; daemon has NO timed exit in ANY auth/pool/outage/server state.
  Only actual agent exit/restart loses the token and requires approval. Logout/
  revoke/lock/outage do not end the daemon. Disk IPC trust material is separate
  and never contains the API token. No client implementation was performed.

## Changed paths / safeguards

- `internal/crypto/vault.go`, new `vault_delivery_test.go` — exact live-lease key copy.
- `internal/server/setup/{setup,installation}.go` — collection/checkpoint JSON and
  durable authorization generation, no setup protocol weakening.
- New `internal/store/identity{,_test}.go` — atomic CAS/session revocation and real
  SQL rollback/single-winner tests, no new schema.
- `internal/server/runtime/plane{,_test}.go`; new `actions{,_test}.go`,
  `identity{,_test}.go`, `passkeys{,_test}.go`, `enrollment_test.go`,
  `recovery.go`, `recovery{,_audience,_concurrency}_test.go`,
  `recovery_rotation{,_test}.go`, `lifecycle_test.go`, `key_delivery_test.go`,
  `transfer_test.go`, `security_tls_test.go` — bounded T3 implementation/evidence.
- `web/src/auth/{auth.ts,auth-gate.tsx,auth.test.tsx}`; new
  `{actions.ts,security-view.tsx,security.test.tsx}`;
  `web/src/api/client{,.test}.ts` — working browser flows and exact fetch grants.
  Ignored generated embedded dist rebuilt from these sources.
- Binding spec, narrow T3/T4 plan notes, `docs/initialization.md`, this report,
  ignored local ledger — current scope, historical distinction and measured handoff.

No protected `mise.toml` read/change, version bump, dependency edit, commit/push/
PR, deployment, release, worktree, children, real DB/migration, external DB/proxy
behavior change, client/T4 implementation or export2. No staging. Stop at bounded
T3 self-review and separately pending external acceptance.

## Bounded T3 review follow-up — P1 recovery ingress / P2 unsubmitted root

Assigned branch/HEAD remain `hieudmg/security-hardening` / `99bcbeb`, with the
existing uncommitted T3 implementation preserved. This follow-up changes only
`internal/server/runtime/{plane.go,actions.go,recovery_ingress_test.go}`,
`web/src/auth/{auth-gate.tsx,auth.test.tsx}`, this report and the local execution
ledger. It is **not T3 acceptance**, M1 acceptance, or authorization for T4.
Systematic debugging and TDD guidance, the binding recovery audience/atomic
replacement contract, prior report and ledger were read before behavior changes.

### P1 — reproduced stale ingress, then revalidated inside the lease

The initial recovery exclusion and durable-session lookup occurred BEFORE
`vault.Acquire`. An ordinary request paused in that gap could acquire a NEW lease
after recovery proof locked/drained old leases and recovery unlocked. Likewise,
after atomic replacement deleted its durable session, subsequent ordinary unlock
allowed the paused request to use its cached session. The earlier blanket claim
that normal management was blocked during recovery was therefore overstated for
this delayed-ingress case.

Before any auth behavior fix, added an **unexported scheduling-only hook** at the
pre-Acquire boundary (nil in production; no authentication verdict or bypass),
and ran:

```sh
go test ./internal/server/runtime -run '^TestRecoveryRejects(OrdinaryIngressDelayedBeforeAcquire|FreshBeginDelayedBeforeBodyRead)$' -count=1 -v
```

Actual RED: real HTTP/server middleware delayed managed requests returned200,
called the managed handler once, and delivered the synthetic secret after
recovery unlock, after replacement/session deletion plus new ordinary unlock,
and after logout plus independent ordinary unlock. Expected423 during recovery
or401 for the revoked session, and ZERO managed calls. Analogous passkey and
rotation ingress reached pending-state rejection403 rather than the required
current-audience/session denial; that was **not** evidence of DEK disclosure.
Separately, a held-body fresh-begin request allocated an ordinary unlock challenge
and returned200 during restricted recovery. Initial RED used a controlled body
reader for that subcase; the final regression was strengthened to actual
net/http over net.Pipe with withheld HTTP bodies. No sleeps authorize ordering.
Log: `/tmp/warden-t3-review-p1-red.log` (ephemeral).

Minimal fix:

- After Acquire, inside `deliver` with cancellation already installed, validate
  the CURRENT durable session/credential and recovery audience under `p.mu`.
  Both managed dispatch and `withVault` passkey/enrollment/rotation paths use
  this check. The lease spans validation, handler, checked Write/Flush and joined
  cancellation cleanup. If recovery reserved first, reject; if it reserves later,
  its Lock must cancel/drain this already-held lease before proof/unlock. Never
  hold `p.mu` across a handler or a draining `vault.Lock`.
- Ordinary unlock cannot acquire a lease while locked: instead serialize durable
  session/audience revalidation, grant validation and key publication under the
  same owner mutex as recovery reservation and atomic identity replacement.
  A queued ordinary unlock with a genuine pre-recovery signed grant cannot
  enable the global vault during recovery, nor after logout revoked its session.
- Fresh/login begin checks recovery again under its existing owner mutex. Fresh
  grant and login-session publication recheck recovery after verifier work;
  fresh grant publication also keeps durable-session revalidation under that
  mutex. Credential-list metadata validates under the same lock. Ordinary
  status/logout/global-lock exceptions remain; no route audience is broadened.

Focused command GREEN. Final `recovery_ingress_test.go` extends it with15
real-socket delayed pre-Acquire cases spanning managed, passkey registration/key,
rotation prepare/key; queued fresh begin/finish/ordinary stale-grant unlock over
real HTTP/net.Pipe; revoked-session unlock after a withheld body; and a real
managed POST admitted before recovery that is canceled/drained before proof
acknowledgement, without mutation or secret delivery. Additional cases are
already-green boundary characterizations, not invented extra RED cycles.
Existing signed normal/recovery enrollment, same-DEK delivery and replacement
journeys still run in the complete runtime suite. The missing-ID key-route
subcases establish rejection BEFORE pending/grant handling, not a standalone
proof of a formerly successful DEK exfiltration.

The existing response buffer, Write+Flush, abort sentinel, WRITE-before-READ
cancellation deadlines, callback stop/join and lease release logic are unchanged.
The shared response-delivery implementation was not rewritten. Restricted
recovery still requires a verified NEW PRF passkey and atomic ALL-old replacement;
abort/rollback behavior and identity/session revocation transactions are unchanged.

### P2 — reproduced typed root resurfacing, then cleared UI state

Before changing AuthGate behavior, ran:

```sh
(cd web && NODE_ENV=test ./node_modules/.bin/vitest run src/auth/auth.test.tsx)
```

Actual RED:4 new tests retained `synthetic-unsubmitted-offline-root` after
passkey login/logout, while competing login awaited the authenticator, after
security epoch invalidation, and across client reset. Only recovery submission
had cleared this state. Log: `/tmp/warden-t3-review-p2-red.log`.

AuthGate now clears unsubmitted recovery input before starting any competing
flow, on security-signal abort/auth-state/client transitions, and during cleanup.
The original submit snapshot remains usable only by the intended recovery call.
No AuthClient asynchronous generation guard was removed or changed. Final focused
suite:9 tests PASS, including unmount/remount and external auth transitions.
One initial GREEN run exposed the existing SecurityView unmount cancellation of
an outstanding logout request; the external-transition test explicitly accepts
only that expected cancellation while still asserting EMPTY input. Production
cancellation was not weakened. Logs: `/tmp/warden-t3-review-p2-green.log`.
This drops UI/DOM state best effort; it is **not GC/string zeroization proof**.

### API/source evidence and final validation

No dependency or third-party WebAuthn/SQLite API changed. Before the React/test
edits, refreshed Context7 React19.2.8 source evidence
`ctx7:docs:79ffe0c5b56a4e0e91ab3440`, Vitest mock guidance
`ctx7:docs:a4e0d50a5c96df6c536a1a60`, and exact React Testing Library16.3.2
`ctx7:docs:ec22f043b654e13a0adb283b`; inspected installed
`@testing-library/react/dist/act-compat.js`. Official installed Go1.25.14
`sync/{mutex,cond}.go` and `go doc sync.Mutex`, `sync.Cond`, `context.AfterFunc`,
HTTP read/write-deadline docs confirm synchronization, Cond.Wait releasing its
mutex, callback join requirements and blocked-I/O interruption. Lock-order review:
owner mutex may take the vault's short state lock, but recovery/lock never drains
while holding the owner mutex. No native Windows runtime evidence is implied.

Broader Go/race/vet checks ran after the frontend build completed; no concurrent
embedded-dist rebuild occurred during Go checks. Focused RED/GREEN and the first
ingress repeat ran earlier in the chronology above:

| Command | Result |
| --- | --- |
| `go test ./internal/server/runtime -run 'TestRecoveryRejects|TestOrdinaryUnlockRevalidates|TestRecoveryActivationDrainsValidated' -count=1 -v` | PASS (final real HTTP/net.Pipe regression version) |
| `go test -race ./internal/server/runtime -run 'TestRecoveryRejects|TestOrdinaryUnlockRevalidates|TestRecoveryActivationDrainsValidated' -count=10` | PASS |
| `(cd web && NODE_ENV=test ./node_modules/.bin/vitest run src/auth/auth.test.tsx)` | PASS9 tests |
| `NODE_ENV=test npm --prefix web test` | PASS17 files/250 tests +13 dist tests |
| `npm --prefix web run build` | PASS; existing >500kB management chunk warning |
| `go test ./cmd/warden-server ./internal/config ./internal/crypto ./internal/store ./internal/server/... ./internal/web -count=1` | PASS |
| `go test -race ./cmd/warden-server ./internal/config ./internal/crypto ./internal/store ./internal/server/... ./internal/web -count=1` | PASS |
| `go test -race ./internal/server ./internal/server/runtime -run 'TestManagedResponse|TestRuntimeKeyDelivery|TestRecoveryActivation|TestRecoveryRejects|TestOrdinaryUnlockRevalidates|TestOrdinarySessionCannotEnterRecovery|TestMiddlewarePropagatesAbortHandler|TestResponseControllerFlushPreservesPanicStatus' -count=25` | PASS25 repetitions |
| `go vet ./cmd/warden-server ./internal/config ./internal/crypto ./internal/store ./internal/server/... ./internal/web` | PASS |
| `go test ./... -count=1` | FAIL solely unchanged SFTP `TestPosixRelMatchesFilepathRel`, `..` vs `../.`; DB suite PASS; no unrelated fix |

Ephemeral logs: `/tmp/warden-t3-review-{p1-red,p1-green,p2-red,p2-green,ingress-repeat,web,build,go,race,boundary-repeat,vet,full}.log`.
The initial P1 GREEN log predates supplemental real-body/stale-grant/drain tests;
final complete Go/race/repeat checks include them. Final focused real-boundary
rerun also PASS: `/tmp/warden-t3-review-final-focused.log`. Tracked diff check
excluding the protected file, gofmt on the three bounded Go files and explicit
seven-file whitespace/newline checks all PASS; no staged files, branch/HEAD
unchanged. No older evidence is relabeled as fresh RED or final-source validation.

Self-review blast radius: normal and sensitive managed dispatch, ordinary versus
restricted passkey/rotation DEK ingress, fresh-grant/login publication, ordinary
global unlock, session revocation/replacement and the AuthGate root lifecycle.
No `deliver`/vault/identity-CAS cryptographic or transport change, dependency or
version edit, T4/client change, staging/commit/push/deploy/worktree/children or
protected `mise.toml` read/change. Genuine-authenticator PRF-positive HTTPS/browser,
native Windows and production-browser CSP remain externally pending. Stop at
bounded T3 review fixes/self-review; **no T3 acceptance claim**.

## Tests-only rereview correction — verified fresh/login publication

Independent rereview found a coverage gap, not a remaining production defect:
`TestRecoveryRejectsQueuedOrdinaryUnlockAndFreshFlow` used an unissued ID and an
empty credential for its queued fresh finish. That request returned403 at the
unknown-ceremony check, BEFORE verification and the final publication guard.
The earlier follow-up's queued-finish coverage must not be read as evidence that
that guard was exercised. The queued begin and genuine stale-grant unlock checks
remain, renamed `TestRecoveryRejectsQueuedOrdinaryUnlockAndFreshBegin`; only the
misleading unknown-ceremony finish subcase was removed.

Added `TestRecoveryRejectsVerifiedFinishPublication/{fresh,login}`. Each starts a
real issued ceremony with the correct session/login cookie context and signs its
actual challenge using the registered ECDSA fixture. The exact assertion is
independently accepted by the real verifier before use. Existing test-only
`afterAssertion` delegates to that same verifier and then blocks on channels;
recovery proof completes and reserves recovery while finish is blocked. Resuming
must return403, consume the challenge, leave ordinary grants empty, and issue no
authenticated response or session cookie. A published cookie is checked against
the durable session store and fails the test. No fake verification verdict,
unknown ceremony, signature bypass, sleeps or new production seam was introduced.
These are synthetic signed assertions, NOT genuine-authenticator PRF evidence.

This is **regression-sensitivity validation against existing production guards**,
not a new test-first chronology or a new production fix:

1. Current production: both subtests PASS (`-count=1 -v`).
2. Temporary local mutation: prepend `false && (...)` to ONLY the final login
   session-publication condition and final fresh grant-publication condition in
   `Plane.finish`. Both subtests FAIL: fresh returned200 with one stored grant;
   login returned200 with authenticated response and session cookie whose durable
   lookup succeeded. The complete fresh condition includes recovery, durable
   session and vault epoch checks; this mutation establishes sensitivity to the
   combined publication guard, not independent necessity of its recovery clause
   (recovery also advances the vault epoch).
3. Restore both conditions exactly. `cmp` against the pre-mutation snapshot PASS;
   pre/post `plane.go` SHA-256 both
   `d2144ee7fbb29a20957b828540579d06b5d41ac449ab17f67cbc2fd6eb54ca87`.
   Restored focused suite PASS, including both verified-finish paths.

Final-source checks for this correction:

| Command | Result |
| --- | --- |
| `go test ./internal/server/runtime -run 'TestRecoveryRejects|TestOrdinaryUnlockRevalidates|TestRecoveryActivationDrainsValidated' -count=1 -v` | PASS |
| `go test -race ./internal/server ./internal/server/runtime -run 'TestManagedResponse|TestRuntimeKeyDelivery|TestRecoveryActivation|TestRecoveryRejects|TestOrdinaryUnlockRevalidates|TestOrdinarySessionCannotEnterRecovery|TestMiddlewarePropagatesAbortHandler|TestResponseControllerFlushPreservesPanicStatus' -count=25` | PASS, including both new signed-finish paths |
| `go test ./cmd/warden-server ./internal/config ./internal/crypto ./internal/store ./internal/server/... ./internal/web -count=1` | PASS, complete runtime and relevant full server regression |

Ephemeral logs: `/tmp/warden-t3-publication-{green,mutation-red,restored-green,race25,server}.log`.
Only `internal/server/runtime/recovery_ingress_test.go`, this report and the
ignored local ledger changed in this correction. No production behavior change,
new third-party API/import, dependency or frontend edit; no frontend build/test
or repository-wide Go suite rerun is claimed here. Earlier broad-suite SFTP
failure and external acceptance limitations remain as previously recorded.
Original ingress/UI fixes, lease through checked Write/Flush, WRITE-before-READ
cancellation deadlines, joined abort cleanup and recovery replacement invariants
are retained unchanged. Protected file untouched/unread; no staging, commit,
push, deploy, worktree or T4. Branch/HEAD remain
`hieudmg/security-hardening` / `99bcbeb`. Stop after tests/docs self-review;
genuine PRF-positive HTTPS/browser, native Windows and production-browser CSP
remain pending, with no T3/M1 acceptance claim.
