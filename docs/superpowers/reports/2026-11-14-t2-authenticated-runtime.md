# T2 authenticated runtime checkpoint

Implemented against branch `hieudmg/security-hardening`, local T1 checkpoint
`dbf7a199e1e67d2c062873857201e291aec29e87`. One writer; no publication.

**This is bounded T2, not T3, M1 acceptance, or a completed security release.**
Genuine PRF-capable authenticator positive HTTPS/browser acceptance from T1 is
still pending. Native Windows execution and production-browser CSP/network
acceptance remain unverified. Signed fixtures, mocked browser PRF and successful
WebCrypto vectors do not replace those proofs.

## Delivered behavior

- Normal `serve` requires the explicit stored HTTPS/RP configuration and a
  complete initialized identity. It starts with a **new locked vault**, never
  calls the old key-taking store constructor, and never loads a disk master key.
- Direct TLS uses the configured certificate/key and minimum TLS1.3. Explicit
  same-host proxy mode requires a literal loopback backend and configured
  authority. Host validation precedes static/API routing, including actual
  `OPTIONS *`; forwarded headers cannot promote an untrusted request.
- Login uses the real pinned WebAuthn verifier and works without PRF/DEK or any
  managed getter. Required UV, exact configured RP/origin, signed assertion,
  credential ownership/userHandle, challenge/purpose/context and server expiry
  checks are independent of PRF output.
- Sessions are CSPRNG32 bearer cookies, Secure/HttpOnly/SameSite=Strict/Path=/,
  host-only `__Host-warden-session`. SQLite stores only bearer and CSRF hashes,
  credential binding and timestamps, not plaintext bearers. CSRF is derived with
  a separate domain label from the opaque bearer and returned only in authenticated
  responses; it is held in browser memory. Login rotates/revokes the prior session.
  Idle30min and absolute12h are enforced on the server. Ordinary session state
  survives server restart; key availability never does.
- Fresh unlock is a **new required-UV assertion**, not a login age flag. The
  server releases only the bound credential's wrapper after verifying it. The
  browser requests stored `prf_input` as standard `eval.first`, unwraps locally
  using the T1 HKDF/AES-GCM contract, and sends only DEK plus the one-use grant.
  No PRF/KEK or generic extension results are serialized to the server. Missing
  PRF permits login but explicitly fails unlock; no plaintext-key fallback.
- Challenges expire after five minutes, are consumed atomically on finish
  attempt, and are checked before **and after** verification. Pending caps are
  eight/context and128 globally, including pre-login contexts. Login starts and
  finishes share the global5/second, burst10 bucket. Grants are single-use60s,
  bound to session, credential, action, credential target and vault generation;
  grant state is also capped128. Generic429 responses include Retry-After1.
- DEK delivery without a session and verified fresh grant is refused even for
  the correct key. Only the initialized authenticated key-check can validate the
  delivered DEK; a client cannot choose a replacement vault key.
- One runtime `crypto.Vault` owns long-lived key access. Store holds its codec
  interface, not a copied permanent codec. HTTP secret operations acquire a
  cancellable lease covering handler execution **and response delivery**. Lock
  blocks acquisition, advances the generation, cancels/drains active leases and
  clears key references before acknowledging. Buffered partial responses are
  discarded on cancellation. Old challenge/grant deliveries cannot re-enable
  access after lock. Clearing Go/JS memory is best effort, not GC erasure proof.
- Logout revokes only that browser session; it does not lock the global vault.
  Lock leaves login sessions intact. Tests cover independent browsers.
- Every existing managed API route family requires a web session and unlocked
  vault, including method/slash variants and unknown API paths. API bearers do
  not substitute for a management session; no client audience is implemented.
  Unsafe cookie requests require exact single Origin, JSON and session CSRF.
  Foreign/null/missing/duplicate origins, bad Host, simple content types and
  foreign Fetch Metadata fail closed. Auth/data success and error paths are
  no-store; sensitive responses are not conditional-cache responses.
- The embedded normal UI now mounts `AuthGate`: usable login, locked status,
  explicit PRF unlock, management, lock and logout controls. Management forms
  unmount on reset. Browser promises and managed JSON/Blob/file reads carry
  generation guards, abort where available, and cannot repopulate state after
  lock/logout or an observed remote lock. No session bearer, PRF, DEK or unlock
  token is persisted in browser storage, caches or URLs.

### Deliberately fail-closed until T3/T4

After session/unlocked gates, these existing routes return
`403 fresh_action_required` rather than exposing an ungated legacy operation:

- All `/api/v1/data/*` export/import operations.
- Key-pair reveal, mutation and dependent subroutes; only `GET /api/v1/key-pairs`
  redacted summaries are available.
- All `/api/v1/transport/*` extraction. These bundles can inject the same vault
  private keys as direct reveal; leaving them functional would be an indirect
  bypass. The final regression specifically tests this path.

The UI explains this restriction. Ordinary SSH/DB/group/project/report
management works after unlock. Existing CLI calls cannot authenticate through the
management audience. T3 owns fresh sensitive-action wiring and passkey/recovery
management; T4 owns the separately allowlisted client audience. No passkey
addition/removal, recovery replacement/rotation, pairing or client implementation
was smuggled into T2.

## Initialized storage and live SQLite evidence

`store.OpenInitialized` validates before original SQLite opens, WAL pragmas,
managed schema creation, chmod or key access:

1. Probe private0600 DB/WAL/SHM copies in a private temporary directory with
   ordinary `mode=ro`, **not** T1's immutable reader. Refuse hot rollback journals.
2. Verify SQLite integrity, exact supported schema, singleton format1 and the
   complete typed T1 JSON: owner/credential, both wrappers, recovery verifier,
   key-check and exact configured origin/RP. Unknown fields/formats or schema
   are not treated as an empty installation. Initial refusal creates no lock
   artifact or original sidecar.
3. Acquire the existing OS init/serve lease and repeat the authoritative probe
   under exclusion. Non-Warden concurrent writers are unsupported; never edit
   live storage externally. A concurrent Warden serve cannot acquire the lease.
4. Only validated identity-only T1 storage gets the existing embedded managed
   migrations, exact migration metadata/index and session table in **one SQLite
   transaction**. Cancellation before commit leaves identity-only storage and
   allows retry. Existing runtime storage must match this supported schema; no
   old encrypted-store compatibility or incremental dirty-schema repair.
5. Live auth reads use `Store.Installation` through the owned normal WAL
   connection, without a key. Verified authenticator counter/backup updates
   preserve the complete identity including recovery and wrappers.

Tests prove an uncheckpointed newer identity exists in WAL, the probe observes
it rather than stale main-file data, and probing leaves original DB/WAL/SHM
bytes unchanged. An owned normal WAL read may update SHM read marks; it is not
claimed immutable. Synthetic legacy live-WAL, corrupt and unknown-schema
refusals preserve original artifacts and modes. The immutable T1 DELETE-journal
reader remains unchanged and is not used by normal startup.

Selected source/documentation evidence:

- `github.com/go-webauthn/webauthn v0.17.4`, official installed
  `/home/hieudm/go/pkg/mod/github.com/go-webauthn/webauthn@v0.17.4/webauthn/login.go`:
  generated challenges, required UV/options, expiry, owner/allowed IDs,
  userHandle, signatures/RP/origin, backup flags and UpdateCounter. Context7
  refreshed `ctx7:docs:d748e4efcc2563b04a3f7801`; original parent references remain
  in T1 report. Valid synced BE/BS credentials with repeated zero counters pass;
  no bespoke increasing-counter or signature validation was added.
- `modernc.org/sqlite v1.57.0/conn.go:56-104` enables file URI processing.
  Official SQLite WAL/URI docs `ctx7:docs:4c64e81aaa9ea1fb3d9ac3a9` explain why
  read-only WAL can still write shared memory and why immutable skips locking/
  change detection. Private probes avoid those effects on refused originals.
- Official installed `golang-migrate/v4@v4.19.1/database/sqlite/sqlite.go:80-87`
  defines migration table/index; the runtime transaction preserves that exact
  schema. Existing migrations/AAD/redacted models and transactions are retained.
- Go1.25.14 installed standard source: `src/crypto/tls/tls.go`,
  `src/net/http/server.go`, `src/net/http/httputil/reverseproxy.go`,
  `src/crypto/sha256/sha256.go`, `src/crypto/subtle/constant_time.go` checked.
- React installed exports/types for useEffect/useSyncExternalStore and Context7
  `ctx7:docs:a79021d365902eae373b81bf` checked before integration. Existing
  WebCrypto and signed-only setup serializer are reused, not replaced. Radix
  dialog `dist/index.mjs:108-124` supplies inline overlay styles: CSP permits
  necessary styles, not inline scripts/eval. Actual browser CSP remains pending.

Private startup probes copy the encrypted DB and sidecars and require temporary
space/time proportional to storage; crash leftovers can be private temporary
probe directories. No raw DEK is in these copies. No performance claim for
large installations or support for externally modified live storage is made.

## Actual test-first checkpoints

The execution ledger records the sequence, not just final passing tests.

| Focused command, before its production edit | Observed RED | GREEN |
| --- | --- | --- |
| `go test ./internal/crypto -run 'TestGlobalLockDrainsSecretOperations|TestRuntimeVaultCodecRevocable' -count=1` | Missing runtime vault APIs | PASS |
| `go test ./internal/store -run TestInitializedRuntime -count=1` | Missing initialized/session APIs | PASS |
| `go test ./internal/server/runtime -run 'TestManagementRoutesRequireSessionAndUnlock|TestLoginWhileLockedWithoutCodec|TestUnlockRequiresFreshVerifiedCeremony|TestSessionExpiryAndLogoutDoesNotGloballyLock' -count=1` | Missing authenticated plane | PASS |
| `go test ./internal/server/runtime -run TestNormalRuntime -count=1` | Missing HTTPS Run/Options | PASS |
| `go test ./internal/server/runtime -run TestRuntimeLoginPersistsVerifierCounterAndCompleteIdentity -count=1` | Verified counter not persisted | PASS |
| `go test ./internal/store -run TestInitializedRuntimeUnknownSchemaRefusedBeforeMutation -count=1` | Unknown schema accepted/migrated; then directory assertion exposed lock artifact on refusal | PASS after both fixes |
| `(cd web && NODE_ENV=test ./node_modules/.bin/vitest run src/auth/auth.test.tsx)` | Missing auth client/gate; later remote-lock observation did not advance epoch | PASS after each change |
| `(cd web && NODE_ENV=test ./node_modules/.bin/vitest run src/api/client.test.ts)` | No no-store/CSRF, late JSON disclosed data, late file read started import | PASS |
| `go test ./internal/server/runtime -run 'TestHTTPSRuntimeSubprocessRestartAuthentication/tls' -count=1` | Actual TLS OPTIONS-star request bypassed Host gate,200 | PASS with403/no-store |
| `go test ./internal/server/runtime -run TestRuntimeGrantSaturationHasRetryAfter -count=1` | Saturation429 lacked Retry-After | PASS |
| `go test ./internal/server/runtime -run TestTransportCannotBypassVaultRevealGate -count=1` | Legacy transport returned private key after session/unlock | PASS, specifically fail-closed |
| `go test ./internal/store -run TestInitializedRuntimeSchemaCreationAtomic -count=1` | Missing atomic first-runtime initializer | PASS; canceled transaction leaves only identity and can retry |

Further already-green acceptance characterizations are not retroactively called
RED: real signature/UV/RP/origin/owner/crossOrigin/unknown credential/replay and
concurrent consume matrix; challenge expiry before/after verification; grant
purpose/target/credential/session/wrong-key/expiry/replay/lock matrix; partial
response cancellation; all route/method/slash families; two-browser logout,
idle/absolute expiry, cookie rotation/hash storage and synced zero counters;
rate/challenge bounds; live WAL preservation; direct/proxy subprocess restart.

Corrected test assumptions are recorded, not hidden: project fixtures have no
created_at column; Go JSON byte fields use base64; owned WAL reads may change SHM
read marks; duplicate accurate status/heading text requires a role-specific UI
query. The transaction schema test also exposed the migration version index,
which was retained exactly rather than weakening schema validation.

## Runnable disposable journeys

Automated Linux journeys (synthetic identities/secrets/certificates only):

```sh
npm --prefix web run build
go test ./internal/server/runtime -run '^TestHTTPSRuntimeSubprocessRestartAuthentication$' -count=1
go test -race ./internal/crypto ./internal/store ./internal/server/runtime -count=1
```

The subprocess test runs the production `Run` with embedded assets and **real**
verifier, through direct TLS and a configured same-host HTTPS proxy, verifying a
trusted private CA without skip-verification. It signs challenges with a synthetic
ECDSA credential, logs in locked, freshly authorizes key-check delivery, creates
an encrypted synthetic SSH profile, reads its redacted getter, denies transport,
stops/restarts the process, retains the browser session but refuses data423 until
another fresh unlock, then proves logout differs from global lock. The helper
has no production verifier/config bypass. Browser PRF is separately mocked only
in JS tests; these journeys do not prove genuine authenticator PRF.

Manual positive acceptance, **not executed here**:

```sh
npm --prefix web run build
go build -o /tmp/warden-server-t2 ./cmd/warden-server
trial=$(mktemp -d)
/tmp/warden-server-t2 init --config "$trial/server.json"
# At prompts choose "$trial/vault.db", a trusted HTTPS origin/RP and either
# configured certificate/key paths or the documented same-host HTTPS proxy.
# Complete actual passkey/PRF registration and saved recovery re-entry.
/tmp/warden-server-t2 serve --config "$trial/server.json"
```

Open the configured HTTPS origin: login must work locked, data must fail423,
explicit PRF unlock must enable ordinary management. Create a synthetic profile,
restart serve with the same configuration, verify locked status with retained
session, freshly unlock again, compare logout to global lock. Never use an
existing/real database for this trial. Do not reset/delete an old DB to make it
start; retain old binary/config/DB+coherent WAL/SHM/key for rollback. Complete
recovery replacement and multi-passkey demonstrations only in authorized T3.

## Runtime wire seams / T3 handoff

All auth paths are under `/api/v1/auth/` and unsafe methods are JSON POST:

- `login/begin {}` -> temporary host-only login cookie plus `{id,options,credential_id}`.
- `login/finish {id,credential}` -> rotated session cookie and authenticated
  `{csrf,credential_id,unlocked}` metadata. Credential serialization includes only
  signed fields and empty generic client extension results.
- `GET status` -> authenticated key-independent status/CSRF/credential metadata.
- `fresh/begin {action:"unlock",credential_id}` -> new `{id,options,credential_id,prf_input}`.
- `fresh/finish {id,credential}` -> credential-bound `{grant,wrapper}`.
- `unlock {grant,dek}` -> validate initialized key-check and generation, enable key.
- `lock {}` -> cancel/drain/drop global key access; preserve browser sessions.
- `logout {}` -> revoke this session only; no global lock.

T3 must extend the complete identity model and exact supported schema together,
add explicit action/target or request-digest grants rather than remove denial
checks, and preserve generation/expiry/consume checks. It owns safe additional
passkeys, last-passkey rules, revocation, recovery proof/replacement/rotation and
fresh sensitive-action UI. Transport extraction must not bypass vault reveal;
T4's future client audience has its own explicit capability allowlist. Recovery
material remains unchanged and is not a management login bypass in T2.

Future client policy remains **documentation only**: existing per-user agent
owns a memory-only token, durable server hash/revocation survives restart, no
expiry/rotation/refresh, daemon stays alive until externally terminated, and SSH
graph idle eviction is independent. No client code changed here.

## Final validation and limits

Toolchains: Go `go1.25.14 linux/amd64`, Node `v26.12.1`, npm `11.20.0`.

| Exact check | Result |
| --- | --- |
| `npm --prefix web run build` | PASS; existing large management chunk warning |
| `NODE_ENV=test npm --prefix web test` | PASS16 files/238 Vitest tests +13 dist tests |
| `go test ./cmd/warden-server ./internal/config ./internal/crypto ./internal/store ./internal/server/... ./internal/web -count=1` | PASS |
| Same package set with `go test -race ... -count=1` | PASS |
| `go vet ./...` | PASS |
| `go build -o /tmp/warden-server-t2 ./cmd/warden-server` | PASS |
| `GOOS=windows GOARCH=amd64 go build -o /tmp/warden-server-t2-windows.exe ./cmd/warden-server` | PASS, compile only |
| `go test ./... -count=1` | FAIL solely known untouched SFTP TestPosixRelMatchesFilepathRel, `..` versus `../.` |

An earlier broad run also hit unchanged DB TestTunnelCloseClosesWholeChain (one
open connection after5s). Its focused `-count=5` and two subsequent full repeats
passed; cause is unverified and no client fix is claimed. A parallel vet/Vite
build briefly raced deletion/recreation of embedded dist; all Go/race/vet/build
checks were then rerun **sequentially after the completed frontend build** against
final assets. Ephemeral logs: `/tmp/warden-t2-web-final.log`,
`/tmp/warden-t2-go-final.log`, `/tmp/warden-t2-go-repeat.log`.

Remaining external/release boundaries: actual PRF-positive HTTPS/browser and
native Windows tests, real-browser CSP/network evidence, T3/T4 and later audit,
dependency/graph/audit/output/distribution/CI hardening. External DB and HTTP
CONNECT proxy behavior is unchanged; their plaintext legs remain scope-excluded
risks. A compromised live host/browser/proxy or same-origin JS can steal live
material. Old backups and already retrieved secrets cannot be retroactively
revoked. No M1/security-release completion claim.

## Bounded review follow-up — P1 managed-response finalization after lock ack

**Named issue:** `T2-P1-response-finalization-after-lock-ack`. Independently
reproduced against the uncommitted T2 checkpoint at `dbf7a19`, then fixed. The
original statement that the lease covered response delivery was not true for a
small successful response: `Plane` called `Write`, returned, and released its
lease while Go's HTTP/1 response buffer still retained the secret. Another
connection could finish global lock before the outer handler returned and
`net/http.finishRequest` emitted those bytes. `statusWriter` also hid transport
controls and swallowed the standard abort sentinel.

### Test-first evidence

Before production edits:

```sh
go test ./internal/server/runtime -run '^TestManagedResponse' -count=1 -v
```

RED: `TestManagedResponseEmittedBeforeLockAckAtHTTPFinalization` recorded
`socket secret writes at lock ack=0; after ack/outer return=1`. This is an actual
`net/http` server with production middleware, a server-side socket-write
observer, a small managed body, a deterministic pause **after Plane returns but
before the outer handler returns**, and authenticated lock on another connection.
It resumes handler finalization before checking the complete ordering. It does
not infer server emission from network arrival time. The controlled writer
regression also failed because no flush was called; injected error cases showed
normal return instead of abort. RED log: `/tmp/warden-t2-delivery-red.log`.

The same focused command after the fix is GREEN: socket ordering is **1 before
ack, 0 after ack**. `/tmp/warden-t2-delivery-green.log`. Extra boundary tests added
after that fix are already-green characterizations, not fabricated RED cycles.

### Fix and failure boundaries

- Preserve whole-handler response buffering: nothing secret is written until
  the managed handler succeeds and its lease context is checked. Cancellation
  during the handler still discards the partial response.
- Flush the completed response via `http.ResponseController` **before releasing
  the lease**. Check write errors, short writes and flush errors. On delivery
  failure/cancellation, panic with `http.ErrAbortHandler`; middleware propagates
  that sentinel so net/http aborts rather than finalizing retained secret bytes.
  Ordinary panic-to-500 handling remains intact.
- `statusWriter.Unwrap` exposes underlying transport controls. Its `FlushError`
  tracks implicit status200 before forwarding the error-aware flush, so a later
  ordinary panic cannot append a second error response after a flush.
- A lease-context cancellation callback advances the transport write deadline
  to interrupt a blocked Write/Flush; the existing runtime write timeout120s is
  retained, never reset/extended on normal completion. Wait for a started
  callback before handler return and release on all exits. No detached writer
  goroutine may retain the response/lease.
- Controlled underlying writer tests prove lock waits for flush completion and
  cover injected write/short-write/flush/deadline failures and both request/lock
  cancellation. Actual net/http over unbuffered `net.Pipe` deterministically
  saturates delivery: lock cancellation, peer closure and a test write deadline
  unblock delivery and lock without emitting retained secret bytes. Separate
  real TLS1.3 HTTP/1.x coverage verifies flushing through production middleware
  before the outer handler returns. Existing global-drain, partial-buffer,
  stale-grant, route-denial and race tests remain green.

### Exact Go API/source evidence and protocol limit

Checked installed official Go **1.25.14** source before API changes, under
`/home/hieudm/.local/share/mise/installs/go/1.25.14/src/`:

- `net/http/responsecontroller.go:21-62,99-117`: Unwrap traversal, error-aware
  Flush and write deadlines; controller use ends at handler return.
- `net/http/server.go:1625-1635,1690-1701,1750-1761`: separate response/chunk/
  connection buffers, handler-return finalization, and HTTP/1 FlushError draining
  both buffers to the connection. `:1928-1950` and ErrAbortHandler docs confirm
  panic abort skips normal response finalization.
- `crypto/tls/conn.go:153-157`: TLS write deadline forwards to the underlying
  connection; timed-out TLS writes cannot subsequently resume successfully.
  `net.Conn.SetWriteDeadline` documents interruption of currently blocked writes.
- `context.AfterFunc` documentation: stopping a started callback does not join it;
  the explicit completion channel prevents ResponseWriter use after return.
- `net/http/server.go:3422-3428`/`Server.Serve` docs and current
  `runtime.Run`: TLS listener has no ALPN `h2`, plain proxy backend is HTTP/1.x,
  and no unencrypted HTTP/2 protocol is configured. No protocol changed here.
- Evaluated `net/http/h2_bundle.go:5120-5162,5284-5295,5310-5415,6839-6862`:
  HTTP/2 has separate frame scheduling/connection buffering; its FlushError
  waits on a DATA-frame writer whose completion can precede the connection
  buffer flush. Do **not** generalize this HTTP/1 emission proof to HTTP/2 or
  enable it without separately establishing the unchanged lock contract. HTTP/2
  is not currently advertised/supported by this runtime; a proxy's client-side
  HTTP/2 connection is outside the server-side backend emission boundary.

Successful flush establishes emission into the server's network stack, **not**
client receipt. Bytes already emitted may arrive after lock acknowledgement;
TCP/TLS/network queues, trusted-proxy buffering and already retrieved secrets
cannot be retracted. Final HTTP/1 chunk terminators may be emitted on handler
return but contain no new secret body. No stronger client-arrival, zeroization,
proxy-erasure, HTTP/2, genuine PRF, native Windows or browser-CSP claim is made.
The spec/lock guarantee and T3 fail-closed routes were not weakened or changed.

### Follow-up validation

| Exact command | Result |
| --- | --- |
| `go test ./internal/server ./internal/server/runtime -run 'TestManagedResponse\|TestResponseControllerFlushPreservesPanicStatus\|TestMiddlewarePropagatesAbortHandler' -count=1 -v` | PASS, actual TLS/finalization/blocked-write and controlled error boundaries |
| Same focused set with `go test -race ... -count=25` | PASS25 repeats |
| `go test ./cmd/warden-server ./internal/config ./internal/crypto ./internal/store ./internal/server/... ./internal/web -count=1` | PASS |
| Same package set with `go test -race ... -count=1` | PASS |
| `go vet ./cmd/warden-server ./internal/config ./internal/crypto ./internal/store ./internal/server/... ./internal/web` | PASS |

Ephemeral logs: `/tmp/warden-t2-delivery-{boundaries,suites,race,repeat,vet}.log`.
Self-reviewed the bounded production diff and all three new test files, then
reran the relevant package/race/vet checks against final Go sources. Tracked
`git diff --check -- ':!mise.toml'`, gofmt, and an explicit whitespace/newline
scan of all eight bounded-fix files (including untracked files/local ledger)
pass. Branch/HEAD remain `hieudmg/security-hardening`/`dbf7a19`.
No frontend/dependency/spec/client changes; no new full-baseline or native/browser
acceptance claim. The previously documented unrelated SFTP baseline is unchanged.

## Bounded re-review follow-up — P2 cancellation blocked by unread-body drain

**Named issue:** `T2-P2-unread-body-drain-lock-responsiveness`. The original P1
flush-after-release issue remains fixed, but its write-only cancellation deadline
was insufficient. Go HTTP/1 `Flush` can first drain an unread request body before
emitting headers. An authenticated keepalive `GET /api/v1/ssh-connections` with
`Content-Length: 1` and the byte withheld held the response lease during that
read, delaying global lock until the unchanged 120-second read timeout.

### Actual RED, diagnosis and narrow fix

Before editing production behavior, read the lock specification, this report,
ledger, systematic-debugging/TDD guidance, and exact installed Go1.25.14 standard
APIs/source: `net/http/responsecontroller.go:80-117` (read/write deadline traversal
and semantics), `net/http/server.go:1390-1464` (HTTP/1 pre-header `io.CopyN` drain),
`go doc net.Conn.SetReadDeadline` (interrupts currently blocked reads), and
`go doc context.AfterFunc` (stop does not join an already-started callback).
The server response methods forward deadlines directly to the connection;
TLS `SetReadDeadline` also forwards to its underlying connection.

```sh
timeout 20s go test ./internal/server/runtime -run '^TestManagedResponseUnreadBodyDrainTerminates/lock-cancel$' -count=1 -v
```

**RED:** failed in about one second with `lock did not promptly cancel read-drain
and release lease: read pipe: i/o timeout`, not the outer safety timeout.
Log: `/tmp/warden-t2-read-drain-red.log`. This uses actual net/http HTTP/1 and
production middleware over net.Pipe. A server socket observer is armed after
the managed handler finishes and detects the subsequent **read**, not a bodyless
blocked write. Only then does another authenticated HTTP connection issue lock.
Both server budgets remain 120 seconds; lock must respond within one second.

The smallest production fix adds `ResponseController.SetReadDeadline(now)` to
the existing cancellation callback. Set the **write deadline first**, then the
read deadline, so resuming the drain cannot emit buffered secrets. Keep the
existing callback stop/join before handler return, flush-within-lease, standard
abort sentinel, and release ordering. No deadline is reset or extended on the
ordinary path; no lock acknowledgement or request budget was weakened.

```sh
timeout 40s go test ./internal/server/runtime -run '^TestManagedResponse(UnreadBodyDrainTerminates|OrdinaryKeepaliveUnaffected|CancellationJoinsReadDeadlineCallback|CompletedRequestStopsCancellationCallback)$' -count=1 -v
```

**GREEN:** all pass; `/tmp/warden-t2-read-drain-green.log`. The canceled read-drain
connection closes without emitting the synthetic secret before or after lock
ack; handler termination and successful lock prove lease cleanup. Added boundary
characterizations also cover malformed chunk cleanup/connection closure, closed
peer cleanup, ordinary complete-body and bodyless requests on the **same**
keepalive connection, joining a deliberately paused read-deadline callback before
return, and stopping the callback on ordinary completion. These characterizations
are not claimed as separate behavioral RED cycles. Malformed input may receive
its managed response before lock; the test does not invent a new rejection policy.

### Fresh final-source validation

| Exact command | Result |
| --- | --- |
| `go test ./internal/server ./internal/server/runtime -run 'TestManagedResponse\|TestResponseControllerFlushPreservesPanicStatus\|TestMiddlewarePropagatesAbortHandler' -count=1 -v` | PASS |
| `go test -race ./internal/server ./internal/server/runtime -run 'TestManagedResponse\|TestResponseControllerFlushPreservesPanicStatus\|TestMiddlewarePropagatesAbortHandler' -count=25` | PASS, 25 repeats including read-drain cancellation |
| `go test ./cmd/warden ./cmd/warden-server ./internal/config ./internal/crypto ./internal/store ./internal/server/... ./internal/web -count=1` | PASS |
| `go test -race ./cmd/warden ./cmd/warden-server ./internal/config ./internal/crypto ./internal/store ./internal/server/... ./internal/web -count=1` | PASS |
| `go vet ./cmd/warden ./cmd/warden-server ./internal/config ./internal/crypto ./internal/store ./internal/server/... ./internal/web` | PASS |

Logs: `/tmp/warden-t2-read-drain-{focused,repeat,suites,race,vet}.log`.
Self-reviewed production callback ordering, new tests and exact current source;
gofmt and tracked plus new-file whitespace checks pass. Changed only runtime
`plane.go`, new `response_delivery_read_test.go`, this report and the local ledger.
No frontend/dependency/spec/T3 changes, commits, push, deployment or worktrees;
protected `mise.toml` was not read/changed. Full Go baseline and frontend were not
rerun for this bounded fix; the previously documented SFTP failure is untouched.
Genuine PRF-positive HTTPS/browser, native Windows, production-browser CSP,
HTTP/2 emission guarantees and T3 remain pending. Stop at bounded T2 self-review,
not security-release acceptance.

## Changed files and scope safeguards

- `cmd/warden-server/main.go` — authenticated serve/HTTPS lifecycle; no key loader.
- `internal/crypto/vault{,_test}.go` — runtime owner, cancellation/drain/generation.
- `internal/store/{store,runtime,runtime_test}.go`,
  `internal/store/transfer_test.go` — interface/live preflight/atomic initialized
  schema/session persistence; one existing test now compares its explicit source
  and destination key fixtures rather than introspecting a concrete codec.
- `internal/server/runtime/{plane,runtime}.go` and
  `{fixture,plane,runtime,runtime_tls}_test.go` — authenticated audience, real
  verifier integration, gates and disposable subprocess acceptance.
- Bounded P1 follow-up: `internal/server/server{,_test}.go`, runtime `plane.go`
  and `response_delivery{,_blocked,_tls}_test.go` — error-aware flush inside the
  lease, cancellation deadlines, abort propagation, status tracking, actual
  net/http finalization/TLS/saturation and controlled failure regressions.
- `web/src/auth/{auth,session}.ts`, `auth-gate.tsx`, `auth.test.tsx`;
  `web/src/api/client{,.test}.ts`, `web/src/main.tsx`,
  `web/src/setup/setup.ts` — memory-only auth UI/reset/no-store/CSRF; signed-only
  serializer exported for safe reuse. Generated ignored embedded dist rebuilt.
- `docs/initialization.md`, narrow T2 execution note in the approved plan, this
  report, and `.superpowers/sdd/2026-11-14-security-hardening-7c97840ce693/ledger.md`
  (ignored local ledger) — measured handoff and runnable instructions.

No dependency/version change, commits, push, PR, worktree, subagent, tags,
release, deployment, real database, live migration or client implementation.
Protected `mise.toml` was not read or changed. Stop at bounded T2.
