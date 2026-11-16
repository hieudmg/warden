# T6 — backend request boundaries, deadlines and cache failures

## Scope / status

Bounded T6 on `hieudmg/security-hardening`, reviewed T5 base **`699dd6f`**.
Single writer; no staging, commit/push, deployment, worktree, children, dependency,
version, external DB/proxy transport or frontend changes. Protected `mise.toml`
was not read or changed. Tests use disposable SQLite, synthetic signed passkeys,
private certificates and loopback sockets, never live credentials/data.

**Implemented and self-reviewed, NOT independently accepted or a security
release.** No T7 work. Genuine PRF-positive HTTPS/browser, production-browser CSP
and native Windows acceptance remain pending. No refreshed frontend tests/build
are claimed because no frontend files changed. T5's historical-export fixture
script and transfer/store/crypto implementations are unchanged.

## Existing behavior characterized, not unnecessarily replaced

The runtime already had exact configured Host/Origin, JSON/CSRF, separate
management-cookie/client-bearer audiences, locked-data gates and outer no-store.
Its 5/120/120/60-second header/read/write/idle settings were already correct.
New tests of these existing behaviors initially passed; these are **not RED**
claims or justification for replacing working security gates.

The added matrices cover create/import/report/login, unknown API routes, missing/
foreign/null/duplicate Origin, missing/wrong CSRF, text/plain/forms/duplicate
Content-Type, good JSON+Origin+CSRF, attacker authority/port/trailing dot/userinfo/
comma/empty Host, spoofed forwarding headers, direct TLS versus explicitly
configured loopback proxy, and stable configured RP ID. Public login/password
bootstrap intentionally has no prior session CSRF requirement; Origin+JSON is
mandatory. Rejected controlled bodies are never read or dispatched. Bearer
without Origin works only on the explicit client audience; foreign Origin fails
and bearer cannot authenticate management/export/auth routes. Existing T4 tests
continue to cover cookie rejection on the client audience and per-request durable
revocation/generation checks.

No blanket CORS grant, extra DNS alias/tailnet/private-host trust, header-derived
RP/origin, external TLS profile change or HTTP/2 server activation was added.

## Actual focused RED → GREEN chronology

| Command before corresponding behavior edit | Observed RED | Minimal retained change / GREEN |
| --- | --- | --- |
| `go test ./internal/server/runtime -run '^TestDataAndAuthResponsesNoStore$' -count=1 -v` | Missing asset returned404 with `public, max-age=31536000, immutable` | Assign immutable only after successful static read; missing asset explicitly no-store. Same focused test passes. |
| `go test ./internal/server/setup -run '^Test(CrossOriginTextPlainPOSTRejected\|SetupOptionsStarCannotBypassHostAndCacheGates\|SetupDeadlineNotExtendedBySlowRequest)$' -count=1 -v` | Setup read the body before rejecting missing CSRF; unknown non-setup paths used different gates. Real `OPTIONS *` with attacker Host returned200 with no cache header. Absolute deadline case already passed. | Check supplied Origin globally, apply unsafe JSON/Origin/CSRF gates before body reading and unknown-route handling, then revalidate setup authorization under its existing state mutex after reading. Preserve eight-request admission before waiting on that mutex. Pass OPTIONS-star to the plane using shared HTTP defaults. Same selection passes. |
| `go test ./internal/server/runtime -run '^TestExpensiveConcurrencySaturationAndCleanup$' -count=1 -v` | Third transfer/fifth key request reached the handler (204) and consumed its grant instead of returning429 | Separate non-waiting two-transfer/four-key lanes before body/grant consumption, held through response delivery and defers. Same focused test passes. |
| `go test ./internal/server/setup -run '^TestSetupSlowHeadersBodiesIdleAndWritesTerminate/tls/write$' -count=1 -v` | Repeated real TCP/TLS stalled-write test retained setup state beyond1s despite250ms injected write budget | Close the raw connection immediately on a failed transport Write, underneath the ordinary TLS listener. Same test and full setup socket selection pass, TLS write cleanup~250ms. |

Initial boundary command also included `TestCrossOriginTextPlainPOSTRejected`,
`TestHostAndDNSRebindingRejectedBeforeRouting` and
`TestBearerNoOriginOnlyClientAllowlist`: all passed existing runtime behavior.
The initial cache harness expected HEAD405, but Go ServeMux correctly supplies
HEAD for a GET registration. Corrected to HEAD200 BEFORE the actual static404 RED;
no production HEAD behavior changed. Setup's deadline characterization was also
already green, not relabeled as a new fix.

Primary logs (ephemeral): `/tmp/warden-t6-cache-red.log`,
`/tmp/warden-t6-setup-red.log`, `/tmp/warden-t6-concurrency-red.log`,
`/tmp/warden-t6-setup-tls-diagnosis.log`,
`/tmp/warden-t6-boundaries-green.log`,
`/tmp/warden-t6-setup-sockets-green.log`.

Shared HTTP-server construction is a behavior-preserving consolidation of existing
runtime/setup defaults except the demonstrated setup OPTIONS-star correction.
The default-field test supplements, never substitutes for, socket evidence.
Documentation/plan/report/ledger edits use the plan's documentation exception:
source/link/diff checks and actual runnable evidence, not a fabricated RED.

## Deadline root cause and retained response-lease invariants

Installed official Go **1.25.14** source was inspected before the transport fix:

- `net/http/server.go` Server timeout definitions, OPTIONS-star behavior and
  `chunkWriter.Write` (~377–398): failed writes call the connection's Close
  **before returning to the handler**.
- `crypto/tls/conn.go` ~145–157 and1430–1488: timed-out TLS writes cannot resume;
  `Close` calls `closeNotify`, which replaces the expired write deadline with a
  NEW five-second deadline. A non-reading peer can therefore keep the setup
  handler/mutex/request slot inside that cleanup. The captured goroutine stack
  shows `Plane.ServeHTTP -> chunkWriter.Write -> tls.Close -> closeNotify -> Write`.
- `net/http/responsecontroller.go`: Unwrap, checked Flush/read/write deadline
  forwarding and no ResponseWriter use after handler return; prior T2/T3
  stop/join/cancellation rationale rechecked against `crypto/vault.go` and current
  runtime `actions.go`.

`server.TLSListener` wraps the **raw accepted connection** before `tls.NewListener`.
On an actual raw Write error it closes that unusable stream, preserving the error
and byte count. It does not wrap away `*tls.Conn`: net/http still performs normal
TLS handshake/Request.TLS handling with TLS1.3 and the configured certificate.
Successful writes, normal keepalive and normal TLS close are unchanged. No custom
protocol, background writer or HTTP/2 support was introduced. Both production
setup and runtime use this listener and the shared defaults.

The managed delivery implementation is **unchanged**: buffer the entire response;
retain lease through checked Write+HTTP/1 Flush; cancellation sets WRITE deadline
then READ deadline; stop/join callback before return/release; propagate
`http.ErrAbortHandler` rather than recover/swallow it. New lanes enclose these
existing defers. Existing real emission/finalization/unread-body/DEK cancellation
regressions and signed production-Run restart/client journeys pass. Emission into
the server's network stack is NOT client receipt or proxy-buffer erasure. Already
emitted bytes/remote sessions are irretractable.

### Actual sockets, not just configuration assertions

`TestSlowHeadersBodiesAndIdleConnectionsTerminate` and
`TestSetupSlowHeadersBodiesIdleAndWritesTerminate` use actual TCP connections,
verified TLS1.3 or the configured literal-loopback plaintext backend hop. They
shorten the returned standard server's budgets to180ms header/idle and250ms
read/write before serving. Partial headers, withheld bodies, idle keepalive,
malformed/duplicate authorities and non-reading16MiB response peers terminate
within test bounds. The stalled runtime write must release its expensive slot
**before** Lock is invoked, so a subsequent Lock cannot hide a missing timeout.
Upload-disconnect waits for admission then verifies slot drain; incomplete imports
leave no managed data and no held vault lease. Setup static writes prove its
request slot/mutex also release after TLS timeout.

`TestSetupDeadlineNotExtendedBySlowRequest` runs the actual setup runtime with
readiness time injected to leave300ms of its unchanged absolute15-minute timer,
then withholds the password request body. The watchdog closes the listener/socket
and returns failure, with no installation. This watchdog socket case uses proxy
backend mode; separate direct-TLS production setup and short-duration TLS socket
checks exercise the shared runtime/transport paths. No15-minute wall-clock test
or claim that proxy/frontend/client receipt can be recalled is made.

Malformed/duplicate Host headers rejected by net/http's parser receive its generic
400 before any application handler; they do not contain managed data and may lack
application headers. Configured-authority rejections that reach the plane are403
with no-store. This is not a claim to rewrite Go's pre-handler parser responses.

## Full-size import/export and resource bounds

`TestFullSizeImportWithinDeadline` builds a deterministic valid v1 bundle, not a
tiny record padded with50MiB whitespace: **52,196,291 bytes** (~49.78MiB),4,096
profiles with synthetic encrypted passwords and~12KiB notes each. Every required
v1 array exists. It submits over trusted TLS1.3 directly and over a trusted HTTPS
same-host Go reverse proxy with a literal-loopback HTTP/1 backend. Both use the
production HTTP factory/listener. Upload is paced to **16MiB/s**. Limit+1 and
trailing second JSON values fail before any managed writes; accepted import is
verified by decrypting the final stored profile. A fresh export then delivers
more than49MiB successfully over HTTPS; no8MiB server transfer cap was added.
Existing exact50MiB/+1 T3 test is retained unchanged.

Final measured command:

```sh
/usr/bin/time -v go test ./internal/server/runtime \
  -run '^TestFullSizeImportWithinDeadline$' -count=1 -v
```

| Mode | Import wall time (paced upload + processing) | Go cumulative allocation delta | Go HeapSys |
| --- | ---: | ---: | ---: |
| Direct TLS | 3.839580554s | 737,791,808 bytes | 573,145,088 bytes |
| HTTPS proxy → loopback HTTP | 3.760695457s | 737,706,160 bytes | 573,014,016 bytes |

Whole invocation:10.80s wall, maximum resident set **522,468KiB**, no swaps;
`/tmp/warden-t6-fullsize-final.log`. HeapSys is reserved Go heap, allocation delta
is cumulative (not peak live memory), and RSS is the measured invocation maximum,
not an asserted deployment memory ceiling. Earlier fixtures briefly used
nonexistent getter names/wrong byte-field comparison and a48.8MiB note size;
corrected against actual store/model source before runnable acceptance, not
reported as behavioral RED. The final fixture also fixes exported_at for stable
body length rather than nanosecond-dependent JSON lengths.

Stopping condition: one bounded request per mode per invocation,120s client
wall deadline and test failure if cumulative allocation delta exceeds2GiB. The
byte/row counts are finite and no growing/endless benchmark exists. The allocation
check is observed after completion, not an OS hard memory limiter. The tested
link fits the existing60s fresh-grant lifetime as well as120s read/write budgets;
no slower-WAN/minimum-link guarantee or authorization lifetime extension is made.

Two concurrent transfers are an ordinary small per-process default, because each
retains large plaintext buffers; four independent key/verification operations
bound the costly sensitive lane without serializing the whole interactive UI.
The design did not prescribe these concurrency literals. Tests also inject a
one-transfer channel before serving, without adding a public configuration or
generic policy framework. Saturation is fail-fast429/Retry-After1/no-store, BEFORE
body reading/grant consumption. Admitted failures consume their grants; rejected
requests retain their exact pending grant/ceremony until normal expiry/generation
change. Error/panic/cancel releases slots and leases. Ordinary CRUD/status remain
available while the heavy lane is saturated. Existing auth/client16 and setup8
request caps stay in force; setup ceremonies already serialize under its state
mutex. The four-slot test uses real issued/signed assertions and the real verifier
before a scheduling barrier, and confirms locked metadata needs no DEK. No claim
that all ordinary CRUD cryptographic work has a new global four-request limit.

## Cache policy and proxy documentation

The outer runtime no-store policy remains; new tests include authenticated key/
export/transport routes, malformed decode, validation,404/401/403/423/429/500,
HEAD and conditional headers, buffered secret followed by panic, error cleanup
and successful immutable nonsecret assets. Unknown static404s no longer inherit
immutable. Application panic handling does not append leaked buffered secrets;
abort sentinel behavior is unchanged. No frontend CSP/privacy/password work was
included (T9 remains separate).

`docs/deployment.md` corrects the stale claim that tailnet membership replaces
application authentication, documents actual budgets/limits, and provides an
HTTP-context NGINX example: trusted public HTTPS, exact authority,50m body cap,
5/120/120/60 client timeouts,120s proxy send/read,5s connect, HTTP/1.1 backend,
no request/response buffering/cache, forwarding-header removal, and real Origin
preserved (never forged). NGINX inactivity intervals are explicitly distinguished
from Warden's absolute read/write budget. External DB/HTTP CONNECT behavior is
unchanged/out of scope.

Official NGINX directive docs were fetched through Context7 before finalizing the
example: `ctx7:docs:19a11bbe19a796fc0acaee36`,
`ctx7:docs:b8cdf83f2ff5522c94584d26` (proxy/core buffering, header removal,
inactivity semantics). Follow-up `ctx7:docs:97f21f94513fe1c43b2c5400` confirms
`ssl_handshake_timeout` belongs to stream SSL, not this HTTP example; that draft
line was removed. No NGINX executable is installed here, so **nginx -t/real NGINX
execution remain unverified**, not claimed from the Go proxy fixture.
No third-party Go API/dependency was added or changed; existing real WebAuthn
fixtures/verifier seams and store APIs are reused.

## Fresh validation / known failures

Go **go1.25.14 linux/amd64**. Frontend untouched; no npm/build execution claimed.

| Exact command | Result |
| --- | --- |
| `go test ./cmd/warden-server ./internal/config ./internal/crypto ./internal/store ./internal/server/... -count=1 -timeout=180s` | PASS final source; runtime17.808s/setup2.116s |
| Same package set `go test -race ... -count=1 -timeout=180s` | PASS final source; runtime78.041s/setup3.234s |
| `go test -race ./internal/server ./internal/server/runtime ./internal/server/setup -run 'Test(SlowHeadersBodiesAndIdleConnectionsTerminate\|StalledWritesReleaseResponseLeaseAndExpensiveSlot\|SetupSlowHeadersBodiesIdleAndWritesTerminate\|SetupDeadlineNotExtendedBySlowRequest\|SetupOptionsStarCannotBypassHostAndCacheGates\|Expensive\|AssertionConcurrency\|ManagedResponse\|RuntimeKeyDelivery\|MiddlewarePropagatesAbortHandler\|ResponseControllerFlushPreservesPanicStatus)' -count=10 -timeout=180s` | PASS; real socket deadlines and existing lease/abort boundaries repeated10, no repeated120s stalls |
| `go vet ./cmd/warden-server ./internal/config ./internal/crypto ./internal/store ./internal/server/...` | PASS |
| `go test ./... -count=1 -timeout=180s` | FAIL solely unchanged SFTP `TestPosixRelMatchesFilepathRel`: `".."` versus `"../."`; DB and all other reported packages pass |

Relevant logs `/tmp/warden-t6-{final-go,final-race,boundary-race10,final-vet,final-full}.log`.
The10-repeat run predates only the deterministic exported_at/cache decode and
one-slot/ordinary-CRUD supplemental fixture extensions; complete relevant final
Go/race checks include deterministic exported_at and cache decode. The final
one-slot/CRUD/cache/error/verification rerun
`go test -race ./internal/server/runtime -run '^Test(Expensive|AssertionConcurrency|DataAndAuthResponsesNoStore)' -count=10 -timeout=90s`
PASS (10.626s, `/tmp/warden-t6-closing-focused.log`). After these final test-only
extensions, repeated scoped vet PASS, `go build -o /tmp/warden-server-t6 ./cmd/warden-server`
PASS, and full `go test ./... -count=1 -timeout=180s` again fails ONLY the named
unchanged SFTP mismatch; DB/all other reported packages PASS (runtime20.712s,
setup2.123s, `/tmp/warden-t6-final-full.log`). Supplemental tests
are not relabeled as preimplementation RED. The known intermittent DB test is not
fixed/waived by this full-run PASS. No native Windows/genuine PRF/browser-CSP,
all-states bounded T12 shutdown or release-acceptance claim is made.

## Changed paths / self-review boundary

- `internal/server/http_server{,_test}.go`, `tls_listener.go`: shared exact budgets,
  setup OPTIONS-star routing and failed-write raw abort, preserving visible TLS
  and HTTP/1 semantics.
- `internal/server/runtime/{runtime,plane,clients}.go`, new `concurrency.go`:
  production wiring and selected heavy-operation admission only; `actions.go`,
  vault/store/crypto, fresh/recovery/revocation delivery logic unchanged.
- New runtime `boundaries_test.go`, `deadlines_test.go`, `concurrency_test.go`,
  `concurrency_errors_test.go`, `verification_concurrency_test.go`: request/cache,
  socket/full-size, signed scheduling and cleanup coverage.
- `internal/server/setup/{runtime,setup}.go`, new `boundaries_test.go`,
  `deadlines_test.go`: pre-body gate ordering, unknown-route consistency and actual
  setup runtime/socket evidence.
- `internal/server/web.go`: successful-static-only immutable policy.
- Deployment doc, narrow T6 plan checkpoint, this report and ignored chronological
  execution ledger. No T5 fixture-script/store/model/client/frontend delta.

Self-review checks the actual production diff and new files, gates BEFORE body
work, admission/defer/lease ordering, raw-write error cleanup, unchanged fresh60s
and setup15min lifetime, no8MiB transfer cap, immutable success/no-store failures,
and explicit external/native/tool limitations. All21 task files (including new
sources/report and ignored ledger) passed explicit newline/whitespace/local
Markdown-target checks; gofmt and `git diff --check` pass. No staged files;
branch/HEAD remain `hieudmg/security-hardening` / `699dd6f`. Scope diff confirms
no module/version/frontend/store/model/crypto/client/`actions.go`/T5-script change.
No new material owner decision was needed; concurrency defaults are ordinary bounded implementation details
within explicit T6 authority. Stop after self-review. Recommended next: independent
T6 review/acceptance and pending external evidence, not automatic T7 or release.

## Bounded review P1 — actual enrollment finish paths missed admission

Same sole writer/branch/HEAD `hieudmg/security-hardening` / `699dd6f`, preserving
the uncommitted T6 outcome. This is a correction before independent acceptance,
not T6 acceptance or later-task authority. No staging, commits, publication,
frontend/dependency/version changes or protected-file access. Documentation edits
record measured evidence using the existing documentation TDD exception.

**Correction to the initial checkpoint:** its four-slot assertion test exercised
`/api/v1/auth/fresh/finish`, not enrollment's actual finish routes. The matcher
recognized `/finish`, `/key`, `/unlock`, etc., but the actual passkey routes are
`/api/v1/auth/passkeys/registration` and `/api/v1/auth/passkeys/assertion`.
They call `FinishRegistration` and `FinishAssertion` in `passkeys.go` without a
`/finish` suffix. Thus the original statement that registration/assertion finishes
shared the four-slot bound was incomplete: these two routes had only the existing
16-request auth cap, plus normal session/recovery/vault-lease checks.

### RED before production correction, then minimal GREEN

```sh
go test ./internal/server/runtime \
  -run '^TestPasskeyVerificationEndpointsRejectSaturationBeforeBodyAndPreserveEnrollment$' \
  -count=1 -v
```

New `passkey_concurrency_test.go` uses a real issued enrollment started with an
exact-request fresh grant. Synthetic registration credentials and signed
assertions go through the real verifier; no fake verdict or mistyped path.
For the assertion case, real registration first establishes its issued assertion
phase. Fill all four actual `keyOperations` slots, then send the correct endpoint
an identical valid payload through a counted body reader.

**Actual RED:** BOTH endpoints returned200/no-store but no Retry-After, read the
body three times, consumed/advanced the pending enrollment, and the subsequent
identical retry returned403. `/tmp/warden-t6-p1-red.log`. The fresh begin grant was
already consumed normally, before saturation; the pending state being tested is
real enrollment state, not a manually invented grant.

**Minimal production correction:** add those **two exact paths** to the existing
key-operation admission case in `concurrency.go`. No changes to handlers,
verification, pending consumption, request-bound grants, leases or cancellation.
No new suffix guess, generic routing framework or unrelated matching-policy edit.

**GREEN:** same command PASS for registration and assertion,
`/tmp/warden-t6-p1-green.log`: saturated requests return429/no-store/Retry-After,
perform zero body reads and retain the identical pending enrollment. After slots
are released, the same valid credential payload succeeds200 through the real verifier
(registration uses standard none-attestation; the assertion is ECDSA-signed).
Replay of its original single-use phase returns403 and no slot remains held.

### One-pass production verifier / decrypt / KDF route audit

Checked actual production call sites and route dispatch, not only suffix names:

| Call sites / actual route | Existing admission after this correction |
| --- | --- |
| Runtime `Plane.finish` → `FinishAssertion`; `auth/login/finish`, `auth/fresh/finish` | Four key-operation slots via existing `/finish`, plus16-request auth cap. |
| Runtime `passkeyHTTP` → `FinishRegistration` / `FinishAssertion`; `auth/passkeys/registration`, `auth/passkeys/assertion` (ordinary enrollment AND restricted recovery) | **Two omissions fixed here** by exact paths, before body/state consumption. |
| Setup `registration/finish`, `assertion/finish` → verifier finishes | Separate setup plane, eight admitted requests and existing state mutex serializes ceremony verification. No runtime four-slot claim/change. |
| Runtime `auth/unlock`, `auth/recovery/unlock` → fixed-size `KeyCheck.Verify` | Existing `/unlock` key lane plus16-request auth cap; publication/one-use checks unchanged. |
| Runtime `auth/passkeys/key`, `auth/recovery/rotation/key` → `KeyForLease` | Existing `/key` key lane, fresh exact-request authorization and delivery lease unchanged. |
| Runtime `auth/recovery/rotation/prepare` | Existing `/prepare` lane; wrapper validation, no server HKDF/unwrap. |
| Runtime `auth/passkeys/commit`, `auth/recovery/rotation/commit` → fixed-size `KeyCheck.Verify` | **Not** in four-slot lane. Existing16-request auth cap plus vault lease/current session/recovery/CAS guards; check is fixed-size AES-GCM authentication, not WebAuthn finish or wrapper KDF. No claim all crypto calls have a four-request global cap, and no unrelated commit-policy change in this P1 fix. |
| Setup prepare/finalize → `NewKeyCheck` / `KeyCheck.Verify` | Setup mutex serializes state/crypto and eight-request cap remains; no runtime matcher. |
| Store `decryptSecret` → vault codec | Import/export share two-transfer lane; explicit client transport and sensitive key reveal/mutation share key lane. Ordinary managed CRUD stays outside this heavy lane by the approved non-serialization intent; vault leases still gate secrets. |
| `crypto.Wrap`, `Wrapper.Unwrap`, `Derive`/HKDF | No production HTTP handler calls these Go wrapping/KDF helpers. Browser wrapping is outside this server matcher; no new backend KDF route found. |

The grep audit excluded `_test.go`; source inspected `passkeys.go`, `plane.go`,
`recovery.go`, `recovery_rotation.go`, `setup.go`, store secret codec and
`crypto/wrap.go`. `/tmp/warden-t6-p1-crypto-call-sites.log`. Unused speculative
suffixes in the original matcher were not removed/expanded in this narrow fix.
No other missing WebAuthn finish route was found. The fixed-size commit checks
are explicitly identified above rather than silently described as four-bounded.
No third-party API/import/dependency changed; fixtures reuse current internal
helpers and the existing verifier API unchanged.

### Fresh correction validation and scope

Go1.25.14 linux/amd64:

- `go test -race ./internal/server/runtime -run '^Test(PasskeyVerificationEndpointsRejectSaturationBeforeBodyAndPreserveEnrollment|AssertionConcurrency|Expensive)' -count=25 -timeout=120s` PASS (27.436s), `/tmp/warden-t6-p1-race25.log`.
- `go test -race ./internal/server/runtime ./internal/server/setup -count=1 -timeout=180s` PASS (runtime73.849s/setup3.223s), `/tmp/warden-t6-p1-runtime-setup-race.log`. Includes existing actual sockets/response-lease cancellation, signed enrollment/recovery, restart/client and bounded full-size transfer checks.
- `go test ./cmd/warden-server ./internal/config ./internal/crypto ./internal/store ./internal/server/... ./internal/web -count=1 -timeout=180s` PASS (runtime17.668s/setup2.118s), `/tmp/warden-t6-p1-backend.log`.

This follow-up changes only `runtime/concurrency.go`, new
`runtime/passkey_concurrency_test.go`, this report and the ignored local ledger.
The broader T6 diff remains uncommitted. No new repository-wide/full-frontend,
native Windows, genuine PRF/browser/CSP, actual NGINX or T12 all-state shutdown
acceptance is inferred. Previous SFTP mismatch/intermittent DB records remain
unresolved; this full-backend run does not include SFTP/DB client packages.
Final focused rerun and scoped `go vet ./internal/server/runtime ./internal/server/setup`
PASS. Self-reviewed the exact admission/test sources; gofmt, `git diff --check`,
and all22 task-file newline/whitespace/local-Markdown-target checks PASS, including
the ignored ledger with the protected file excluded before reads. Scope checks
confirm unchanged handlers, grants, crypto/store, delivery, client/frontend and
T5 scripts. No staged files; branch/HEAD still `hieudmg/security-hardening` /
`699dd6f`. Stop after correction self-review; independent T6 rereview/acceptance
is next.
