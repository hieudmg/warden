# Blocked HTTP flush required-check follow-up — 2026-11-16

## Boundary and original failure

Baseline `71b6c2a789307f24f3bad3b7c3278d7b60f9cb84`, branch
`hieudmg/security-hardening`, single writer; explicit initial HIGH retained, no
model/thinking override. This is a separate bounded Linux
required-check fix before queued Windows consent, not consent implementation or
release acceptance. All three release fields remain0.23.0. No Git staging,
commit/push, PR/CI dispatch, services/live installers, trust/GUI action, signing,
release/tag/merge/worktrees or global environment/tool changes are authorized.
Protected `mise.toml` is excluded before content reads/hashes/copies; unrelated
cache and private evidence are preserved. Evidence root `/var/tmp/wbf` is0700;
parent/logs077/0600, test children alone use the existing fixtures' normal022
umask. Exact TMPDIR=/var/tmp, GOTOOLCHAIN=go1.26.11,
PYTHONDONTWRITEBYTECODE=1.

Hosted run43831002522attempt1, head71b6c2a, actual merge
`02bccd2db51721bc025e4e67929ecc7cdad21aa6`, basec104353: Linux job133176057518
FAILED the first `go test ./... -count=1 -timeout=180s`.
`TestManagedResponseBlockedHTTPFlushTerminates/write-deadline` failed at
response_delivery_blocked_test.go:102 with `unexpected EOF` (variant0.65s,
parent0.69s, runtime package31.352s). This is a CURRENT blocker, not waived by
prior local/full or upgrade/client race passes. Hosted full race/vet/SSHDBrace25,
curl5/CI contracts/source-vulnerability gates were NOT REACHED; frontend279/
build/audit passed. Original logs/raw JSONL/API/inventory are copied unchanged
under `hosted/`, with the original directory preserved.

Native R6 remained16names once15PASS/1FAIL/0SKIP. Its owned-control observation
succeeded with NO ACTION/zero downloads, rejecting non-standalone certificate
identity as designed. Actual public control evidence exists for a later separate
consent task; no Windows source, contract or action is changed here. Native,
genuine PRF/production trust, privileged Unix and hosted artifact/OIDC/signature
acceptance remain open; no clean-module or publication claim.

## Before fixture edits: hypothesis and test-first approach

Systematic debugging and TDD skills plus repository memory conventions were read.
Actual fixture, checked Write+Flush/lease cancellation production path, related
read-drain/callback/TLS tests and installed exact Go1.26.11 source were inspected.
Official pinned Go source was fetched before uncertain deadline use. In that
version, net/http readRequest installs Server.WriteTimeout on EACH accepted
connection after request-header parsing; finishRequest flushes the real buffer,
and write failure prevents connection reuse. net.Pipe returns an actual deadline
error on an expired write, while ReadResponse maps pre-status-line EOF to
ErrUnexpectedEOF. These source facts do not prove the historical trigger.

Main falsifiable hypothesis: the fixture's server-wide50ms write timeout covers
both the intentionally blocked secret response AND the independent authenticated
lock response. Controlled lock-handler work spanning exactly that short-budget
boundary should reproduce the observed EOF on the real lock connection, with
both socket deadlines and real Write results observed. No arbitrary padding,
peer/wait deadline inflation, fake Flush, fake lock or weaker200 assertion.
If this scope error is causal, separate actual HTTP servers/listeners sharing the
same plane/middleware can retain secret50ms and ordinary lock120s without a
custom deadline-rewriting wrapper. That choice is contingent on RED evidence;
production changes require their own causal evidence and any new consequential
security trade-off requires owner escalation.

## Causal RED before correction

`deadline-scope-red.log`,08:41:24->08:41:26UTC, EXIT1, actual
`go test ./internal/server/runtime -run
'^TestManagedResponseBlockedHTTPFlushDeadlineIsConnectionScoped$' -count=1
-timeout=30s -v`. The new regression shares the original three-variant fixture,
wraps real net.Pipe sockets only to observe deadlines/Write results, and holds
the actual lock handler until its header-time50ms interval has elapsed. It does
not substitute Flush, middleware, authentication, vault lock,200 or client parsing.
The original50ms/120s/peer3s/waitDelivery3s values and assertions remain intact.

Observed secret first write budget49.999879ms; actual Write returned at50.329387ms
with n=0 and `write pipe: i/o timeout`. Observed lock first write budget49.999708ms;
actual HTTP/1.1 200 Write at53.685313ms returned n=0 and the same timeout, then
actual ReadResponse returned `unexpected EOF`. This proves the wrong-scope
server deadline can cause the exact hosted wire error. Exact historical CI
scheduling/handler latency is not retrospectively proven; no production defect
is inferred and prior green runs do not waive this current failure.

Choose the ordinary fixture-only two-server correction, ONLY for write-deadline:
first actual server remains50ms, independent lock server has existing normal120s,
with the same plane/session/CSRF/middleware/lock lifecycle, two actual pipes and
joined Serve/Close lifetimes. No cap wrapper means zero-clear, earlier/past or
cancellation deadlines are never rewritten. Other variants retain their existing
server and120s budget. Add a direct observed-lock-budget guard alongside the
original real status200/no-secret-after-abort checks. No larger test budget,
arbitrary padding, production/security/installer/Windows/helper/crypto/auth edit.

## Correction and fresh GREEN

The only behavior correction is an independent actual HTTP server/listener for
the lock connection in the write-deadline variant, sharing `srv.Handler` and the
same authenticated plane. Its WriteTimeout is the fixture's pre-existing normal
120s. The first server stays50ms; lock-cancel and closed-client continue using
the existing normal120s server. Both actual Serve goroutines are closed/joined.
The observer forwards every deadline and Write unchanged, logging only public
budgets/counts/error/status-line metadata, never cookie/CSRF/body/key values.

`deadline-scope-green.log`,08:43:05->08:43:07UTC, EXIT0: all three original
variants and new regression PASS. Secret budget49.999865ms, actual write timeout
at50.236676ms with n=0; lock budget1m59.999999901s, actual HTTP200 socket write at
52.930585ms with498bytes and nil error. The first peer still consumes no response
until after abort/lock; original ReadAll/no-secret assertion remains. The new
regression also directly verifies the secret actually expired at its short
budget without emitting bytes and the lock connection did not inherit50ms.
This is causal failure->minimal correction->GREEN, not a passing-rerun waiver.

Fresh commands all use exact Go1.26.11/TMPDIR and child-only022; full argv/UTC/
exit in `commands.jsonl`, detailed nested HTTPS commands in `https-commands.json`:

| Check | UTC start→end | Result |
| --- | --- | --- |
| `go test ./... -count=1 -timeout=180s -json` | 08:45:05→08:45:31 | 807 top-level PASS,3existing skips |
| `go test -race ./internal/server/runtime -run '^TestManagedResponse\|^TestRuntimeKeyDelivery\|^TestClientTransportResponseLease' -count=25 -timeout=180s -json` | 08:45:05→08:46:38 | 14named tests each25;350top PASS/775all-level PASS,zero skips |
| `go test -race ./... -count=1 -timeout=180s -json` | 08:47:49→08:49:20 | 807top PASS,3existing skips; includes required server/store/client657PASS/3skips |
| `go vet ./...` | 08:47:49→08:47:50 | PASS |
| Fresh production HTTPS runner Go section and4declaration contracts | 08:47:50→08:47:57 | PASS |

Full Go also includes required server/store/client657PASS/3skips. Three existing
skips in both broad commands are two opt-in browser fixture tests and privileged
Unix wrong-owner validation; no new skip or waived acceptance. Focused race25
covers all three saturated/no-consumer variants, this scope regression, HTTP/TLS
finalization, lease retention/drain, write/short-write/flush failures, request/lock
cancellation, slow/unread bodies, cancellation callback joins, completed-callback
retirement, ordinary keepalive and client/key response leases. Deadline/50MiB
import/recovery suites are also included uncached in fresh full Go/full race.

Fresh production binaries were built with `-trimpath` into private `bin/`, then
the unchanged `scripts/test.sh` Go section was executed explicitly: named
`TestSecurityLifecycleHTTPS` (actual init/serve/CLI, verified HTTPS/signed WebAuthn
fixtures, synthetic TEST-ONLY PRF), legacy/import/rollback suites, permanent-agent/
graph lifecycle characterizations and4runner contracts. This was NOT a full
`scripts/test.sh` invocation: frontend reinstall/test/build/audit was intentionally
not repeated for a Go-test-only change. Existing production assets are hash-bound;
hosted279/frontend/build/audit success is BORROWED raw evidence, not fresh local
execution. No npm shim or fake TLS/lock/binary path. No live installer/service or
operator state; only the authorized disposable HTTPS fixtures execute binaries.

No prior local Go/race pass is reused as this fix's fresh proof. Prior/private
hosted evidence remains historical failure/context. Hosted full race/vet/SSHDB25,
HTTPS/curl/CI/vulnerability gates were not reached in run43831002522; the new local
checks do not turn that hosted run green. Whole SSH/DB25, curl5, CI/publication
contracts/source scan were not rerun in this test-only task and are not claimed
fresh or clean. Native/privileged/genuine PRF/production trust/artifact-OIDC/
signature gates remain open; public signing unauthorized.

## Review checkpoint and next boundary

Only this test file, this new report, the existing plan and the append-only ignored
ledger are task paths. Every production/installer/upgrade/Windows/Unix/helper/
crypto/auth/workflow/module input is baseline-identical. Original ledger prefix
and full task delta, hosted logs/error and all RED/GREEN evidence are preserved.
Same HEAD/branch/empty index and three0.23.0 versions. Self-review covers full
diff, formatting/whitespace/doc links, source/production-asset/evidence hashes,
original bounds, exact hosted identity/disposition, nonapplying reverse patch and
bundle checksums; no independent approval implied.

Bundle `/var/tmp/warden-blocked-flush-review.{diff,json,sha256}` is a bounded Linux
fixture-fix checkpoint. Parent independent review/fresh checks and LOCAL COMMIT
must precede a separate queued Windows-consent handoff. Do not push this Linux
fix alone: that repeats the unchanged NO ACTION native checkpoint. No worker
staging/commit/push, PR/CI rerun/dispatch, consent/trust/GUI action, global changes,
installation/service/signing/release/merge/worktree operation. STOP here.

## Parent local acceptance checkpoint

Independent reviewer `01a1e1ea-4a07-7503-b4c7-e7dc96ff6f22` found no issues in the exact bounded patch against `71b6c2a`; review inspected evidence and ran no tests. Parent inspected the actual diff, verified all 4 task/468 input/51 evidence hashes and all 13 production asset hashes, then freshly ran with child-only umask `022`, `TMPDIR=/var/tmp`, `GOTOOLCHAIN=go1.26.11`:

- Focused blocked-flush race25: PASS, `/var/tmp/warden-blocked-flush-parent-focused-race.log`.
- Uncached full Go, original hosted command `go test ./... -count=1 -timeout=180s`: PASS, `/var/tmp/warden-blocked-flush-parent-full.log`.
- Uncached required server/store/client race: PASS, `/var/tmp/warden-blocked-flush-parent-required-race.log`.
- Full vet: PASS, `/var/tmp/warden-blocked-flush-parent-vet.log`.

The first private asset validator used the outer `production_assets` object instead of its `assets` mapping and failed before reading an asset; the corrected mapping verified all 13. This was a validator error, not a test result. Reviewed task hashes still matched before this prose-only append. Worker fresh-binary HTTPS Go-section evidence remains inspected reuse bound to matching inputs/assets, not parent-fresh execution; frontend was not rerun. This accepts a local commit only. Do not push until the separately approved Windows consent patch has completed its own review/checks. Native and external acceptance remain open.
