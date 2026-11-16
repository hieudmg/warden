# T17 — local integrated acceptance checkpoint, not release acceptance

## Parent verification and independent review checkpoint

Independent review found no issues in the bounded local T17 implementation.
The reviewer independently matched the patch, 18 task files, 454 listed inputs,
109 evidence files and 13 assets, and inspected the recorded results; it did not
execute tests or build assets. Parent separately executed these fresh checks:

- `bash scripts/test.sh`: PASS, including clean include-dev frontend install,
  tests, production build, audit0, actual binaries, composed HTTPS and separate
  preservation/agent suites. Log: `/var/tmp/warden-t17-parent-integration.log`.
- `go test ./... -count=1 -timeout=180s`, required server/store/client race scope
  and `go vet ./...`: PASS. Logs: `/var/tmp/warden-t17-parent-{full,race,vet}.log`.
- All 12 offline CI contracts, actionlint and offline installer fixtures: PASS.
  Logs: `/var/tmp/warden-t17-parent-{ci,actionlint,installers}.log`.
- Exact-Go source govulncheck: 0 symbol / 0 imported-package / 8 module-only
  findings, not a clean module scan. Log: `/var/tmp/warden-t17-parent-vuln.log`.
- Parent rehashed all 18 task files and 13 freshly built assets against the
  review manifest, checked whitespace and the exact three-field version-only
  delta. A fresh fetch still reports approved base release 0.22.1.

These checks close the local parent-review gate only. Genuine PRF/production
trust, native Windows, privileged Unix cross-owner and hosted artifact/OIDC/
signature requirements remain unresolved. A draft PR is the next authorized
checkpoint, not merge or release approval. The original worker report below
retains its historical pre-parent-review wording. This documentation-only
checkpoint follows the reviewed source and test snapshot.

## Disposition and scope

**Local implementation/checkpoint: PASS; overall security/release acceptance:
BLOCKED.** Required genuine authenticator PRF with production certificate trust,
NativeWindowsSecurity, and hosted artifact/OIDC/signature evidence remain
**UNRUN**. The three release declarations are **0.23.0**, not a published release.
The owner explicitly allowed bounded local T17 while these external T16 gates
remain blocked. Parent review/fresh validation and external evidence are required.

Work starts from `774ce3b7d995cdb3f72dc9734eeb05108f0c5f96` on
`hieudmg/security-hardening`. The parent freshly verified upstream 0.22.1;
this worker re-read cached `origin/main:web/package.json` as 0.22.1, not a new
remote fetch. Exactly package.json version and lockfile top-level/root-package
version become 0.23.0; no dependency, integrity or lock graph changes. This is the
approved breaking encrypted-storage/auth transition, not patch compatibility.
Recheck latest upstream before eventual publication; this worker publishes nothing.

Task/report filenames retain the approved 2026-11-14 task date; actual command
execution is **2026-11-16 UTC**, not backdated. Private evidence root:
**`/var/tmp/w17.vohx`**, pointer `/var/tmp/warden-t17-evidence-path`.
`commands.jsonl` records every instrumented command's complete argv, UTC start/end,
exit, environment and log path. Early failures are retained, not overwritten.
Review patch/manifest are `/var/tmp/warden-t17-review.diff` and
`/var/tmp/warden-t17-review.json`; `.sha256` binds both. These are local/private
review artifacts, not signed provenance.

Before editing, documentation/version declarations were explicitly treated as
TDD exceptions: validate consistency, exact version-only delta, links and actual
builds, not fabricated runtime RED. New lifecycle coverage characterizes already
implemented production behavior: its first run was GREEN, **not a new production
RED→GREEN claim**. Runner/CI declaration contracts, production-build environment
and terminal cancellation behavior have actual focused RED→GREEN below.

Memory was available and consulted before implementation and again during
validation. Approved source/owner direction wins over historical memory. A
correction was ingested for contradictory historical claims that authentication
or ALL-old recovery disposition were still undecided; neither is reopened.

## What changed

- Replaced `scripts/test.sh`'s unauthenticated HTTP/plaintext-key lifecycle with
  disposable Linux HTTPS acceptance. It installs locked **include-dev** web
  dependencies, tests/builds/audits them, builds actual server/client executables
  embedding the production distribution and invokes the named composed journey.
- Extended the existing signed `security_tls_test.go` lifecycle rather than
  duplicating its registration/recovery/fresh-action protocol. New source-named
  `security_lifecycle_test.go` owns real init/serve subprocesses, controlling PTY,
  private CA, CLI/protected IPC and deterministic agent/graph fixtures.
- One `TestSecurityLifecycleHTTPS` installation flows through actual init
  password/registration/assertion/wrappers/atomic completion/process exit; normal
  locked serve; signed login/unlock; multiple passkeys; secret create/read/export;
  logout versus lock; locked restart; restricted recovery and ALL-old replacement;
  ordinary replacement login/unlock after restart; paired CLI; server restart
  retaining credential but locking data; graph expiry without agent/token loss;
  external agent stop/restart and reapproval; revoke/logout with agent still alive;
  recovery-rotation protocol; export/import/export into another fresh initialization.
- Setup and normal unlock use real signed assertions plus wrappers with explicit
  **synthetic PRF** material. There is no debug verifier bypass, plaintext-key file,
  plaintext HTTP fallback or assertion-free DEK unlock. The fixture checks wrapper
  unwraps preserve the expected random DEK and persisted installation omits encoded
  raw DEK/recovery root/proof. Saved recovery round-trip is programmatic here;
  human/provider behavior and genuine browser PRF are not established by it.
- Init/serve/CLI fixture subprocesses strip inherited `WARDEN_*` settings so
  per-field environment overrides cannot redirect disposable config to operator
  state. The composed test deliberately supplies a conflicting disposable DB
  path and invalid API origin and asserts the ambient DB is never created.
- CLI is an actual executable. Its test-owned agent is the real in-process runtime
  over private pinned TLS IPC; only graph dialing/clock are injected. Simulating
  24 hours expires a ten-minute graph while retaining auth. A real external stop
  joins that runtime; a fresh runtime loses its token even though its durable
  verifier remains approved. This is **not** an actual remote SSH handshake in the
  composed test. Separate real-SSH ownership and fake-clock daemon tests run too.
- `LegacyRefusalAndRollback` is explicitly a **separate suite aggregate**, not
  mislabeled as part of the single composed journey. It reruns actual old-state
  preservation, old v1 fixture import, rollback/retry/identity and concurrent import
  characterizations. No real legacy state is opened/exported/migrated.
- Read-only `test.yml` now invokes the actual runner. Four offline runner contracts
  require that wiring, reject obsolete constructs and verify production-build
  declarations/emitted React runtime. Existing 12 publication contracts remain.
- Production builds in the runner, read-only test workflow and release builder
  explicitly set `NODE_ENV=production`, independent of the test environment.
  No action pin, publisher privilege, source/type/byte/run guard, trigger or
  publication policy changes. No Go production auth/crypto/network code changed.
- README, initialization/recovery, security, deployment, migration, development
  and IPC documentation now describe the current implementation, test substitutions,
  limits and pending gates. Existing accurate CLI/install/state/upgrade/help
  contracts were reviewed and retained, not needlessly rewritten. Historical
  T1–T16 reports remain chronological; current status is here and in the plan.

## Actual failure chronology and fixes

1. **`runner-red`, exit 1:** new offline contracts fail against obsolete HTTP/key
   runner and CI that never invokes it. Minimal replacement/wiring follows.
   **`runner-green` is misleadingly named but exited 1**: a literal substring
   assertion did not match grouped test-name regex. The command was made explicit
   with complete test names; no coverage was removed. `integration` then passes.
2. `lifecycle-first`, `lifecycle-current`, then `lifecycle-final` pass; later
   fixture strengthening asserts returned wrapper unwraps and daemon ownership.
   These are new characterizations of existing behavior, not manufactured REDs.
3. **`browser`, exit 1:** initial status `net::ERR_ABORTED` with no HTTP status is
   correctly rejected by the original strict body-complete network gate. Traced
   the cause: exporting `NODE_ENV=test` through Vite build bundles React development
   code and duplicate initial effects. Current emitted JS contained
   `react_stack_bottom_frame`; pinned Vite 8.2.4 `dist/node/chunks/node.js`
   explicitly uses `process.env.NODE_ENV || config.mode` and React's installed
   `index.js` selects development unless exactly production. Context7 reference
   `ctx7:docs:7dc164fd1c85e6db4a07c833` corroborates, exact installed source checked.
   **`production-assets-red`, exit 1:** declaration and actual emitted-development
   marker regressions fail before changing build commands. Explicit production
   build fixes that cause; `production-assets-green` passes, then two fresh real
   Chromium journeys pass. **The network gate, request/error exceptions and test
   assertions were NOT broadened, retried away or waived.** Original failed
   trace/network JSON remain under `browser/`.
4. Self-review found default `CommandContext` SIGKILL could skip PTY owner's child
   join on cancellation. **`init-cancellation-red`, exit 1:** a ready terminal
   process cannot run its join marker before cancellation. Minimal helper sends
   SIGTERM, lets Python finally terminate/kill and wait for init (3-second bound),
   with Go's 5-second terminal-owner fallback. `init-cancellation-green` passes
   both this focused test and composed lifecycle under race, count3. This is
   test-fixture ownership, **not a discovered/fixed production daemon defect**.
5. Actual stripped scans exit **3**, initially and again against final production
   assets/CGO-disabled trimpath `-s -w` binaries. They remain non-passing scanner
   evidence; no symbol-stripped conservative fallback is recast as a clean scan.
6. Private source-reference self-review initially exits1 on documentation-only
   `.test.ts` versus `.test.tsx`, then a `key_test.go` versus real
   `keyfile_linux_test.go` reference. Corrected references, not runtime checks;
   original failing self-review logs remain. Final source/path/link checks cover
   the corrected matrix rather than leaving plausible nonexistent test names.
7. Final source review found `LoadServer`/`LoadClient` apply per-field environment
   after explicit config files. **`fixture-environment-red`, exit1:** actual Python
   subprocess sees injected Warden overrides. Added a specific fixture environment
   filter to init/serve/CLI (not production config behavior). Composition deliberately
   conflicts with a disposable ambient DB/API origin and verifies DB non-use.
   **`fixture-environment-green`, exit0**, all three focused tests under race count3;
   `integration-isolated`, full/race JSON, vet and Windows compile then pass on final
   test source. Final source and stripped scans are rerun, stripped **still exit3**.

## Requirement / evidence acceptance matrix

**PASS-local** means executed current applicable Linux/source/browser checks;
not global acceptance. All source paths below are repository-relative. Full and
race logs cover the existing negative matrices as well as this new composition.

| Approved requirement / finding | Concrete source / evidence | Disposition and boundary |
| --- | --- | --- |
| T1 eight-character CSPRNG terminal-only password, ready-time 15-minute expiry, guessing bounds, setup-only atomic exit | `cmd/warden-server/init_test.go`; `internal/server/setup/{setup,deadlines,runtime,runtime_tls}_test.go`; new `security_lifecycle_test.go`; full/race + integration logs | PASS-local. Production init executable/PTY/private verified CA in composition; genuine authenticator remains UNRUN. |
| T1/T5 old-state/config/DB/key/WAL/SHM preservation and no implicit deletion | `cmd/warden-server/main_test.go` `TestServeRefusesUninitializedAndLegacyWithoutMutation`; `internal/store/legacy_refusal_test.go` `TestLegacyDBRefusalPreservesArtifacts`; runner preservation group | PASS-local synthetic state/byte/mode assertions; no live migration or old-release write. |
| T1–T3 signed UV, challenge/expiry/replay/origin/RP/userHandle/owner and required PRF/no fallback | `internal/server/auth/ceremony_test.go`; `internal/server/runtime/plane_test.go`; `web/src/setup/setup.test.tsx`, `web/src/setup/vault-wrap.test.ts`; `web/src/auth/auth.test.tsx` | PASS-local real signed verifier and wrap vectors/negative UI tests. Synthetic PRF is not genuine support proof. |
| T2 sessions/cookie/CSRF/login while locked/restart locked/logout distinct from lock | runtime `plane_test.go`, `runtime_tls_test.go`, `security_tls_test.go`; `TestSecurityLifecycleHTTPS` | PASS-local, composed actual server restarts and existing direct/proxy restarts. |
| T2/T3 key-delivery lease, checked write/HTTP1 flush, cancellation stop/join, post-Acquire authorization | runtime `key_delivery_test.go`, `response_delivery*_test.go`, `recovery_ingress_test.go`, `clients_boundary_test.go` | PASS-local full/race. No HTTP2, proxy-buffer recall or client-receipt guarantee; unchanged protections. |
| T3 multiple wrappers, last-passkey rule, exact-request fresh action/single-use bindings | runtime `enrollment_test.go`, `actions_test.go`, `lifecycle_test.go`, composed second-passkey enrollment/fresh export/reveal/import | PASS-local; assertions include grant purpose/method/path/digest/session/credential/replay. |
| T3 proof before recovery wrapper/key, restricted audience, ALL-old atomic replacement preserving DEK, abort identity, saved-confirmed rotation | runtime `recovery{,_rotation,_concurrency,_ingress}_test.go`, `lifecycle_test.go`, `identity_test.go`; `web/src/auth/{auth,security}.test.tsx`; composition | PASS-local protocol/rollback/concurrency and UI. Composed programmatic round-trips do not prove hardware or human saved-key practice. |
| T4 individually web-approved CLI, token memory-only, per-request audience/generation/revocation/no expiry | runtime `clients{,_boundary,_https}_test.go`; agent `api_transport_test.go`, `api_lifecycle_test.go`; new CLI/IPC/HTTPS composition | PASS-local. Actual server restart returns locked rather than losing approval; actual agent restart is unpaired, reapproval needed. Stolen token survives legitimate exit until explicit revocation/recovery invalidation. |
| T4/T10 daemon permanent across graph TTL/logout/revoke/outage/restart/lock and unauthenticated empty pool | agent `lifecycle_test.go` `TestAuthAgentLivesUntilExternalCancellation`; `server_test.go` `TestSSHPoolIdleExpiryDoesNotEndAuthAgent`; `agent_graph_lifecycle_test.go`; composition | PASS-local deterministic clocks, separate real SSH graph, explicit external cancellation/join. No idle/time exit added; composition's graph is synthetic. |
| T5 v1 compatibility, AAD re-encryption, empty managed/auth coexistence, atomic failure/retry/identity | `internal/store/transfer_preservation_test.go`; runtime `transfer_preservation_test.go`, `transfer_test.go`; `internal/store/profiles_test.go`; runner named legacy group and fresh two-installation round-trip | PASS-local. Full old shape/fault coverage remains separate, not implied by composition's one synthetic key. Plaintext exports need private handling. |
| T6 hostile Host/DNS/Origin/text/plain/CSRF, client-only bearer/no-origin, error no-store | runtime `boundaries_test.go`, `plane_test.go`; setup `boundaries_test.go`; full/race | PASS-local route/header/error matrices, no API-token management alias. |
| T6 socket/read/write/idle budgets, near-50MiB import, expensive-operation bounds | runtime `deadlines_test.go`, `concurrency{,_errors}_test.go`, `verification_concurrency_test.go`, `passkey_concurrency_test.go`; setup `deadlines_test.go` | PASS-local actual sockets/current unchanged 5/120/120/60 budgets, bounded crypto/import/export; no timeout inflation. |
| T7 cumulative duplicate DAG/depth/budget/cancellation/order, validate before any secret decrypt | profiles `resolve_budget_test.go`, `resolve_counts_test.go`; store graph snapshot tests; full/race | PASS-local 1,024-occurrence boundary, snapshot/decrypt spies; order/duplicates preserved. |
| T8 classifications/UA512/metadata4KiB/no raw validation secrets | server audit/profile/report/runtime `audit*_test.go`; full/race | PASS-local adversarial SQLite/slog/caps; no historical-row rewrite, allowed User-Agent can still contain caller secrets. |
| T9 framing/CSP/nosniff/referrer, every emitted asset/body, masked credentials, Markdown opt-in, no stale secret/download | `web/src` 279 tests; 13 dist tests; standalone 19 network-gate tests; runtime/setup `ui_privacy_test.go`; `browser-production/` and `browser-repeat/` | PASS-local real Chromium 151.0.7922.34, nine complete manifest assets, zero CSP/page errors, zero implicit image requests/one deliberate/no Referer/noopener. Signed synthetic authenticator/injected PRF and **test-only cert exception**, not production trust. |
| T1/T14 legacy master-key stat/open TOCTOU | runtime/installer key loaders removed; `internal/crypto/keyfile_linux_test.go` retained descriptor utility race test; full Go + offline installers | PASS-local, no new plaintext fallback or automatic old-key scrub. |
| T10 private authenticated confidential IPC before bytes, versioned discovery ownership/collision/deadline | agent `tls_test.go`, `protocol_test.go`, `credentials_test.go`, `runtime_security_unix_test.go`, publication/startup tests; actual CLI IPC composition | PASS-local applicable branches. Unix wrong-owner chown test SKIP: privilege unavailable; native cross-user evidence not claimed. Windows tests separately UNRUN. |
| T11 Windows traversal and private staging / exclusive local+remote copy | `internal/client/sftp/*_test.go`; full/race; T11 report | PASS-local applicable adapters. Native Windows traversal/ACL UNRUN. Accepted exclusive CREATE→handle chmod0600→WRITE still permits retained-descriptor pre-chmod race; no pkg/sftp fork, rsync future-only. |
| T12 authentication agent without forwarding, pooled ownership, second hop/proxy CONNECT/DB channel cancellation and fixture joins | SSH `agent_lifecycle_test.go`, `lifecycle_test.go`, `cancel*_test.go`, `relay_fixture_test.go`, `fixture_listener_test.go`, `pty_fixture_test.go`; agent `transport_lifecycle_test.go`; DB tests | PASS-local full/race and **whole SSH/DB race25**, unchanged bounds. Earlier PTY sequencing and fixture leaks retain T12/T15 chronology; passing reruns are not their explanation. |
| External DB and HTTP CONNECT plaintext legs | `docs/security.md`, deployment/CLI docs, approved owner scope | **Not fixed / scope excluded.** Warden-owned HTTPS does not secure direct/onward DB/proxy legs or change profiles/v1 format. |
| T13 hostile redirects before credential/body bytes, diagnostic/DB control escaping, raw SSH/file streams | `internal/client/clienthttp`, API/report/agent redirect tests; terminal/DB tests; full/race | PASS-local; same-origin/API redirects refused, release HTTPS redirects distinct. No whole-stream SSH sanitizer. |
| T14 verified-HTTPS release/install transport, size/deadline/temp/replacement/state/service safeguards | `internal/upgrade/{http,security,stream,proxy,establishment}_test.go`; `scripts/test-installers.sh`; `scripts/installers_test.py`; full Go | PASS-local offline/curl/streaming fixtures only. No real install/upgrade/elevation/service operation. Native PowerShell remains UNRUN. |
| T15 exact toolchain/dependencies and local shadcn removal/provenance | Go1.26.11/x/crypto0.56.0; clean npm ci/test/build/include-dev audit; source/stripped scans; unchanged `web/vendor/shadcn-4.19.0` | PASS-local build/tests/npm known findings0. Eight Go module-only exposures retained; actual stripped scans exit3, **not PASS**. Exact CSS/MIT/provenance retained; no shared tooling change. |
| T16 contents-read build/test, pinned actions, isolated publisher/exact byte/source/run/type/repo guards | 12 fresh `scripts/ci` offline contracts, pinned actionlint, current workflow/build diff; T16 reports | PASS-local declarations/fake-gh/tamper guards. Hosted artifact identity/downstream/OIDC/Sigstore evidence UNRUN. No signing/publication/dispatch done. |
| T16 official Action runtime residuals | `2026-11-14-t16-action-runtime-risk.md`, current owner disposition | **Owner-accepted narrowly**, not remediated: documented enabled trusted-service/terminating-proxy Undici risks and DSSE/PAE limitation only. Historical nonzero action audits retained, not freshly rerun here or blanket waived. |
| Mutable same-version force/clobber and executable-only/manual restart | release workflow/T14 installer contracts/docs; fresh offline CI/installer checks | **Intentional retained policy**, not immutability/anti-rollback or automatic service cutover. |
| T17 integrated local runner, operational/security/recovery/migration docs, three-field version parity | this report, updated runbooks/README, four runner contracts, full diff + manifest/version-only validation | PASS-local implementation, **not overall T17 acceptance**. |
| Genuine M1/PRF with production trust | approved M1 steps in plan, not fulfilled by synthetic fixtures | **UNRUN / BLOCKS release acceptance.** Need actual standard PRF-capable authenticator/provider/browser and trusted HTTPS chain. |
| NativeWindowsSecurity | `scripts/ci/test-windows.ps1` exact 16-name native matrix and hosted-only trusted HTTPS C# fixture | **UNRUN / BLOCKS release acceptance.** No Windows/PowerShell host here; cross-compilation is not native proof; no global tool/trust-store changes. |
| Hosted artifact/downstream/OIDC/signatures and independent combined review | T16 exact source/run/artifact/subject guards; parent review next | **UNRUN / PENDING / BLOCKS release acceptance.** No workflow dispatch, public test attestation or release authority. |

## Validation and reproducibility

All Go tests/builds/scans use **`GOTOOLCHAIN=go1.26.11 TMPDIR=/var/tmp`**.
`run.py` records ordinary child umask022 (private evidence root); fixtures create
private storage/files. Node **v26.12.1**, npm **11.20.0**, Python **3.12.15**,
Linux amd64. Scanner **govulncheck v1.9.0**, itself built Go1.26.11 at
`/var/tmp/w15r.65nV/bin/govulncheck`; pinned private actionlint **v1.7.12** reused from
`/var/tmp/w16.Bmqg/bin/actionlint` (version/build metadata logged). No global
install/default change. Build commands override only `NODE_ENV=production`;
web tests keep `NODE_ENV=test` and installs/audits explicitly include dev deps.

Authoritative current-input commands (complete timestamps/argv in commands.jsonl):

| Evidence name / command | UTC start → end (2026-11-16) | Exit / result |
| --- | --- | --- |
| `integration-isolated`: `bash scripts/test.sh` | 00:58:02 → 00:58:34 | 0: npm ci, 279+13 tests, production build/verifier, audit0, both binaries, composed HTTPS, separate preservation/daemon suites, four contracts |
| `fixture-environment-green`: focused environment/cancellation/lifecycle `go test -race ... -count=3 -timeout=180s -v` | 00:57:40 → 00:58:02 | 0, all three named tests |
| `go-json-isolated`: `go test -json ./... -count=1 -timeout=180s` | 00:57:40 → 00:58:36 | 0; 787 top-level passes, 3 test skips, 2 no-test packages |
| `go-race-json-isolated`: `go test -race -json ./internal/server/... ./internal/store ./internal/client/... -count=1 -timeout=180s` | 00:57:40 → 00:59:32 | 0; 653 top-level passes, same 3 test skips |
| `ssh-db-race25`: `go test -race ./internal/client/ssh ./internal/client/db -count=25 -timeout=180s -failfast -v` | 00:36:06 → 00:37:51 | 0; whole packages, no bound inflation |
| `vet-isolated`: `go vet ./...` | 00:58:36 → 00:58:36 | 0 |
| `installers`: `bash scripts/test-installers.sh` | 00:25:59 → 00:26:05 | 0, offline only |
| `installer-https`: `python3 scripts/installers_test.py` | 00:26:05 → 00:26:08 | 0, actual curl to local fixtures |
| `ci-contracts-final`: `python3 -m unittest discover -s scripts/ci -v` | 00:34:40 → 00:34:44 | 0, 12 contracts; fake gh, no publication |
| `network-gate`: `node --test web/scripts/ui-privacy-network.test.cjs` | 00:34:39 → 00:34:39 | 0, 19 tests, gate unchanged |
| `browser-production`: `WARDEN_UI_ARTIFACTS=.../browser-production node web/e2e/ui-privacy.cjs` | 00:32:57 → 00:33:07 | 0, real shared Chromium, 1 journey |
| `browser-repeat`: same, artifacts `.../browser-repeat` | 00:38:42 → 00:38:49 | 0, independent fresh journey |
| `source-isolated`: `govulncheck -show verbose ./...` | 01:00:41 → 01:00:45 | 0, **0 symbol / 0 package / 8 module-only** |
| `stripped-isolated-build`: CGO0 trimpath `-ldflags="-s -w"` Linux CLI/server + `go version -m` | 01:00:45 → 01:00:45 | 0; embeds final production assets, not uploaded |
| `stripped-isolated-{cli,server}-scan`: `govulncheck -mode=binary .../bin/{warden,warden-server}` | 01:00:45 → 01:00:47 | **3 EACH, conservative stripped-symbol fallback**, not clean scans |
| `actionlint`: private pinned tool `-shellcheck= -pyflakes=` | 00:38:42 → 00:38:42 | 0; shellcheck/pyflakes unavailable, not claimed run |
| `syntax`: `bash -n scripts/test.sh scripts/build-release.sh scripts/test-installers.sh` | 00:33:02 → 00:33:02 | 0 |
| `windows-isolated-compile`: `GOOS=windows GOARCH=amd64 go test -c -o .../runtime.test.exe ./internal/server/runtime` | 00:59:32 → 00:59:34 | 0, **compile only**, never executed; not NativeWindowsSecurity |

Earlier `integration-final`, full/race normal and JSON results remain in the
command ledger; they precede the final test-only environment filter and are not
substitutes for the fresh `-isolated` runs. All 13 production assets match their
pre-isolation/browser snapshot byte-for-byte; production Go/module/frontend inputs
are unchanged by the final fixture-only correction. The saved
`isolation-input-comparison.json` binds 186 matching production/frontend/build
inputs, all 13 assets and both stripped binaries. Thus whole SSH/DB race25 and
browser evidence above remain relevant to unchanged source/assets, not newly rerun
claims after that correction.

`test-summary.json` derives actual skips from fresh Go JSON. The full/race suites
skip opt-in `TestUIBrowserSetupFixture`/`TestUIBrowserRuntimeFixture`; these are
run by the **separate actual browser runner**, not silently treated as normal-suite
passes. `TestRuntimeUnixRejectsWrongOwner` skips because chown privilege is absent;
that native cross-owner fixture remains UNRUN, not replaced by structural owner
checks. `internal/model` and `migrations` have no test files. Windows build-tagged
cases are absent on Linux, not counted as executed or skipped-native passes.
Integration's selected suites have no skips. Browser expected initial/logout401
and independently verified cancellation exceptions remain explicitly recorded in
result.json, not zero-HTTP-errors claims. Existing >500KB management chunk build
warning remains; it is not a security-test failure.

Eight retained Go module-only IDs: **GO-2026-5932, GO-2026-6603,
GO-2026-6610, GO-2026-6611, GO-2026-6612, GO-2026-6617,
GO-2026-6860, GO-2026-6866**. Source reachability is narrower than stripped-binary
scanner fallback. Do not substitute unstripped/JSON/zero exit for actual failed
stripped scans. Application npm audit0 does not establish official Action safety.

## Self-review, artifacts and next gate

Reviewed source/actual original-to-current diff against the named requirements:
no auth/crypto/response-lease change, insecure transport or raw-key bypass; signed
assertions remain independent from PRF material; post-Acquire/recovery/client
checks remain intact. Checked fixture ownership/cleanup, current build mode,
legacy preservation and import identity, CLI/restart/TTL distinctions, exact
version-only JSON delta, current help/install/state docs and retained external
DB/proxy/SFTP/retrieved-secret/live-memory/backup residuals. Current local checks
and honest skips/failures above do not constitute independent review.

The complete review patch includes tracked changes, **all three new task files**
and the **entire append-only ledger delta** from `ledger.before.md`; manifest
hashes task files, source/test/doc/build inputs, emitted assets, final stripped
binaries, command/evidence files and the ledger prefix/delta. The ignored ledger
is not silently omitted because `git diff` cannot see it. SHA256SUMS authenticate
nothing independently: they bind this private review snapshot only. Private
browser traces/videos/screenshots can include synthetic recovery material; do
not publish them as ordinary public CI artifacts. Recompute after any edits.

No staging/commit/push/PR/tag/release/workflow dispatch/signing/transparency write,
live installer/service/upgrade/migration/deployment, branch switch/rebase/worktree,
child writer, external DB/proxy transport change, global tooling change or
protected `mise.toml` content access. Original ledger history and unrelated
evidence retained. Stop at this bounded implementation/self-review report.

**Next:** parent independently reviews the complete diff/manifest and freshly
validates applicable checks. Obtain genuine PRF+production trust, native Windows
(including private staging/ACL/PowerShell HTTPS), privileged Unix cross-owner and
hosted artifact/downstream/OIDC/signature evidence through separately authorized
routes. Keep the narrow T16 risk disposition, all nonzero findings and external
blockers explicit. No release-ready/all-complete declaration or publication here.
