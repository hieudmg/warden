# T9 — Production UI privacy and stale-secret boundaries

## Scope and acceptance status

Bounded T9 implementation/self-review on `hieudmg/security-hardening`, starting
and ending at reviewed HEAD `41238eb`; changes remain unstaged and uncommitted.
T1–T8 and resequenced T10 are preserved. No T11/T12 work, dependency/version
changes, deployment, real-data access, migration, staging, commit or publication.
Protected unrelated `mise.toml` was neither read nor changed. Release publication
still owns the approved breaking `0.22.1 -> 0.23.0` synchronized version update;
this task leaves the existing `0.22.1` fields unchanged.

This is a bounded implementation checkpoint, **not independent acceptance, M1,
or a security-release claim**. Production HTTPS assets/CSP/network behavior was
exercised in real Chromium, with **synthetic signed WebAuthn + injected PRF** and
a **test-only certificate-trust exception**. Genuine PRF-capable authenticator,
production certificate-chain trust and native Windows acceptance remain pending.

## Source/API preflight

Read root contributor instructions, approved design/T9 plan, chronological
execution ledger and authoritative T3/T6 reports before the implementation.
Playwright setup/run skills and the machine's
`/home/hieudm/.local/share/playwright-global/README.md` were consulted before
browser setup. Context7 documentation supplemented exact installed sources:
React `19.2.8`, react-markdown `10.1.0`, Radix Dialog `1.1.23`, Base UI `1.7.0`,
react-style-singleton and Testing Library. Relevant inspected seams include
react-markdown's default URL transformation/raw-HTML handling, React external
store/effect cleanup, Radix scroll-lock style injection, Base UI positioning and
Testing Library rendering/unmount behavior. No dependency was installed or
upgraded. Vite is `8.2.2`; Vitest is `4.1.11`.

Browser APIs were checked against the existing read-only Playwright `1.62.0`
installation's documentation/types/source at
`/var/www/code/php/dispatcher/node_modules/playwright-core/`, including remote
`connect`, context/tracing/network/page APIs, init scripts and explicit remote
video `saveAs`. The runner loads it through the documented shared-machine
adapter; it does not add Playwright to Warden's package files or invent a service
endpoint.

## Retained implementation

### Presentation and Markdown privacy

- `PasswordInput` masks SSH password, HTTP CONNECT proxy password and DB password
  by default, disables autocomplete and provides explicitly labeled Reveal/Hide
  controls. Reveal state belongs only to the mounted field and resets on close,
  replacement and auth-root remount. Private-key passphrases remain password
  inputs without a reveal control. Old deliberate plaintext-type assertions were
  replaced rather than preserved as contradictory tests.
- Untrusted report Markdown never creates an `img`, preload or CSS network
  primitive. Each supported image renders a visible IP-disclosure warning and
  accessible `Open image … externally; reveals your IP address` button. Only an
  explicit click opens that image in a separate tab with `noopener,noreferrer`.
  HTTP(S) image targets are supported; invalid/unsafe protocols are unavailable.
  This deliberately preserves an external-open flow rather than enabling remote
  images inside the application or widening its CSP.
- The renderer keeps its default safe URL transformation, disables raw HTML and
  gives external links `target="_blank" rel="noopener noreferrer"`. Tests include
  unsigned/untrusted Markdown, hostile image URLs, unsafe links, raw HTML and
  style/background-image payloads. jsdom assertions establish DOM/activation
  behavior only; the independent image-host counter in real Chromium supplies
  the network evidence below.

### Async secret lifecycle and request policy

- The memory-only security epoch is observable through React's external-store
  hook. `App` keys its complete management subtree to that epoch, detaching list,
  form, transfer and notification state rather than merely hiding secret DOM.
  Key-pair content also observes the epoch when mounted independently.
- Existing vault request IDs and file-read generations remain intact. Added
  cleanup/request guards discard late vault loads, file text and save errors
  after close, replacement or unmount; SSH/DB save callbacks cannot contaminate a
  replacement dialog. Resource/report loaders invalidate IDs during cleanup.
- Export/import retain per-dialog generations and cancellation. Late export
  completion cannot create an object URL, click a download or update a new
  dialog; permitted downloads revoke their URL immediately. Import file reads
  check both caller cancellation and the global epoch before requesting a fresh
  grant or submitting the original exact body.
- Generic/export fetches retain `cache: 'no-store'`, same-origin credentials and
  existing CSRF/fresh-action headers. Caller and global abort signals are
  combined. Epoch checks now follow asynchronous success/error-body reads too;
  stale errors cannot repopulate current UI. Auth API requests separately retain
  client-side `cache: 'no-store'`; this is distinct from server response caching.
- Auth operations capture local **and global** generations; fetch and native
  credential operations receive the combined abort signal. Recovery rotation,
  saved confirmation and AuthGate busy/error handling reject stale results.
  Prepared rotation state is epoch-bound and cannot be reused after an external
  reset. AuthGate observes the epoch itself and binds pending state/results to
  it, including multiple resets batched before effect re-subscription.
  Recovery/security inputs and displayed recovery material clear on
  competing operations and reset. Deferred tests cover cancel, global reset and
  unmount, plus close/new-dialog paths where applicable.
- No raw DEK, PRF, recovery key, file text or plaintext export is added to durable
  stores, browser storage or URLs. Byte arrays keep existing `finally` clearing;
  JavaScript strings cannot be zeroed. This implementation detaches live UI
  references and prevents stale reuse, not memory-forensics erasure or reversal
  of a request/grant already admitted by the server. It adds no automatic retry
  or re-encoding that could change exact-body binding/consumed-grant semantics.

### Production headers, assets and browser-discovered setup fix

Existing runtime/setup header policy was already present and was characterized,
not falsely presented as new RED remediation. New
`TestUIFramingAndCSPProductionAssets` tests in both packages enumerate actual
embedded production assets and UI routes, asserting DENY framing, nosniff,
no-referrer, restrictive CSP, nonempty successful assets and missing-resource
`no-store`. Runtime tests cover locked/unlocked routing and immutable hashed
asset caching. Setup continues to use the generated minimal setup allowlist;
management assets are not exposed through a speculative expanded setup route.

No CSP directive was broadened. Scripts remain `script-src 'self'`, with no
`unsafe-eval` or blanket inline-script allowance. The source comment was corrected:
Radix scroll locking injects **style tags**, while positioning uses style
attributes/CSS variables. Existing management-only style `'unsafe-inline'`
therefore supports more than attributes; it is not represented as a nonce or
attribute-only policy. Setup requires no unsafe allowance. Raw report HTML/CSS
is not passed through. Real dialogs/popovers and emitted styles/fonts loaded
without violations under this actual policy.

The first real-browser setup attempt exposed a genuine existing bug: native
`fetch` was stored directly and called with `SetupClient` as its receiver,
producing **Illegal invocation**. A focused test reproduced the receiver failure
before changing the default fetcher to an ordinary wrapper. This enables the
unchanged password-cookie/Origin/CSRF setup ceremony; no verifier or request-gate
bypass was added.

## Actual RED evidence

Commands were run from the repository; frontend focused commands used
`cd web && NODE_ENV=test ./node_modules/.bin/vitest run …`.

| Log under `/tmp/` | Focused selection | Actual observed RED |
| --- | --- | --- |
| `warden-t9-ui-red.log` | `src/features/ssh/ssh-form.test.tsx src/features/db/db-form.test.tsx src/features/projects/projects-reports-tab.test.tsx src/app.test.tsx src/auth/security.test.tsx` | **8 failed / 101 passed**: SSH/DB plaintext types, implicit `img`, three late export URL/downloads and two recovery-key restorations after cancel/global reset. |
| `warden-t9-async-red.log` | `src/api/client.test.ts src/auth/security.test.tsx` | **6 failed / 34 passed**: stale generic/export errors returned synthetic secret text, cancelled import file read proceeded toward fetch (unconfigured mock then produced TypeError), global-reset authenticator promise returned a grant, and the two still-unfixed recovery UI restorations. The latter are overlapping failures, not six additional distinct defects. |
| `warden-t9-key-save-red.log` | `src/features/key-pairs/key-pairs-tab.test.tsx src/api/client.test.ts` | **1 failed / 50 passed**: the pending key-pair save dialog did not close. Execution stopped at the first absence-of-dialog assertion, before opening a replacement or rejecting the old save; replacement contamination was not an observed RED. Later GREEN covers those later assertions. |
| `warden-t9-profile-red.log` | `src/features/ssh/ssh-tab.test.tsx src/features/db/db-tab.test.tsx` | **2 failed / 41 passed**: pending SSH/DB save dialogs did not close. Both tests stopped before replacement/rejection assertions; stale-error contamination was not an observed RED. Later GREEN covers the complete close/replacement/error-guard flows. |
| `warden-t9-auth-gate-red.log` | `src/auth/auth.test.tsx` | **1 failed / 9 passed**: late auth rejection restored synthetic sensitive error text after global reset. |
| `warden-t9-batched-auth-red.log` | `src/auth/auth.test.tsx -t 'batched security resets'` | **1 failed / 10 filtered skips**: two resets batched around a new pending action missed abort-listener re-subscription and restored a stale sensitive alert. Focused GREEN then passed all 11 auth tests (`warden-t9-batched-auth-green.log`). |
| `warden-t9-setup-fetch-red.log` | `src/setup/setup.test.tsx` | **1 failed / 4 passed**: default fetch rejected with receiver-dependent Illegal invocation. |
| `warden-t9-auth-abort-red.log` | `src/auth/security.test.tsx -t 'global epoch cancels'` | **1 failed / 12 filtered skips**: global reset discarded eventual results but had not aborted the signal supplied to the native credential operation. |
| `warden-t9-rotation-reuse-red.log` | `src/auth/security.test.tsx -t 'pending rotation cannot'` | **1 failed / 13 filtered skips**: saved rotation confirmation resolved and submitted commit after an external epoch reset. |

Additional header/cache matrices and passing extensions are characterizations,
not fabricated RED. Early browser attempts also included selector/required-field
fixture errors (global dialog lookup, wrong DB action name, wrong project save
label and missing report project selection); only the setup receiver failure
above established a production defect. Those harness errors were corrected
without changing production security behavior. Initial remote video recording
needed explicit `saveAs` to transfer artifacts locally; the final run includes
both downloaded videos.

## Original implementation checks — before the three review fixes

These historical results are retained, not silently promoted to validation of
the review changes. The follow-up section below is authoritative for those
changes and the strengthened browser gate.

Toolchain: Go `go1.25.14 linux/amd64`, Node `v26.12.1`, npm `11.20.0`.
No dependency download/update or toolchain upgrade was requested.

```sh
(cd web && NODE_ENV=test ./node_modules/.bin/vitest run \
  src/api/client.test.ts src/auth/auth.test.tsx src/auth/security.test.tsx \
  src/app.test.tsx src/features/key-pairs/key-pairs-tab.test.tsx \
  src/features/ssh/ssh-form.test.tsx src/features/ssh/ssh-tab.test.tsx \
  src/features/db/db-form.test.tsx src/features/db/db-tab.test.tsx \
  src/features/projects/projects-reports-tab.test.tsx src/setup/setup.test.tsx)
NODE_ENV=test npm --prefix web test
npm --prefix web run build
node web/scripts/verify-dist.mjs internal/web/dist
WARDEN_UI_ARTIFACTS=/tmp/warden-t9-browser-acceptance-reviewed node web/e2e/ui-privacy.cjs

go test ./cmd/warden-server ./internal/config ./internal/crypto ./internal/store ./internal/server/... ./internal/web -count=1 -timeout=180s
go test -race ./cmd/warden-server ./internal/config ./internal/crypto ./internal/store ./internal/server/... ./internal/web -count=1 -timeout=180s
go vet ./cmd/warden-server ./internal/config ./internal/crypto ./internal/store ./internal/server/... ./internal/web
go test ./... -count=1 -timeout=180s
git diff --check
```

- Focused frontend: **11 files / 224 tests PASS**, `warden-t9-focused-green.log`.
- Whole frontend: **17 files / 275 tests PASS**, plus **13/13** emitted-dist
  verifier tests, `warden-t9-web-final.log`. No final frontend skips/failures.
- Production TypeScript/Vite build and emitted-dist verifier PASS,
  `warden-t9-build-final.log` / `warden-t9-dist-final.log`. Existing ordinary
  >500-kB management chunk warning remains; no scope-expanding chunk refactor.
- Affected Go normal and race commands PASS across all 12 named/expanded
  packages. Runtime **19.013s / 79.332s**, profiles **2.284s / 37.720s**, store
  **1.319s / 20.944s** (normal/race); affected-package vet PASS.
  Logs: `warden-t9-go-final.log`, `warden-t9-race-final.log`,
  `warden-t9-vet-final.log`.
- Fresh full Go FAILS only at unchanged
  `internal/client/sftp/TestPosixRelMatchesFilepathRel`:
  `posixRel("a", ".") = ".."`, expected `"../."`.
  `internal/client/db` PASS **0.078s** on this run; earlier intermittent DB
  failures are neither fixed nor waived. Log: `warden-t9-full-go-final.log`.
- Ordinary package runs intentionally skip the two opt-in browser fixture tests
  without `WARDEN_UI_BROWSER_DIR`. The browser runner invokes both with its own
  new disposable directory, real TLS listeners, production assets and real
  signature verifier. These skips do not replace the actual browser run.

## Original browser evidence and security boundaries — gate subsequently corrected

This historical journey used a request-presence asset gate, not successful-body
completion verification. The refreshed follow-up below supersedes that gap.

Original browser result: **one complete journey PASS, zero failed**, Chromium
`151.0.7922.34`, origin `https://localhost:46243` for this disposable run.
The shared machine's existing headless Chromium service was used through
`/home/hieudm/.local/share/playwright-global/index.cjs` and the existing reference
project; no additional service was deployed. `PW_REFERENCE_PROJECT`
may select another already-installed compatible reference project.

The runner creates a private temporary fixture directory, a temporary self-signed
certificate and fresh DB; only its opt-in Go `_test.go` fixtures read the test
configuration. It injects synthetic ES256-signed registration/assertions and PRF
outputs through browser automation, never through production routes or an
accepted environment bypass. Setup password, cookie Origin/CSRF, authenticated
session, fresh exact-request grants and normal runtime signature verification
remain active. No pre-seeded session cookie, fake server verifier, mocked API
response, plaintext-key fallback or bearer-audience relaxation is used.
The browser's explicit self-signed-certificate exception is **test-only**: HTTPS
and secure-context/CSP behavior are exercised, but production certificate-chain
trust is not accepted by this test.

The journey covers setup/save/re-enter/finalize, runtime locked login, explicit
unsupported-PRF refusal without unlock submission, successful injected-PRF
unlock, SSH save/password reveal-reset, DB/key-pair dialogs and combobox/popover,
export with fresh verification, import warning dialog, project/report creation,
hostile Markdown, global lock and browser logout. It does not claim a browser
recovery/restart M1 journey or native authenticator capability.

- The independent hostile image host recorded **0 requests before activation**
  at its pre-click assertions, then **exactly 1 request after the image's
  warning-labeled button was clicked**. Contrary to the earlier report wording,
  that original runner had no awaited 500-ms observation window. The image had a unique
  path `/unique-hostile-1794710935321.svg` on the fixture's own independent HTTP
  origin. It received no Referer; the opened page's `window.opener` was null.
  Raw HTML/style payloads did not create requests or DOM script/style nodes.
  This proves the exercised external-open flow, not absence of every conceivable
  browser side channel or correctness of an unimplemented inline-image flow.
- **0 CSP violations and 0 page errors.** Requests for all nine emitted
  JS/CSS/WOFF2 assets were recorded, and all five font subsets were explicitly
  exercised via FontFace. The original general asset assertion proved request
  presence, not successful response/body completion for every asset. Original management JS is
  `management-DyT7SrSm.js`; CSS `management-BOTD-X8P.css`; setup entries/chunks
  `setup-74dRtrDo.js` and `setup-DPL8Tbm1.js`. The generated allowlist remains
  independently checked by the emitted-dist verifier.
- No test fixture remains running after completion. The runner disconnects its
  browser connection without stopping the shared service and removes only its
  newly created temporary DB/certificate directory. Output artifacts remain
  private test evidence outside the checkout; they contain synthetic secrets
  and should still be handled as sensitive, ephemeral artifacts.

Artifacts under **`/tmp/warden-t9-browser-acceptance-reviewed/`**:
`index.html`, `result.json` (asset/network/image counters), `trace.zip`,
`setup.png`, `login.png`, `dialog-popover.png`, `markdown-before.png`,
`markdown-explicit.png`, `video/page-0.webm`, `video/page-1.webm`, `setup.log`
and `runtime.log`. Command output is
`/tmp/warden-t9-browser-acceptance-reviewed.log`. Earlier failed/superseded attempts
remain in other `/tmp/warden-t9-browser-*` directories and are not relabeled as
final acceptance. `/tmp` is not durable publication storage.

## Self-review and handoff

Reviewed production/test/fixture diffs for root-state detachment, deferred result
checks, retained request/file generations, exact import bytes, fresh headers,
URL revocation and Markdown URL/HTML/opener boundaries. Reviewed actual CSP
rather than substituting jsdom for browser enforcement. No external DB/proxy TLS,
server crypto/schema/auth-audience/response-lease or grant-consumption change.
Only backend production change is the corrected CSP explanatory comment.

Documentation-only TDD exception was declared before this report/checkpoint/
ledger edit: evidence prose is checked against source, commands, links and diff,
not a fabricated runtime failing test. Independent review is the next step;
genuine authenticator PRF, production trust, native Windows and final-release
integration remain separately pending. Stop at this T9 self-review checkpoint;
this report does not authorize T11, T12, commits or publication.

Original closing validation: all **34** changed/new task files (including the ignored
ledger, excluding the protected file before content reads) pass explicit
whitespace/final-newline/local Markdown-target checks; all three touched Go
files are gofmt clean, both browser fixture scripts pass `node --check`, and
`git diff --check` passes. An existing missing final newline in the already
modified DB form test was normalized; its 30 tests passed again at that point
(`warden-t9-closing-db-test.log`), and the subsequent final full checks above
include it. No staged files; branch/HEAD remain as assigned. Only evidence prose
changed after those original production/test/browser checks.

## Bounded T9 follow-up — three review P2 findings

### Independent verification and corrections

Same sole-writer scope and assigned branch/HEAD; no commits, protected-file
access, dependencies, version edits or T11/T12 work. Only the API client/test,
browser runner, its new pure network gate and Node tests, this report, bounded
plan checkpoint and local ledger changed during this follow-up.

1. **Caller-only export abort:** source inspection confirmed a missing caller
   signal check immediately after fetch and after `responseError`. The global
   epoch check existed at both points; the caller check after Blob reading
   already existed. Four deferred regressions hold the global epoch constant:
   error fetch, successful fetch, error-body read and Blob read. Before the fix,
   **3 failed / 1 passed / 27 filtered skips**: both error cases returned
   `ApiError`, and successful fetch still began reading its Blob after caller
   cancellation. Post-Blob rejection was already passing. Two added
   `signal?.throwIfAborted()` checks make **31/31 client tests pass**. Tests also
   assert exactly one fresh grant, one fetch, unchanged empty-body request
   binding, same-origin credentials and no-store. No retry or grant/body change.
2. **Asset/network evidence gate:** extracted the original presence assertion
   unchanged into `web/e2e/ui-privacy-network.cjs` before adding negative tests.
   That extraction was behavior-preserving, not a fabricated runtime RED.
   The initial Node suite then had **8 failed / 3 passed**: the old predicate
   accepted a completed stylesheet 500, incomplete 200 headers, transfer failure,
   failed/pending fixture APIs, failure hidden by retry, and image-host 503.
   The strengthened gate requires a successful status **and `requestfinished`**
   for every actual manifest asset before writing PASS. All fixture HTTP
   statuses, terminal transport failures and body completion are recorded;
   successful request issuance or 200 headers alone cannot satisfy it.
3. **Historical evidence accuracy:** independently read the saved key/profile
   RED logs. Their first failing assertion was that the pending dialog had not
   closed; neither replacement opening nor old-save rejection had executed.
   The historical table above is corrected. Complete later passing assertions
   remain coverage, not retroactive RED contamination evidence. Inspected the
   old runner and confirmed that its claimed 500-ms delay did not exist. The
   old wording is qualified above; only the refreshed run below establishes an
   explicit observation window and completed-response asset evidence.

### Browser refinement: explicit expected traffic, not blanket exclusions

Context7 `ctx7:docs:09d85f54455ac07e5294ab3b` plus exact installed Playwright
`1.62.0` types confirmed `response` means status/headers, `requestfinished` means
body downloaded, and HTTP 4xx/5xx are not `requestfailed`. The same preflight
covered `Request.failure()` and `ConsoleMessage.location()` from installed
source/types. Required Playwright skills and machine service README were read
again; the shared service/reference package and synthetic/HTTPS boundaries are
unchanged.

The first strict browser refresh correctly failed rather than claiming PASS:
it exposed the normal initial status 401 and lifecycle `net::ERR_ABORTED`
requests previously invisible to the gate. Two diagnostic attempts waited for
the intentionally unread initial 401 body to finish/terminate before login;
those waits timed out and were removed. Another strict run reached the end and
failed on an aborted first-mount read. No blanket abort or error-status
allowlist was added. Final handling is narrow and has negative tests:

- Only the initial **GET `/api/v1/auth/status` with observed 401 headers** can
  discard its body with exactly `net::ERR_ABORTED`; another failure code,
  method, route or phase is rejected. The ordinary fully consumed initial 401
  is also expected. Unsupported PRF produces a local explicit refusal, not an
  HTTP failure exception: the runner separately asserts **no unlock submission**.
- Only the **first** GET of each of the five current mount-list routes, in the
  management phase, may be cancelled with exactly `net::ERR_ABORTED`, status
  absent/200, and only when a **later successful completed replacement** exists.
  Missing replacements, later cancellations, wrong phases, other transport
  errors and HTTP 500 still fail. Assets have no cancellation exemption.
- Lock/logout POST aborts are accepted only in their exact transition phase
  and only after separate normal-cookie, no-store status probes prove the
  server is actually **locked** and then rejects the logged-out session.
  Corresponding probes must themselves finish successfully (200 for lock;
  intentional 401 for logout), and independent state assertions must pass.
  Merely changing optimistic UI is insufficient. No authorization check or
  production endpoint was bypassed, and no auth implementation was changed.
- All console errors are recorded, including ordinary resource-load errors.
  Only the exact expected unauthenticated-status 401 console message for a
  gate-validated status probe is tolerated. Other console/page/CSP errors fail.
  Statuses, transport errors and expected reasons remain visible in artifacts.

These refinements had their own focused REDs: initial expected 401 handling
**1 failed / 12 passed**, initial discarded-body handling **1 failed / 13
passed**, and lifecycle/probe handling **4 failed / 15 passed**. Final pure
network-gate suite: **19 passed / 0 failed**. The gate uses no arbitrary
production test route, environment bypass, mocked API or added dependency.
The Node-only suite was moved into the existing Vitest-excluded `web/scripts/`
location after an initial whole-web run discovered it as a Vitest suite; all
279 frontend assertions had passed in that failed discovery run. This was test
placement, not a production regression; its log remains preserved.

### Follow-up commands and results

```sh
(cd web && NODE_ENV=test ./node_modules/.bin/vitest run src/api/client.test.ts -t 'caller-only export cancellation') # observed RED before fix
(cd web && NODE_ENV=test ./node_modules/.bin/vitest run src/api/client.test.ts)
node --test web/scripts/ui-privacy-network.test.cjs
NODE_ENV=test npm --prefix web test
npm --prefix web run build
node web/scripts/verify-dist.mjs internal/web/dist
WARDEN_UI_ARTIFACTS=/tmp/warden-t9-review-p2-confirmed node web/e2e/ui-privacy.cjs
go test ./internal/server ./internal/server/setup ./internal/server/runtime ./internal/web -count=1 -timeout=180s
go test -race ./internal/server ./internal/server/setup ./internal/server/runtime -run '^TestUIFramingAndCSPProductionAssets$|^TestServeUI' -count=1 -timeout=180s -v
git diff --check
```

- API focused GREEN **31/31**; RED log
  `/tmp/warden-t9-review-export-red.log`, GREEN
  `/tmp/warden-t9-review-export-green.log`.
- Node gate GREEN **19/19**, `/tmp/warden-t9-review-network-green.log`.
  Initial presence-gate RED was run at its then-location
  `web/e2e/ui-privacy-network.test.cjs`; log
  `/tmp/warden-t9-review-network-red.log`. Refinement RED logs:
  `/tmp/warden-t9-review-status-probe-red.log`,
  `/tmp/warden-t9-review-status-body-red.log`,
  `/tmp/warden-t9-review-lifecycle-gate-red.log`.
- Whole web GREEN **17 files / 279 tests**, plus **13/13** existing dist tests:
  `/tmp/warden-t9-review-web.log`. Node gate tests are run separately by the
  explicit command above, not counted as part of that npm result. Initial
  discovery-only failure: `/tmp/warden-t9-review-web-discovery.log`.
- Production build and emitted-dist verification PASS:
  `/tmp/warden-t9-review-build.log`, `/tmp/warden-t9-review-dist.log`.
  Existing >500-kB chunk warning remains. No version/dependency changes.
- Affected embedded-UI/server packages normal PASS:
  server **0.005s**, setup **2.124s**, runtime **17.746s**, web **0.001s**;
  `/tmp/warden-t9-review-go.log`.
- Focused header/cache/UI race checks **11 tests PASS** across server/setup/
  runtime; `/tmp/warden-t9-review-headers-race.log`. Full-package race, vet and
  full Go were **not rerun in this follow-up**; their original results above are
  historical. Known unrelated SFTP failure and earlier DB intermittence remain
  unresolved, with no new fix or current whole-suite PASS claim.

### Refreshed HTTPS production-browser evidence

**One journey PASS / zero failed**, Chromium `151.0.7922.34`, disposable origin
`https://localhost:36645`. All prior setup/login/PRF-negative/unlock/dialog/
popover/export/import-warning/report/lock/logout flows remain, with actual
server-state confirmation added for the final transitions.

- Every one of the **nine actual manifest assets** has **HTTP 200 and completed
  response body**, recorded in `completedAssets`. Current management JS is
  `management-D6Es6t8_.js`; setup/CSS/font names otherwise match the emitted
  manifest. These receipts, not manifest/request presence alone, gate PASS.
- An explicit `await delay(500)` occurs after report render/screenshot and
  before the final pre-click image/network counters. Recorded
  **`imageObservationMs: 500`**, **0 pre-activation requests**, **1 after explicit
  activation**, unique `/unique-hostile-1794712753375.svg`, no Referer and null
  opener. This is a bounded observation, not proof about all future time or
  unexercised rendering flows.
- **0 CSP violations, 0 page errors, 0 unexpected network/console failures.**
  The artifact explicitly records nine expected non-success entries: the
  initial status 401/body cancellation, five replaced mount-read cancellations,
  two independently server-confirmed transition cancellations, and the completed
  logout-status 401. Two expected status-401 console messages are retained.
  This is **not** a claim of zero raw aborted requests or console errors.
- Final browser log: `/tmp/warden-t9-review-p2-confirmed.log`.
  Artifacts: **`/tmp/warden-t9-review-p2-confirmed/index.html`**, `result.json`,
  `trace.zip`, five screenshots, `video/page-0.webm`, `video/page-1.webm`,
  `setup.log`, `runtime.log`. No prior artifact directory was overwritten.
  Failed/diagnostic directories are `/tmp/warden-t9-review-p2-browser/`,
  `/tmp/warden-t9-review-p2-probe/`, `/tmp/warden-t9-review-p2-server-state/`
  and `/tmp/warden-t9-review-p2-server-verified/`.
  Parent-supplied `/tmp/warden-t9-parent-browser` remains prior evidence, not
  proof of this new gate.

Synthetic signed WebAuthn/injected PRF and the test-only certificate-trust
exception remain explicit; genuine authenticator PRF, production trust, native
Windows and independent acceptance remain pending. Disposable fixtures are
stopped/removed, while the shared browser service and private synthetic output
artifacts are preserved. Stop at bounded T9 self-review; no later-task or
publication authority is implied.

Follow-up self-review/hygiene: the accumulated T9 scope is **36 files**, with
**8 files** touched by this follow-up (including the ignored ledger). All pass
explicit whitespace/final-newline/local Markdown-target checks; the three
previously touched Go files remain gofmt clean and all four browser/helper/Node
test CommonJS files pass `node --check`. Final **19/19** gate rerun:
`/tmp/warden-t9-review-network-final.log`. Browser asset receipts match the
current emitted manifest, every listed artifact is nonempty, and no owned
setup/runtime fixture process remains. Branch/HEAD and synchronized `0.22.1`
version fields are unchanged; nothing staged. Reviewed the actual follow-up
source/tests/expected-traffic rules and corrected prose. No unresolved new
implementation decision; independent review and external acceptance remain
separate. Only evidence prose changed after the final source checks.
