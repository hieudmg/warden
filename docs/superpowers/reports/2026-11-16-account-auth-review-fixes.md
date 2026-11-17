# Account/passkey auth review follow-up: F1 and strict browser evidence

## Scope and disposition

Implemented the bounded follow-up in `/var/tmp/warden-auth-review-fix-brief.md`, after the directory writer stopped. Read the independent `/var/tmp/warden-account-review/review.md` and the accepted `/var/tmp/warden-passkey-cancellation-diagnosis/report.md` before implementation.

**Local implementation and the checks below pass; independent parent re-review/verification remains pending.** This is not merge, release, deployment, genuine-PRF, native-Windows or production-trust acceptance. No commit/push/PR, worktree, subagent, browser installation, trust-store change or live installation operation was performed.

The completed Task1 init/config/ancestor-durability follow-up was protected. No Go/backend/configuration/crypto/schema/identity/dependency graph changes were made. The existing 0.24.0 release fields remain unchanged. Nonblocking F2 remains outside scope: canceled account setup preparation can leave that init process requiring restart; this follow-up does not fix it.

> 🧠 **From Hindsight memory (Conventions and patterns)** — The recorded project practice requires deterministic regression evidence, preservation of security bounds, and separation of local checks from independent acceptance. The implementation and results here are current-source/execution evidence, not reliance on a historical claim that this issue was already fixed.

## Root cause and correction

### F1: a view canceled the operation responsible for its own render/unmount

`AuthClient.lock()` and `logout()` cancel old work, publish the optimistic closed snapshot, and issue their authority-changing POST. SecurityView's effect cleanup formerly called the same shared `client.cancel()` when `state.unlocked` changed or logout unmounted the view. That canceled the **new** POST, not just the old secret work. Delayed dispatch could therefore leave an authenticated/unlocked server while the browser presented locked/logged-out UI. The causal source predates Task2, but the new account mode exposed it too.

- SecurityView's effect now invalidates only its own local result generation. AuthGate still owns the actual client/application lifetime and cancels on true app unmount or client replacement. SecurityView is only mounted by AuthGate in production.
- Explicit **Cancel security operation** still calls global client cancellation. AuthClient transitions still immediately abort old controller/security-epoch work and clear old recovery/password-modal state. No AbortSignal or epoch check was disabled.
- AuthClient records a pending lock/logout transition. Polling and login/unlock/recovery reentry cannot replace that closed snapshot while the POST is pending. Fresh action requests and recovery abort also reject transition overlap. Previously started work remains subject to the original epoch checks.
- Success removes only the pending marker; it does not restore authenticated/unlocked state from an old response. An explicit transition ownership token retires the old finalizer when identity/recovery replacement publishes another snapshot, so a late logout cannot clear a replacement session's CSRF or publish its old error. Cancellation or failure keeps local access closed, exposes a persistent server-confirmation error, and suppresses automatic status reopening until successful explicit authentication. Ordinary denial handling still resets recovery state as before, while retaining the transition fence/error.
- Logout still clears client/global CSRF in its finally path. Header transition buttons are disabled while pending. There is no automatic success claim for a failed/canceled authority POST.

### Retained passkey-list failure: sequencing, not an abort exception

The accepted diagnosis separately established that a naturally initiated **post-lock** list load can be canceled by immediate logout. This does not prove that the server failed to lock/logout, but the read cannot be called successfully completed.

Both runners now register full-completion barriers **before** the relevant action. The passkey runner waits for the new post-lock passkey and device-list bodies before logout. The account runner also waits for the required management reads after restart/re-unlock before logout; otherwise its newly strict gate correctly detected those reads being canceled.

The obsolete gate allowance for aborted lock/logout POSTs with lucky successful server probes was removed. A null-status abort, an abort after 200 headers, and an incomplete transition now fail even when a separate status probe confirms the server changed. Initial unauthenticated status-body discard and narrowly replaced first-mount reads retain their existing limited exceptions; arbitrary metadata/API/asset failures remain rejected.

## Browser evidence correction

Shared `web/e2e/auth-lifecycle.cjs` provides:

- request/response/requestfinished/requestfailed tracking (including pre-response failures);
- correlation of a newly initiated request with successful full response completion, rather than accepting a 200 response event or an old request completion;
- same-cookie server status confirmation after lock, plus protected management 423 using the pre-lock cookie;
- browser status 401 after logout, plus a separate replay of the pre-logout cookie requiring 401, so deleting the cookie alone cannot fake session revocation;
- opt-in, explicitly test-only signal-aware held dispatch via `WARDEN_UI_HOLD_TRANSITIONS=1`.

The hold pauses native fetch dispatch across the optimistic render/effect cleanup, observes the real supplied AbortSignal, and releases the unmodified request only if it remains live. Two browser rendering turns expose cleanup before release. It does not mock responses, seed sessions, alter cookies, bypass authentication/CSRF, or claim real authenticator PRF support. The normal journey does not install this scheduling hook.

The account runner now feeds every tracked request to the strict gate rather than filtering only response statuses. Both runners require the actual transition POSTs to complete successfully **before** server proofs and before re-unlock/recovery/relogin. `serverProofs` in each result records sanitized outcomes. The old-cookie HTTP probes use the existing test-only self-signed localhost exception and never print cookie values.

Both runners retain trace/screenshot/video capture; account remote videos are explicitly downloaded as the existing passkey runner already did. Pending download promises now have an immediate rejection handler so a renderer crash reaches normal failure capture/finally cleanup rather than becoming an unhandled Node rejection. The awaited promise still rejects; no failure is converted into success.

## RED → GREEN evidence, including test corrections

Private evidence root: **`/var/tmp/warden-auth-review-fix/`**. All paths below are beneath it unless absolute.

1. **Initial focused unit RED, before production edits:** added the real AuthGate/SecurityView/AuthClient signal-aware lifecycle test and ran with the explicit test config. `unit-red.log` recorded 11 failing tests. Both logout variants and the cancellation cases directly observed the new transition signal already aborted by cleanup. The two initial lock cases hit a test-double defect first: the same deferred device-read slot was reused by the new locked-state read and overwrote the recorded old signal. This is not claimed as a correct lock-specific self-abort assertion.
2. Corrected that harness to consume each deferred slot once and assert DOMException by name instead of cross-realm `instanceof Error`. After the ownership fix, the focused/adjacent suite passed (`unit-green.log`, 38 tests at that stage).
3. **Corrected causal regression check:** temporarily reintroduced only the old SecurityView shared-cancel cleanup, ran the four primary cases, and restored the fix immediately. `corrected-harness-causal-red.log` records **4/4 failures exactly at `authority.signal.aborted` expected false / actual true**, while the assertion that old work was canceled had already passed. This is a post-fix sensitivity replay, not falsely described as the initial test-first run. `focused-final-green.log` ultimately records all **18 focused cases passing**, including the later stale-owner regression below.
4. **Network gate RED:** `gate-red.log` records two failures because the old gate accepted aborted lock/logout with verified status probes. After removing that exception, `gate-green.log` passed all 26 gate/helper cases; the final npm test also includes them.
5. **Production-browser RED against the retained pre-build assets:** both strengthened held runners rejected self-cancellation, before the first build of the fix:
   - `browser-red-account.log` / `browser-red-account/`: `transition POST was canceled by its own render cleanup`, true !== false.
   - `browser-red-passkey.log` / `browser-red-passkey/`: same assertion.
   - `assets-before-build.json` records the exact old distribution. These full journeys stop at the first (lock) failure; logout's pre-fix browser consequence in both modes remains independently established by the accepted diagnosis, and the corrected unit replay covers all four mode/operation combinations.
6. **Stale finalizer RED → GREEN during self-review:** `stale-owner-red.log` demonstrates a previously started recovery-abort finally replacing the view while logout's body is held, followed by successful replacement login. The late logout then wrongly published its old error (and would clear the replacement CSRF). This public-API interleaving prompted the explicit ownership-token check in the finalizer. The regression now passes and asserts both the replacement snapshot and its CSRF survive. This is within the brief's stale-transition/identity protection, not a setup F2 fix.
7. **Actual rebuilt-browser GREEN:** after that final correction, the four `current-*` journeys below successfully dispatch both transitions and establish the real server states. These are not merely passes on an unchanged old binary; earlier `verified-*`/`stable-*` greens are retained as intermediate evidence, not substituted for this final source.

The initial unconfigured Vitest attempt did not collect tests due to node:crypto browser externalization and is not counted as RED; subsequent runs explicitly selected the existing Vitest config. A first build attempt also caught RTL `getByRole` calls incorrectly using Playwright's `exact` option; removing that unsupported option fixed TypeScript compilation without weakening matching assertions. These setup/type corrections are not production-fix evidence.

## Final stable-source validation

Commands from the checkout:

```sh
cd web
NODE_ENV=test npm test
NODE_ENV=production npm run build
```

The npm test entry now explicitly uses the existing Vitest config and runs both `.test.mjs` distribution tests and `.test.cjs` network/helper tests, so the new browser evidence regressions are included in the normal test command.

| Check | Result | Private log/artifact |
|---|---|---|
| Focused real-component lifecycle suite | 18 PASS | `focused-final-green.log` |
| Complete frontend suite | 301 PASS, 20 files | `verified-npm-test.log` |
| Node distribution + strict gate + evidence helper suites | 39 PASS, 0 skipped (13 distribution + 19 gate + 7 helper) | `verified-npm-test.log` |
| TypeScript + production Vite build + verify-dist | PASS; existing large-chunk warning only | `verified-build.log` |
| Account normal HTTPS journey | PASS | `current-account-held0/`, matching `.log` |
| Passkey normal strict HTTPS/CSP/assets journey | PASS | `current-passkey-held0/`, matching `.log` |
| Account deliberately held lock AND logout dispatch | PASS | `current-account-held1/`, matching `.log` |
| Passkey deliberately held lock AND logout dispatch | PASS | `current-passkey-held1/`, matching `.log` |
| Protected-source comparison and diff whitespace check | PASS | `protected-before.json`, final hash manifests; `git diff --check` |

Every final browser result independently records:

```text
POST /api/v1/auth/lock:   200, finished=true, failure=null
lock status probe:       200, authenticated=true, unlocked=false
pre-lock management:     423 after lock
POST /api/v1/auth/logout: 200, finished=true, failure=null
browser logout status:   401
pre-logout session replay: 401
```

For passkey journeys the complete emitted-asset/strict network gate remains in use, with no metadata cancellation exemption. Account journeys also reject all observed failed/incomplete requests. Real Go setup/runtime HTTPS fixtures serve the rebuilt production assets for these journeys; backend fixture source was not changed. Full unrelated Go/race/vet suites were not rerun in this frontend-only follow-up.

`verified-browser-summary.json` contains sanitized post/probe summaries. `final-source-sha256.json` and `final-assets-sha256.json` identify the tested source/assets. Served asset resources in all four final traces were byte-compared to the current distribution. The protected baseline comparison covered 311 Go/config/init/mise file entries and found no changes, including the completed directory-durability work. `mise.toml` and `scripts/ci/__pycache__/` were not edited. No package-lock or dependency graph changes were made.

## Retained intermediate failures and limits

- The original `/var/tmp/warden-task2-evidence/passkey-browser-final/` failure is preserved and not retroactively declared a pass. Its distinct metadata-read race is diagnosed in the accepted external report.
- `browser-held-account/` initially failed the strengthened gate on post-restart management reads canceled by immediate logout. The account runner was corrected to await their required full completions; no gate exemption was added. `browser-held-account-current/` then passed.
- During an intermediate batch, `final-passkey-held0/` suffered `Target crashed` at the existing Reveal password click, before transition checks. `final-account-held1.log` records `Page crashed` while waiting for export download, also before transitions; its unhandled pending download rejection originally prevented normal trace-finalization. This led to the rejection-handler correction described above, not to acceptance of the crash. Its underlying renderer-crash cause was **not established**. Host resource snapshots and a safe shared-service status check did not establish an OOM cause. The shared service was not stopped/reset. Bounded fresh-context reruns were recorded separately, and the subsequent `stable-*`, `verified-*`, and final `current-*` four-run matrices all passed. Passing reruns do not prove the historical crash root cause or waive F1; the focused causal checks and explicit server proofs establish the F1 correction independently.
- Account mode forbids navigator.credentials access in the journey. Passkey mode still uses signed synthetic WebAuthn/injected PRF. Neither mode establishes production certificate trust; genuine PRF/native Windows/real power-loss acceptance remains outside this task.
- Raw traces, screenshots, videos and fixture logs can contain disposable secrets. Directories are private; share this report and sanitized summaries rather than raw artifacts publicly.

## Changed files and next gate

- `web/src/auth/auth.ts`, `auth-gate.tsx`, `security-view.tsx`: ownership correction, pending/failure fence and visible error handling.
- `web/src/auth/transition.test.tsx`: 18 lifecycle/race/failure/cancellation/modal regressions.
- `web/e2e/auth-lifecycle.cjs`: strict full-completion/server-proof/held-dispatch helpers.
- `web/e2e/account-lifecycle.cjs`, `ui-privacy.cjs`: strengthened evidence and required-read synchronization.
- `web/e2e/ui-privacy-network.cjs`: obsolete transition-abort allowance removed.
- `web/scripts/auth-lifecycle.test.cjs`, `ui-privacy-network.test.cjs`: completion/rejection regressions.
- `web/package.json`: normal test command includes the CJS regressions; no dependency/version change.
- This focused report. Generated ignored production assets were rebuilt for validation.

**Next gate:** parent read-only security re-review and independent verification of these bounded fixes before publication. F2 remains intentionally unimplemented. Stop here; no publication or unrelated work is authorized by this report.
