# Resumable setup/account authentication: parent acceptance

## Delivered scope

Branch `hieudmg/resumable-account-setup`, approved base `606abb8` (`origin/main`, re-fetched unchanged before publication). Task1 checkpoint `2206984` plus the reviewed Task2 and follow-ups deliver:

- Fresh init config/database/TLS-path defaults under `~/.warden`, immediate private persistence of each submitted non-secret answer, editable invalid/incomplete drafts and reprompted saved defaults.
- Account username/password as the new-init default, or passkey; no unauthenticated mode or TOTP. Legacy missing modes remain passkey and initialized installations are not converted/reset.
- Temporary terminal-password-gated HTTPS account creation, password-protected DEK login/unlock, fresh password grants for sensitive actions, offline recovery preserving the DEK with prior-session/client revocation, and a modest setup-page refresh.
- Compatibility/private ownership/canonical draft/publication safeguards, including Unix ancestor-directory durability barriers.
- Corrected UI lock/logout lifetime ownership with completed authority requests and independent server-state browser proofs. Cancellation and epoch safeguards remain, and strict browser network checks are stronger rather than waived.

The release changes **0.23.0 -> 0.24.0 (minor)** because account authentication is a backward-compatible new capability. All three release fields match. Dependency versions and lock graph are unchanged; the web test command additionally runs the strict CJS evidence regressions.

## Parent inspection and independent review

The parent inspected actual config/draft/publish/ancestor code, password envelope, account setup/runtime/recovery boundaries, auth UI/client lifetime changes, strengthened request/server-proof helpers, serialized version changes, test assertions and reports. The parent visually inspected the clean account-creation screenshot; secret-bearing recovery traces/screenshots were not published.

Independent setup review originally blocked custom legacy omitted-DB defaults, draft aliases and publication durability. Follow-ups added focused regressions and corrections; its final bounded verdict was **OK, no Task1 blockers**. The Unix newly-created-ancestor gap was explicitly re-reviewed and closed at source/primitive level, not claimed proven under physical power loss.

Independent auth review originally blocked self-canceling lock/logout and inadequate account-browser proofs. Read-only diagnosis reproduced the real server no-op in both modes under delayed dispatch. The production ownership fix, pending/failure/stale-finalizer fences and stronger runners received focused RED/GREEN evidence. Final bounded re-review: **F1 CLOSED, OK with notes, no new blockers**. The reviewer directly inspected all four parent browser result artifacts. Reviewers performed source/artifact review, not independent behavioral test execution.

Nonblocking F2 remains: canceling an in-flight account preparation can require restarting terminal init. This is fail-closed, preserves saved non-secret answers and does not commit a partial identity. Same-process browser retry hardening was not added to this PR.

## Parent-executed final validation

Private logs/artifacts: `/var/tmp/warden-parent-validation/`. Final code was stable; frontend generation completed before the final Go/browser matrix.

```sh
NODE_ENV=test npm --prefix web test
NODE_ENV=production npm --prefix web run build
TMPDIR=/var/tmp go test ./... -count=1
TMPDIR=/var/tmp go vet ./...
TMPDIR=/var/tmp go test -race ./internal/config ./cmd/warden-server ./internal/crypto ./internal/server/setup ./internal/store ./internal/server/runtime -count=1
```

PASS: **301 frontend tests**, **39 Node distribution/network/evidence tests**, TypeScript/Vite production build and `verify-dist`; all 25 Go packages with tests passed (model/migrations have no test files); all six race packages passed; vet exited 0. The existing >500 kB management-chunk warning is not a build failure. Logs: `web-test-final.log`, `web-build-final.log`, `go-all-stable-assets.log`, `go-race-final.log`, `go-vet-final.log`.

The parent separately reran command/config tests after the ancestor fix, then rebuilt both trimpath production binaries against final assets and exercised both composed production-binary HTTPS journeys:

```sh
TMPDIR=/var/tmp go build -trimpath -o /var/tmp/warden-parent-validation/bin/warden-server ./cmd/warden-server
TMPDIR=/var/tmp go build -trimpath -o /var/tmp/warden-parent-validation/bin/warden ./cmd/warden
WARDEN_ACCEPTANCE_BIN=/var/tmp/warden-parent-validation/bin TMPDIR=/var/tmp \
  go test ./internal/server/runtime -run '^Test(AccountSecurityLifecycleHTTPS|SecurityLifecycleHTTPS)$' -count=1 -v
TMPDIR=/var/tmp GOOS=windows GOARCH=amd64 go test -c ./cmd/warden-server -o /var/tmp/warden-parent-validation/warden-server-final.test.exe
PYTHONDONTWRITEBYTECODE=1 python3 scripts/test_integration_runner.py
git diff --check
```

PASS: account production init/login+unlock/export/lock/logout/restart/CLI pairing+revocation/password recovery; retained passkey production lifecycle; Windows compilation; four runner contracts; whitespace. See `composed-final.log`. Compilation is not native Windows execution.

### Final browser acceptance

Executed sequentially for `held=0` and `held=1` using the existing documented shared Chromium and fresh isolated HTTPS fixtures/contexts:

```sh
WARDEN_UI_HOLD_TRANSITIONS="$held" WARDEN_ACCOUNT_ARTIFACTS="/var/tmp/warden-parent-validation/final-account-held$held" TMPDIR=/var/tmp node web/e2e/account-lifecycle.cjs
WARDEN_UI_HOLD_TRANSITIONS="$held" WARDEN_UI_ARTIFACTS="/var/tmp/warden-parent-validation/final-passkey-held$held" TMPDIR=/var/tmp node web/e2e/ui-privacy.cjs
```

**Four journeys PASS, zero final browser failures.** The held-dispatch variant intentionally delays native fetch across optimistic render/cleanup while respecting the actual AbortSignal; it does not mock responses or bypass server authentication. Parent inspected every `result.json`:

- All **eight** lock/logout POSTs: status 200, `finished=true`, `failure=null`.
- Each lock: same-cookie status 200, authenticated=true, unlocked=false; pre-lock cookie protected-management request 423.
- Each logout: browser status 401 and replay of the pre-logout session cookie 401.
- Account journey forbids navigator.credentials; account setup/recovery/fresh password paths run without PRF. Both modes retain strict completed-request/asset checks.

Each `final-{account,passkey}-held{0,1}/` contains result JSON, screenshots, trace and video. These custom CJS runners do not generate a Playwright HTML report. Artifacts are private and include disposable secrets; they are not repository/PR assets.

## Test-first evidence and retained failures

Worker reports preserve actual RED/GREEN chronology, distinguishing absent-API compile failures, behavioral failures, post-fix sensitivity replays and additional post-implementation coverage. References:

- `2026-11-16-resumable-setup-task1.md`
- `2026-11-16-resumable-setup-task2.md`
- `2026-11-16-init-ancestor-durability-followup.md`
- `2026-11-16-account-auth-review-fixes.md`

Earlier passkey-list cancellation was diagnosed as logout canceling a newly started metadata read; runners now await required body completion without adding an abort exemption. The lock/logout no-op was separately reproduced and fixed. Earlier renderer crashes remain retained with cause unproven; passing later matrices are not an explanation or claimed crash fix.

One parent `go test ./...` attempt overlapped web rebuilding of the embedded asset tree and failed account PTY startup with password EOF (`go-all-final.log`). Its exact subprocess error was not captured by the existing fixture's suppressed stderr. This mutable-asset run is not passing final-state evidence and does not prove a production root cause. After asset generation stopped, the complete stable-assets run passed; production binaries and all four browser journeys were subsequently built/run sequentially against matching final assets.

## Limits and publication boundary

No native Windows ACL/ancestor-publication execution, real power-loss/filesystem/hardware experiment, genuine-authenticator PRF, production certificate trust, privileged Unix cross-owner check, live proxy/deployment, or hosted release provenance/signing was established. Browser HTTPS uses the disclosed disposable self-signed localhost exception; passkey tests use signed synthetic WebAuthn/injected PRF. Ordinary full Go runs skip the four opt-in browser fixture tests (all were explicitly exercised by the browser runs) and the existing privilege-dependent cross-owner test. The entire installer/dependency-reinstalling `scripts/test.sh` was not run; its relevant tests/build/composed lifecycle and runner contracts were run directly.

No remaining required review finding is open for this PR scope. The parent accepts the bounded implementation and local checks for PR publication, not general production-security or release acceptance. No merge, tag, release, deployment, live migration or trust-store operation is authorized/performed. Unrelated `mise.toml` and `scripts/ci/__pycache__/` remain untouched and excluded from staging.
