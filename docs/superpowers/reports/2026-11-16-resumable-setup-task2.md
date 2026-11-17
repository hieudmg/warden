# Task 2: account authentication end-to-end

## Bounded outcome and authority

Implemented on `hieudmg/resumable-account-setup`, after Task1 checkpoint
`2206984`, as the sole checkout writer. The authoritative Task2 brief and plan
were the contract. No children, worktrees, commits, push, PR, deployment, migration,
live operations, trust installation, browser/dependency installation, or changes
to unrelated `mise.toml` / `scripts/ci/__pycache__/` were made.

This is **local implementation evidence, not parent/independent acceptance**.
The 0.23.0 → 0.24.0 minor bump adds account capability without converting existing
passkey installations. Exactly three version fields changed; dependency versions,
lock graph, `go.mod` and `go.sum` are unchanged.

## Implemented contracts

- New init explicitly asks `account` (default) or `passkey`, persists the answer,
  and reuses saved defaults. Missing legacy config/identity mode means passkey.
  Runtime rejects mismatched, mixed, missing-account and malformed identities.
  No unauthenticated mode, TOTP, multi-account service, dual-method enrollment or
  mode conversion exists.
- Temporary terminal-password-gated HTTPS creates the single owner account with
  username/password confirmation. Random account ID is an actual account
  credential, not a fake WebAuthn credential. Preparation wraps a random DEK and
  tests the protected wrapper round-trip; offline recovery-key re-entry is still
  required before atomic installation publication. Failed/canceled/expired setup
  cannot initialize storage. New passkey installs explicitly record passkey mode.
- Account envelope v1: Argon2id, 64 MiB, 3 passes, 4 lanes, 32-byte output; random
  32-byte salt, AES-256-GCM with fresh 12-byte nonce and explicit version/purpose/
  vault/credential/KDF binding. Costs must exactly match v1 **before derivation**.
  Authenticated unwrap plus the DEK key-check verifies passwords; no independent
  decrypt-capable password verifier is stored. Username is exact UTF-8, 1–64
  bytes, without surrounding whitespace/controls. Password is exact UTF-8,
  12–1024 bytes, no trimming/normalization/composition rules. Wrong valid username
  still performs the same password derivation before generic rejection.
- Account login authenticates **and unlocks**, including after restart. Global
  lock drops the DEK; re-unlock needs a fresh password. Logout revokes only that
  session. Account fresh verification issues the existing 60-second,
  session/credential/target/digest/vault-epoch-bound single-use grants; all existing
  sensitive operations, including CLI approval/revocation and recovery rotation,
  retain the exact-request gate. Passwords are never cached for future actions.
- Four existing bounded runtime crypto slots admit account operations before
  body reads (at most 256 MiB Argon2 working memory, plus ordinary overhead).
  Setup has two bounded crypto slots. Account auth bodies are capped at 8 KiB;
  shared setup bounds remain 64 KiB. Existing origin/CSRF/cookie/audience/rate/
  admission/delivery/vault protections remain. Argon2 runs outside the publication
  mutex, followed by current identity generation/credential/session/recovery/
  vault-epoch/cancellation checks. Logout revocation now shares that publication
  mutex, closing a self-reviewed final-recheck/revocation race for both modes;
  vault lock is never drained while holding it.
- Offline recovery unlock remains restricted to credential replacement, never
  management/export. Account replacement keeps the username and **same DEK**,
  creates a fresh random credential ID, verifies the new password wrapper and
  key-check, then uses existing identity CAS/all-session/client revocation.
  Failure/abort preserves identity. Completion returns locked to ordinary login.
  No passkey/PRF operation is used for account recovery.
- Nonsecret `GET /api/v1/auth/method` selects the frontend journey; anonymous
  `/auth/status` still returns 401. Wrong-mode endpoints fail closed. Account
  login/unlock forms clear submitted state, and each sensitive action opens an
  accessible existing-Dialog-based password form (including inside export's
  dialog). Cancel/security reset rejects pending verification. Recovery renders
  confirmed replacement-password fields, and passkey-only controls are hidden.
  The setup page has modest responsive spacing, selected-method explanation,
  three-step progress, validation guidance and private recovery handling.

### Verified API evidence

The parent supplied current React controlled-form and Vitest 4.1.12 guidance.
The exact installed official source
`/home/hieudm/go/pkg/mod/golang.org/x/crypto@v0.56.0/argon2/argon2.go:1-105`
was read before implementing `IDKey`; its documented RFC 9106 second
recommendation is the selected fixed cost. No new dependency is needed.
Local Dialog wrappers were inspected before reusing them. Browser APIs reuse the
existing runner and installed official Playwright type/documentation source at
`/var/www/code/php/dispatcher/node_modules/playwright-core/types/types.d.ts`.
The full shared-service README was read; there was no local-launch fallback.

## Task1 independent BLOCK findings integrated here

The parent verified three findings against immutable Task1 source. Prior passing
Task1 suites did **not** cover them. Corrections are part of this Task2 diff,
not retroactively claimed as Task1 acceptance:

1. **Custom legacy omitted DB:** decoding every existing unmarked config with
   omitted `db_path` retains `/var/lib/warden/warden.db`, irrespective of pathname.
   Fresh init always writes explicit home storage. Loader/draft tests use custom
   safe config files; init's injected storage checker verifies the resolved legacy
   name then checks a disposable occupied DB, without reading/writing live
   `/var/lib` storage. Initialized custom config remains byte-identical.
2. **JSON aliases/duplicates:** canonical top-level and nested `security` keys
   are checked before the case-insensitive struct decoder; noncanonical,
   unknown or duplicate keys reject before init rewrite. This covers aliases
   beyond `initialization_draft`, and duplicate exact/equivalent keys. Parser,
   loader and init preservation tests establish the boundary.
3. **Publication barrier:** staged bytes still Sync/Close first. Unix publication
   uses exclusive Link initially / Rename for updates, then opens and Syncs the
   containing directory and propagates errors **before setup callback**. Windows
   uses sibling `MoveFileExW(MOVEFILE_WRITE_THROUGH)`, with REPLACE_EXISTING only
   for updates and no COPY_ALLOWED. Parent supplied official Microsoft docs:
   <https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-movefileexw>.
   Installed x/sys v0.47.0 `windows/syscall_windows.go:195` and
   `windows/types_windows.go:2050-2053` confirm wrapper/constants. This is evidence
   for the chosen primitive, not proof of native runtime/power-loss behavior.
   Injected final-barrier failure prevents setup, and a positive-ordering test
   observes durable-publication call before the callback. Store DB code is unchanged.

## Actual RED → GREEN chronology

Private evidence root: `/var/tmp/warden-task2-evidence/`. Logs contain actual
results; the representative excerpts below are not synthetic expected output.
All Go commands used `TMPDIR=/var/tmp`. Compile failures are explicitly labeled.
Tests added after implementation to deepen coverage are **not** presented as
initial RED tests.

### Crypto

```sh
TMPDIR=/var/tmp go test ./internal/crypto -run TestAccountEnvelope -count=1
```

RED (`crypto-red.log`), exit 1: compile failures for absent `WrapPassword`,
`AccountEnvelope`, `ValidUsername`. Implemented the password envelope, then the
identical command GREEN (`crypto-green.log`):

```text
ok  warden/internal/crypto  0.241s
```

Assertions cover serialized nonplaintext, round-trip, wrong/exact-spaces password,
vault/credential binding, version/purpose/ciphertext/salt tamper, forbidden KDF
costs, randomization and username/password bounds.

### Configuration and selector

```sh
TMPDIR=/var/tmp go test ./internal/config -run TestAuthMethod -count=1
TMPDIR=/var/tmp go test ./cmd/warden-server -run TestInitAuthentication -count=1
```

First RED (`config-red.log`): compile failures for absent `AuthMethod` /
`AuthenticationMethod`; GREEN `ok .../internal/config 0.002s`.
Selector RED (`init-auth-red.log`): `new default: &{AuthMethod: ...} <nil>` instead
of account. Implemented the init-only default/prompt and legacy saved-default
handling. GREEN (`init-auth-green.log`): `ok .../cmd/warden-server 0.337s`.
Existing successful init fixtures were updated to answer the added prompt;
prefix/draft failure fixtures retain their original assertions.

### Setup account confirmation

```sh
TMPDIR=/var/tmp go test ./internal/server/setup -run TestAccountSetup -count=1
```

RED (`setup-red.log`): compile failures for absent account/mode installation
fields. Added additive account record, mode-aware routes, bounded unlocked-mutex
password preparation and shared final confirmation. GREEN (`setup-green.log`):
`ok .../setup 0.145s`. This test serializes the real prepared installation,
consumes it as `Installation`, unwraps its envelope and proves no commit before
correct recovery re-entry; password-confirmation and wrong-proof failures do
not publish. Later noncommit/admission tests are additional characterizations,
not a separate initial RED.

### Runtime login/unlock/fresh/recovery

```sh
TMPDIR=/var/tmp go test ./internal/server/runtime -run 'TestAccount(Runtime|Recovery)' -count=1
```

RED (`runtime-red.log`): both lifecycle/recovery tests failed with
`incompatible initialized storage or RP/origin` before account mode was supported.
Implemented mode validation, mode-aware active credentials, method discovery,
account login/unlock/fresh/reset, admission and recovery integration. Identical
command GREEN (`runtime-green.log`): `ok .../runtime 0.911s`.

The tests carry actual random password envelopes through raw installation JSON,
login/unlock, a fresh single-use export grant, lock/logout, new locked Plane/Vault,
actual pairing/approval/client request, recovery proof/unlock, restricted access,
failed reset, same-DEK reset, old session/client revocation and old/new passwords.
Additional deterministic hook-based characterizations cover 15 combinations of
in-flight login/unlock/fresh against lock/logout/identity replacement/recovery
reservation/cancellation, reset cancellation/abort after KDF, admission before
body reads, malformed identities and recovery abort preservation. These were
added after the minimal behavior passed and are not claimed as initial RED.

### Frontend

```sh
cd web
NODE_ENV=test ./node_modules/.bin/vitest run src/auth/account.test.tsx src/setup/account.test.tsx
```

An earlier invocation inherited `NODE_ENV=production` and failed to collect tests
with Vite's `node:crypto` browser externalization (`No such built-in module:
node:`). That is not behavioral RED. With the explicit test environment, actual
RED (`web-red.log`): **4 failed**, including missing
`authenticationMethod`, setup showing `Register the owner passkey` instead of
`Create your owner account`, missing Username form and absent account state.
Implemented the account branches/forms and new-per-action password requester.
GREEN (`web-green.log`): **2 files, 4 tests passed**. No navigator credential/PRF
calls are allowed by those test doubles. Existing passkey mocks were taught the
new real method-discovery response, not allowed to infer account mode.

The password modal reuses existing local Dialog components to preserve focus
stacking when an existing export dialog requests fresh verification; production
browser coverage below exercises the nested path. Secrets reset on submit,
cancel and security epochs. No local/session storage password cache was added.

### Independent Task1 findings

```sh
TMPDIR=/var/tmp go test ./internal/config -run TestCustomLegacy -count=1
TMPDIR=/var/tmp go test ./internal/config -run TestServerCanonicalKeys -count=1
```

RED (`review-config-red.log`): custom legacy runtime got the home DB default,
not `/var/lib/warden/warden.db`. Separate RED (`review-alias-red.log`):
`draft alias accepted {"Initialization_Draft":true,"security":{}}`.
After decode corrections:

```sh
TMPDIR=/var/tmp go test ./internal/config -run 'Test(CustomLegacy|ServerCanonicalKeys)' -count=1
# ok warden/internal/config 0.006s (review-config-green.log)
```

A no-op injection seam was introduced without changing publication behavior,
then the barrier tests were run **before** calling/implementing the barrier:

```sh
TMPDIR=/var/tmp go test ./cmd/warden-server -run 'TestInit(CustomLegacy|Canonical|Publication)' -count=1
```

RED (`review-init-red.log`): both `failure` and `ordering` subtests failed
`setup before durability barrier`. Implemented platform publication and barrier
call/error propagation. Identical command GREEN (`review-init-green.log`):
`ok .../cmd/warden-server 0.020s`. The custom-path/alias init caller tests were
already GREEN after the decoder fixes; they are not represented as initial RED.
An existing error-string test initially failed because the new canonical parser
omitted `unknown field`; retained that existing diagnostic contract and reran.

### Self-reviewed publication/logout ordering

```sh
TMPDIR=/var/tmp go test ./internal/server/runtime -run TestLogoutSerializesWithCredentialPublication -count=1
```

RED (`logout-red.log`): `logout revoked during serialized credential publication`.
Added the same mutex around logout revocation (not around vault lock/drain).
Identical command GREEN (`logout-green.log`): `ok .../runtime 0.750s`.
The test holds the publication mutex, starts logout, proves revocation waits,
then releases it and verifies successful session deletion.

Account audit allowlist was separately RED (`audit-red.log`, route returned empty
operation) then GREEN (`audit-green.log`, `ok .../runtime 0.003s`) using:

```sh
TMPDIR=/var/tmp go test ./internal/server/runtime -run TestAccountAudit -count=1
```

Only exact server-owned route names are admitted, never password/body/raw paths.

### Composed production-binary account path

```sh
TMPDIR=/var/tmp go test ./internal/server/runtime -run '^TestAccountSecurityLifecycleHTTPS$' -count=1
```

RED (`account-https-red.log`): `setup registration/begin: 403`; the shared
production fixture still attempted passkey setup in configured account mode.
This RED is **composition/fixture coverage**, not claimed as a new initial
production-code RED. Added the real account producer branch while retaining the
existing passkey branch. One intermediate run mistakenly unlocked inside the
shared client restart callback and correctly failed `server restart did not
lock`; fixed the fixture callback, not the runtime/assertion. GREEN
(`account-https-green.log`): production init/login+unlock/export/lock/logout/
restart/CLI pairing+revocation/password recovery PASS, `ok .../runtime 3.876s`.

The expanded runner keeps the old passkey command and adds a distinct exact
account test with a `-list` existence guard. The whole `scripts/test.sh` was not
run because it reinstalls dependencies; its relevant tests/build/binary paths and
Python contract checks were executed directly without installing anything.

## Broader validation and browser artifacts

The full Go suite passed repeatedly, including after the final backend fixes,
additional boundary tests and stable latest production assets (25 packages `ok`,
model/migrations no test files). Six-package race checks also passed twice on
current backend source. The final UI-only device-approval wording change was
followed by fresh web/build/browser, full Go, composed-binary, vet and Windows
compile checks. Final log results:

```sh
TMPDIR=/var/tmp go test ./... -count=1
# go-all-current.log: runtime 32.847s; config .010s; server cmd .472s;
# setup 2.916s; crypto .631s; all 25 tested packages ok.
TMPDIR=/var/tmp go test ./... -count=1 -json
# go-current.jsonl: 2069 passing test/subtest terminal events, 5 skips, 0 failures.
TMPDIR=/var/tmp go test -race ./internal/crypto ./internal/config ./cmd/warden-server ./internal/server/setup ./internal/server/runtime ./internal/store -count=1
# go-race-final.log: crypto 3.683s; config 1.045s; server cmd 3.535s;
# setup 7.080s; runtime 132.849s; store 52.871s; all six ok.
TMPDIR=/var/tmp go vet ./...
TMPDIR=/var/tmp GOOS=windows GOARCH=amd64 go test -c ./cmd/warden-server -o /var/tmp/warden-task2-evidence/warden-server.test.exe
PYTHONDONTWRITEBYTECODE=1 python3 scripts/test_integration_runner.py
git diff --check
```

Vet, Windows cross-compilation and whitespace checks exited 0. Python runner
contracts passed all four checks (`runner-contract-final.log`). Web final checks:

```sh
NODE_ENV=test npm --prefix web test
NODE_ENV=production npm --prefix web run build
```

**19 Vitest files / 283 tests passed; 13 node distribution tests passed, zero
skips.** TypeScript and production Vite build passed; `verify-dist: ok`.
The existing >500 kB management chunk warning remains, not a build failure.
Generated `internal/web/dist/` stays ignored and was not committed.

After a stable production build, actual trimmed `warden` and `warden-server`
executables were built under the private evidence `bin/` directory and passed:

```sh
WARDEN_ACCEPTANCE_BIN=/var/tmp/warden-task2-evidence/bin TMPDIR=/var/tmp \
  go test ./internal/server/runtime -run '^Test(AccountSecurityLifecycleHTTPS|SecurityLifecycleHTTPS)$' -count=1 -v
# composed-current.log: account PASS 3.61s, passkey PASS 2.75s,
# ok warden/internal/server/runtime 6.372s
```

Production account composition uses the real controlling PTY, CSPRNG terminal
password, pinned disposable private-CA HTTPS, actual binary init/serve/CLI,
ordinary cookies/CSRF, restart and same-DEK password replacement. It has no
WebAuthn/PRF substitute. Shared agent graph/clock substitutes remain explicit in
the CLI TTL portion; no real remote SSH operation is claimed.

Browser commands used only the documented shared global Chromium, no installs
or local-launch fallback:

```sh
WARDEN_ACCOUNT_ARTIFACTS=/var/tmp/warden-task2-evidence/account-browser-current \
  node web/e2e/account-lifecycle.cjs
WARDEN_UI_ARTIFACTS=/var/tmp/warden-task2-evidence/passkey-browser-current TMPDIR=/var/tmp \
  node web/e2e/ui-privacy.cjs
```

Account browser PASS: temporary setup, saved recovery re-entry, login+unlock,
modal fresh export inside existing export dialog, new-password entry on every
fresh action, recovery rotation/re-entry, global lock/re-unlock, locked restart,
logout, restricted account recovery, password replacement and normal login.
It traps **any** `navigator.credentials` access, checks none occurred, verifies
no passkey/fresh-WebAuthn requests and no CSP/page errors. It uses real production
assets and production Run fixtures, not seeded sessions or response mocks.
Screenshots include welcome, account form, recovery, login, management, fresh
verification, lock and recovery replacement. Trace/video are present. The setup
form screenshot was visually inspected for modest polish.

**Retained failed browser attempt:** `passkey-browser-final.log` failed the strict
network gate on a `GET /auth/passkeys/list` `net::ERR_ABORTED` during `lock`.
`passkey-browser-final/failure.json` records status=null/unfinished for that
request, plus independently confirmed locked/logged-out server state and zero
CSP/page errors. This run was alongside other validation processes. The same
unchanged runner passed before (`passkey-browser/`) and afterward standalone
(`passkey-browser-standalone/`, and again latest assets in
`passkey-browser-current/`). No gate/assertion was relaxed and no speculative
production fix was made. Cancellation during the view's lock-transition fetch
is observed; exact scheduling/root cause and flake elimination are **not proven**.
A passing rerun is not a fix or waiver. Parent should review this retained risk.

All browser artifacts are under private 0700 directories; account files are
0600. Traces/videos/recovery screenshots contain disposable secrets and must not
be published. HTTPS `ignoreHTTPSErrors` is exclusively the browser fixture's
self-signed loopback exception, not system/browser trust mutation or production
trust proof. The final JSON full-suite run has exactly five skipped tests: setup's
`TestUIBrowserSetupFixture`, `TestUIBrowserAccountSetupFixture`; runtime's
`TestUIBrowserRuntimeFixture`, `TestUIBrowserAccountRuntimeFixture` (all four were
explicitly executed successfully by the browser runners); and agent's existing
`TestRuntimeUnixRejectsWrongOwner` (requires chown privilege on this non-root
runner). Native Windows build-tagged tests are not executable on Linux, not
passed checks. No test failure occurred in this final full-suite run.

## Changed source files

- Init/config: `cmd/warden-server/{init.go,init_config.go,init_config_unix.go,init_config_windows.go,init_auth_test.go,init_review_test.go,init_draft_test.go,main_test.go}`;
  `internal/config/{config.go,setup.go,canonical.go,auth_method_test.go,legacy_alias_test.go}`.
- Crypto: `internal/crypto/{account.go,account_test.go}`.
- Setup: `internal/server/setup/{setup.go,account.go,account_test.go,account_boundaries_test.go,ui_privacy_test.go}`.
- Runtime: `internal/server/runtime/{plane.go,identity.go,concurrency.go,recovery.go,audit.go,account.go,account_test.go,account_boundaries_test.go,account_recovery_boundaries_test.go,account_logout_test.go,account_audit_test.go,account_tls_test.go,security_lifecycle_test.go,ui_privacy_test.go}`.
- Frontend: `web/src/setup/{setup.ts,setup-view.ts,main.ts,setup.css,account.test.tsx}`;
  `web/src/auth/{auth.ts,auth-gate.tsx,security-view.tsx,devices-view.tsx,account.test.tsx,auth.test.tsx,security.test.tsx}`;
  `web/e2e/account-lifecycle.cjs`; the three version fields in
  `web/{package.json,package-lock.json}`.
- Runner/docs: `scripts/test.sh`, `README.md`,
  `docs/{configuration.md,initialization.md,security.md,cli.md,deployment.md,development.md}`,
  the approved resumable-account plan, the historical Task1 report's review-status
  correction and this Task2 report. Generated assets/private evidence are not
  repository changes.

## Self-review and remaining checks

Inspected backend/frontend diffs and new envelope/account code; verified no
password in saved answers/installation serialization, no fake passkey, no new
dependency graph, no unguarded account recovery/management bypass, and no KDF
inside the publication mutex. Verified CAS/revocation and delivery-lease ordering,
including abort during reset and logout serialization. Inspected real setup
screenshot. Fresh per-test contexts and disposable fixtures are cleaned; browser
service is intentionally left running. No secret-bearing browser artifacts are
in the repository.

Open acceptance: parent and independent security review (including Task1 BLOCK
corrections), the retained passkey browser cancellation failure, native Windows
publication/ACL behavior, real power-loss/filesystem durability, genuine PRF with
production certificate trust, live proxy/trust behavior, and hosted release
provenance/signing remain separate/unproven. Go/JS buffer clearing is best effort;
strings/GC/Argon2 internals cannot promise secure erasure. No general production
security or release acceptance is claimed. Stop after bounded Task2; parent owns
review, further decisions and any Git/publication operations.
