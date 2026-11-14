# T1 initialization implementation checkpoint

Session `01a1da56-9b75-7503-b4c7-e65fa6163746`; branch
`hieudmg/security-hardening`, unchanged base/HEAD
`c10435358456dda0c1044fa5606b6ab5af014eef`.

**Implemented initialization only. This is not M1, normal management, or a
completed security-hardening release.** T1's genuine PRF-capable authenticator
positive HTTPS/browser acceptance remains pending. No T2/T3 runtime/login or
management operations were added. Normal serve deliberately fails closed even
for initialized storage. Plan checkboxes remain unchecked while acceptance is
pending.

## Runnable commands

See [the setup runbook](../../initialization.md) for the exact prompts, config
shape, TLS/proxy boundary, recovery confirmation and storage-preservation rules.

```sh
npm --prefix web run build
go build -o /tmp/warden-server-t1 ./cmd/warden-server
/tmp/warden-server-t1 init --config /your/fresh/private-directory/server.json
```

Use an actual controlling terminal, a trusted HTTPS public origin and either
certificate/key paths or a same-host HTTPS proxy with literal-loopback backend.
Do not use real existing storage for a trial. Setup exits after commit; `serve`
will not start management at this checkpoint. Never reset/delete old storage to
make it start.

## Implemented outcome and interfaces

- CLI `init`: interactive config/storage/origin/RP/TLS-or-proxy prompts, private
  exclusive nonsecret config creation/reuse, no disk master-key loading. A
  conflicting existing config is not silently accepted/overwritten.
- Password: CSPRNG eight symbols from exactly
  `23456789ABCDEFGHJKLMNPQRSTUVWXYZ`, controlling-terminal only. Bind-ready time
  fixes the 15-minute deadline, including password generation, blocked terminal
  output, slow requests and verification. Failed bind/RNG does not disclose a
  password. Global wrong-password cap20, rate1/second/burst5; no IP-indexed state.
- Setup only: embedded `setup.html` and its generated dependency graph plus
  `/api/v1/setup/*`. Normal SPA/API/report/profile/transport/export/import routes
  are absent. Host, exact single Origin, JSON and CSRF gates; Secure/HttpOnly/
  SameSite=Strict host-only setup cookie. Eight concurrent request slots, 64-KiB
  bodies and one pending ceremony (stricter than general-runtime challenge caps).
- Registration and a separate signed assertion: required UV, resident credential,
  no identifying attestation policy, exact configured RP/origin, enforced
  five-minute ceremony expiry, context/purpose/owner/credential binding, consume
  on finish attempt and no replay. Expiry is also checked after verification.
  Expiry/cancellation closes sockets without waiting behind verifier work.
- Browser PRF: creation may return only capability; always perform follow-up get
  with stored raw `prf_input` as `eval.first`, without double domain separation.
  Independently submit the signed assertion. Serialize no generic client extension
  results/PRF output to the server. Required missing PRF fails before preparation.
- Browser WebCrypto: random DEK32, HKDF-SHA-256/non-extractable AES256-GCM KEK,
  exact version1 positional JSON AAD, fresh IV12/tag128, strict canonical encodings
  and lengths. Test passkey wrap/unwrap before key-check preparation.
- Recovery: random root32, separate wrap/auth HKDF labels, SHA256 auth verifier.
  Display/save, hide, manually re-enter, unwrap locally, submit derived auth proof
  and recovered DEK against fixed pending verifier/key-check. Checkbox-only,
  wrong re-entry or wrong recovered DEK cannot finalize. Raw recovery root and PRF
  never leave the browser. Buffers/references are cleared best effort.
- Persistence: one SQLite `installation` row (`singleton=1`, `format=1`, typed
  JSON identity) created in a transaction in a private sibling staging DB, synced,
  then exclusively hard-linked to the absent target. Marker, owner/credential,
  wrappers, recovery verifier and authenticated key-check are published together.
  No raw DEK/PRF/recovery root/auth subkey/resume-unlock token is persisted.
  OS-owned sidecar lock excludes concurrent initializers and releases on crash;
  target publication cannot replace existing storage. Prepublication crashes may
  leave private staging files and nonsecret config/lock, never an initialized
  target; retry is explicit, without automatic artifact deletion.
- Normal serve: no SQLite open/migrations/pragmas/WAL/chmod/key read at all.
  Refusal preserves DB/WAL/SHM/config/key bytes and modes and explains fresh init
  or old-release export/retained rollback artifacts. Export format1 is unchanged.

Setup endpoints are POST-only JSON under `/api/v1/setup/`: `password`,
`registration/begin`, `registration/finish` (returns pending assertion/options and
public wrapping inputs), `assertion/finish`, `prepare`, `finalize`. Preparation
consumes the assertion-authorized key-delivery phase within60s; recovery saved
confirmation is restricted to the original setup lifetime. Setup authorization
never provides managed-data access.

### Downstream T2/T3 handoff

- `auth.Owner`/`auth.Verifier` verify identity without any vault codec or DEK.
  Production `setup.Run` always creates the real verifier. Injection is through
  unexported test seams, not config, flags, environment or HTTP bypasses.
- `setup.Installation` is the persisted typed JSON format. `store.ReadInstallation`
  is an immutable, read-only **T1 DELETE-journal** metadata reader; it refuses
  journal sidecars rather than ignoring newer state. T2 must supply its live
  metadata reader when it introduces runtime writes/WAL, validate the complete
  record and compare configured RP/origin before serving. Do not use the T1
  immutable reader for a live WAL database.
- `crypto.Wrapper`, `Derive`, `Decode`, `NewKeyCheck`/`Verify` and shared test vectors
  define the v1 crypto contract. Key-check purpose/AAD is source-defined separately
  from wrappers; it authenticates a supplied DEK but cannot recover it.
- There is **no runtime vault owner/session/login/unlock/management gate yet**.
  Do not reopen the old key-file serve path to finish T2. T2 must start locked,
  authenticate independently and require a fresh verified grant plus key-check.
  T3 owns management security/recovery replacement and M1 demonstration.
- Init creates only the identity table, no managed-table migration. Future
  initialized-store opening/import must preserve this identity; existing export
  `warden-data` version1 is retained for T5, not extended here.

## Test-first evidence

The append-only checkpoints in
`.superpowers/sdd/2026-11-14-security-hardening-7c97840ce693/ledger.md` record
commands and observations at the time, before implementation. Initial missing
new APIs produced compile/import REDs; review regressions produced actual
incorrect-result REDs. Additional already-green boundary characterizations are
explicitly labeled as such, not retrospectively described as RED.

| Focused test/command (before its production edit) | Observed RED | Subsequent GREEN |
| --- | --- | --- |
| `go test ./cmd/warden-server -run '^TestServeRefusesUninitializedAndLegacyWithoutMutation$' -count=1` | Old disk-key loading/no init-export refusal guidance | PASS after removing old serve startup |
| `go test ./internal/crypto -run 'TestWrapContractAndRecoverySavedRoundTrip\|TestVaultKeyCheckHasNoKeyFallback' -count=1` | Missing wrapping/key-check APIs | PASS |
| `go test ./internal/config -run '^TestSetupHTTPSAndProxyConfiguration$' -count=1` | Missing config type; later noncanonical443 accepted | PASS after each bounded change |
| `go test ./internal/store -run 'TestInitRefusesInitializedAndConcurrentInit\|TestSetupFinalizeAtomicSingleWinner' -count=1` | Missing reservation/publication APIs | PASS |
| `go test ./internal/server/auth -run '^TestCeremonyRealSignedFixtures$' -count=1` | Missing real verifier adapter | PASS with actual ECDSA-signed fixtures |
| `go test ./internal/server/setup -run 'TestInit\|TestSetup' -count=1` | Missing setup handler APIs | PASS |
| `(cd web && NODE_ENV=test ./node_modules/.bin/vitest run src/setup/vault-wrap.test.ts)` | Missing helper; later unknown envelope field decrypted | PASS; final4 tests |
| `(cd web && NODE_ENV=test ./node_modules/.bin/vitest run src/setup/setup.test.tsx)` | Missing setup client, then missing view at separate UI step | PASS; final4 tests |
| `node --test web/scripts/verify-dist.test.mjs` | Missing setup graph allowlist export | PASS;13 tests |
| `go test ./internal/web -run '^TestEmbeddedSetupDependencyAllowlist$' -count=1` | Missing setup-only filesystem | PASS |
| `go test ./cmd/warden-server -run '^TestInitHelpAndPromptedConfiguration$' -count=1` | Missing prompt/command | PASS |
| `go test ./internal/server/setup -run 'TestInitFailedBindDisclosesNoPassword\|TestInitRejectsRedirectedTerminal' -count=1` | Missing runtime | PASS |
| `go test ./internal/server/setup -run '^TestProductionSetupHTTPSAtomicExitAndLockedRestart$' -count=1` | Missing private runtime test seam | PASS: real TLS/SQLite with fake ceremony boundary |
| `go test ./internal/server/setup -run '^TestInitListenerFailureExitsImmediately$' -count=1` | Listener failure waited for context timeout | PASS |
| `go test ./internal/server/setup -run '^TestSetupRejectsAmbiguousOriginAndPlainDirectTransport$' -count=1` | Duplicate Origin accepted200 | PASS |
| `go test ./internal/server/setup -run '^TestSetupCloseDoesNotWaitForBlockedCeremony$' -count=1` | Close blocked behind ceremony mutex | PASS |
| `go test ./internal/server/setup -run '^TestInitExpirationDoesNotReportInitialization$' -count=1` | Expired setup reported success | PASS |
| `go test ./internal/store -run '^TestInitProcessCrashBoundaries$' -count=1` | Missing private staging boundary helper | PASS: subprocess before/after publication |
| `go test ./cmd/warden-server -run '^TestInitConfigPrivateReusableAndNeverSilentlyReplaced$' -count=1` | Conflicting existing config silently accepted | PASS |
| `go test ./internal/server/setup -run '^TestInitDeadlineIncludesBlockedTerminalOutput$' -count=1` | Blocked TTY extended lifetime | PASS |
| `go test ./internal/server/setup -run '^TestInitReadyDeadlineDoesNotMoveDuringPasswordGeneration$' -count=1` | Injected16-minute generation moved deadline/disclosed stale password | PASS |
| `go test ./internal/server/setup -run '^TestSetupCeremonyExpiryCheckedAfterVerification$' -count=1` | Registration/assertion completing after5-minute expiry accepted200 | PASS |

Additional coverage includes real old-schema encrypted SQLite with real WAL/SHM
preserved byte-for-byte/mode-for-mode; canceled/constraint-failed transactions,
concurrent single winner, process crash/retry/refusal; independent assertion before
key-check, expired/disconnected/failed finalization; registration owner/purpose/
UV/origin/RP/expiry/crossOrigin/duplicate and assertion signature/userHandle/
unknown-ID/encoding/trailing-JSON/raw-PRF negatives. Shared passkey and recovery
vectors independently generated with Node WebCrypto fix AAD, KEK, ciphertext,
recovery-auth and verifier bytes across Go and JS. PRF is mocked in client tests:
**these are not genuine authenticator PRF compatibility evidence**.

## Final checks and limitations

Toolchains: Go `go1.25.14 linux/amd64`; Node `v26.12.1`; npm `11.20.0`.

| Command/check | Final result |
| --- | --- |
| `go test ./cmd/warden-server ./internal/config ./internal/crypto ./internal/store ./internal/server/... ./internal/web` | PASS |
| `go test -race ./cmd/warden-server ./internal/config ./internal/crypto ./internal/store ./internal/server/... ./internal/web` | PASS |
| `go vet ./...` | PASS |
| `npm --prefix web run build` | PASS; existing large management-chunk warning, not setup dependency |
| `NODE_ENV=test npm --prefix web test` | PASS:15 files/230 Vitest tests +13 asset-verification tests |
| `go build -o /tmp/warden-server-t1 ./cmd/warden-server` | PASS |
| `GOOS=windows GOARCH=amd64 go build -o /tmp/warden-server-t1-windows.exe ./cmd/warden-server` | PASS; compile only, **not native Windows evidence** |
| `go build -o /tmp/warden-server-t1 ./cmd/warden-server && python3 /tmp/warden-t1-tty-check.py` | PASS actual Linux controlling PTY; no password in redirected stdout/stderr/HTTP, setup-only routes, SIGTERM exit, no preconfirmation DB/key, config0600 |
| `go test ./...` | FAIL only known untouched SFTP `TestPosixRelMatchesFilepathRel`: `".."` versus `"../."` |
| `git diff --check -- ':!mise.toml'` | PASS for tracked diff; new task files also checked separately before handoff |

An early mistaken `npm --prefix web test -- --run ...` invocation ran the full
shell-script suite under inherited `NODE_ENV=production`; old React tests failed
with missing `React.act`. Focused commands were corrected to direct Vitest with
`NODE_ENV=test`; final full suite above passes. This was not fixed by weakening
existing tests. Ephemeral logs: `/tmp/warden-t1-web-final.log`,
`/tmp/warden-t1-go-final.log`; durable facts are in this report/ledger.

Still pending: genuine PRF-capable authenticator positive HTTPS/browser ceremony,
native Windows execution/TTY/ACL/privacy, full production-browser CSP/network
acceptance, later runtime/M1 and T15 dependency-vulnerability work. Linux
cross-builds, signed fixtures, mocked PRF and WebCrypto vectors do not replace
these proofs. Do not advertise provider/browser compatibility or a completed
security release. No real databases, migrations, services or deployment used;
all DB fixtures/storage and certificates were disposable.

### Third-party evidence before integration

Selected maintained verifier `github.com/go-webauthn/webauthn v0.17.4`, whose
README supports Go1.25 and whose go.mod requires Go1.25. Its dependency toolchain
directive is not inherited. Latest v0.18.2 requires Go1.26; no silent toolchain
bump. Official selected-version source under
`/home/hieudm/go/pkg/mod/github.com/go-webauthn/webauthn@v0.17.4/` was inspected for
types, registration/options, login/ownership/UV/expiry/origin/backup/counter and
credential serialization. Context7 initial/refresh evidence was supplementary.
SQLite `modernc.org/sqlite v1.57.0` official installed `sqlite.go`, `driver.go`,
`conn.go`, `tx.go` confirmed URI, transactions, commit/rollback and read-only
behavior before new calls. x/sys v0.47.0 OS-lock declarations and x/term v0.45.0
IsTerminal source were checked; x/net publicsuffix graph-selected v0.57.0 is now
directly used. x/crypto remains v0.55.0, not downgraded. Normative WebAuthn3 PRF and
WebCrypto HKDF/AES-GCM standards and installed Vite8.2.2/Vitest4.1.11 declarations
were inspected. These are API evidence, not vulnerability-clearance claims.

## Bounded T1 review fixes — relative SQLite paths and JSON fixtures

Both findings were reproduced against Go `go1.25.14 linux/amd64` and pinned
`modernc.org/sqlite v1.57.0` before changing the faulty behavior. This follow-up
changes only `internal/store/installation{,_test}.go`,
`cmd/warden-server/main_test.go`, this report and the execution ledger.

### Exact URI evidence and P1 RED/GREEN

Before the production edit, inspected installed Go `src/net/url/url.go:877-919`
(`URL.String` writes `//` for a scheme/path with an empty host, then the escaped
path), `src/path/filepath/path_windows.go:55-67` (`Abs` uses native FullPath),
and SQLite v1.57.0 `conn.go:56-104` (file DSN retained, `SQLITE_OPEN_URI`).
SQLite `lib/sqlite_windows.go:86778-86855` rejects nonempty authorities other
than localhost and decodes percent escapes as filename bytes rather than query
delimiters; `:125041-125053` explicitly discards the initial slash in `/X:`
native drive paths. The corresponding shared URI parser at
`lib/sqlite_g_0000000000000003.go:72484-72509` has the same authority and escaping
rules. These are installed exact-source observations, not a native Windows run.

- RED: `go test ./internal/store -run '^(TestInstallationRelativePathsPublishAndRead|TestReadInstallationRelativePaths)$' -count=1`
  failed before the fix. Publication of `vault.db` returned
  `SQL logic error: invalid uri authority: . (1)`; `state/vault.db` returned
  `invalid uri authority: state (1)`. Independent reads of DBs published through
  absolute paths failed too: basename authority was
  `vault.db?mode=ro&immutable=1`, nested authority was `state`.
- Additional helper test RED: `go test ./internal/store -run '^TestSQLiteFileURL$' -count=1`
  failed to compile with `undefined: sqliteFileURL`; this is separate from the
  actual incorrect-result reproductions above.
- Fix: one `sqliteFileURL` resolves relative paths with native `filepath.Abs`,
  converts native separators and prefixes drive paths with `/`, then uses
  `url.URL.Path` for percent encoding. Staging and immutable reading both use it;
  the reader still sets exactly `mode=ro&immutable=1`. Hard-link exclusive
  publication, transactions, locks and sidecar refusal are unchanged.
- GREEN: `go test ./internal/store -run '^(TestSQLiteFileURL|TestInstallationRelativePathsPublishAndRead|TestReadInstallationRelativePaths)$' -count=1` PASS.
  Coverage includes basename/nested relative paths, spaces, `#`, literal `%25`,
  and Unix-legal `?mode=memory&_pragma=journal_mode(WAL)`-shaped filenames and
  directories. Publication/read-back reaches the intended physical file, cannot
  replace existing identity, and reading preserves bytes/modes/directory entries.
  Windows excludes `?` filesystem cases because it is not a legal native name.
  A lexical `/C:/...` encoding assertion runs on Linux; native drive assertions
  are present for future Windows execution, not claimed executed here.

### P2 test-fixture RED/GREEN

Extracted the existing concatenation unchanged into `serveRefusalConfigFixture`
so the existing preservation test and the new deterministic regression share
one fixture builder. Before correcting that builder,
`go test ./cmd/warden-server -run '^TestServeRefusalConfigFixturePreservesWindowsPaths$' -count=1`
failed: `invalid character 's' in string escape code` for `C:\state\warden.db`.
The builder now uses `encoding/json.Marshal`; the regression verifies exact
DB/key path round-trip. The same regression plus
`TestServeRefusesUninitializedAndLegacyWithoutMutation` passed with `-count=1`.
Existing DB/WAL/SHM/config/key bytes, modes and directory assertions are retained.
This is Linux serialization evidence for Windows-shaped input, not native
Windows execution or privacy/ACL evidence.

### Follow-up validation and unchanged limits

- `go test ./internal/store ./internal/server/setup ./cmd/warden-server -count=1` PASS.
- `go test -race ./internal/store ./internal/server/setup ./cmd/warden-server -count=1` PASS.
- `go vet ./internal/store ./internal/server/setup ./cmd/warden-server` PASS.
- Windows amd64 `go test -c` for store and server CLI PASS, outputs under
  `/tmp/warden-t1-review-{store,cli}.test.exe`; compilation only.
- Tracked diff whitespace and separate untracked review-file whitespace checks
  PASS; actual changed source reviewed. No dependency edits or new dependencies.

The earlier full-suite SFTP baseline is untouched and was not rerun for this
bounded follow-up. Genuine PRF-positive HTTPS/browser acceptance, native Windows
execution/TTY/ACL/privacy and production-browser CSP/network evidence remain
pending. No T2, normal serving, commit/push/deployment or worktree activity.
Protected `mise.toml` was not read or changed. Stop at T1.

## Changed paths / scope safeguards

- CLI: `cmd/warden-server/{main,main_test,init,init_test}.go`.
- Config: `internal/config/{config,setup,setup_test}.go`.
- Crypto: `internal/crypto/{wrap,wrap_test}.go`,
  `internal/crypto/testdata/{wrap-v1,wrap-recovery-v1}.json`.
- Verifier: `internal/server/auth/{ceremony,ceremony_test}.go`.
- Setup: `internal/server/setup/{setup,setup_test,runtime,runtime_test,runtime_tls_test}.go`.
- Persistence: `internal/store/{installation,installation_test,installation_unix,installation_windows}.go`.
- Assets: `internal/web/{embed,embed_test}.go`, `web/setup.html`,
  `web/src/setup/{main,setup,setup-view,vault-wrap}.ts`,
  `web/src/setup/{setup.test.tsx,vault-wrap.test.ts}`,
  `web/scripts/verify-dist{,.test}.mjs`, `web/{vite.config.ts,tsconfig.app.json}`.
  Generated ignored `internal/web/dist` rebuilt; its setup allowlist includes only
  setup HTML, setup JS and shared modulepreload helper, not management assets.
- Go module declarations/checksums: `go.mod`, `go.sum`.
- Docs: setup runbook, this report, linked security design/plan, execution ledger.

**No client-auth or local-agent implementation was touched.** At the owner's
mid-task steering, only future spec/plan T4/T10/T12/T17 and ledger were updated:
agent-owned memory-only API token/API requests, durable server hash/revocation,
no automatic token expiry/rotation/refresh, reapproval after agent restart, and
daemon alive until external termination in all authentication/pool states.
Logout/revocation/outage/restart/vault lock do not exit it; SSH graph eviction is
independent. Fake-clock lifetime acceptance and stolen-token-until-revocation risk
are documented. Disk IPC trust/discovery material remains separately allowed and
must never contain the API token. None of that policy is implemented by T1.

No source under `internal/client/`, `cmd/warden`, external transport or transfer
model changed. No release version bump (deferred to T17), stage/commit/push/PR,
tags/releases/deployment, live migration, automatic reset/delete or master-key
fallback. Protected `mise.toml` was never read, changed or staged. Sole writer;
no subagents or worktrees. Stop at this initialization checkpoint.
