# T7 — bounded transport graph resolution before secrets

## Scope and status

Implemented **T7 only** on `hieudmg/security-hardening`, starting at reviewed
HEAD `78e7931`. Sole writer, no children/worktrees, staging, commits, push,
publication, deployment or real-data operations. Protected unrelated `mise.toml`
was not read or edited. No dependencies, versions, frontend, external DB/proxy
transport, transfer schema/export, auth policy or T8 audit framework changes.

Read root `AGENTS.md`, the approved sibling design, T7 plan and chronological
ignored ledger before implementation. Prior T1–T6/T10 checkpoints are preserved.
This is an implementation/self-review checkpoint, **not independent acceptance,
M1 or a security release**. Genuine PRF-positive HTTPS/browser, production-browser
CSP/network and native Windows acceptance remain pending. No subsequent task is
authorized by this report.

## Exact contract and implementation

See [the security model](../../security.md#transport-graph-validation-and-budget-t7)
for user-facing examples and cancellation/snapshot semantics.

- `MaxResolutionOccurrences = 1024`: root = 1, plus each traversed profile
  reference, duplicates included. Reserve before lookup/recursive descent.
  A DB root and the complete SSH tunnel graph share one counter/transaction.
  Exactly 1,024 succeeds; attempting occurrence 1,025 fails with
  `ErrJumpBudgetExceeded` wrapped by `GraphError` before that lookup.
- Existing `MaxJumpDepth = 32` counts SSH nodes per path including SSH target;
  the DB root is not an SSH depth level. Depth 33 fails before lookup 33.
- Full reachable SSH structure is read and validated using metadata only;
  selected-key existence/SQL-NULL private-key presence is then validated for
  every SSH occurrence. No password/proxy/key field decrypts during these
  passes. Missing/archived/cyclic/malformed/deep/over-budget routes and
  missing/cleared key selections return no partial bundle or decrypted secrets.
- After validation, use the same snapshot to load profiles/pairs and construct
  the existing target plus deterministic postorder jumps. Duplicates remain
  duplicated in both work and output. No deduplication or jump-order change.
- Parse arrays incrementally rather than allocating all edges up front; retain
  only ID/key-ID references in the bounded postorder list. Graph errors contain
  fixed text and numeric IDs/limits, never raw JSON/decoder values.
- Existing handler mapping stays unchanged: `422 invalid_graph` for graph errors;
  generic `404 not_found` for initial missing and archived profiles (including
  tunnel targets/hops). Crypto failures still propagate as crypto/storage
  failures and return no partial bundle. T8's broad raw validation/audit cleanup
  remains untouched.
- Context checks precede snapshot acquisition, metadata lookups, recursive
  descent, edge/key validation, secret row loads and successful return. Context
  cancellation during validation means zero decrypt callbacks. Each started
  row's bounded synchronous field-codec work is not individually interruptible;
  no new goroutine/cancellation mechanism or SSH network guarantee is claimed.

For N <= 1,024 profile occurrences, there are N metadata profile queries, at
most one key-presence query per SSH occurrence, then N secret profile queries
and at most one secret pair query per selected SSH occurrence. Total row queries
are <= 4,096; field decrypt callbacks <= 5,120 (two SSH fields plus three key
fields; DB has only one). These bounds are not milliseconds, ciphertext byte
limits, whole-host memory ceilings or backend availability guarantees.

### Snapshot evidence and narrow store seam

The original `GetSSH` decrypted password/proxy fields immediately, `GetDB`
decrypted before resolving its tunnel, and separate live getters could observe
updated graph/key/archive rows. Existing runtime vault leases control key access
and response emission; they do not serialize profile CRUD/archive updates.

`Store.BeginResolution` now returns a narrowly scoped read snapshot exposing
metadata getters, key-presence checks and existing secret getters, all through
one `sql.Tx`, closed by rollback on every exit. The metadata SQL selects `NULL`
instead of ciphertext columns; key presence selects `private_key IS NOT NULL`.
The existing ordinary getter scanners/decrypt logic are reused through a
row-query-only internal interface, not a new datastore/policy abstraction.
Production `NewResolver(*store.Store)` and the bundle API are unchanged.

Pinned source inspected **before** the seam's transaction calls:
`/home/hieudm/go/pkg/mod/modernc.org/sqlite@v1.57.0/tx.go` (`newTx`, deferred
`begin` for ReadOnly; rollback/context interruption) and `conn.go` (`BeginTx`).
`ReadOnly` does not itself enforce SQL write denial in this driver; the exposed
seam provides reads only. The transaction uses normal owned WAL storage, not an
immutable URI, second database or exported snapshot file. Supplemental SQLite
WAL source documentation retrieved through Context7 after initial implementation
(`ctx7:docs:44c4b23a1a07d29632cc4476`, `wal.h`/reader mxFrame algorithm) confirms
that readers retain their first-read snapshot while writers append new frames.
It is supplemental, not relabeled preflight evidence. No third-party import or
dependency was added.

`TestResolutionSnapshotMetadataAndSecrets` deterministically interleaves an
active first-read snapshot with **committed** archive, route, password, DB-tunnel
and key-deletion updates via other WAL connections. Both later secret phases
still read the old validated rows; a live getter sees the committed new archive
and route. The real store field-codec spy sees zero decrypt callbacks for
metadata and the exact SSH/password/proxy/DB/private-key/passphrase AAD callbacks
during secret loads. This is measured snapshot consistency, not a speculative
claim that a runtime key lease freezes profile updates. A later archive does not
retroactively cancel a resolution already admitted against the earlier snapshot;
new resolutions see it. Existing response/vault lease semantics are unchanged.

## RED → GREEN evidence

Toolchain for every check below: `go1.25.14 linux/amd64`.
Logs under `/tmp/warden-t7-*.log` are ephemeral aids; commands/results here are
the durable record. No benchmark or wall-clock stopping condition substitutes
for operation counts.

### Actual behavioral RED before production edits

```sh
go test ./internal/server/profiles \
  -run '^TestResolve(DuplicateDAGCumulativeBudget|BudgetPreservesOrderAndDuplicates|InvalidGraphBeforeAnySecretDecrypt)$' \
  -count=1 -v
```

FAIL, `/tmp/warden-t7-red.log`:

- Eleven actual SQLite rows with repeated edges expanded into **2,047** profile
  occurrences: returned success with **2,046** jumps instead of a graph failure
  (`0.11s`, finite workload even on the unfixed resolver).
- Corrupted target password plus missing hop, archived target, archived hop,
  cycle or malformed route returned `decrypt password ... authentication failed`
  before structural validation. Corrupted DB password plus invalid tunnel
  returned `decrypt password ... invalid blob length 1` before the tunnel error.
- The exact nested duplicate order characterization already passed. It is not
  presented as a newly failing behavior.

Before adding the new store seam, this command failed compilation because
`Store.BeginResolution` was absent:

```sh
go test ./internal/store -run '^TestResolutionSnapshot' -count=1
```

`/tmp/warden-t7-store-red.log`. Likewise the bounded fake-getter counter tests
failed compilation before the private snapshot seam/budget sentinel existed
(`/tmp/warden-t7-counts-red.log`). These API-absence checks are **not** the actual
bug reproduction; the real-store behavioral RED above is.

### GREEN and deterministic assertions

```sh
go test ./internal/server/profiles ./internal/store \
  -run '^TestResolve|^TestResolutionSnapshot' -count=1 -v
```

PASS, `/tmp/warden-t7-green.log`, after implementing the budget/snapshot phases.
Extended passing coverage (not retroactively labeled RED) adds real corrupt hop
private keys, real SQLite 1,024/1,025 SSH and DB boundaries, safe transport/audit
mapping, key callbacks and cancellation boundaries:

```sh
go test ./internal/server/profiles ./internal/store \
  -run '^TestResolve|^TestResolutionSnapshot|^TestTransportGraphFailuresSafeClassification$' \
  -count=1 -v
```

PASS, `/tmp/warden-t7-focused-green.log` (the later full package runs also cover
the final real-store boundary test).

Key tests and measured assertions:

- `TestResolveDuplicateDAGCumulativeBudgetCounts`: depth-30 binary duplicate DAG
  would exceed a billion occurrences. Fake metadata getter has a hard failure
  at lookup **1,025**, independent of the resolver, so regression cannot expand
  indefinitely. Actual result: budget GraphError, **1,024** profile lookups,
  **0** secret loads/**0** real AEAD-decrypt callbacks, no partial bundle, snapshot
  closed. The eleven-row real-store test independently reproduces the old bug.
- `TestResolveBudgetPreservesOrderAndDuplicates{,Counts}`: `R -> [B,A,B]`,
  `B -> [A]` yields `[A,B,A,A,B]`, target separate; six profile metadata lookups,
  six secret loads and six password AAD decrypt callbacks.
- `TestResolveBudgetBoundaryDepthAndCancellation` and
  `TestResolveBudgetBoundaryRealStore`: exactly 1,024 total occurrences succeeds
  for SSH and DB; 1,025 rejects with at most 1,024 metadata profile lookups and
  no secret load. Depth32 succeeds; depth33 rejects after 32 lookups.
- Cancellation before work and after metadata lookups 1/19/1,024 for SSH,
  1/2/19/1,024 for DB: exact lookup counts, no subsequent lookup, no decrypt,
  no partial bundle, transaction cleanup. Pre-cancel does not open a snapshot.
- `TestResolveInvalidGraphBeforeAnySecretDecrypt{,Counts}`: corrupt password,
  private key/passphrase and DB password with missing, archived target/hop,
  cycle, depth, malformed, missing/cleared key and tunnel failures. Fake getter
  decrypts through the ordinary `crypto.Codec` callback with AAD-specific spies;
  zero actual callbacks on structural errors, not just an output assertion.
  Real SQLite counterparts also exercise corrupt password/private-key blobs.
- `TestResolveValidatedKeySecretsAndFailures`: healthy graph loads real AEAD
  private key/passphrase twice for duplicate hops (five decrypt callbacks,
  five secret loads); corrupt selected key on a valid graph invokes the real
  private-key callback and fails without a partial bundle or GraphError.
- `TestTransportGraphFailuresSafeClassification`: actual SSH/DB handlers return
  422/`invalid_graph` for budget and malformed numeric-exponent routes; supplied
  conversion-error marker appears in neither response nor persisted audit error.
  Existing archived generic-404 tests and key/AAD/import tests remain green.

## Final checks against current source

| Exact command | Result |
| --- | --- |
| `go test ./internal/server/profiles ./internal/store ./internal/server/runtime -count=1 -timeout=180s` | PASS, final profiles 2.046s/store 1.113s/runtime 18.922s; `/tmp/warden-t7-final-packages.log` |
| `go test -race ./internal/server/profiles ./internal/store ./internal/server/runtime -count=1 -timeout=180s` | PASS, final profiles 34.858s/store 17.228s/runtime 78.098s; `/tmp/warden-t7-final-race.log` |
| Repeated cancellation/count/snapshot command below | PASS, profiles 2.368s/store 6.574s; `/tmp/warden-t7-final-cancellation-race25.log` |
| `go vet ./...` | PASS; `/tmp/warden-t7-vet.log` |
| `go test ./... -count=1 -timeout=180s` | FAIL **only** unchanged SFTP `TestPosixRelMatchesFilepathRel`: `posixRel("a", ".") = ".."`, wanted `"../."`; `/tmp/warden-t7-full.log`. DB PASS (0.107s); prior intermittent DB failure remains unresolved, not fixed by this run. |

Exact repeated-count command:

```sh
go test -race ./internal/server/profiles ./internal/store \
  -run '^TestResolve(DuplicateDAGCumulativeBudgetCounts|BudgetBoundaryDepthAndCancellation|DBBudgetCancellation|InvalidGraphBeforeAnySecretDecryptCounts)$|^TestResolutionSnapshot' \
  -count=25 -timeout=180s
```

Closing self-review removed an unused test-spy hook and made the counted
selected-key fixture explicitly clear its password, matching stored
password/key-pair exclusivity (five actual callbacks, not seven). No production
change followed the full checks. Fresh checks after that test-only cleanup:

```sh
go test ./internal/server/profiles ./internal/store -count=1 -timeout=180s
go test -race ./internal/server/profiles ./internal/store -count=1 -timeout=180s
# Repeat the exact count/cancellation/snapshot command above, then:
go vet ./...
```

All PASS: profiles/store normal 1.729s/0.918s, race 31.003s/15.308s,
repeated race 2.163s/6.063s. Logs `/tmp/warden-t7-closing-{packages,race,cancellation-race25,vet}.log`.
The full repository/runtime results above preceded only this test-fixture cleanup,
not a later production change.

The complete runtime normal/race runs retain TLS/restart/client, vault lease,
response flush/abort/cancellation, fresh-action and T6 boundary/full-size tests.
No frontend/browser/native Windows/NGINX command was run for T7; no new evidence
for their pending acceptance is inferred. No external service/account was used.

## Bounded review follow-up — cancellation after secret loading begins

The independent review reported a **test gap, not a production defect**: prior
cancellation tests stopped in metadata validation. The owner authorized this
same-T7 follow-up on `78e7931`, paused it for the Hindsight upgrade after the
first test-hook edit, then resumed it. The paused instrumentation was explicitly
unformatted/untested and is not counted as passing evidence. Existing dirty T7
work was preserved; no staging, commits or protected-file access occurred.

This follow-up is **passing characterization, not TDD or a new production fix**.
Only `resolve_counts_test.go`, `store/resolution_test.go`, this report and the
ignored ledger changed. No retained production change, new graph policy or T8
work was needed.

### Additional deterministic coverage

`TestResolveSecretPhaseCancellation` has **20 cases**. Test-only hooks cancel
inside secret getters, either after the current row load or immediately after a
real ordinary `crypto.Codec.Decrypt` callback. The fixtures cover:

- SSH: all four loads (target, first hop, selected-key hop profile, private pair),
  and all four decrypt callbacks, including final private key/passphrase.
- Direct DB: its sole load/decrypt is both the first and final boundary; there is
  no intermediate load on a direct DB resolution.
- Tunneled DB: all five loads (DB, SSH target, first hop, selected-key hop profile,
  private pair), and all five decrypt callbacks.

Every case asserts `context.Canceled`, the **entire zero-value bundle**, exact
metadata/key-validation counts, and exactly one snapshot-close call. Secret
getter attempts are recorded **before** their context checks: an unwanted later
call still fails the test even if the fake getter would immediately reject it.
The attempted/completed load sequence must equal only the expected prefix. A
private-key callback may cancel while its already-started pair getter goes on to
decrypt the passphrase; the test explicitly permits that bounded synchronous
row completion and requires no subsequent secret getter. No crypto-call
interruptibility or response/network timing guarantee is inferred.

`TestResolutionSnapshotSecretCancellationCleanup` adds **five real SQLite/codec
cases**: SSH password, proxy password, DB password, private key and passphrase.
Metadata causes zero callbacks; cancellation comes from the actual field-codec
callback after SQL Scan. The already-started row completes normally, including
its remaining fields. All three later snapshot secret-getter calls reject with
`context.Canceled` without another crypto callback. After `Close`, a query on the
transaction yields `sql.ErrTxDone`. With the pool restricted to **one** connection,
a fresh connection can execute `SELECT 1` and return to `InUse == 0`.

This separates the evidence honestly: the resolver fake proves no partial output,
no later getter attempts and deferred closure; the real-store test proves
cancelled SQL snapshot disposal/pool-slot release. Context cancellation may have
already initiated automatic rollback, so the real-store test does not claim
which rollback/Close won. Its five-second probe context is only a test deadlock
safety bound, not a performance or synchronous-codec cancellation requirement.

### Passing baseline and isolated sensitivity check

```sh
go test ./internal/server/profiles ./internal/store \
  -run '^TestResolveSecretPhaseCancellation$|^TestResolutionSnapshotSecretCancellationCleanup$' \
  -count=1 -v
```

PASS immediately against unchanged production: profiles 0.006s/store 0.033s,
`/tmp/warden-t7-secret-characterization.log`.

An isolated mutation temporarily removed **only** the final `ctx.Err()` guards
before returning the SSH and DB bundles, then ran:

```sh
go test ./internal/server/profiles \
  -run '^TestResolveSecretPhaseCancellation$' -count=1 -v
```

Expected FAIL (exit 1), `/tmp/warden-t7-secret-mutation.log`: eight terminal
boundaries returned nonempty bundles (three SSH selected-key boundaries, two
direct-DB boundaries, three tunneled selected-key boundaries). Intermediate
boundaries still passed through their existing next-operation checks. This is
post-characterization **mutation sensitivity**, not a historical RED or a newly
discovered production bug.

The original file was backed up outside the checkout and restored under a shell
cleanup trap immediately after the test. All four production checksums matched
before further validation. Resolver SHA-256 before/after:
`d2154c8d7b1c529f49bf2e66dba5057ce00c66fc10f5e63c730c472ac84a2291`.
The checked manifest covers `profiles/resolve.go` and
`store/{profiles,key_pairs,resolution}.go`; no temporary mutation remains.

### Fresh checks after final test-only cleanup

Toolchain: `go1.25.14 linux/amd64`.

```sh
go test -race ./internal/server/profiles ./internal/store \
  -run '^TestResolveSecretPhaseCancellation$|^TestResolutionSnapshotSecretCancellationCleanup$' \
  -count=25 -timeout=180s

go test ./internal/server/profiles ./internal/store ./internal/server/runtime \
  -count=1 -timeout=180s

go vet ./internal/server/profiles ./internal/store
```

All PASS: focused race profiles **1.408s**/store **13.176s**; normal packages
profiles **1.708s**/store **0.956s**/runtime **17.597s**; scoped vet no diagnostics.
Logs `/tmp/warden-t7-secret-final-{race25,packages,vet}.log`. Earlier follow-up
race and normal checks also passed; the final commands supersede them.

Source/self-review and explicit formatting/whitespace/local-link/checksum checks
are recorded in the ledger. This follow-up did not rerun the full repository,
full-package race or external/browser/native checks; prior results elsewhere in
this report are historical, not newly established by the focused run. Known
SFTP/earlier intermittent DB and external acceptance limits remain unchanged.
No material implementation issue was found. Stop at bounded test-gap self-review
for independent rereview; no T8 or publication authority.

## Changed files and self-review

Production:
`internal/server/profiles/resolve.go`,
`internal/store/{profiles,key_pairs,resolution}.go`.
Tests:
`internal/server/profiles/resolve_{budget,counts}_test.go`,
`internal/store/resolution_test.go`.
Documentation:
`docs/security.md`, this report, narrow T7 checkpoint in the approved plan, and
`.superpowers/sdd/2026-11-14-security-hardening-7c97840ce693/ledger.md` (ignored).

Documentation-only TDD exception was declared before prose edits: these record
the exact implemented count definition/evidence, not application behavior;
strongest checks are source/test/diff inspection, whitespace/newline checks and
local-link verification. Reviewed current production diff and all new source
files for counter-before-recursion/lookup ordering, no decryption in metadata,
full graph/key validation before secrets, shared DB counter/transaction, snapshot
closure on all paths and unchanged output order/duplicates. Formatting, final
whitespace/local-link/scope/staging/branch checks are recorded in the ledger.

No archive persistence/import/exports/schema/AAD change, broad datastore
abstraction, external TLS, auth/recovery/response-lease change, or T8
implementation. Stop after T7 self-review. Recommended next: independent T7
review; retain external acceptance requirements and await separate authorization
before proceeding to T8.
