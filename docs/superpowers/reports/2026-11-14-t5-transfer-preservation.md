# T5 — v1 transfer preservation, refusal and rollback

## Bounded status

Implemented/tested/self-reviewed on `hieudmg/security-hardening`, reviewed
**HEAD `3ebf59e`**, unchanged. Sole writer. **No new importer was necessary:**
reviewed T3 already supports fresh-authorized documented v1 transfer into empty
managed tables. Current `internal/model/transfer.go` and
`internal/store/transfer.go` match historical `c104353` byte-for-byte. Retained
production edits are CLI help only; the rest is tests, synthetic provenance and
manual migration/rollback documentation. This is not independent acceptance,
M1, a security release, native Windows or a real-account migration.

No commits/staging/push/PR/deploy/worktrees/children, live account/DB operations,
version/dependency changes or protected `mise.toml` reads/changes. No old encrypted
DB compatibility, automatic deletion, export v2, TLS profile/schema/external
DB/proxy change, deadline/graph/audit hardening or broader storage abstraction.
T1–T4/T10 fresh/session/recovery/generation and checked response-lease semantics
are unchanged. Root AGENTS, binding spec, plan T5/migration boundaries, T3/T4
reports and the append-only execution ledger were read before implementation.

## Historical producer → fixture → current consumer

Source read with `git show c104353`: transfer models and profile types, historical
store exporter/importer, HTTP export serializer path and migrations 001–007.
The source schema has string transfer secrets, raw jump JSON **inside a string**,
DB arrays with `is_default`, separate notes, no project/note timestamps and
optional archive flags. Today's model/import code was not used to invent input.

`scripts/test-transfer-fixture.sh` extracts **historical** go.mod/go.sum and
store/model/crypto/migrations (no old tests) into `mktemp`. A retained test
constructor seeds actual old tables with direct SQL, encrypts explicit synthetic
values under explicit historical AAD, calls actual old `ExportData` and
`encoding/json.MarshalIndent`. This is the same model returned by the old HTTP
handler's `WriteJSON`. Only `exported_at` is frozen; all managed timestamps are
seeded nanosecond SQL values. It compiles/runs **only this test**, with
`GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off`. No old service/binary/network endpoint,
worktree, real data or fallback key loader is executed.

The constructor generated the fixture; default script execution regenerated and
**byte-compared** it against the retained JSON (PASS, also rerun after formatting).
Random-nonce source ciphertext artifacts are retained separately and decrypted
with the historical synthetic key by current preservation tests. Source/destination
keys differ. No source DEK is supplied to ImportData or the HTTP import endpoint.

| Artifact under `internal/store/testdata/` | SHA-256 |
| --- | --- |
| `export-c104353_test.go.txt` | `fe77cdac61fff6163919386c363b980947168511d4e95c3016204a3f96c722f7` |
| `warden-data-v1-c104353.json` | `732de3caaac4993b39baffcec6ea7c3328b3c620d91837e763ab9eefc8933337` |
| `ciphertexts-c104353.json` | `1d0376d350660cee5b8dfdd14164dad65e682a875ceea1b2d8aa719d2b2d7cf9` |

Counts: **2 groups, 2 key pairs, 3 SSH, 2 DB, 2 projects, 2 reports, 7 notes**.
Includes nullable/empty key fields, seven populated encrypted fields, plaintext
string secrets, proxy/default directory, active/archive flags, raw duplicate and
whitespace-bearing jump text, valid and dangling group/key/jump/tunnel refs,
nonfirst-default multdb settings, Unicode/empty/orphan/unknown/empty-type notes,
and hard project/report references. Full expected output comes from the actual
historical producer, not current implementation reflection. Checksums are also
asserted in store tests. See [fixture provenance](../../../internal/store/testdata/README.md).

## Evidence chronology: passing-existing vs actual RED/GREEN

### Passing-existing characterizations (NOT new behavioral TDD)

These tests passed current production code without a storage/auth/transfer fix:

- `TestVersion1ExportFixtureIntoInitializedEmptyVault`: fresh publication/open,
  distinct destination DEK, preexisting identity/session/client/audit; exact full
  decrypted re-export, every count, getters, IDs/timestamps/settings/relationships/
  notes/archive flags; successful import and nonempty refusal leave exact auth
  rows unchanged. The store-layer identity is intentionally opaque; the TLS test
  uses a complete real initialized installation instead.
- `TestVersion1ImportedSecretsUseDestinationKeyAndExactAAD`: old ciphertexts
  decrypt to destination values; destination stored blobs differ from old ones
  and plaintext. All seven secret fields decrypt only with destination DEK and
  exact resource/row/field AAD; old key, wrong row/field/resource and tag tamper
  reject with no partial plaintext. Empty fields remain empty/null as exported.
- `TestImportFailurePreservesIdentityAndManagedData`: second-encryption failure,
  late report SQL trigger, **actual COMMIT** deferred-FK constraint failure,
  context cancellation after earlier groups/encryption and hard report/project
  validation failure all leave zero managed rows and exact destination auth/audit
  unchanged. Each trial removes only its synthetic fault and retries successfully.
  COMMIT case explicitly requires the `commit import:` error, not merely any
  insertion error; no fabricated commit hook or new production seam.
- `TestConcurrentInitializedImportsSingleWinner`: codec rendezvous holds the first
  transaction after group writes with the SQLite writer lock. The overlapping
  contender sees no committed rows but cannot upgrade its read snapshot to a
  writer; it fails, then the reserved writer completes. Final complete fixture,
  no loser data, exact auth. Channels + safety context, no timing-based winner.
  This proves single-winner preservation, **not** a promised 409 for every race.
- `TestLegacyDBRefusalPreservesArtifacts`: absent, uninitialized SQLite, actual
  historical 001–007 encrypted live WAL without an identity marker, unknown
  schema, corrupt bytes, partial schema, partial/unknown identity and orphan WAL.
  Before/after complete directory entries, bytes and modes (including DB/WAL/SHM,
  synthetic config/master key/old binary) match. Init also refuses existing
  artifacts. Known old schema comes from unchanged historical migrations, not a
  current keyed Open pretending to be the old format. Existing relative-path,
  Windows-shaped JSON and live-WAL private-probe tests ran in the complete suites.
- `TestHTTPSVersion1ImportPreservesIdentityAndFailureRetry/{none,encryption,SQL,commit,cancellation}`:
  actual private-CA verified TLS, production Plane/handlers/verifier, actual
  ECDSA assertions over issued fresh challenges, separate locked login + unlock,
  exact v1 fixture. Fresh destination has generation9 and an existing client.
  All faults roll back then retry; full decrypted dataset and fresh HTTPS export
  match the old producer. Owner/wrappers/recovery/generation, session binding and
  client rows remain unchanged; legitimate session Seen may advance. Existing
  generation-bound client still reads imported profiles. Auth never exports;
  nonempty import returns409 without overwrite. Each retry obtains a new grant.

TLS injection is fixture-only: temporary failing nonce reader is installed
**inside an already-authorized managed handler** and restored before TLS response
delivery; cancellation uses a child request context during encryption. SQL faults
are triggers/auxiliary deferred-FK tables in a disposable DB, created after normal
strict initialization and removed before retry. No production injection surface
or schema-compatibility relaxation. Package tests are not parallel; race suites
pass. Cancellation legitimately prevents its audit write, producing only a generic
`context canceled` warning. Audit growth/Seen is not an import rollback violation.

An initial TLS fixture failed because replacing its Store retained old client
route closures (status200 with old empty data). Reconstructing Plane against the
new disposable store fixed **only the fixture**. This is not a production RED.

### Actual focused RED → minimal help change → GREEN

Before editing production `main.go`/`init.go`:

```sh
go test ./cmd/warden-server \
  -run '^TestServerHelpDocumentsOldExportFreshImportAndRollback$' -count=1 -v
```

**RED:** root/init/serve help lacked exact old `warden-data version 1` export,
fresh storage, authenticate/unlock/import/verify/rollback/plaintext/runbook
instructions; init still claimed normal serve disabled until T2.
**GREEN:** same command after a shared short guidance paragraph and corrected
locked-start wording. No startup/import/auth behavior was changed.
Logs `/tmp/warden-t5-help-{red,green}.log`.

Documentation/provenance-tool exception was recorded before runbook/report/doc
edits: source/serializer comparison, shell/link/diff checks and disposable tests
are the strongest meaningful checks; no fabricated runtime RED for prose.

### Temporary sensitivity controls, NOT retroactive TDD

1. Ignored only the existing managed-emptiness error. Historical preservation test
   failed because nonempty import reached UNIQUE insertion instead of returning
   `ErrDestinationNotEmpty` (`/tmp/warden-t5-mutation-empty.log`). This isolates
   early conflict classification, not a claim bypassing it defeats SQL atomicity.
2. Changed only SSH imported-password encryption AAD from row ID to ID+1. The
   independent historical ciphertext/destination-AAD test failed authenticated
   decryption (`/tmp/warden-t5-mutation-aad.log`).

Restored both guards immediately. `internal/store/transfer.go` pre/post SHA-256
**matches** `610c6df23fca122012dfd945da682386737ba521f4da545d1e08bc473374933f`;
`git diff --exit-code -- internal/store/transfer.go` PASS. Restored focused tests
and all later validation below include original production code.

## Exact SQLite/API evidence

Before SQL/crypto integration, consulted Context7
`ctx7:docs:643603c760a9ab0c71c82c6d`. That reference is current/unversioned and
mentions newer hooks: **none are assumed available**. Exact installed
`modernc.org/sqlite@v1.57.0/tx.go` was read: default deferred `begin`, context
interruption, Commit's check of low-level autocommit and rollback after failed
commit before returning the original error. `conn.go` confirms file URI handling,
`SQLITE_OPEN_URI` and DSN pragmas. Existing private-copy/WAL startup probe and
strict supported-checkpoint/schema validation remain unchanged. Only existing
`database/sql`, standard crypto and SQL trigger/deferred-constraint capabilities
were used, no third-party API or dependency changes. Installed `doc.go` lists
SQLite3.53.3 for Linux/amd64. Supplemental official SQLite documentation
`ctx7:docs:a6ddff6b1d4373bda4322659` (retrieved after fixture execution, not
relabeled preflight) confirms deferred FK COMMIT failures leave transactions
open and deferred reader→writer upgrades may return SQLITE_BUSY. The pinned
driver's rollback behavior and the actual executed fixture establish cleanup,
not a speculative hook or a new general storage-engine abstraction.

## Measured checks

Go **go1.25.14 linux/amd64**. No frontend source touched or fresh npm execution;
prior T4 reports record252 Vitest +13 distribution tests/build passing, historical
reused-state evidence only (not this writer's execution).

| Exact command | Current result |
| --- | --- |
| `bash -n scripts/test-transfer-fixture.sh` | PASS |
| `bash scripts/test-transfer-fixture.sh` | PASS actual historical serialization/byte comparison |
| `go test ./cmd/warden-server ./internal/store ./internal/server/profiles ./internal/server/runtime ./internal/crypto -count=1 -timeout=180s` | PASS |
| Same set `go test -race ... -count=1 -timeout=180s` | PASS; store15.526s/profiles18.185s/runtime37.554s |
| `go test -race ./internal/store ./internal/server/runtime -run '^Test(ConcurrentInitializedImportsSingleWinner|ImportFailurePreservesIdentityAndManagedData|HTTPSVersion1ImportPreservesIdentityAndFailureRetry)$' -count=10 -timeout=180s` | PASS store9.258s/runtime18.800s |
| `go vet ./...` | PASS |
| `go test ./... -count=1 -timeout=180s` | FAIL only unchanged SFTP `TestPosixRelMatchesFilepathRel`: `posixRel("a", ".")` = `".."`, want `"../."`. DB and every other reported package PASS. |

Focused complete runtime includes existing production-Run signed TLS security
and two-device CLI/server/agent restart journeys; new T5 TLS tests use real HTTP
Plane/handlers but are not claimed as another production-Run subprocess fixture.
Earlier recorded intermittent DB `TestTunnelCloseClosesWholeChain` remains
unresolved; a passing current DB run does not fix or waive it. No unrelated
transport fix. Ephemeral logs `/tmp/warden-t5-{provenance,focused,race,repeat,vet,full}.log`
and initial characterization logs; commands/results/hashes here and ledger are
the durable evidence, not a promise `/tmp` logs will persist.

## Changed paths / independent self-review

- `cmd/warden-server/{main,init}.go`, new `transfer_help_test.go`: only retained
  production change is current help, actual focused RED/GREEN above.
- New `internal/store/{transfer_preservation,legacy_refusal}_test.go`,
  `internal/server/runtime/transfer_preservation_test.go`.
- New `internal/store/testdata/{README.md,export-c104353_test.go.txt,warden-data-v1-c104353.json,ciphertexts-c104353.json}`,
  `scripts/test-transfer-fixture.sh`.
- New `docs/migration.md`, this report; README, docs deployment/security/
  initialization and narrow T5 plan checkpoint; local ignored execution ledger.

Self-review checks producer-to-consumer exact shape, independent source fixture
and ciphertexts, counts/getters/export, initialized auth exclusion, no-overwrite,
transaction failure/retry and concurrency, old-artifact byte/mode boundaries,
real signed HTTPS auth/fresh grants, existing client generation and rollback
instructions. There is no retained transfer/store/crypto/auth/migration change,
so existing checked flush/write+read deadlines/lock drain and recovery admission
ordering remain intact. Diff/gofmt/whitespace/local-link/shell checks are recorded
in the closing ledger checkpoint. No native Windows, genuine PRF/browser/CSP,
external DB account or power-failure directory-fsync acceptance is claimed.

## T6 handoff / stop boundary

[Manual runbook](../../migration.md): old-release export while writes are quiesced;
retain exact old binary/config/coherent stopped DB+WAL/SHM/key; independent fresh
init/PRF/saved recovery; locked serve → login/unlock → exact v1 import → full
verify → operator cutover. Handle lost response/commit ambiguity by inspecting
state, not deleting/retrying blindly. Preserve old artifacts and account for
post-cutover writes on rollback. No cleanup/in-place legacy copy or migration.

`scripts/test.sh` is still the historical unauthenticated HTTP/master-key lifecycle;
**not executed or claimed passing**. T17 owns full lifecycle replacement. T5's
separate offline fixture script deliberately avoids broad lifecycle rewrite.
T6 may reuse these v1 fixtures for actual socket deadlines, full50MiB supported-link
and slow/cancel/overlimit/cache/Host/Origin boundaries; do not weaken T2's response
leases, fresh60s binding, audit exclusion or SQLite atomicity. Full50MiB/deadline
proof belongs to T6, graph work to T7, audit hardening to T8, genuine PRF/CSP/native
Windows/final integration to their separately tracked acceptance. Independent
review is next; no automatic next-task/publication authority or security claim.
