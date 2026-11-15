# T8 — classified audit events and bounded safe metadata

## Scope and checkpoint

Implemented **T8 only** on `hieudmg/security-hardening`, starting and ending at
HEAD `896cbed`. Sole writer; no children/worktrees, staging, commits, push,
deployment, real-data operation, version/dependency/installers/frontend change or
T9 work. Protected unrelated `mise.toml` was not read or edited. Read root
`AGENTS.md`, the approved T8 plan/sibling specification, chronological ledger,
prior T3/T4 auth evidence and T7 graph report/source before changing behavior.
Repository memory was searched/read before tests; live source remains authoritative.

This is an implementation/self-review checkpoint, **not independent acceptance,
verified M1 or a security release**. Genuine PRF-positive HTTPS/browser,
production-browser CSP/network and native Windows evidence remain pending. No
new external/native/browser validation is claimed.

## Implemented contract

The exact field/type/byte contract and historical-row limitation are documented
in [the security model](../../security.md#audit-classifications-and-metadata-boundary-t8).

- `audit.Classify` accepts only a fixed classification vocabulary and known
  store/vault/context sentinels. Unknown errors, including arbitrary values of
  the classification type, become `internal`. It never calls `err.Error()` or
  formats the unknown error. Profile/report-local decoder and graph errors are
  mapped at their source rather than creating an import cycle or parsing text.
- Metadata is copied by fixed-key lookup, not an iteration/deep walk of caller
  structures. Exact built-in counts, archive boolean, status and bounded safe IDs
  are retained. Custom Stringers/JSON marshalers, maps/slices/channels and unknown
  fields are never formatted/marshaled. Strings are length-checked before ID
  validation; UA is bounded before filtering. JSON is generated only for the
  resulting small built-in primitives.
- UA is at most **512 UTF-8-safe bytes**, not runes. Invalid/incomplete UTF-8 and
  controls are dropped from the bounded prefix. Metadata is at most **4,096
  encoded JSON bytes**, including escaped bytes and punctuation. Fields that
  would exceed that bound are omitted deterministically, with UA last so actors
  and counts survive. Caller metadata is not mutated.
- Peer source is numeric IP or IP:port (input at most 64 bytes), never forwarded
  or actor headers. Resource IDs are canonical positive signed-64-bit decimal
  IDs, not request names. Project creation now uses its numeric ID; report
  creation keeps its numeric report ID; listing reports omits the unsafe
  name-as-ID and retains a report count. Caller-controlled names, project/model/
  device labels and report contents do not enter new audit rows.
- Runtime request actors come from validated web/client authentication context.
  Login success records the verified public credential ID, ordinary web events
  carry that ID, and client data/security events carry the durable nonsecret
  client ID. Sessions expose only a token hash today, so no session hash or
  invented new session-ID format is recorded. Restricted recovery has no fake
  `credential_id: recovery`. No tokens, full verifiers, root keys, proofs or DEKs.
- Exact existing security routes now record classified success/failure with
  numeric HTTP `status`. HTTP 400/401-or-403/404/409/413/423/429 map to
  invalid-json/unauthorized/not-found/conflict/payload-too-large/locked/rate-limited;
  other error statuses and panic/abort use `internal`. Generic 5xx is not decoded
  from its response body. Static route matching never logs raw URLs, query
  strings, caller action headers or arbitrary method/path values. Unknown routes
  do not acquire an attacker-selected operation name.
- The status wrapper preserves `Unwrap`, error-aware flush, actual Write errors
  and panic/abort propagation. Existing vault lease, write-then-read cancellation,
  callback join, checked delivery and HTTP/1 flush ordering remain intact. No
  auth/grant/recovery/rate/response status policy was changed.
- `Store.AppendAudit` returns only `ErrAuditWrite` (`audit persistence failed`),
  without wrapping the original driver error. Producers still surface audit loss
  as `audit write failed`, with fixed `storage` classification and safe operation/
  numeric-resource identity only. Existing best-effort handling remains; successful
  operations are not silently disabled or turned into a new transactional audit
  policy. No raw driver data reaches those warnings or response bodies.

### Producer/consumer inventory

Inspected every production `RecordRequest`/`Record`/`AppendAudit` call and every
profile/report `h.record` call, including success and error branches:

| Source | Finding/change |
| --- | --- |
| `profiles/handlers.go`, `groups.go`, `key_pairs.go`, `transfer.go` | All existing producers use `Handler.record` → recorder. Operations/types are internal names; IDs are decimal or empty. Archive boolean and seven transfer counts are the only original safe metadata. Local decoder/graph sentinels now classify explicitly; all validation/unknown errors classify centrally. |
| `reports/handlers.go` | All four handlers use the same record seam. Removed raw project-name IDs/metadata and `agent_model`; preserve numeric project/report IDs and safe count. No report title/summary is logged. |
| `runtime/{runtime,plane,clients,passkeys,recovery,recovery_rotation,actions,concurrency}.go` | There were **no existing auth audit producers**; only recorder construction for managed/client muxes. Added exact-route runtime security auditing plus validated actor propagation to existing managed events. No credentials/body capture. |
| `server/auth/`, `server/setup/` | No existing Recorder/AppendAudit or slog producers. Setup has no durable store before atomic publication. No speculative setup persistence or raw-proof logger was added. |
| `store/audit.go` | The only production AppendAudit caller is Recorder. The store remains an internal persistence primitive for already-vetted events, not a new schema/policy layer. Failure is now generic. Other direct calls are isolated store tests. |
| `model/audit.go`, migrations, transfer, web/API source | No audit-list route, AuditList API, or audit UI/response consumer exists in the checked source. No model/schema/transfer/API response change was needed. Existing report test expectations for unsafe labels were updated to the approved T8 omission contract, not preserved as an unsafe promise. |

No historical rows were rewritten/deleted and no existing initialized storage was
migrated by this change. Previously persisted audit plaintext can remain in old
DBs/backups; this does not retroactively remove it. `warden-data` v1 remains
managed-data-only and never imports/exports auth/audit state. Existing validation
responses are not globally masked; audit classifications and persistence warnings
are the bounded T8 leak paths changed here.

## Exact RED → GREEN evidence

All commands used **Go1.25.14 linux/amd64**. `/tmp/warden-t8-*.log` files are
ephemeral execution aids; commands/results here are the durable evidence.

### Actual behavioral RED before any production edit

```sh
go test ./internal/server/audit ./internal/server/profiles ./internal/server/reports \
  -run '^TestAudit(NeverPersistsRawValidationValues|ClassificationsAllowlist|MetadataCapsAndNoCallerMutation|PersistenceFailureLogsNoDriverValues)$' \
  -count=1 -v
```

FAIL (`/tmp/warden-t8-red.log`):

- Real SQLite audit rows retained synthetic secrets in invalid transfer format,
  invalid SSH name, invalid project name, successful project/report labels, and
  an unknown SQLite trigger error from report creation.
- Graph and strict-JSON failures retained human-readable error strings rather
  than fixed classifications. T7 already omitted raw graph JSON; that passing
  absence is **not** relabeled as a new T8 secret-leak reproduction.
- A trigger rejecting audit insertion placed its synthetic raw driver error in
  captured `slog` for both profiles and reports; warnings were not silent.
- Known sentinel wrappers and unknown errors retained their original messages.
  Caller metadata was mutated and a custom `MarshalJSON` ran; cyclic metadata
  made unrelated safe fields disappear. Invalid source text was retained.

The initial selector test incorrectly expected HTTP 400. Source confirms the
existing transport-validation contract is **422**, which was preserved. After
correcting only that expectation, before production edits:

```sh
go test ./internal/server/profiles \
  -run '^TestAuditNeverPersistsRawValidationValues/database_selector$' -count=1 -v
```

FAIL (`/tmp/warden-t8-selector-red.log`): actual row error was
`store: validation failed: database "synthetic-T8-secret" not found`.

Explicit UA-only adversarial cases were added before production edits, so a
cyclic map could not hide a missing cap:

```sh
go test ./internal/server/audit \
  -run '^TestAuditMetadataCapsAndNoCallerMutation$' -count=1 -v
```

FAIL (`/tmp/warden-t8-caps-red.log`): UA/encoded metadata unbounded or unsafe,
caller mutation, custom method invocation, unsafe source retention.

Before adding runtime auth production code:

```sh
go test ./internal/server/runtime \
  -run '^TestAuditNeverPersistsRawValidationValues$' -count=1 -v
```

FAIL (`/tmp/warden-t8-auth-red.log`): no persisted events for recovery proof,
login finish, unlock, poll or lock; existing client-managed row lacked its
validated nonsecret client actor. No compilation/missing-symbol failure is used
as the behavioral RED evidence.

### GREEN and passing extensions

The first combined focused selection after implementation passed
(`/tmp/warden-t8-green-initial.log`). Subsequent coverage extended the already
GREEN behavior, not a fabricated additional historical RED:

- Signed real-verifier login success, recovery proof success/failure, successful
  pairing, failed key/grant/token submissions, locked and fake-clock-saturated
  rate outcomes; scan **all persisted row columns plus captured slog** for API/
  polling/session/action tokens, full hashes, device label, root/proof and DEK.
- Unknown error with an `Error()` method that panics; a forged classification
  containing a synthetic secret; all selected fixed classifications/sentinels.
- UTF-8 split boundary (513-byte input becomes 510 safe bytes); HTML-escaping
  expansion with large actor IDs requires UA omission to fit encoded 4 KiB;
  actor/header spoof attempts, caller-map equality, cyclic/channel/custom values
  under both unknown and known fields, and a >1-MiB unsupported string.
- Generic store failure sentinel/no unwrap/no partial audit row; real trigger
  failures through profile, report and runtime warning paths; preserved status
  and non-silent generic warning.

One extension initially left its intentional login-rate saturation active when
starting the separate successful recovery journey, producing expected 429 rather
than running the intended success fixture. Reset only that test lane's tokens
between scenarios, with a fixed test clock; no production rate policy change.
The complete final named selection passed:

```sh
go test ./internal/server/audit ./internal/store ./internal/server/profiles \
  ./internal/server/reports ./internal/server/runtime \
  -run '^TestAudit|^TestAppendAudit' -count=1 -v
```

PASS (`/tmp/warden-t8-focused-final.log`). Tests capturing global `slog.Default`
are sequential and restore it with cleanup; no server package test uses
`t.Parallel`, and different packages have separate test processes.

## API/source evidence

No new third-party production API/import/dependency was introduced. Before new
SQL driver/trigger test calls, Context7 SQLite documentation was retrieved
(`ctx7:docs:6b047283787d338e22b13f9d`) and exact installed
`modernc.org/sqlite@v1.57.0/{sqlite,conn,stmt,error}.go` inspected for registered
`sqlite` driver, bound primitive arguments, ExecContext/QueryContext delegation,
statement step/error return and driver errors containing raw message data. The
Context7 page is not presented as a v1.57.0 version pin; installed exact source
is the pinned evidence. Tests exercise real SQLite `RAISE(FAIL, ...)` errors,
not a fake recorder returning a pre-sanitized error. All other new calls use Go
standard-library APIs and existing project seams.

Documentation-only TDD exception was declared before prose/plan/ledger edits:
record exact implemented contract and measured evidence; verify source, test
results, links and diff instead of inventing a runtime RED for documentation.

## Final checks against current source

| Exact command | Result |
| --- | --- |
| `go test -race ./internal/server/audit ./internal/store ./internal/server/profiles ./internal/server/reports ./internal/server/runtime -run '^TestAudit\|^TestAppendAudit' -count=25 -timeout=180s` | PASS; audit 8.317s/store 9.915s/profiles 26.908s/reports 20.159s/runtime 8.970s; `/tmp/warden-t8-repeat-race25.log` |
| `go test ./cmd/warden-server ./internal/crypto ./internal/store ./internal/server/... -count=1 -timeout=180s` | PASS; runtime 17.647s, profiles 1.897s, store 1.071s; `/tmp/warden-t8-final-packages.log` |
| `go test -race ./cmd/warden-server ./internal/crypto ./internal/store ./internal/server/... -count=1 -timeout=180s` | PASS; runtime 76.310s, profiles 33.111s, store 16.651s; `/tmp/warden-t8-final-race.log` |
| `go vet ./...` | PASS; `/tmp/warden-t8-vet.log` |
| `go test ./... -count=1 -timeout=180s` | FAIL **only** unchanged SFTP `TestPosixRelMatchesFilepathRel`: `posixRel("a", ".") = ".."`, expected `"../."`; `/tmp/warden-t8-full.log`. DB PASS (0.089s); earlier intermittent DB remains unresolved, not fixed by this run. |

The complete runtime normal/race suites retain existing signed HTTPS/restart/
client/recovery, T6 full-size/deadline, and lease/checked-write/HTTP1-flush/abort/
unread-body/cancellation tests. No fresh frontend, real-authenticator PRF, browser
CSP/network, NGINX or native Windows run was performed or inferred. Known SFTP
is T11 scope, not fixed here. This is not a dependency vulnerability remediation
or full security-release check.

## Changed files and self-review

Production: `internal/server/audit/audit.go`,
`internal/server/profiles/handlers.go`, `internal/server/reports/handlers.go`,
`internal/server/runtime/{audit,plane,clients}.go`, `internal/store/audit.go`.
Tests: `internal/server/audit/audit_test.go`,
`internal/server/profiles/audit_test.go`,
`internal/server/reports/{audit,handlers}_test.go`,
`internal/server/runtime/{audit,audit_failure,plane}_test.go`,
`internal/store/audit_boundaries_test.go`.
Documentation: `docs/security.md`, this report, narrow T8 checkpoint in the
approved plan, and `.superpowers/sdd/2026-11-14-security-hardening-7c97840ce693/ledger.md`
(ignored).

Inspected actual production diff and all new source/tests for fixed error
classification, omission before arbitrary formatting/marshaling, byte/encoded
bounds, trusted actor context, no raw labels/paths/proofs in event/warning fields,
unchanged authorization/lease/abort policies, and historical/managed-transfer
preservation. Formatting, whitespace/local links, branch/HEAD, staging and final
scope checks are recorded in the ledger. No unresolved material T8 implementation
decision was encountered. Stop at bounded self-review; recommended next is
independent T8 review, not automatic T9 execution or publication.
