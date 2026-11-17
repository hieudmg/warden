# Task 1: resumable setup answers

## Bounded outcome

Implemented Task 1 only on `hieudmg/resumable-account-setup`. No account
selection/authentication, version bump, dependency change, commit/push/PR,
worktree, deployment, migration or live trust operation. The approved Task 2
setup-page usability requirement was appended to the parent-owned plan.
Unrelated `mise.toml` and `scripts/ci/__pycache__/` were not modified.

Fresh defaults are `~/.warden/server.json`, `~/.warden/warden.db`,
`~/.warden/tls/fullchain.pem` and `~/.warden/tls/private.key`. Explicit custom
paths remain supported. Both commands honor explicit config selection (flag
before environment). Serve discovers `/etc/warden/server.json` only when the
new default is absent, without copying/migrating it; that legacy path also keeps
its old omitted DB default. Malformed/incomplete home config never selects an
unrelated legacy installation as fallback.

## Implementation and safety review

- Init strictly parses one file snapshot without runtime validation/environment
  overrides, then reprompts every applicable field using saved defaults. Each
  submitted answer is synced and atomically published before another prompt.
  Invalid/incomplete answers and storage-refused answers survive retry.
- `initialization_draft: true` distinguishes an editable answer file from a
  config that can have initialized storage. Serve rejects drafts even when their
  answers happen to validate. An occupied storage answer in a draft is editable
  without opening the storage. Validated answers lose the marker **before** setup
  can run/commit, so a postcommit crash cannot leave that installation's config
  editable as a draft. Do not manually toggle this init-owned marker.
- Existing config without security settings, malformed/unknown-field JSON,
  symlink config, and published config referring to occupied DB/sidecar storage
  are refused before any config rewrite. Existing identities/data are never
  opened, reset or migrated by answer persistence. Legacy key settings already
  present remain intact; new configs do not emit a master-key fallback.
- Sibling staging files use 0600, newly created directories use 0700; staged
  writes are synced/closed before exclusive first publication or atomic update.
  Existing parent permissions are not changed. Recognized non-prompted settings
  are retained. Switching TLS/proxy clears incompatible transport settings.
- A nonblocking OS-owned `*.setup.lock` lease covers prompts through setup. Parent
  directory aliases are resolved before taking it. The inode is never unlinked;
  close/crash releases kernel ownership. Expected inode/content snapshots reject
  observed conflicting external changes. Concurrent non-Warden editing of live
  config/lock/storage remains unsupported (not a general filesystem CAS claim).
- Setup's independent DB `ReserveInitialization`/exclusive identity publication
  remain unchanged and authoritative, including conflicts through different
  config paths. Existing DB/WAL/SHM/journal refusal is preserved.
- Updated the composed HTTPS fixture to respond to all seven saved TLS prompts,
  rather than relying on the old prompt-skipping behavior. It asserts those
  prompts occurred before accepting terminal password disclosure. Production
  authentication, verifier, HTTPS and lifecycle assertions were not weakened.

## Actual RED → GREEN chronology

Tests were written and run before the corresponding behavior implementation;
existing passing tests were not counted as RED. The additional setup-callback
failure/ambiguous-commit test characterizes the implemented boundary and is not
claimed as an independent initial RED.

### Initial answer/default/ownership regressions

```sh
gofmt -w cmd/warden-server/init_draft_test.go
go test ./cmd/warden-server -run 'TestInit(PersistsEachAnswer|RetryReprompts|DraftStorageRefusal|NeverRewrites|ConfigOwnership|HomeDefaults)' -count=1
```

RED exit 1: `TestInitPersistsEachAnswerBeforeReadingNext/0` through `/7` each
failed reading a missing JSON file (`no such file or directory`). Other actual
failure messages:

```text
TestInitRetryRepromptsSavedInvalidAnswersAndPreservesOtherSettings:
  json: unknown field "initialization_draft"
TestInitDraftStorageRefusalCanBeCorrectedWithoutTouchingStorage:
  accepted occupied storage
TestInitNeverRewritesMalformedLegacyOrInitializedConfig/initialized:
  accepted protected config
TestInitConfigOwnershipCoversPromptsAndRejectsExternalReplacement:
  no such file or directory
TestInitHomeDefaultsMatchServeAndTLS:
  config default "/etc/warden/server.json"
FAIL warden/cmd/warden-server
```

After implementation, the same focused `go test` command returned:

```text
ok  warden/cmd/warden-server  0.006s
```

The real filesystem assertions decode serialized JSON after every input prefix,
reject those files through the runtime loader, check private permissions, retry
invalid values, preserve other settings and occupied storage bytes, and inject a
conflicting writer before the next answer. No mocked persistence is used.

### Runtime validation and legacy discovery

A test-only legacy-path injection field was added to `ServerOptions` to avoid
reading/writing real `/etc` fixtures; it had no behavior before this RED run:

```sh
gofmt -w internal/config/setup_draft_test.go
go test ./internal/config -run 'Test(LoadServerRejectsUnfinishedInitialization|ServerConfigDiscovery)' -count=1
```

RED exit 1:

```text
TestLoadServerRejectsUnfinishedInitialization/{"security":{}}:
  runtime loader accepted incomplete setup
TestServerConfigDiscoveryPrefersHomeThenLegacyWithoutMigration:
  lost implicit legacy config ... DBPath:/var/lib/warden/warden.db ... <nil>
FAIL warden/internal/config
```

The same command after implementation returned:

```text
ok  warden/internal/config  0.002s
```

A further compatibility assertion was added before implementing retention of the
omitted DB default for discovered legacy config:

```sh
go test ./internal/config -run TestServerConfigDiscovery -count=1
```

RED exit 1: `changed discovered legacy DB default` showed
`DBPath:/tmp/.../.warden/warden.db` rather than `/var/lib/warden/warden.db`.
GREEN is included in the same focused config rerun and full suite below.

### Explicit config selection

```sh
gofmt -w cmd/warden-server/init_draft_test.go
go test ./cmd/warden-server -run TestInitConfigSelection -count=1
```

RED exit 1: both `empty-flag` and `empty-env` got
`init requires a controlling terminal; no password is written to redirected output`
instead of rejecting their empty explicit config selections. Added the selection
checks before terminal acquisition. GREEN is included in the package and full
suite below.

### Integration fixture adaptation

An initial `go test ./... -count=1` failed with `/tmp` disk-quota errors in
linking/writes, and a lifecycle timeout. No unrelated temporary files were
removed. Reproduced the lifecycle separately on a disk-backed temp filesystem:

```sh
TMPDIR=/var/tmp go test ./internal/server/runtime -run '^TestSecurityLifecycleHTTPS$' -count=1
```

RED (independent of quota):

```text
--- FAIL: TestSecurityLifecycleHTTPS (30.80s)
    security_tls_test.go:27: controlling terminal did not disclose setup password EOF
FAIL warden/internal/server/runtime 30.806s
```

Inspection established that the fixture prewrites valid TLS config but never
answers prompts; the approved retry behavior now prompts instead of skipping.
After the narrowly scoped prompt-aware fixture update, the identical command:

```text
ok  warden/internal/server/runtime  3.334s
```

### Self-review: init must retain the same legacy omitted DB default

Self-review found that draft parsing also needs the selected config path: without
it, a legacy `/etc` config omitting `db_path` could be checked against the fresh
home default instead of its original storage. A path argument was added as a
nonbehavioral seam before adding/running this regression:

```sh
TMPDIR=/var/tmp go test ./internal/config -run TestParseServerDraftKeepsLegacyStorageDefault -count=1
```

RED exit 1: `init lost legacy storage protection` showed
`DBPath:/home/hieudm/.warden/warden.db` rather than `/var/lib/warden/warden.db`.
The test is a pure decode and does not access real `/etc` or storage. Added the
same legacy default to draft parsing; GREEN:

```text
ok  warden/internal/config  0.002s
```

## Broader verification

```sh
go test ./internal/config ./cmd/warden-server ./internal/server/setup ./internal/store -count=1
go test -race ./internal/config ./cmd/warden-server ./internal/server/setup ./internal/store -count=1
go vet ./internal/config ./cmd/warden-server ./internal/server/setup ./internal/store
```

All passed (four package PASS/`ok` lines for each test invocation; vet exit 0).

After the fixture adaptation (before the final legacy draft-parser finding):

```sh
TMPDIR=/var/tmp go test ./... -count=1
```

PASS: 25 packages reported `ok`, with `internal/model` and `migrations` reporting
`[no test files]`; no failing or skipped package. Relevant results:

```text
ok  warden/cmd/warden-server        0.169s
ok  warden/internal/config          0.006s
ok  warden/internal/server/runtime 24.794s
ok  warden/internal/server/setup    2.122s
ok  warden/internal/store           4.794s
```

```sh
TMPDIR=/var/tmp go test -race ./internal/config ./cmd/warden-server ./internal/server/setup ./internal/store ./internal/server/runtime -count=1
TMPDIR=/var/tmp go vet ./...
build_dir=$(mktemp -d /var/tmp/warden-task1-windows-XXXXXX)
trap 'rm -rf "$build_dir"' EXIT
TMPDIR=/var/tmp GOOS=windows GOARCH=amd64 go test -c ./cmd/warden-server -o "$build_dir/warden-server.test.exe"
git diff --check
```

```text
ok  warden/internal/config          1.015s
ok  warden/cmd/warden-server        1.119s
ok  warden/internal/server/setup    3.224s
ok  warden/internal/store          18.458s
ok  warden/internal/server/runtime 82.038s
```

Vet, Windows cross-compilation, and whitespace checks exited 0 with no output.
The private temporary Windows binary directory was removed by its own trap.

After the final legacy draft-parser fix, repeated the full suite, five-package
race suite, full vet and whitespace checks with the same commands above:

```text
# full suite: all 25 tested packages ok, model/migrations have no test files
ok  warden/cmd/warden-server        0.236s
ok  warden/internal/config          0.011s
ok  warden/internal/server/runtime 24.822s
ok  warden/internal/server/setup    2.115s
ok  warden/internal/store           4.674s
# race suite
ok  warden/internal/config          1.012s
ok  warden/cmd/warden-server        1.115s
ok  warden/internal/server/setup    3.232s
ok  warden/internal/store          18.419s
ok  warden/internal/server/runtime 81.634s
```

Full vet and whitespace checks again exited 0 with no output. Windows
cross-compilation was also repeated after this final source change (exit 0).

## Limits and next step

Self-review is complete; parent/independent review is not implied. Tests exercised
real serialized files and production init/serve HTTPS with synthetic signed
passkeys/PRF, isolated temporary storage/certificates and a real Linux controlling
PTY. No genuine authenticator, real browser/trust installation, power-loss
filesystem durability experiment or native Windows execution was performed.
Windows compilation does not prove native ACL/privacy or rename/lock behavior.
The first quota-constrained full run remains a failed historical attempt, not a
passing run; the disk-backed rerun passed without unrelated cleanup.

Task 1 was verified locally at this historical checkpoint, not independently
accepted. The subsequent immutable review **BLOCKED** it on custom-path legacy
omitted-DB defaults, case-insensitive/duplicate JSON aliases, and the missing
post-publication directory durability barrier. Earlier passing suites did not
cover those cases. The sole Task2 writer integrated focused corrections and
regressions; see [Task2 evidence](2026-11-16-resumable-setup-task2.md). Parent
re-review of those fixes remains required. No historical result above is promoted
to proof of the newly identified cases.
