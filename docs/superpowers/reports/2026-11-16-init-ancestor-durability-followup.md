# Init ancestor-directory durability: bounded P1 follow-up

## Scope and verified gap

Worked on `hieudmg/resumable-account-setup`, HEAD `2206984`, preserving the
existing uncommitted Task2 work. Read the current Task1/Task2 reports,
`init_config.go`, both platform helpers, `init_review_test.go` and the current
init caller before changing code. This is a focused follow-up, not revised
historical RED evidence or acceptance of either overall task.

The existing Unix publication barrier synced the config's final containing
directory after Link/Rename. However, `openInitializationConfig` could first
create multiple missing parent directories with `os.MkdirAll`. Their directory
entries in their own parents had no durability barrier. A later independent DB
commit must not rely on those unsynchronized config ancestors.

## Changes and ordering

Exactly these source/test files were changed by this follow-up:

- `cmd/warden-server/init_config.go`: after MkdirAll and parent canonicalization,
  require the platform ancestor barrier before creating the config lease or
  returning a session that can publish answers.
- `cmd/warden-server/init_config_unix.go`: resolve absolute ancestry and Sync
  parents root-to-leaf, propagating open/Sync/close errors with the failed
  ancestor path. The small `synchronizeInitializationAncestor` injection seam
  defaults to the existing real directory Sync helper.
- `cmd/warden-server/init_config_windows.go`: add only the platform no-op for
  Unix-style ancestor syncing, with an explicit native-durability limitation.
  The existing documented write-through MoveFileEx publication is unchanged.
- `cmd/warden-server/init_directory_unix_test.go`: focused nested-directory,
  canonical-parent-symlink, ordering, failure and retry regressions.

This report is the only additional documentation file.

The Unix sequence is now:

1. Preserve the existing config/storage preflight; MkdirAll with mode 0700.
2. Canonicalize the parent. Sync all resolved ancestor parents root-to-leaf.
3. Acquire the existing exclusive config lease and recheck config under it.
4. Preserve staged file Write/Sync/Close, expected-file conflict checks and
   exclusive first Link / atomic replacement Rename.
5. Preserve the final containing-directory Sync after every publication.
6. Only after validated draft-removal publication and its barriers can the
   existing setup callback run; independent DB reservation is unchanged.

All ancestors are checked, not only paths missing in this process: directories
left by a prior failed/interrupted attempt may already exist without having
crossed the barrier. Treating existence as evidence of durability would make a
retry bypass the same failure. Unsupported/erroring Unix directory sync fails
closed; no durability fallback is silently accepted. Concurrent non-Warden
mutation of config/locks/ancestry remains unsupported, as before.

No changes were made to authentication, frontend/browser cancellation or its
gates, DB/storage implementation, unrelated `mise.toml`, or
`scripts/ci/__pycache__/`. No children, worktrees, commits, push/PR, deployment,
trust changes or live operations were performed. No third-party API was newly
called or changed; the fix uses ordinary Go standard-library path and file APIs.

## Actual focused RED → GREEN

Private retained command logs:
`/var/tmp/warden-task1-ancestor-followup-o40k1X/` (directory mode 0700).

First added the Unix ancestor injection variable pointing to the existing Sync
helper, without calling it or otherwise changing behavior. Then wrote tests
using genuinely absent two-level directory chains, rather than an already
existing config parent. The positive tests wrap real directory Sync calls and
assert that both parents of the new entries are synchronized in order while
neither config nor lock exists. They test direct paths and a symlink to the
existing parent. The failure tests inject the same sentinel at the existing
anchor and at a newly created parent, then require no config/lock/DB publication
or setup callback. Retry must visit the barrier again with directories left over.

Command before implementation:

```sh
TMPDIR=/var/tmp go test ./cmd/warden-server -run 'TestInit(NestedDirectorySync|AncestorSyncFailure)' -count=1
```

Actual RED, exit 1 (`red.log`):

```text
--- FAIL: TestInitNestedDirectorySyncBeforePublication
    direct: missing or out-of-order ancestor sync ... before config publication; synced []
    parent-symlink: missing or out-of-order ancestor sync ... before config publication; synced []
--- FAIL: TestInitAncestorSyncFailurePreventsPublicationAndSetup
    existing-anchor: ancestor sync failure did not prevent publication/setup: err=<nil> visited=false published=true setup=true
    new-parent: ancestor sync failure did not prevent publication/setup: err=<nil> visited=false published=true setup=true
FAIL warden/cmd/warden-server 0.031s
```

The full log retains exact test line numbers and disposable path names. After
implementing the barrier, the identical test command returned (`green.log`):

```text
ok  warden/cmd/warden-server  0.052s
```

These tests establish real directory traversal, synchronization call order and
error propagation. They do **not** simulate or prove survival of a power loss.

## Affected validation on the final source

Browser fixtures were explicitly excluded; no web/browser tests or builds ran.

```sh
TMPDIR=/var/tmp go test ./cmd/warden-server ./internal/config ./internal/server/setup ./internal/server/runtime ./internal/store -skip '^TestUIBrowser' -count=1
```

Exit 0 (`affected.log`):

```text
ok  warden/cmd/warden-server        0.411s
ok  warden/internal/config         0.011s
ok  warden/internal/server/setup   2.785s
ok  warden/internal/server/runtime 34.967s
ok  warden/internal/store          5.164s
```

```sh
TMPDIR=/var/tmp go test -race ./cmd/warden-server ./internal/config ./internal/server/setup ./internal/server/runtime ./internal/store -skip '^TestUIBrowser' -count=1
```

Exit 0 (`race.log`):

```text
ok  warden/cmd/warden-server         1.469s
ok  warden/internal/config          1.026s
ok  warden/internal/server/setup    4.470s
ok  warden/internal/server/runtime 99.680s
ok  warden/internal/store          22.916s
```

```sh
TMPDIR=/var/tmp go vet ./cmd/warden-server ./internal/config ./internal/server/setup ./internal/server/runtime ./internal/store
TMPDIR=/var/tmp GOOS=windows GOARCH=amd64 go test -c ./cmd/warden-server -o /var/tmp/warden-task1-ancestor-followup-o40k1X/warden-server.test.exe
git diff --check
```

All exited 0 with no output (`vet.log`, `windows-compile.log`, and the command
transcript). The Unix-only regressions are intentionally absent from Windows
compilation. The cross-compiled executable is retained only in the private
evidence directory, not the checkout.

## Self-review and limits

Inspected the follow-up edits against the source read at dispatch, not just
against HEAD (which does not contain Task2). Only the five listed files were
written. Existing malformed/legacy/canonical-marker protection, lease lifetime,
snapshot conflicts, exclusive/atomic publication, per-publication final-parent
barrier, and independent storage reservation remain in place. New sync failures
return before the lock/config is created; errors preserve `errors.Is` identity.
The retry test specifically covers directories retained after the failure.

This fixes the demonstrated Unix ancestor-barrier gap with deterministic ordering
and failure evidence. It does not assert real power-loss/filesystem/hardware
acceptance, native Windows directory/publication durability, or platform ACL
acceptance. Windows' documented write-through move path is preserved, not newly
proved. Independent re-review remains the parent's next step. The separately
reported authentication-cancellation and browser-gate issues are untouched and
remain separate; passing these Go checks does not close them. No further product
or security decision was needed for this bounded fix.
