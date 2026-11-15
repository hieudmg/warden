# T11 — SFTP boundaries, revised staging contract and historical blocker

## Owner superseding decision — resumed implementation

The owner explicitly supersedes only **remote private-at-creation**: keep pinned
`pkg/sftp v1.13.11`, use O_WRONLY|O_CREATE|O_EXCL without O_TRUNC, then handle
FSETSTAT chmod0600 **before any Write**. Unsupported/failed chmod fails closed,
closes and cleans only owned staging. Local exclusive private-at-creation,
path containment, collisions/symlinks, old-target preservation and failure cleanup
remain required. No fork/new SFTP library/dependency update/custom frames/rsync.
Possible future cp-to-rsync replacement is outside this PR.

The owner explicitly accepts that the initially public remote file can be opened
by another user before chmod; that descriptor may read later contents or write
if initial permissions allow, and chmod does not revoke it. **Do not call this
private-at-creation, full original T11 satisfaction, or blanket security approval.**
Native Windows/genuine PRF acceptance remains separate. This authority update
was recorded in plan/spec/security/report/ledger before new tests or code; prose
uses the documented TDD exception, validated against the explicit owner decision.

The following initial blocked attempt and its measured proof are historical,
not erased or promoted to proof of the revised implementation. New measured
RED/GREEN and final checks will be appended separately.

## Status and scope

**BLOCKED; T11 is not implemented. No production or repository test changes.**
Owner-authorized T11 only, branch `hieudmg/security-hardening`, reviewed HEAD
`78f8090`, Go `go1.25.14 linux/amd64`. Read root AGENTS, approved design, T11
plan, ledger and relevant filesystem/transfer/remote sources before investigation.
Sole writer; no children/worktrees/staging/commits/push/deployment/version or
dependency edits. Protected unrelated `mise.toml` was not read or changed.
No live SFTP/SSH/Warden connection, real data or production ACL mutation.

The owner explicitly requires private **creation**, not creation followed by
chmod, and directs a material-blocker report if the pinned client cannot provide
it. That condition was confirmed before any production edit. Stopping here
avoids introducing partial behavior or silently disabling all remote uploads.
There is no supervisor-contact tool in this session; this report is the escalation.

## Pinned official API/source evidence

`go list -m -f '{{.Path}} {{.Version}} {{.Dir}}' github.com/pkg/sftp`:

```text
github.com/pkg/sftp v1.13.11 /home/hieudm/go/pkg/mod/github.com/pkg/sftp@v1.13.11
```

Context7 `/pkg/sftp`, `ctx7:docs:bf829d0b5c5a718e3f8879a8`, was fetched before
writing the disposable probes. Its excerpt describes OPEN flags and server
handler interfaces, not a version-pinned client mode API. Exact selected-version
official installed source is decisive:

- [`client.go:295–305`](https://github.com/pkg/sftp/blob/v1.13.11/client.go#L295-L305):
  `Create` requests read/write, create and truncate; no exclusive flag.
- [`client.go:661–691`](https://github.com/pkg/sftp/blob/v1.13.11/client.go#L661-L691):
  `OpenFile(path string, f int)` can express `O_EXCL` but accepts no mode.
  Both calls reach private `open`, which sets only ID, Path and Pflags in
  `sshFxpOpenPacket`. It leaves `Flags=0` and `Attrs=nil`.
- [`packet.go:744–781`](https://github.com/pkg/sftp/blob/v1.13.11/packet.go#L744-L781):
  OPEN serializes the attribute flags and optional attributes. The packet type
  is unexported. Private dispatch in `conn.go:155–185` is not an exported raw
  request escape hatch; the public client method/option inventory offers no
  creation-attributes override. No unsafe/reflection/linkname/frame workaround
  was attempted.
- [`client.go:967–986`](https://github.com/pkg/sftp/blob/v1.13.11/client.go#L967-L986):
  `Mkdir` likewise accepts no mode and omits creation attributes. A private-dir
  workaround cannot establish 0700 **at creation** with this API either; no
  mkdir-then-chmod workaround was substituted.
- `client.go:623–630`: `Chmod` sends a later SETSTAT, not OPEN attributes.
- [`server.go:481–526`](https://github.com/pkg/sftp/blob/v1.13.11/server.go#L481-L526):
  the official in-process server defaults creation to 0644 when OPEN omits
  permission attributes, while honoring supplied permission attributes. This
  server can support the desired protocol behavior; the pinned client cannot
  request it through its public creation API. This is not a claim that SFTP v3
  itself lacks private creation.
- `request.go:187–218`, `request-attrs.go:7–28`: the RequestServer exposes decoded
  OPEN Pflags and raw attribute payload to the disposable observation handler.
  For OPEN, `Request.Flags` holds Pflags, so `Request.AttrFlags()` would be an
  incorrect way to infer OPEN attribute flags. The probe uses `Pflags()` and
  the raw payload length, combined with the exact packet construction above.

Warden `remoteFilesystem.Create` directly delegates to `client.Create`;
`localFilesystem.Create` delegates to `os.Create`. `copyFile` writes all content
before closing and chmodding the staging path. Neither current adapter fulfills
the requested private/exclusive staging contract.

## Actual RED and preflight characterization (no GREEN fix)

All new executable evidence lives outside the checkout:
`/tmp/warden-t11-preflight-wCUvHu/{creation_test.go,overlay.json,*.log}`.
A Go build overlay temporarily presents the test file as
`internal/client/sftp/t11_preflight_test.go`; that path was **not** created in the
repository. These files/logs are ephemeral, not shipped regression coverage.
The test source uses only official public client/server APIs, no custom frames.

### Baseline before edits

```sh
go test ./internal/client/sftp -run '^TestPosixRelMatchesFilepathRel$' -count=1
```

**FAIL**, exit 1: `posixRel("a", ".") = ".."`, expected `"../."`.
The implementation applies `path.Clean` to the constructed relative result.
No exact new regression or fix was added because the task stopped at the API
blocker. The original assertion is unchanged; no containment test was weakened.

### Actual adapters: private creation, collision and symlink RED

```sh
go test -overlay /tmp/warden-t11-preflight-wCUvHu/overlay.json \
  ./internal/client/sftp \
  -run '^TestT11PreflightPrivateExclusiveStagingBeforeFirstWrite$' \
  -count=1 -timeout=30s -v
```

**FAIL**, exit 1, all six subcases, before any production change:

| Actual adapter | Observation immediately after Create, before any Write | Existing-file collision | Symlink collision |
| --- | --- | --- | --- |
| Local | zero bytes, mode 0664, not 0600 | accepted; synthetic old bytes truncated | accepted; synthetic referent bytes truncated |
| SFTP | zero bytes, mode 0644, not 0600 | accepted; synthetic old bytes truncated | accepted; synthetic referent bytes truncated |

The local mode is an observation under this environment, not a promised default
on other systems. Neither probe calls Write at all. Each test creates only its
own disposable local directory and synthetic files. The SFTP case invokes
**Warden's actual `NewRemoteFilesystem`** backed by the pinned real client and
`NewServer` over `net.Pipe`; it is not a fake filesystem assertion. Symlinks point
to separate synthetic referents whose contents are checked after the attempted
creation. This proves current unsafe collision behavior, **not** the required
post-fix rejection or containment outside the destination. Server/client ends
close and the server goroutine is joined at fixture cleanup.

### Public O_EXCL API still omits creation attributes

```sh
go test -overlay /tmp/warden-t11-preflight-wCUvHu/overlay.json \
  ./internal/client/sftp \
  -run '^TestT11PreflightOpenFileExclusiveOmitsCreationAttrs$' \
  -count=1 -timeout=30s -v
# Same command with -race also PASS.
```

**PASS characterization**, not a GREEN security fix. A real pinned client calls
`OpenFile("synthetic-stage", os.O_WRONLY|os.O_CREATE|os.O_EXCL)` over `net.Pipe` to
the pinned RequestServer. The handler observes `create=true exclusive=true
write=true attribute-payload-bytes=0`, then rejects OPEN with permission denied.
No file or data is created. This confirms exclusivity alone is available but
0600 creation attributes are absent. It does **not** establish production
unsupported-private-create fail-closed behavior: that behavior is unimplemented.

## Unchanged-source validation

```sh
go test ./internal/client/sftp ./cmd/warden -count=1 -timeout=180s
go test -race ./internal/client/sftp ./cmd/warden -count=1 -timeout=180s
```

Both exit 1 solely at the unchanged SFTP baseline above. CLI passes (normal
0.087s, race 2.282s); SFTP reports no additional failures in these runs. Existing
actual-adapter integration tests run as part of that package, but they do not
prove private creation. No broad passing-suite or T11 completion claim follows.

## Required decision and remaining work

A **supported client API that sends permissions in the exclusive OPEN request**
is needed to implement the approved outcome. Authorize an evidence-reviewed,
bounded dependency API change (or another explicitly reviewed supported
mechanism) before resuming. No particular newer release or fork was evaluated or
selected. An unconditional remote-create refusal would disable all uploads with
the current client; it was not silently adopted as a substitute for implementing
both adapters. The approved per-server fail-closed requirement remains binding.
Do not weaken it to create-then-chmod, rely on remote umask/default ACLs, send
bespoke protocol frames, or use an SSH shell workaround without new authority.

Still unimplemented/unverified: portable entry validation before either join,
cleaned/native target containment, exact POSIX Rel regression/fix, local exclusive
0600 creation and Windows owner/DACL creation, supported private SFTP OPEN,
unsupported-server fail-closed handling, pre-write permission/exclusivity proofs
after the fix, old-target preservation/cleanup across copy/source-close/
write-close/chmod/rename failures and cancellation, and native Windows tests.
Existing same-host/self-copy/symlink protections are unchanged, not expanded.

No Windows cross-compile or native execution was performed: no Go source changed.
Native Windows traversal/ACL/replacement execution is still required, and cannot
be inferred from Linux results or future cross-compilation. No new full-Go run
was performed for this blocked documentation-only checkpoint; historical DB
intermittence remains unresolved. No T12 SSH lifecycle/forwarding, external TLS,
x/crypto/T15, installer or release change. **Next: resolve this T11 API blocker,
resume T11 with fresh RED→GREEN evidence, then only separately authorized T12.**

## Documentation exception and self-review

The runtime tests above were written/run before any implementation; no runtime
fix was made and no GREEN is claimed. Documentation-only TDD exception was
announced before editing this report, security contract, plan checkpoint and
ledger: verify against exact source/command output, links and actual diff rather
than invent an executable RED for prose. The security document distinguishes the
approved future path contract from currently unimplemented behavior. No new
POSIX filename restriction is shipped at this historical checkpoint.

---

## Revised implementation checkpoint — current result

**The owner-authorized limited T11 implementation is now retained; native Windows
and independent acceptance remain pending.** The historical blocked attempt above
is not the current implementation status. The stronger original remote private
creation requirement is intentionally **not met**, by explicit owner decision.
No dependency/fork/new library/custom frames/rsync implementation was introduced.

### Contract and changed files

Production files:

- `internal/client/sftp/filesystem.go`: bounded original-operand `CheckPath` and
  comparison/containment `Clean` methods (local native absolute paths, remote
  POSIX-clean paths), exclusive creation,
  remote handle chmod and owned-stage cleanup, exact POSIX Rel dot fix.
- `internal/client/sftp/transfer.go`: check raw operands before normalization;
  preserve operational source spelling, normalize separately for containment;
  validate entries before source join; check each native/adapter derived child;
  fail closed on stat/Lstat errors other than absence; reject file destination
  symlink ancestors as well as directory ancestors; preserve close/error/rename
  sequencing and return cleanup errors rather than hide them.
- `internal/client/sftp/path_contract.go`: one portable component spelling and
  validation shared by recursion and basenames appended to existing directories.
- `internal/client/sftp/staging_unix.go`: `O_WRONLY|O_CREATE|O_EXCL`, 0600 at creation.
- `internal/client/sftp/staging_windows.go`: native CREATE_NEW with a protected
  current-owner-only DACL supplied at creation, then handle-based owner/DACL
  validation; no POSIX-mode privacy fallback. A failure cleans the newly created
  stage; a failed CREATE_NEW never removes a preexisting collision.

Tests: new `filesystem_test.go`, `transfer_boundaries_test.go`,
`remote_boundaries_test.go`, `containment_test.go`, `staging_windows_test.go`;
existing `transfer_test.go` only normalizes native expected separators with
`filepath.ToSlash` in the POSIX Rel equivalence test. Its original dot expectation
and error/containment assertions were not weakened. All files are under
`internal/client/sftp/`.

Docs: this report, `docs/security.md` portable path/accepted-risk contract,
approved plan/spec and ignored execution ledger. No `remote.go`, SSH lifecycle,
agent/CLI production, external TLS, x/crypto, module/lockfile or version changes.

### Exact policy and namespace scope

The [security path contract](../../security.md#file-transfer-path-and-staging-contract-t11--revised-owner-decision)
lists unsupported portable components: empty/dot/parent, either separator, colon
(drive-relative/absolute/ADS), invalid UTF-8, ASCII controls below U+0020, Windows
reserved punctuation/devices and trailing dot/space aliases. Reserved stems are
case insensitive and checked before an extension, including COM/LPT superscript
¹/²/³ variants and spaces trailing the stem. Ordinary Unicode, internal spaces,
`.hidden`, `..child`, `COM0`, `COM10.txt` remain accepted.

This is an intentional compatibility restriction for **entries and appended
basenames**, including legal POSIX colon filenames during recursion. Explicit
POSIX source/destination full paths may contain colon; a real remote adapter
copy proves that case. Original operand components are checked before lexical
normalization; existing symlink components are rejected even before `..` or a
trailing slash/dot. Source Lstat/Open retain operational spelling, never lexical
substitution. Missing/non-directory source operands fail rather than selecting
normalized existing data; missing destination components cannot be traversed
with `..`. Local paths use native `filepath.Abs` only for comparison/containment,
which closes the relative-source/absolute-descendant self-copy bypass. Remote
paths use only `path.Clean` and POSIX Rel, never Windows volume or case semantics.
Explicit caller dot/root directory sources retain their existing contents-target
behavior: use an existing destination directory directly without joining a dot
or rooted component. Untrusted entries do not use this exception. Each derived child must Rel back to exactly its
validated component before any creation there. Existing same-host, source
symlink/special-file and descendant checks remain. Lstat checks are not a new
race-proof root primitive against concurrent replacement of writable ancestors;
no OS case-normalization or arbitrary adversarial-filesystem guarantee is made.
Directory copies are not atomic whole-tree transactions.

### Updated acceptance table (not original full-private acceptance)

| Boundary | Implemented / measured evidence | Remaining limitation |
| --- | --- | --- |
| Before either join | Core hostile-component tests; real malicious SFTP listings for names preserved by the client; marker outside target unchanged | Native Windows execution pending |
| Native containment | Escaping-Join target rejected; file symlink ancestor denied; relative-source/absolute-descendant self-copy denied before target creation | No concurrent ancestor-substitution/rooting guarantee |
| POSIX Rel | Exact new `a -> .` / `a/b -> .` regressions; original filepath-equivalence test now passes | Remote namespace stays POSIX on Windows clients |
| Local staging | Actual adapter is exclusive0600 before first Write on Linux; file/symlink collisions neither truncated nor removed | Windows CREATE_NEW/owner-DACL tests cross-compiled, not executed |
| Remote staging | Real OPEN flags write/create/exclusive/no truncate; handle FSETSTAT before WRITE; zero content before chmod | OPEN still has no permission ATTRS; initial0644 observed and accepted |
| Unsupported/failed chmod | Real pinned client/RequestServer returns unsupported or permission-denied; zero writes, exactly one close and removal of owned stage | A server may lie about permissions; no hostile-server confidentiality promise |
| Copy/close/mode/rename errors | Actual local and SFTP destinations preserve old target and clean owned stage on read error, partial write error, source cancellation, source-close, write-close, final-chmod and rename failures | Removal itself may fail; the returned error includes cleanup failure rather than claiming removal succeeded |
| Commit | Source permissions only after content plus both successful closes; existing PosixRename path, no delete-target fallback | Remote server must support PosixRename; no new fallback |

### Fresh RED chronology before implementation

Fresh baseline, before source edits:

```sh
go test ./internal/client/sftp -run '^TestPosixRelMatchesFilepathRel$' -count=1
```

FAIL `".."` versus `"../."`, unchanged from the historical preflight.
New repository tests were then written before implementation and run with:

```sh
go test ./internal/client/sftp \
  -run '^Test(RemoteEntryNamesRejectedBeforeJoin|CopyTargetContainment|PosixRelRetainsDotTargetComponent|PrivateExclusiveStagingBeforeFirstWrite|ExclusiveStagingCollisionsPreserveExisting|RemoteUnsupportedStagingChmodFailsBeforeWrite|CopyFailurePreservesOldTargetAndCleansStage)$' \
  -count=1 -timeout=60s -v
```

Initial `/tmp/warden-t11-resumed-eZlNHD/red.log` recorded genuine staging REDs:
local0664 / remote0644 before first write, remote OPEN0x1b with truncate/no
exclusive/no FSETSTAT, collisions truncated files/referents, unsupported chmod
accepted and wrote one packet without cleanup. The empty-entry fixture then
recursed without bound (it returned the same directory on every ReadDir), causing
stack overflow. This test-harness error is retained, not called successful bounded
RED evidence. Added a test-only post-Join Lstat stopping guard, leaving the
pre-join assertion independent of the error. No production change had occurred.
The same command then exited1 normally in0.006s (`red-bounded.log`):

- Every unsafe component reached source Join before rejection.
- Escaping destination Join wrote the outside test path; a file through a
  symlink ancestor wrote into a separate disposable directory.
- New exact dot regressions returned `..`/`../..` instead of `../.`/`../../.`.
- The staging/collision/unsupported-chmod failures above remained RED.
- Failure preservation/cleanup and ordinary cleaned target **already passed**;
  these are characterizations, not fabricated REDs.

Implemented the minimal path/creation/cleanup changes; same focused command plus
original Rel test GREEN (`green-initial.log`). Subsequent real REDs, each before
its corresponding additional fix:

```sh
go test ./internal/client/sftp -run '^TestRemoteEntryNamesRejectedBeforeJoin/invalid-' \
  -count=1 -timeout=30s -v
# FAIL: invalid UTF-8 reached source Join; added utf8.ValidString.

go test ./internal/client/sftp \
  -run '^TestCopyTargetContainmentRelativeSourceAbsoluteDescendant$' -count=1 -v
# FAIL: read=true, target created, test stopping guard reached instead of self-copy rejection.
# Added adapter Clean: native local absolute versus remote POSIX-only clean.
```

Logs `invalid-utf8-red.log`, `native-containment-red.log`; both GREEN in final
normal/race/repeated suites. Later ordinary-name/explicit-colon, real-listing,
partial-write and permission-denied extensions are passing additional coverage,
not new preimplementation RED claims.

Closing self-review also found that local absolutization changed the basename
of an explicit `.` directory source and moved its contents under a new child.
Added `TestCopyExplicitDotSourcePreservesContentsTarget`, ran it RED before the
compatibility fix (`explicit-dot-red.log`: destination/file absent), then retained
the caller's original basename and selected the existing destination directly
for explicit dot/root directory sources. No dot/root component is joined and
unsafe entry rejection is unchanged. Real in-process remote dot/root-source
characterizations also pass without reading the host filesystem root.

A real-listing extension initially expected raw `../escape` to reach Warden's
validation. Pinned `client.go:414–417` filters dot/dotdot and applies
`path.Base(filename)` before returning FileInfo, so the actual name was safe
`escape`; the test's assumption was wrong. Removed that raw-name expectation
from the real-server matrix; the independent core tests still exercise and
reject the original slash/parent names before joining. The actual client/server
matrix retains unsafe backslash, UNC/drive, ADS, reserved, empty and trailing-dot
names. No production workaround or weakened original containment assertions.
Intermediate failed package/race runs are retained as `packages.log`/`race.log`;
corrected and final commands below pass.

### API evidence and real pre-write protocol proof

Refreshed Context7 exact library ID `/pkg/sftp`,
`ctx7:docs:9c83e06f08bdc0a207d68b82`; selected-version official installed source
was inspected before writing third-party calls:

- `github.com/pkg/sftp@v1.13.11/client.go:664–691`: OpenFile flags and omitted OPEN
  attributes, unchanged from the historical evidence.
- `client.go:2143–2154`: `File.Chmod` locks this file's handle and calls fsetstat,
  unlike path-based `Client.Chmod`.
- `client.go:564–579`: FSETSTAT packet carries Handle, permissions flag and mode.
- `server.go:574–603`: actual server resolves the handle and invokes `f.Chmod`.
- `request-server.go:283–300`, `request.go:475–480`: supported RequestServer
  mapping for injected unsupported/denied FSETSTAT failures.

`TestPrivateExclusiveStagingBeforeFirstWrite` uses **Warden's actual adapters**.
Remote side is pinned `NewClientPipe` + `NewServer` over net.Pipe; test requests
use only absolute paths in their own disposable directories. The server itself
is not a chroot. A receive-side test observer
reads packet types/OPEN flags without constructing or modifying frames; it is
not a production protocol implementation. It distinguishes handle FSETSTAT10
from path SETSTAT9, asserts no WRITE6 before Create returns, and checks physical
0600 mode at each WRITE arrival. Before handling FSETSTAT, it observes physical
zero-byte stage mode0644. After Create returns: zero bytes/mode0600. OPEN flags
are 0x2a (write/create/exclusive), attribute flags0, no truncate. Local actual
adapter separately asserts zero bytes/mode0600 before any Write. Collision tests
check both original bytes and Lstat symlink identity. Unsupported and denied
chmod handlers observe zero writes, exactly one close and one removal; only
synthetic owned stage is removed. Server/client close and fixture goroutine join
are part of cleanup. No live connection/data/ACL mutation.

```sh
go test ./internal/client/sftp \
  -run '^Test(PrivateExclusiveStagingBeforeFirstWrite|RemoteUnsupportedStagingChmodFailsBeforeWrite|PosixRelRetainsDotTargetComponent|PosixRelMatchesFilepathRel)$' \
  -count=1 -v
```

PASS, `closing-permissions-and-rel-green.log`: explicitly logs **initial0644** and
**OPEN attrs0**. This is **pre-write chmod proof, not private-at-creation proof**.
The owner-accepted retained-descriptor exposure remains even after chmod.

Windows API preflight: Context7 `/golang/sys`,
`ctx7:docs:f6f182e2acf5c4bca68d2d0a`; exact installed
`golang.org/x/sys@v0.47.0/windows/{security_windows.go,zsyscall_windows.go}` for
GetCurrentProcessToken/GetTokenUser, SecurityDescriptorFromString, SecurityAttributes,
CreateFile, GetSecurityInfo and descriptor/ACE accessors. Existing T10
`internal/client/agent/runtime_windows.go` provides the repository owner/DACL
pattern; no agent refactor. Native test source was written before helper code,
but a native runtime RED is unavailable: declared exception before implementation,
strongest checks are source review, Windows test cross-compilation and full build.
**No native ACL/privacy/path/replacement test is claimed executed.**

### Earlier worker handoff validation — Go1.25.14 linux/amd64

These are historical worker runs before the P1 finding. They do not supersede
the later parent full-suite failure or the P1 follow-up results below.

```sh
go test ./internal/client/sftp ./cmd/warden ./internal/client/agent -count=1 -timeout=180s
# PASS: SFTP0.064s / CLI0.123s / agent11.651s

go test -race ./internal/client/sftp ./cmd/warden ./internal/client/agent -count=1 -timeout=180s
# PASS: SFTP1.174s / CLI2.315s / agent15.364s

go test -race ./internal/client/sftp \
  -run '^Test(RemoteEntryNamesRejectedBeforeJoin|CopyTargetContainment.*|CopyExplicit.*|PrivateExclusiveStagingBeforeFirstWrite|ExclusiveStagingCollisionsPreserveExisting|RemoteUnsupportedStagingChmodFailsBeforeWrite|CopyFailurePreservesOldTargetAndCleansStage|ActualSFTPHostileListingRejectedBeforeJoin)$' \
  -count=25 -timeout=180s
# PASS:1.626s

go test ./... -count=1 -timeout=180s
# PASS all packages; DB0.088s, SFTP0.096s, runtime17.672s.

go vet ./...
# PASS

GOOS=windows GOARCH=amd64 go test -c ./internal/client/sftp -o /tmp/warden-t11-resumed-eZlNHD/sftp.test.exe
GOOS=windows GOARCH=amd64 go test -c ./internal/client/agent -o /tmp/warden-t11-resumed-eZlNHD/agent.test.exe
GOOS=windows GOARCH=amd64 go test -c ./cmd/warden -o /tmp/warden-t11-resumed-eZlNHD/cli.test.exe
GOOS=windows GOARCH=amd64 go build ./...
# All PASS — compile/build only, not native execution.
```

Final handoff logs `/tmp/warden-t11-resumed-eZlNHD/handoff-{packages,race,boundaries-race25,full-go,vet}.log`.
Earlier full-Go runs also passed. Closing self-review isolated the fault reader's
Close error to the source-close case, so read/cancellation checks no longer also
inject a close error. This final set includes that refinement, the explicit-dot
compatibility RED→GREEN, real remote dot/root characterizations, partial-write
and denied-chmod coverage. All Windows test binaries/builds were refreshed
against this final source, still compile-only. Earlier DB intermittence is unresolved,
not called fixed because DB passed now. No full-repository race, frontend/browser,
genuine PRF or native Windows execution was run/claimed for this task.

### Remaining risks and stop boundary

- **Explicitly accepted:** initial remote public creation/retained-descriptor
  race, including later reads or writes if initially allowed. No claim of full
  original private-staging guarantee. Future cp-to-rsync replacement is outside
  this PR; no replacement implementation or migration is present.
- Server permissions and PosixRename semantics must be honored; no fallback
  weakens chmod or deletes the old target. A connection lost after the server
  applies rename but before its reply can leave the commit outcome ambiguous;
  injected pre-commit rename failures do not prove otherwise. If the server/transport prevents
  cleanup, failure is returned and a stage can remain. Cancellation coverage is
  a source returning context.Canceled after open; this is not a new interruptible
  Copy API or SSH/channel cancellation guarantee (T12 remains separate).
- Native Windows traversal/ACL/collision/replacement execution and independent
  review remain required. Cross-compilation does not prove them. Existing
  ancestor Lstat checks do not constitute a concurrency-safe filesystem root.
- No T12, module/version, publication, deployment, production data or protected
  file operation. Scoped source/test/diff self-review completed; explicit
  16-owned-file whitespace/newline/local-link scan, all11 Go file gofmt checks
  and tracked diff whitespace checks pass. No staged files; branch/HEAD remain
  `hieudmg/security-hardening` / `78f8090`; `go.mod`/`go.sum` unchanged. Protected
  `mise.toml` excluded before content checks, never read/changed.
  Stop here. Recommended next: independent review/native Windows acceptance of
  revised T11, then separately authorized T12—not a release/security-certification claim.

## P1 source identity follow-up — closed on owner review

Reviewer claim verified against actual code: Copy assigned `filepath.Abs` /
`path.Clean` back to source.Path before its first source Lstat. For
`work/link -> data/nested`, raw `work/link/../file` reads `data/file`, but lexical
cleaning selected `work/file`. This was a static wrong-source bug, not only a
TOCTOU limitation. The same normalization hid invalid source components and
unsafe destination components. No CLI/agent operand rewrite is needed to reach
it; the adapter passes these operands through.

### Actual RED before this behavior fix

Added repository tests first, then ran:

```sh
go test ./internal/client/sftp \
  -run '^TestCopySource(OperandIdentity|InvalidUncleanedOperand|AncestorAliasRejectsDescendant)$' \
  -count=1 -timeout=60s -v
# FAIL:0.009s, source-identity-red.log

go test ./internal/client/sftp -run '^TestCopyDestinationOperandIdentity$' \
  -count=1 -timeout=60s -v
# FAIL:0.006s, destination-identity-red.log
```

Both actual local and actual pinned SFTP adapters reproduced the failures:

- `TestCopySourceOperandIdentity`: a direct adapter Open of the raw absolute
  operand independently read `operational bytes`; Copy instead returned success
  and created a destination from the lexically substituted file. Trailing
  slash/dot variants already passed and are retained as characterizations, not
  fabricated REDs. The later local-relative variant is added passing coverage.
- `TestCopySourceInvalidUncleanedOperand`: a missing or regular-file prefix
  followed by `..` failed original Lstat but Copy normalized it away and replaced
  the synthetic old target with different data. All four cases failed.
- `TestCopySourceAncestorAliasRejectsDescendant`: a source-ancestor link, with
  plain, parent-component and trailing-slash spellings, bypassed containment and
  created a directory in its real absolute descendant before reaching the
  bounded test-only ReadDir guard. All six local/SFTP cases failed; no unbounded
  recursion was allowed.
- `TestCopyDestinationOperandIdentity`: original destination symlink, missing
  and non-directory components followed by `..` were erased; all six cases
  succeeded and replaced the lexically selected old target.

Logs are under `/tmp/warden-t11-resumed-eZlNHD/`. Fixtures use disposable trees
and in-process pinned NewClientPipe/NewServer, not a mocked source resolver.
Their absolute POSIX operands reach the OS uncleaned; the real server is not a
chroot. Ancestor Lstat checks inspect metadata up to the filesystem root; no
host-root enumeration/content copying or live connections/data/ACL mutations.

### Fix and preserved boundaries

`Filesystem.CheckPath` is a bounded adapter operation: local resolves only the
working directory/drive, concatenating the untouched operand; remote uses raw
POSIX spelling. Shared prefix inspection uses slicing, never Join/Dir/Clean.
Existing symlink components fail before `..` or trailing slash/dot can hide them;
non-directory intermediates fail, and a missing prefix followed by `..` fails
instead of normalizing onto another existing destination. Missing normal
creation parents remain supported. Local drive/UNC roots remain native; no
remote Windows reinterpretation, realpath protocol dependency or generic new
filesystem framework was added.

Copy checks both original operands first and keeps the operational source for
Lstat/Open/ReadDir. Separate local-absolute/remote-POSIX comparison paths retain
the mixed relative-source/absolute-descendant check. Source-ancestor aliases
fail under symlink policy before recursive reads or target writes, rather than
being followed or silently substituted. Existing entry checks, explicit caller
dot/root contents-target behavior, same-host policy, exclusive staging,
collision integrity, old-target preservation and cleanup remain covered.
`TestCopySourceOperationalSpellingPreserved` adds a positive real-adapter check:
ordinary existing `nested/../file` is copied, with the exact operand retained for
both Lstat and Open. This was additional passing coverage, not a claimed RED.

Context7 `/pkg/sftp` `ctx7:docs:17ab869bb3b15fc46e522b84` was refreshed before
new test calls; exact installed v1.13.11 client Lstat packet construction sends
Path unchanged. Official `server_unix.go:10–16` leaves absolute paths unchanged;
its working-directory Join cleans relative paths, so real-SFTP identity proofs
intentionally use absolute disposable operands. RealPath was not introduced:
its availability does not establish universal server symlink resolution, and
following aliases is unnecessary under this explicit rejection policy.

### Fresh validation after follow-up

```sh
go test ./internal/client/sftp ./cmd/warden ./internal/client/agent -count=1 -timeout=180s
# PASS: SFTP0.091s / CLI0.169s / agent11.801s

go test -race ./internal/client/sftp ./cmd/warden ./internal/client/agent -count=1 -timeout=180s
# PASS: SFTP1.232s / CLI2.356s / agent15.863s

go test -race ./internal/client/sftp \
  -run '^Test(Copy(Source(OperandIdentity|OperationalSpellingPreserved|InvalidUncleanedOperand|AncestorAliasRejectsDescendant)|DestinationOperandIdentity|TargetContainment.*|Explicit.*)|ExclusiveStagingCollisionsPreserveExisting|RemoteUnsupportedStagingChmodFailsBeforeWrite|PrivateExclusiveStagingBeforeFirstWrite|ActualSFTPHostileListingRejectedBeforeJoin|RemoteEntryNamesRejectedBeforeJoin)$' \
  -count=25 -timeout=180s
# PASS:1.941s

go vet ./...
# PASS

GOOS=windows GOARCH=amd64 go test -c ./internal/client/sftp -o /tmp/warden-t11-resumed-eZlNHD/p1-sftp.test.exe
GOOS=windows GOARCH=amd64 go test -c ./internal/client/agent -o /tmp/warden-t11-resumed-eZlNHD/p1-agent.test.exe
GOOS=windows GOARCH=amd64 go test -c ./cmd/warden -o /tmp/warden-t11-resumed-eZlNHD/p1-cli.test.exe
GOOS=windows GOARCH=amd64 go build ./...
# PASS: compilation/build only, no native execution.
```

Logs: `p1-final-{packages,race,boundaries-race25}.log`, `p1-vet.log`,
`p1-windows-cross.log`; focused GREEN in `source-identity-green.log` preceded
added positive and relative variants, which are included in the final runs.

**Latest parent independent full-Go run was NOT green:**
`/tmp/warden-t11-parent-full.log` records only
`internal/client/db/TestTunnelCloseClosesWholeChain` failing after5.01s:
`ssh server still has 1 open connections` (`tunnel_test.go:255`). SFTP passed
that parent run. No new full-Go run was performed for this follow-up, and older
worker full-Go passes do not supersede that failure. No DB/T12 fix or resolved
lifecycle claim is made.

Remaining limits are unchanged: no universal ancestor-swap/TOCTOU protection,
no filesystem case-canonicalization guarantee, native Windows traversal/ACL/
replacement execution still required, and the initial remote public-creation
retained-descriptor race remains explicitly accepted. No full original private-
staging satisfaction or security-release acceptance. Only the four SFTP source/
test files and security/report/plan/ledger were changed in this follow-up. No
dependency/version, stage/commit/push/deployment, protected-file or T12 work.
Closing follow-up self-review read the four changed SFTP source/test files and
actual tracked diff. Explicit16-owned-file newline/whitespace/local-link checks,
all11 Go-file gofmt checks, `git diff --check`, unchanged-module checks and empty
staging checks passed. Branch/HEAD remain `hieudmg/security-hardening` / `78f8090`.
**P1 is closed on the owner's subsequent review.** Its operational-path fix
remains retained; the bounded P2 follow-up below is the current checkpoint.

## P2 Windows root-spelling follow-up — current rereview checkpoint

Owner review identified a separate compatibility bug in destinationPath:
`Dir(source.Path) == source.Path` compared a normalized parent to the raw source.
On Windows, `Dir("C:/")` is `C:\` and Base is `\`; the failed root comparison
sent that basename into containedChild, which correctly rejected it as unsafe.
Canonical `C:\` worked. Root spellings must retain contents-into-existing-target
semantics without weakening entry checks or reopening the closed P1.

### Native TDD exception and source evidence

**Before test or production edits**, commentary and the ledger explicitly
recorded the native TDD exception: this is Go1.25.14 linux/amd64, with no native
Windows runtime. Native Windows RED/GREEN cannot be claimed. The strongest
feasible checks are a host-independent dispatch regression and Windows-only
native-path unit tests cross-compiled, not executed.

Inspected the installed Go1.25.14 sources, not guessed Windows APIs:
`src/path/filepath/path_test.go` Windows Clean cases at84, Base at980 and Dir
at1026; `src/internal/filepathlite/path.go` Base225 and Dir251; native Abs in
`src/path/filepath/path_windows.go`. They establish slash normalization,
root Base `\`, and drive/UNC Dir behavior. No third-party API or dependency
change is involved.

### Effective host RED, then minimal fix

Added `internal/client/sftp/root_source_test.go` and
`internal/client/sftp/root_source_windows_test.go` before the behavior fix.

```sh
go test ./internal/client/sftp \
  -run '^TestCopy(RootSourceSpellingContentsTarget|NonRootSourceSpellingStillAppendsBasename)$' \
  -count=1 -timeout=60s
# FAIL:0.005s, p2-root-spelling-corrected-red.log
```

The deterministic host fake returns Windows normalization/Dir/Base values, not
an alternative production Windows parser. `C:/`, mixed-slash drive roots,
forward/mixed UNC roots and the forward-slash rooted form failed before source
ReadDir with unsafe basename `\`. Canonical drive/UNC/backslash-root forms and
the non-root placement control already passed. Each root also tests unsafe
listed entries: failure must be after reaching raw source ReadDir, not an
unrelated basename rejection. Initial `p2-root-spelling-red.log` had an inaccurate
fake Dir result for the unqualified backslash root; corrected it against Go
source and reran the RED above **before production edits**. No native RED is
claimed from these host fakes.

Production change is only in `transfer.go` destinationPath: for a directory
source and an existing destination directory, compute a separate cleaned
sourceComparison and test `Dir(sourceComparison) == sourceComparison` for root
recognition. The original endpoint path is never assigned that value. Source
CheckPath/Lstat/Open/ReadDir and P1 policy stay operational/raw; a Clean error
propagates. Explicit dot behavior is retained. Ordinary directories still append
their basename, and recursive entries still pass the same portable validator.
No new architecture, filesystem API or special case allowing root-like entries.

Tests cover `C:/`, `C:\`, mixed separators ending in backslash and slash, `/`,
`\`, and standard UNC roots with no trailing separator, backward/forward
separators and mixed-final-backslash forms. The Windows-only test uses the
actual NewLocalFilesystem path functions, with all source/root I/O faked;
only disposable destination directories are created/inspected/chmodded. Final
fixture hardening also fakes destination ancestor metadata, so it does not stat
real drive roots. No real drive/UNC root is enumerated or opened, and no live
remote filesystem is used by these root-spelling tests. The ordinary-source
control checks that exactly its basename directory is created. Empty-root
contents dispatch and malicious-entry rejection keep exact raw source metadata/
ReadDir spellings and never source-join a root or unsafe entry.

Focused GREEN plus the closed-P1 regressions, existing explicit dot/root and
mixed relative/absolute containment ran in `p2-root-spelling-green.log` (0.015s).
After final destination-metadata fixture isolation, the following fresh runs
include all final test source:

```sh
go test ./internal/client/sftp ./cmd/warden ./internal/client/agent -count=1 -timeout=180s
# PASS: SFTP0.088s / CLI0.150s / agent11.780s

go test -race ./internal/client/sftp ./cmd/warden ./internal/client/agent -count=1 -timeout=180s
# PASS: SFTP1.227s / CLI2.321s / agent15.582s

go test -race ./internal/client/sftp \
  -run '^Test(Copy(RootSourceSpellingContentsTarget|NonRootSourceSpellingStillAppendsBasename|Source.*|DestinationOperandIdentity|TargetContainment.*|Explicit.*)|RemoteEntryNamesRejectedBeforeJoin|ExclusiveStagingCollisionsPreserveExisting)$' \
  -count=25 -timeout=180s
# PASS:1.948s

go vet ./...
# PASS

GOOS=windows GOARCH=amd64 go test -c ./internal/client/sftp -o /tmp/warden-t11-resumed-eZlNHD/p2-sftp.test.exe
GOOS=windows GOARCH=amd64 go test -c ./internal/client/agent -o /tmp/warden-t11-resumed-eZlNHD/p2-agent.test.exe
GOOS=windows GOARCH=amd64 go test -c ./cmd/warden -o /tmp/warden-t11-resumed-eZlNHD/p2-cli.test.exe
GOOS=windows GOARCH=amd64 go build ./...
# PASS: compilation/build only, NO native Windows execution.
```

Logs `/tmp/warden-t11-resumed-eZlNHD/p2-final-{packages,race,boundaries-race25,vet,windows-cross}.log`.
No full-Go rerun was needed/performed; the latest parent DB-only failure in
`/tmp/warden-t11-parent-full.log` remains unresolved and is not superseded.
Native Windows root-spelling/ACL/traversal/replacement execution remains required.
The accepted initial remote retained-descriptor race and non-race-proof ancestor
checks remain unchanged; no full original T11 or security-release acceptance.
This follow-up changes only transfer.go, the two new root test files, this
report and the ignored ledger. No commit/stage/T12, dependency/version,
production data, deployment or protected `mise.toml` operation. Closing review
checked the source/test changes and report against measured output: explicit18-
owned-file whitespace/newline/local-link scan, all13 Go-file gofmt checks and
`git diff --check` passed; module files are unchanged, nothing staged, branch/
HEAD still `hieudmg/security-hardening` / `78f8090`.
**Stop for independent rereview.**
