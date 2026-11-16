# Native Windows follow-up — PR #45

## R3 parent local checkpoint — push held for terminal failure

Independent review found no issues in the bounded R3 helper/fixture patch,
verified all 9 task paths, 461 inputs and 41 evidence files, and retained the
separate terminal validation blocker. Parent freshly passed upgrade race tests
and upgrade vet: `/var/tmp/warden-windows-r3-parent-{upgrade-race,vet}.log`.
Parent inspected the actual failed broad-race stack and Unix source; this is a
real send/close race, not a waived baseline failure. Checkpoint the reviewed
Windows changes locally, then fix and independently verify terminal ownership
before the next push. R3 is still native UNRUN and certutil is still a candidate,
not established noninteractive success. No release/signing approval follows.

## R2 parent diagnostic-push checkpoint

Independent rereview found no issues in the second diagnostic patch, matching
all 6 task paths, 461 listed inputs and 42 evidence files. Parent separately
freshly passed the streaming/helper diagnostic race tests at count10, full Go
and vet: `/var/tmp/warden-windows-r2-parent-{focused,full,vet}.log`.
This supports a bounded diagnostic push only. No production helper/C# change,
native GREEN, merge, manual signing or release approval follows.

## Parent diagnostic-push checkpoint

Independent review found no issues in this bounded test-only patch, verified the
9 task files, 460 listed inputs and 34 evidence files, and approved it for a
diagnostic push only. The reviewer did not execute tests or have native Windows.
Parent separately freshly passed the focused extractor/diagnostic contracts,
full Go suite, upgrade race suite and vet under Go1.26.11. Logs:
`/var/tmp/warden-windows-parent-{focused,full,race,vet}.log`.
The native helper cause remains unknown; no production fix or native GREEN is
claimed. Existing draft PR #45 may receive this reviewed diagnostic checkpoint
so automatic read-only CI exposes the first native exception. No manual rerun,
dispatch, signing, merge, release or production operation is authorized.

## Authority, baseline and pre-edit exception

Bounded bugfix/diagnostic task on `hieudmg/security-hardening`, baseline
`d8aa80213e8977d3aaa453afa08b7a972c9f3719`. Sole writer; parent alone may
review/commit/push/update draft PR #45. No service/installer/downloaded-binary
execution, workflow dispatch/rerun, signing/publication, global-tool changes,
protected `mise.toml` content access, staging or Git history changes authorized.
Release **0.23.0** stays unchanged in all three fields. Existing Python cache
residue and prior evidence are unrelated and preserved.

**Recorded before edits:** Windows PowerShell 5.1/.NET Framework is unavailable
on this Linux host (`powershell.exe` and `pwsh` not found). Native helper runtime
TDD is therefore infeasible here. Original hosted RED is real symptom evidence,
not proof of its cause. Use deterministic portable RED→GREEN for the actual
shared C# extractor; investigate official version-specific contracts before any
production helper fix. If the suppressed helper exception remains unknown,
retain production behavior and add bounded test-only diagnostics for a
parent-reviewed diagnostic push. Cross-compilation is compile-only, not native
GREEN. No timeout inflation, skipped acceptance or weaker assertions.

Private evidence root: `/var/tmp/ww.da24`; `TMPDIR=/var/tmp`, exact
`GOTOOLCHAIN=go1.26.11` for Go checks. Ledger baseline was snapshotted before edits.

## Observed hosted RED

Run [43786023388 attempt 1](https://github.com/hieudmg/warden/actions/runs/43786023388),
`pull_request` event head `d8aa80213e8977d3aaa453afa08b7a972c9f3719`, checked out PR
merge `c987a687d308ab39e1bb55f138016295e33a4b1f` with base
`c10435358456dda0c1044fa5606b6ab5af014eef` (base identity supplied by parent).
Linux job `133033735087` succeeded (parent-read evidence); Windows job
`133033735279` failed on Server2025, PowerShell5.1.26100.33648,
.NET release533509, Go1.26.11.

Parent failed log `/var/tmp/warden-pr45-windows-parent.log` was read directly;
full Windows job log obtained by read-only GET:

```sh
gh api --allow-escape-sequences repos/hieudmg/warden/actions/jobs/133033735279/logs > /var/tmp/ww.da24/windows-full.log
```

Initial GET without `--allow-escape-sequences` refused terminal escape sequences
(exit1); the explicit data-file GET succeeded (exit0). No log was executed.

Correct arithmetic: agent7 PASS + SFTP5 PASS + upgrade private-stage1 PASS =
**13/16 top-level PASS, three required top-level FAIL, zero reported skips**.
Helper locked-failure subtest passed; replacement subtest failed exit1 after
1.51s, with only CLIXML module-preparation progress, not the suppressed exception.
Both C# tests failed at LF-only extraction before C# compilation or trusted-CA
installation/cleanup assertions.

Checkout log confirms Git2.56.0.windows.4 and exact merge checkout, but does not
print `core.autocrlf` or actual file bytes. There are no tracked `.gitattributes`
files; `git check-attr --all -- scripts/install-client.ps1` is empty and local
`git ls-files --eol` reports index/worktree LF. CRLF checkout is a hypothesis
consistent with the hosted symptom; synthetic CRLF reproduction can prove the
extractor defect, not retrospectively measure hosted file bytes.

## Reproduction and minimal test-only changes

### Confirmed portable extractor defect — RED → GREEN

Both native tests now call **one test-only** `installerDownloaderSource` in
`internal/upgrade/common_test.go`; the initial shared implementation was the
unchanged LF-only `strings.Cut` logic from those tests. New source-named
`installer_source_test.go` executes that actual shared function against both LF
and CRLF versions of the **actual** `scripts/install-client.ps1`. An independent
line-based oracle selects the entire C# block; equality checks every byte after
line-ending normalization and excludes installer entry-point code. Negative
cases reject absent/wrong start, absent/wrong end and empty source.

Actual focused command before the extraction fix:

```sh
TMPDIR=/var/tmp GOTOOLCHAIN=go1.26.11 go test ./internal/upgrade -run '^TestInstallerDownloaderSource' -count=1 -v
```

`extractor-red.log`, exit1: LF passes; CRLF fails `missing embedded downloader`.
The old logic also accepts wrong closing-marker suffix and empty source. Minimal
fix normalizes CRLF before matching, requires a standalone closing boundary and
rejects empty source. Same command then passes (`extractor-green.log`, exit0).
No product API, Git attributes/configuration, production C#, installer entry
point, HTTPS/ACL/checksum/rollback behavior or CA-store fixture logic changed.

Separate deterministic **Git's own filter** experiment (no config mutation):

```sh
git -c core.autocrlf=true cat-file --filters HEAD:scripts/install-client.ps1 > /var/tmp/ww.da24/install-client-crlf.ps1
```

`checkout-eol.json` records CRLF counts, input/output hashes and exact equality
after normalization. The old start marker is absent in this filtered actual
script. This establishes an ordinary checkout transformation that reproduces
the symptom; it does not prove the unrecorded original hosted bytes.

### Helper: cause remains unconfirmed; diagnostic push required

No production helper change was made. In particular, `upgrade.go` and
`replace_windows.go` remain byte-identical to baseline: atomic
`[IO.File]::Replace($source, $target, $null)`, production90s retry/30s parent wait,
encoded command/environment paths, private staging, detached scheduling and
failure cleanup are intact. No delete/move substitution, forced cutover or
permission weakening.

API investigation used Context7 `/powershell/powershell`; its returned current
source excerpt did **not** settle Desktop5.1 method binding. Official versioned
Microsoft documents were then read and saved as data, not executed:

- [NullString, PowerShell5.1 reference assembly](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.language.nullstring?view=powershellsdk-1.1.0): explicitly provides a way to pass null to a .NET string parameter.
- [File.Replace, .NET Framework4.8.1](https://learn.microsoft.com/en-us/dotnet/api/system.io.file.replace?view=netframework-4.8.1): pass null for no backup; malformed backup paths can fail.
- [PowerShell language conversions](https://learn.microsoft.com/en-us/powershell/scripting/lang-spec/chapter-06?view=powershell-7.1): null-to-string conversion is empty string. This is general language documentation, **not exact proof of the installed5.1 overload binder**.

These support a **hypothesis**, not a demonstrated cause: `$null` could become
an empty backup string at the PowerShell/.NET boundary. Existing CLIXML gives no
exception type/message/HRESULT and cannot distinguish binding from filesystem
failure. An attempted Microsoft reference-source raw lookup returned no usable
source; it is not evidence of exact implementation. No unsupported production
substitution to `NullString`, retry/budget change or passing-rerun waiver follows
from this investigation.

Instead, `replace_source_test.go` adds a **test-only** transformation of the
actual helper's uniquely matched retry catch. It reports only the first failure,
at most four exception-chain entries (type, HRESULT and message), then continues
the unchanged sleep/retry/cleanup. The ordinary file/path fixture contains no
secrets; there are no environment dumps, stack traces or production logging.
A portable source contract checks that removing only that inserted diagnostic
block recovers the exact production program. This is structural characterization,
not native execution or runtime RED→GREEN.

`replace_windows_test.go` retains the original ordinary-path replace and
locked-failure cases and adds corresponding metacharacter-path cases (`%`, `&`,
`'`, brackets) using the same environment-only argument flow. Every case retains
old/new byte assertions, source cleanup, directory inventory, join check, the
existing1s test retry and8s subprocess bound. The top-level16-name CI matrix is
unchanged; no test is bypassed or accepted merely for returning any exit code.
The original ordinary-path failure must still pass on native Windows before
acceptance. **The diagnostic change is not claimed to fix it.**

## Current-source local validation

All Go commands use `TMPDIR=/var/tmp GOTOOLCHAIN=go1.26.11`. Instrumented command
argv/UTC times/exits are in `commands.jsonl`. Early extractor RED/GREEN and Git
filter experiment predate that recorder; their actual commands are above and
original logs are retained. Python validation sets
`PYTHONDONTWRITEBYTECODE=1`; unrelated existing cache remains untouched.

| Command / evidence | Actual result |
| --- | --- |
| `go test ./internal/upgrade -run '^(TestInstallerDownloaderSource\|TestWindowsHelper)' -count=1 -v` (`focused-final-current.log`) | PASS portable extraction, helper argument/source/lifecycle contracts and diagnostic-only source contract; no Windows runtime proof |
| `go test -json ./... -count=1 -timeout=180s` (`final-full-go.log`) | PASS26.36s;790 top-level passes, three explicitly recorded test skips |
| `go test -race -json ./internal/upgrade ./internal/client/... -count=1 -timeout=180s` (`final-upgrade-client-race.log`) | PASS17.86s;335 top-level passes, one explicit test skip |
| `go vet ./...` (`final-vet.log`) | PASS |
| `GOOS=windows GOARCH=amd64 go test -c -o /var/tmp/ww.da24/upgrade.test.exe ./internal/upgrade` (`windows-final-compile.log`) | PASS **compile-only**, never executed |
| `bash scripts/test-installers.sh` (`installers.log`) | PASS offline wrappers, not live installation/service execution |
| `python3 scripts/installers_test.py` (`installer-https.log`) | PASS four methods/matrices, actual curl/private verified-TLS fixtures |
| `python3 -m unittest discover -s scripts/ci -v` (`ci-contracts.log`) | PASS all12 offline CI contracts; fake publication only |
| `/var/tmp/w16.Bmqg/bin/actionlint -shellcheck= -pyflakes=` (`actionlint.log`) | PASS existing private pinned1.7.12; optional shellcheck/pyflakes unavailable, not claimed run |

Final Go JSON summaries are in `test-summary.json`. Full Go skips the two opt-in
browser fixture servers and `TestRuntimeUnixRejectsWrongOwner` (no chown privilege).
Client race skips only that wrong-owner fixture. Windows build-tagged tests are
absent on Linux, **not** counted as passing or skipped-native evidence. Full/race
results were refreshed after the final test-source changes, not inferred from
previous passes. Python3.12.15, PyYAML6.0.3, curl8.18.0/OpenSSL3.5.5; no tools
installed. Existing frontend/browser/production-build and scan evidence is
historical for unchanged inputs; no fresh browser, PRF, vulnerability scan,
release build or full-repository race run is claimed here.

## Self-review and delivery

Changed scope: six test-only Go files (three existing/native, three new/shared
portable), this report, append-only plan checkpoint and ignored ledger delta.
No production source, embedded C#, installer, workflow/pin/privilege/type/byte/
source/run guard, frontend/dependency/version file changed. Three release fields
remain0.23.0. All task Go files are formatted; whitespace checks and complete
patch reverse-apply checks are run without changing the index. The baseline
ledger prefix is preserved byte-for-byte. Protected content is excluded before
file enumeration/read/hash/diff construction; unrelated artifacts are preserved.

Parent review artifacts:

- `/var/tmp/warden-windows-review.diff`: complete original `d8aa802` → current
  task diff, including all new files and **only** this task's ignored-ledger delta.
- `/var/tmp/warden-windows-review.json`: task hashes, tracked source/runtime-input
  hashes and baseline comparisons, compiled fixture binary and evidence hashes,
  ledger baseline/full/delta hashes and review patch hash.
- `/var/tmp/warden-windows-review.sha256`: diff/manifest checksums, private binding
  only, not independent authentication or signed provenance.

**Disposition: portable fixture fix locally verified; native bugfix outcome
INCOMPLETE / requires diagnostic push.** Parent should independently review and
freshly check the exact patch, then decide whether to commit/push the bounded
extractor fix and diagnostics to the existing draft PR for automatic read-only CI.
This worker performs no push, PR edit, rerun/dispatch or publication. Diagnose
the next native exception before approving a production helper fix; all16 named
native tests must ultimately pass exactly once with zero skips, including actual
C# compilation/verified HTTPS, private ACLs/collisions, rollback, both ordinary
and metacharacter helper paths, locked-target preservation and CA cleanup.

Original13/3 is not native acceptance. Genuine PRF/production trust, privileged
Unix cross-owner and hosted artifact/OIDC/signature gates remain open. The narrow
T16 owner-accepted Undici trusted-service/proxy and Sigstore PAE risks do not
waive any gate or authorize manual signing/public attestations/transparency writes.
No task checkbox is completed. Stop at this bounded self-review/report.

## Round 2 — new native evidence and pre-edit exception (2026-11-16)

Resumed at parent-committed/pushed `6c385371681d654f0691696db99951cd518a4810`.
Authority and prohibitions are unchanged; parent alone controls delivery.
Private evidence `/var/tmp/ww2.ckkE`, baseline ledger `ledger.before.md`.
Actual logs read: `/var/tmp/warden-pr45-hosted/43789164306.log` and
`43789164306-windows-job.log`; copies are evidence data, never executed.

Run43789164306 attempt1, pull_request head6c385371, actually checked out merge
`0fbbf0afd1e2898b613351387e4aca3588a9bb00` into basec104353. Linux133043430649
succeeded; Windows133043430885 failed on the same PS5.1/.NET533509/Go1.26.11.
Correct **current** arithmetic: agent7 + SFTP5 + upgrade2 = **14/16 top-level
PASS, two FAIL, zero reported skips**. Original13/3 above remains historical.
The private-files/HTTP-refusal actual-C# test now passes. Helper ordinary and
metacharacter positives fail with inner System.ArgumentException
HRESULT-2147024809, `The path is not of a legal form`; outer method invocation
HRESULT-2146233087. Locked negatives report the same invalid-path error, so
those passes do **not** yet prove sharing-lock handling. HTTPS matrix reaches
its2min process-context boundary (120.70s) with only CLIXML progress; no existing
phase evidence proves compilation, CA insertion or any Download executed in
that process. Independent cleanup produced no error, **not proof of CA absence**.

**Before round-2 code edits:** native PS5.1 remains unavailable locally. Keep
native runtime TDD exception explicit: original hosted RED is real, but neither
cross-compilation nor source contracts establish native GREEN. .NET reference
source resolved from Microsoft main to commit
`ec9fa9ae770d522a5b5f0607898044b7478574a3` shows File.Replace normalizing a
backup iff non-null, and empty-path normalization throwing Arg_PathIllegal.
The official PS5.1 NullString reference documents the supported true-null string
argument. Context7 again returned irrelevant current environment-provider source;
PowerShell6 source is supplementary only, not installed5.1 binder proof. An
initial raw URL used an annotated-tag object and returned404; dereferenced source
was obtained separately. Exact observed argument values are still missing.
Accordingly retain production helper for now and add test-only actual-argument,
C# literal-null and PowerShell null/NullString comparison probes on disposable
copies. Do not substitute a speculative production fix for that evidence.

HTTPS stall is likewise unlocalized. Add streamed fixed phase labels around
runtime/assembly/compilation/certificate/store/add/download/cleanup operations,
first exception type/HRESULT, fixture-only peer/request counts, context outcome
and exact-CA absence checks. Preserve every production constant and TLS/chain/
revocation check, all matrix assertions and the2min/20s fixture budgets. Test the
portable log streaming/cancellation join seam first where feasible; native phase
execution itself remains UNRUN locally. No timeout increase, TLS bypass, broad
trust mutation, production C# instrumentation, new workflow/signing or live
installer/service execution is authorized. Stop after bounded checks/report for
parent review and a possible next diagnostic push if runtime cause stays open.

### Round-2 implementation: diagnostic-only, not a production fix

- `replace_source_test.go` prefixes the existing fixture-only helper diagnostics
  with a small PS5.1/C# boundary probe. It checks the source/target strings equal
  the exact environment values, normalizes both with .NET Path.GetFullPath and
  requires both files exist. It never prints their paths or the ambient
  environment. File.Replace controls operate only on exclusively copied,
  disposable sibling marker files; ownership flags clean only successful copies.
  C# literal-null control must replace successfully. PowerShell `$null` records
  the actual received null/empty string and replacement/refusal result; explicit
  `[System.Management.Automation.Language.NullString]::Value` must replace those
  copies successfully. Nonempty backup arguments are refused before filesystem
  use. These probes leave the actual helper inputs unchanged before its existing
  ordinary/metacharacter success and locked-failure cases run. The portable
  source contract removes just the probe prefix/diagnostic insertion and still
  reconstructs the exact production helper. Probe C# compilation/execution is
  **UNRUN locally**, not established by Go cross-compilation.
- `installer_https_windows_test.go` now streams stdout and stderr line-by-line
  through the same portable runner tested below. Fixed phase labels surround
  runtime checks, HTTP assembly load, compilation of the unchanged actual C#,
  certificate load, CurrentUser store open/add, each private directory/download,
  and certificate cleanup. At most four exception-chain types/HRESULTs are
  emitted; no environment, key/certificate bytes or raw URL/query is dumped.
  Fixture-owned origin/CDN connection transitions, payload handler begin/end,
  CRL requests and aggregate counters supplement the process labels. A handler
  end label is **not** a goroutine-join claim. Existing httptest cleanup remains.
- Main and independent cleanup additionally assert the exact generated
  thumbprint is absent after removal, while independent removal still compares
  exact DER bytes before touching any certificate. There is no LocalMachine
  access or broad trust-store purge. Native absence assertions and store phases
  are **UNRUN**; no prior cleanup success is retroactively promoted to proof.
- New `powershell_fixture_test.go` owns the narrow output runner: separate
  stdout/stderr partial-line buffers capped at1024bytes prevent unbounded CLIXML
  buffering and prevent stderr fragments hiding stdout phase labels. Cmd.Run
  waits for the owned process and its output-copy goroutines before flushing
  final partial lines; the actual context error is logged after that join.
  Native budgets remain2min matrix/20s independent cleanup; helper retains1s
  test retry/8s subprocess and production90s retry/30s parent wait. C# download
  budget remains5min, deliberately **not** accommodated by increasing the
  fixture limit. A stall inside that mismatch still fails with a useful phase.

No production helper/C#, installer, workflow, privilege/pin/byte/type/source/run
check, authentication/crypto, release field or TLS/hostname/revocation policy
changed. No atomic replacement workaround, timer inflation or assertion
weakening. The new checks strengthen diagnostics/CA absence only. Null backup
coercion is still a hypothesis until the actual native boundary probe reports;
HTTPS cause is still unknown. Next native run may still fail—this is intentional
honest diagnosis, not an all16-pass claim.

### Round-2 measured RED/GREEN and validation

The streaming diagnostic capability, **not the unknown HTTPS cause**, has a
portable focused RED→GREEN. The initial extracted runner retained the old
CombinedOutput behavior. A real child test process prints a phase then blocks;
its observer cancels only when that phase is delivered. Before implementation:

```sh
TMPDIR=/var/tmp GOTOOLCHAIN=go1.26.11 go test ./internal/upgrade -run '^TestPowerShellFixtureCommandStreamsAndJoinsOnCancellation$' -count=1 -v
```

`stream-red.log` exit1 at02:18:57UTC: phase is buffered until the2s fallback
context deadline, so phase-driven cancellation cannot work. Minimal streamed
bounded writer implementation makes the same test pass (`stream-green.log`,
exit0 at02:19:50UTC), with phase observed before cancellation and owned process
waited. This exact runner is now used by the native HTTPS fixture. A separate
fragment/CRLF/truncation test characterizes the1024-byte bound. Both pass race10
(`stream-race10.log`); this is real subprocess/logging proof on Linux, not a
PowerShell, TLS chain, CA-store or native root-cause proof.

All tests use exact Go1.26.11/TMPDIR=/var/tmp and Python validation suppresses
bytecode generation. `commands.jsonl` records test argv/UTC/exit/environment.
Early read-only source/log investigation precedes that recorder; API URLs and
source versions are in `api-sources.json`, and parsed actual hosted events and
correct14/2 summary are saved separately. Full authoritative hosted logs remain
unaltered in their original location and in this private evidence root.

| Current-source command / evidence | UTC start→end, 2026-11-16 | Result |
| --- | --- | --- |
| `go test -race ./internal/upgrade -run '^(TestPowerShellFixture\|TestWindowsHelper\|TestInstallerDownloaderSource)' -count=1 -v` (`focused-green.log`) | 02:24:36→02:24:38 | PASS portable source/extractor/stream contracts only |
| `go test -json ./... -count=1 -timeout=180s` (`full-go.log`) | 02:26:29→02:26:56 | PASS792 top-level tests; three explicit test skips |
| `go test -race -json ./internal/upgrade ./internal/client/... -count=1 -timeout=180s` (`upgrade-client-race.log`) | 02:26:29→02:26:48 | PASS337 top-level tests; one explicit skip |
| `go vet ./...` (`vet.log`) | 02:26:48→02:26:48 | PASS |
| Windows/amd64 `go test -c` upgrade fixture (`windows-final-compile.log`) | 02:26:48→02:26:49 | PASS **compile-only**, no PS/C# execution |
| `bash scripts/test-installers.sh` (`installers.log`) | 02:26:29→02:26:36 | PASS offline wrappers only |
| `python3 scripts/installers_test.py` (`installer-https.log`) | 02:26:36→02:26:39 | PASS four methods/matrices, actual curl/private verified TLS |
| `python3 -m unittest discover -s scripts/ci -v` (`ci-contracts.log`) | 02:26:39→02:26:41 | PASS all12 offline contracts; fake publication only |
| Existing private pinned actionlint1.7.12, optional analyzers disabled (`actionlint.log`) | 02:26:41→02:26:41 | PASS; shellcheck/pyflakes unavailable/not claimed |
| `go test -race ./internal/upgrade -run '^TestPowerShellFixture' -count=10 -timeout=30s -v` (`stream-race10.log`) | 02:28:33→02:28:34 | PASS both portable diagnostic tests10times, no native outcome inferred |

`test-summary.json` records the same three full-suite skips (two opt-in browser
fixture servers and unprivileged Unix wrong-owner); affected race skips only
wrong-owner. Windows build-tagged cases do not execute on Linux. Unchanged
frontend/browser/build/scan evidence stays historical; none was rerun or
upgraded to acceptance. No full-repository race claim. The new two portable
logging tests account for792 versus prior790, not additional native acceptance.

### Round-2 self-review and handoff

The complete `6c385371`→current patch includes all three changed/new test Go
files, this chronological report append, plan checkpoint and the whole new
ignored-ledger delta. Production inputs and0.23.0 remain baseline-identical.
Private review files are `/var/tmp/warden-windows-r2-review.diff`, `.json`,
`.sha256`; manifest binds task/source/runtime/evidence hashes and original
ledger prefix/delta, including source-only assembled native program inputs and
compile-only fixture binary. Protected content is excluded before reading or
hashing. No index/history/remote change or unrelated cleanup is performed.

**Required next step: parent independent review/fresh checks, then consider
another bounded diagnostic push to automatic PR CI. No production bugfix or
native GREEN is claimed in this round.** Obtain the actual argument-control
outcomes and last streamed HTTPS phase before approving a production change.
All16 named native tests once PASS/zero skips remains required, including
ordinary/metacharacter atomic replacement and genuine locked-target behavior,
actual C# trusted-HTTPS matrix/ACLs/rollback and verified exact-CA cleanup.
Genuine PRF/production trust, privileged Unix cross-owner and hosted artifact/
OIDC/signature gates remain open. The narrow T16 risk acceptance is not a gate
waiver or authorization for manual signing/dispatch/public attestations/tlog
writes. The outstanding manual-signing question is unanswered; no related work
was implemented or run. Stop after this bounded diagnostic self-review.

## Round 3 — demonstrated helper binding defect; Root insertion stall (2026-11-16)

Resumed at parent-reviewed/committed/pushed
`41fa49bab2c0078eed6339c68a966bf95e35fa34`. Same sole-writer authority and
prohibitions; no model/thinking override or fallback attempted. Evidence root
`/var/tmp/ww3.9hre`; original ledger snapshot `ledger.before.md`. Actual full/job
logs from run43793981262 attempt1 are copied as data only. Actual PR checkout
`f87c2d48cf129a4feff92421b3cce0f2f8dcda13`, basec104353; Linux133058505878
SUCCESS and Windows133058505659 FAIL. Latest **14/16 named top-level PASS,
two FAIL, zero reported skips**: agent7/SFTP5 aggregate PASS markers plus the
upgrade JSON's2PASS/2FAIL (do not mistake only the four printed upgrade JSON
results for the entire native matrix). Historical13/3 and14/2 above remain
unchanged. Native runtime PS5.1.26100.33648/.NET release533509/Go1.26.11.

**Pre-edit native TDD exception:** local powershell.exe/pwsh remain unavailable.
The hosted old-helper failures are native RED with matching successful boundary
controls, not locally reproduced native RED/GREEN. Add a portable focused
regression against the actual encoded helper, observe it fail for the old backup
expression, then make the minimal authorized production change. Portable source/
encoding GREEN and Go compile-only Windows cannot establish native GREEN;
ordinary/metacharacter positives and genuine sharing-lock negatives still need
actual future CI. Keep90s/30s production,1s/8s helper test and2min/20s HTTPS
budgets unchanged, with every assertion/security safeguard retained.

All four helper cases now show exact environment/legal existing source/target,
C# literal-null replacement PASS, PowerShell `$null` received as **empty** and
ArgumentExceptionHRESULT-2147024809/refusal, then explicit
`[System.Management.Automation.Language.NullString]::Value` received as **null**
and replacement PASS. The unchanged production helper then has the same illegal
backup-path failure. Combined with the saved official PS5.1 NullString contract
and Framework File.Replace null-backup handling, this isolates the third string
argument coercion—**no longer an unproven argument hypothesis**. Approved fix:
use that exact native-PASS true-null expression in atomic File.Replace, without
fallback/delete-move, cleanup/path/environment/lifecycle changes. Existing probe
controls remain for comparison; locked negatives must demonstrate genuine lock
failure, not accept another invalid-backup refusal.

HTTPS phases now establish actual C# compilation completed, certificate loaded,
CurrentUser Root store opened, and last reached `unique-CA-add:begin`; no add end
before the2min kill. All fixture connection/payload/CRL/exact/CDN/forbiddenHTTP
counts are0. Independent cleanup reports exact-certificate absence PASS and
process joined without error. Thus the stall is **at `$store.Add($ca)` before
network**, not an unlocalized compilation/TLS/network failure. UI consent is a
hypothesis, not observed fact. Parent's independent read-only scout owns official
noninteractive-import research; do not duplicate it or edit the CA fixture until
parent steer. Any supported replacement must preserve unique CurrentUser-only
ownership/preexistence guard, exact DER/thumbprint postconditions, checked exit,
bounded join/cleanup inside existing budgets and all real verified-HTTPS modes.
No LocalMachine/elevation/registry hack, validation bypass or new trust contract.
Manual signing remains unanswered/unauthorized. Stop at bounded review once CA
steer is considered, not with a premature helper-only acceptance handoff.

### Round-3 CA steer and pre-edit fixture exception

Parent subsequently forwarded the read-only scout's official Microsoft certutil
reference: `certutil [options] -addstore CertificateStoreName InFile`, with
`-user` selecting user rather than machine stores. Parent authorized evaluating
**`certutil.exe -user -addstore Root <CAfile>`**, no `-f`, only inside this owned
CI fixture. The docs list `-f` but do not establish consent suppression or
noninteractive behavior; Import-Certificate docs likewise prove supported store
targets, not the observed stall's UI cause. The candidate is not known working
until native CI. Microsoft cautions certutil is not recommended for production
code: this invocation remains test-only. Official page syntax was read before
coding; no duplicate CA investigation, new trust scope or production import.

**Before CA edits:** native import/runtime TDD cannot run here. Retain the actual
old `$store.Add($ca)` timeout as RED symptom evidence, but do not call it a local
candidate RED→GREEN. Strongest feasible checks: current native fixture source/
Go cross-compilation, portable process streaming/exit/cancel-join tests and exact
ownership/deadline self-review; actual import plus all verified HTTPS modes and
CA absence remain pending. Keep the existing2min **shared overall** budget for
read-only preflight, Go-owned CLI import and main PowerShell matrix; independent
cleanup retains its separate20s budget. A successful preflight must verify the
unique thumbprint absent **before** cleanup is armed. Arm only exact-DER-owned
cleanup before starting import, covering partial failure/timeout. Launch certutil
directly from Go, not nested beneath killable PowerShell; require successful exit
and subsequent exact-DER/thumbprint store postcondition before any Download.
Reserve1s inside that shared deadline for certutil Cmd.WaitDelay (verified
Go1.26.11 documentation), so unexpected open output pipes cannot cause an
unbounded join or add a new budget. Preserve all negative/positive assertions,
CurrentUser-only targeting, no force flag, policy mutation or TLS bypass.

### Round-3 implementation and measured validation

- Production `internal/upgrade/upgrade.go`: only the atomic File.Replace backup
  expression changes to the exact native-PASS NullString sentinel, with one
  constraint comment explaining empty-string coercion. Existing wait/retry/
  cleanup/exit/environment/literal-path behavior is otherwise byte-preserved.
  `replace_windows.go`, actual installer/C#, all crypto/TLS/ACL/collision/state/
  rollback/manual-cutover safeguards and0.23.0 stay unchanged.
- Added `TestWindowsHelperEncodedReplacementUsesTrueNullBackup` against the
  **actual production encoded program**, independently expecting the native-PASS
  expression and exactly one atomic call. At03:02:45UTC, exactGo1.26.11 focused
  command failed for the old third argument (`helper-red.log`, exit1). At
  03:03:51UTC all portable helper tests passed after the minimal change
  (`helper-green.log`, exit0). Existing lifecycle expectation now names true
  null. Diagnostic preservation still reconstructs the exact production program.
- Native ordinary/metacharacter cases retain all success/content/inventory/
  stage-cleanup/join assertions. Locked negatives additionally require the main
  helper's System.IO.IOException HRESULT_FROM_WIN32(ERROR_SHARING_VIOLATION),
  -2147024864, not another unrelated nonzero exit. The intentionally failing
  `$null` **probe** is separate from the main-helper diagnostic prefix. New
  locked assertions and replacement positives remain pending native runtime;
  no assumption that a previous invalid-argument negative proved lock handling.
- CA fixture: a read-only Desktop/framework/certificate/thumbprint/absence
  preflight completes successfully before exact-DER cleanup is armed. Go owns
  certutil directly with literal argv `-user -addstore Root <private CAfile>`;
  no nested PS launch, force flag, import fallback or changed production trust.
  Output is bounded/streamed; nonzero exit, expired import context or WaitDelay
  error fails. The import's child deadline is shared matrix deadline minus1s,
  with1s WaitDelay reserved inside the original2min total. Main PS reopens only
  CurrentUser Root and requires exactly one thumbprint match with exact DER
  before any actual Download. Main and independent cleanup retain exact CA
  removal/absence; partial import failure also reaches independent20s cleanup.
  No certutil operation executed locally. The supported candidate's ability to
  avoid the observed stall is **UNVERIFIED**, not an established UI-prompt fix.
- New portable command-exit characterization checks real child exit0 versus7 and
  joined ProcessState; existing runner behavior already passed it, so this is
  **not** a fabricated RED→GREEN. Existing phase-before-cancel/output-bound
  regressions plus it pass race10. No additional Go runner implementation or
  speculative fixture framework was added.

Every recorded test command uses TMPDIR=/var/tmp, GOTOOLCHAIN=go1.26.11 and
PYTHONDONTWRITEBYTECODE=1. `commands.jsonl` binds exact argv/UTC/exit/environment;
`hosted-summary.json` separates12 aggregate agent/SFTP passes from printed
upgrade JSON2PASS/2FAIL. Initial read-only parser incorrectly expected all16 in
printed JSON and was corrected; no native outcome/test was rerun or changed.
API sources/official scout limits are in `api-evidence.json`; source-only native
program inputs and exact downloader/probe bytes are bound by review manifest.

| Current-source command / evidence | UTC start→end, 2026-11-16 | Result |
| --- | --- | --- |
| `go test ./internal/upgrade -run '^TestWindowsHelperEncodedReplacementUsesTrueNullBackup$' -count=1 -v` (`helper-red.log`) | 03:02:45→03:02:46 | expected RED on old actual program, exit1 |
| `go test ./internal/upgrade -run '^TestWindowsHelper' -count=1 -v` (`helper-green.log`) | 03:03:51→03:03:51 | portable helper GREEN, exit0 |
| `go test -race ./internal/upgrade -run '^(TestWindowsHelper\|TestPowerShellFixture\|TestInstallerDownloaderSource)' -count=1 -v` (`focused-green.log`) | 03:08:55→03:08:57 | PASS portable contracts/process tests |
| Windows/amd64/CGO0 `go test -c -o /var/tmp/ww3.9hre/upgrade.test.exe ./internal/upgrade` (`windows-compile.log`) | 03:08:57→03:08:58 | PASS **compile only**, binary never executed |
| `go test -json ./... -count=1 -timeout=180s` (`full-go.log`) | 03:10:28→03:10:58 | PASS794 top-level tests; three existing explicit skips |
| `go test -race -json ./internal/upgrade ./internal/client/... -count=1 -timeout=180s` (`upgrade-client-race.log`) | 03:10:28→03:10:49 | **FAIL**338 passes/one failure/one explicit skip; terminal race below |
| `go test -race ./internal/upgrade -run '^TestPowerShellFixture' -count=10 -timeout=30s -v` (`stream-race10.log`) | 03:10:28→03:10:41 | PASS three portable logging/process tests10times |
| `go vet ./...` (`vet.log`) | 03:11:45→03:11:46 | PASS, run separately after failed race short-circuited initial chain |
| `bash scripts/test-installers.sh` (`installers.log`) | 03:10:28→03:10:39 | PASS offline wrappers only |
| `python3 scripts/installers_test.py` (`installer-https.log`) | 03:10:39→03:10:42 | PASS four actual-curl/private verified-TLS matrices |
| `python3 -m unittest discover -s scripts/ci -v` (`ci-contracts.log`) | 03:10:42→03:10:45 | PASS12 offline contracts, fake publication only |
| Existing private actionlint1.7.12 with optional analyzers disabled (`actionlint.log`) | 03:10:45→03:10:45 | PASS; shellcheck/pyflakes unavailable, not claimed |

Full-suite skips remain two opt-in browser fixture servers and unprivileged Unix
wrong-owner; race skips only wrong-owner. Windows build-tagged code does not run
on Linux. The new helper regression and command-exit characterization explain
794 versus792, not additional native acceptance. Frontend/browser fixture inputs
remain baseline-identical; no frontend/browser rerun is claimed. Prior release-
build/scan evidence is historical for its original inputs, not proof for the
changed production helper.

### Round-3 open local race — not waived or silently fixed

The requested broad affected race command **failed**, and no passing rerun is
used to waive it. `TestResizeEventsPropagate` timed out after2s without its
SIGWINCH event; deferred Restore then triggered a detector-confirmed send/close
race. Stack: `internal/client/terminal/terminal_unix.go:87` closes events in
Restore while `:113` sends in startResize after releasing s.mu. Test callsite
`terminal_linux_test.go:250,258`. Both source files are byte-identical to
41fa49b (`terminal-race-inputs.json`); no terminal file was edited and no separate
baseline execution was performed. The timeout's delivery cause is not isolated;
concurrent full/race/installer checks are recorded, not treated as a cause.
The actual race is an unresolved validation blocker, **not a baseline waiver**.
Upgrade package itself passed within that failed command; this does not turn
the broader command green. Parent must decide separate terminal triage/fix scope
and reconcile the failed check before treating local validation as complete.

### Round-3 bounded self-review and handoff

Complete **original41fa49b→current** private review files:
`/var/tmp/warden-windows-r3-review.diff`, `.json`, `.sha256`. Includes all six
modified Go paths, this chronological report, plan checkpoint and entire new
ignored-ledger delta. Protected content is excluded before reads/copies/hashes;
unrelated cache/evidence, index/HEAD and all three0.23.0 fields remain unchanged.
Manifest binds current/baseline source bytes, only the authorized production
call/comment delta, actual unchanged C# and source-only assembled native programs,
Go/tool runtime metadata, compile-only binary, evidence and ledger prefix/delta.
Format/whitespace, nonapplying reverse-patch, prefix and checksum verification
are required; no independent review is implied by self-review.

**Implemented production binding correction; CA CLI remains a bounded native
candidate; broader local race FAILED. No all-native acceptance claim.** Parent
independent review/fresh checks and terminal-failure disposition precede any
possible diagnostic/fix push to automatic PR CI. Still require all16 named native
tests once PASS/zero skips, ordinary/metacharacter success plus genuine locked
failure, actual trusted-HTTPS good bytes/full negative matrix and exact CA
absence. Genuine PRF/production trust, privileged Unix wrong-owner and hosted
artifact/OIDC/signature gates remain open. No T16 residual acceptance waiver,
manual signing/dispatch/public attestations/transparency writes, service/global
policy operations or publication authority. No checkbox completed. Stop at this
bounded self-review/report; parent controls the next step.

## Round 4 — helper native GREEN; sole CA-import gate (2026-11-16)

Resumed sole writer at `df07a756ae213be8f3650313387301ac12ef4729`, containing
reviewed R3native fixdf6d3aa and the separately reviewed Unix resize correction.
No model/thinking override/fallback attempted. Protected content and unrelated
cache/evidence remain untouched; version0.23.0 and all authority limits remain.
Private evidence `/var/tmp/ww4.8oX2`, ledger original prefix `ledger.before.md`.
Actual `/var/tmp/warden-pr45-final-native/` logs/three native JSONL files and
metadata were copied as data and independently reconciled, not merely trusting
scout arithmetic. Run43801723735 attempt1 pull_request headdf07a75, actual merge
`b0ac0f7ca10a0c0bd7e08cf501472b6c3f501c65` into basec104353: Linux133083319416
SUCCESS, Windows133083319948 FAIL. **16 unique top-level names each run once:
15PASS, one FAIL, zero skips.** Only trusted-HTTPS matrix fails. All four helper
ordinary/metacharacter success/locked subcases PASS; both locks show actual
System.IO.IOException sharing HRESULT-2147024864, with bytes/stage cleanup/
inventory/join assertions. This **closes the helper native defect**; do not edit
helper or Unix source further. Stale Hindsight claims that null binding remained
unconfirmed were corrected with actual evidence. Earlier failures remain history.

Remaining failure: preflight absence PASS and direct Go-owned **no-force**
certutil starts, prints Root store and `Signature matches Public Key`, then is
killed/joined with deadline error (matrix119.70s). Independent exact-DER CA
absence cleanup PASS/normal close/join. All connection/payload/CRL/exact/CDN/
forbiddenHTTP counts0; no import end, store postcondition or main HTTPS matrix
runs. C# compilation in the *earlier* process was proven; no HTTPS mode executed
in this latest run. UI consent versus other interaction is still **unproven**.

**Before R4 code edits: native TDD exception.** No local powershell.exe/pwsh or
native certutil; actual missing-import hosted RED is symptom evidence, not local
native candidate RED→GREEN. Add a portable contract against the actual shared
command builder's Cmd.Args, observe old missing-`-f` RED, then the minimal fixed
argument list GREEN. This establishes literal argv/current-user/root/file scope,
not import or TLS runtime success. All16 native tests once PASS/zero skips,
11actual HTTPS modes/good bytes/full negatives/postconditions/absence remain
required after parent review and at most the authorized next candidate push.

Full official Microsoft certutil page was read through global Options (metadata
commit `4282dd47a285a65de44c1512e8e9abd2384582a8`): -addstore lists -f/-user;
`-f | Force overwrite.` and -user targets HKEY_CURRENT_USER certificate store.
This corrects the earlier section-only omission, **not** proof that -f suppresses
UI or guarantees noninteractive operation. Parent explicitly supersedes the
previous no-force restriction only for one bounded **`-user -f -addstore Root
<unique private CAfile>`** fixture candidate. Keep random128-bit serial/CN and
thumbprint preexisting-absence guard before cleanup arming, exact DER/thumbprint
postcondition before any Download, partial-failure cleanup, direct owned child/
checked exit/kill+join/WaitDelay inside shared120s and independent20s cleanup.
No evidence in this documented single-InFile operation indicates unrelated-root
replacement; no broad store overwrite, policy/elevation/LocalMachine/registry/
TLS validation change is authorized. Abort/escalate if contrary evidence appears.

Optional owned-window diagnostic was considered, **not implemented**. Official
Framework4.8.1 MainWindowHandle docs describe only a graphical main window,
cached state requiring Refresh, zero for absent/hidden windows, and startup
coordination. A negative snapshot cannot identify/exclude the cause of this
headless console stall; reliable modal-window attribution would add process/
window orchestration disproportionate to this minimal one-variable candidate.
No P/Invoke/UI framework, global enumeration/screenshot, title collection,
button click/sendkeys/autoapproval or extra diagnostic subprocess was added.
Limitation is explicit: if this one -f candidate also blocks, existing streamed
phase/output/context/cleanup evidence still cannot prove UI causation. That
result falsifies the missing-force-switch-alone hypothesis and requires a new
bounded evidence/decision checkpoint, not another blind retry or timeout change.
Manual public signing remains unanswered/unauthorized; external gates unwaived.

### Round-4 implementation, portable RED→GREEN and local checks

`installer_https_source_test.go` is the small shared **test-only** command builder
used by the actual Windows fixture. It fixes exactly `executable, -user, -f,
-addstore, Root, CAfile`; no caller-selected operation/store/flags, shell or
fallback. Its portable Cmd.Args test includes spaces, percent, ampersand,
apostrophe and brackets in the literal CA path and requires context cancellation
ownership. First extracted the old exact no-force argv into this actual builder:
`args-red.log`,04:21:15UTC exit1, prints old missing-`-f` argv versus expected
list. Then added only -f: `args-green.log`,04:22:23UTC exit0. Nothing executed
certutil locally; an argument-construction proof is not native import GREEN.
Windows caller changes only from inline command to builder plus an explicit
`candidate=force-overwrite; UI behavior unverified` phase label. Existing
preflight/ownership arming/DER/cleanup/WaitDelay/deadlines/all11 modes and their
assertions are byte-preserved; all production/helper/Unix code stays unchanged.

All fresh commands use exactGo1.26.11/TMPDIR=/var/tmp and bytecode-off Python.
`commands.jsonl` records argv/UTC/exit/environment; `test-summary.json` records
actual top-level counts/skips, with no failing test waived or passing rerun.

| Current-source command / evidence | UTC start→end, 2026-11-16 | Result |
| --- | --- | --- |
| `go test ./internal/upgrade -run '^TestCertutilFixtureImportCommandArguments$' -count=1 -v` (`args-red.log`) | 04:21:15→04:21:16 | expected RED on old exact argv, exit1 |
| Same command after adding -f (`args-green.log`) | 04:22:23→04:22:23 | portable argv GREEN, exit0 |
| `go test -race ./internal/upgrade -run '^(TestCertutilFixtureImportCommandArguments\|TestPowerShellFixture)' -count=1 -v` (`focused-race.log`) | 04:22:23→04:22:26 | PASS literal argv and existing bounded process/exit/cancel contracts |
| Windows/amd64/CGO0 `go test -c -o /var/tmp/ww4.8oX2/upgrade.test.exe ./internal/upgrade` (`windows-compile.log`) | 04:22:26→04:22:26 | PASS **compile only**, binary never executed |
| `go test -json ./... -count=1 -timeout=180s` (`full-go.log`) | 04:22:42→04:23:09 | PASS798 top-level tests, three existing explicit skips |
| `go test -race -json ./internal/upgrade ./internal/client/... -count=1 -timeout=180s` (`upgrade-client-race.log`) | 04:22:42→04:23:01 | PASS343 top-level tests, one existing wrong-owner skip |
| `go vet ./...` (`vet.log`) | 04:23:01→04:23:01 | PASS |
| `bash scripts/test-installers.sh` (`installers.log`) | 04:22:42→04:22:49 | PASS offline wrappers only |
| `python3 scripts/installers_test.py` (`installer-https.log`) | 04:22:49→04:22:52 | PASS four actual-curl/private verified-TLS matrices |
| `python3 -m unittest discover -s scripts/ci -v` (`ci-contracts.log`) | 04:22:52→04:22:54 | PASS12 offline contracts; fake publication only |
| Existing private actionlint1.7.12, optional analyzers disabled (`actionlint.log`) | 04:22:54→04:22:54 | PASS; shellcheck/pyflakes unavailable, not claimed |

Full-suite skips remain the two opt-in browser fixture servers and Unix
wrong-owner; affected race skips only wrong-owner. No added skip or relaxed
assertion. The one new portable argument test explains798 versus797, not native
acceptance. Prior Unix failures remain historical and were causally corrected
in the separately reviewed df07a75 work, not waived by this fresh pass. Parent's
required server/store/client race, whole terminal race25 and production HTTPS
integration proofs are **reused for unchanged source, not rerun in R4**;
`reuse-evidence.json` binds their source/log hashes. No frontend/browser/build/
scan/privileged cross-owner/PRF/signing run was newly claimed here. Latest hosted
Linux whole-pipeline success is independent, and does not turn15/16 into16/16.

### Round-4 self-review and required next evidence

Complete **originaldf07a75→current** review bundle is
`/var/tmp/warden-windows-r4-review.diff`, `.json`, `.sha256`, including the new
source-named test builder, two-line native caller change, this chronological
report, plan checkpoint and entire new ignored-ledger delta. Manifest binds
baseline/current safe source inputs, unchanged production/helper/Unix/actual C#,
actual supplied native JSON and job logs, official full documentation bytes,
source-only native programs/CLI argv, current compile-only binary/runtime metadata,
new and reused evidence, ledger prefix/full/delta. Protected content is excluded
**before** reads/copies/hashes; unrelated cache/prior evidence is preserved.
Formatting/whitespace, version0.23.0×3, unchanged HEAD/index, report/ledger prefix,
reverse-patch check and checksums are verified for bounded self-review, not
independent acceptance. No stage/commit/push/PR/CI operation or runtime trust
mutation performed by this worker.

**One authorized -f candidate implemented, native effect UNVERIFIED.** Parent
independent review/fresh checks precede any possible one automatic-PR candidate
push. Require import successful exit/join, exact-CA store postcondition before
network, all11 real HTTPS modes/good bytes/negative outcomes with unchanged chain/
hostname/revocation checks, byte caps/redirect/digest/duplicate/truncation/header
assertions, exact removal/
absence and all16 named tests once PASS/zero skips. Do not reopen the natively
verified helper or edit Unix code. If import still stalls, stop with actual
phase/output/deadline/cleanup evidence and explicit lack of UI attribution; no
blind repeat, longer budget or unsupported policy workaround. Genuine PRF with
production trust, privileged Unix owner and hosted artifact/OIDC/signature gates
remain open. Manual public signing remains unanswered/unauthorized; narrow T16
risk acceptance is not a waiver. No checkbox or final release accepted. Stop at
this bounded report; parent alone controls the next step.

Self-review command04:31:55→04:31:56UTC exit0 (`self-review.log`), including
all5task paths/462safe tracked inputs plus one new source file (463total),
unchanged production/helper/Unix/source programs, version/prefix/reverse checks.
No runtime source changed after checks. ExactGo1.26.11 Cmd docs (`go-api-doc.log`)
also confirm existing command/cancellation construction. Final bundle is refreshed
**after** the recorder closes, binding immutable command/output hashes rather
than an in-flight log. `verify.py` checks all463input/5task/42evidence/reused-log
hashes plus the bundle digests, actual command exits/counts, unchanged HEAD/index
and nonapplying reverse patch. This is bounded self-review, not parent approval.

### R4 parent local acceptance checkpoint

Independent reviewer `01a1e1ea-4a07-7503-b4c7-e7dc96ff6f22` found no issues in the exact bounded R4 patch against `df07a75`; review inspected stored evidence and did not execute tests or native operations. Parent independently verified all 5 task, 463 input and 42 evidence hashes, inspected the actual builder and unchanged certificate ownership/budget checks, then freshly ran:

- `GOTOOLCHAIN=go1.26.11 TMPDIR=/var/tmp go test -race ./internal/upgrade ./internal/client/...`: PASS, `/var/tmp/warden-windows-r4-parent-race.log`.
- `go vet ./...` under the same toolchain/environment: PASS, `/var/tmp/warden-windows-r4-parent-vet.log`.
- Windows amd64 upgrade-test cross-compilation: PASS, `/var/tmp/warden-r4-upgrade-windows.test.exe`; **not native execution**.

Reviewed task hashes still matched before this documentation-only append. Fresh fetched approved base remains `0.22.1`; the existing three `0.23.0` fields remain unchanged. These checks accept only the test-only candidate for the authorized PR update. They do not establish successful import, UI causality, any download-mode success or all16 native acceptance. The next checkpoint is the existing automatic read-only PR CI after push, not manual dispatch, public signing, merge or release.

## Round 5 — force hypothesis falsified; owned observation only (2026-11-16)

Baseline `9a12611e6cf4dc9b244628448fb17f9361f8bae4`, same sole-writer branch;
inherited initial HIGH retained, no override/fallback attempted. Parent independently
reviewed R4 without issues and freshly checked affected race/vet/Windows compile
before the authorized push. Actual run43805627542 attempt1 checked out merge
`2335af14279e4fa2d89a14c439da7a447ee2b506` into basec104353. Independent parsing
of all three supplied JSONL streams in `/var/tmp/warden-pr45-native-r4/` proves
16 unique names each run once: **15PASS/one FAIL/zero skips**, only trusted-HTTPS
matrix fails. All4helper cases still PASS, including genuine sharing HRESULT
-2147024864. Linux entire pipeline PASS including full race and SSH/DB race25.
The R4 **`-user -f -addstore Root CAfile`** import prints Signature matches Public
Key, then119.37s deadline/exit1/join. No import-end, DER postcondition/main cleanup/
download; all6network counters0. Independent exact-CA absence PASS and joined.
**Missing-f-alone hypothesis is FALSIFIED. UI cause is still UNKNOWN.** Earlier
13/3,14/2 and15/1 runs remain history; no helper or Unix change is permitted.
Private evidence `/var/tmp/ww5`; complete ledger prefix saved before edits.

**Before R5 code edits: native TDD exception and bounded design.** No local
Windows runtime, PowerShell or C# compiler. Official Microsoft Win32 signatures,
callback convention/return semantics, cross-process GetWindowTextW caption limits
and supported OS versions were read before coding; Go1.26.11 Cmd/NewCallback docs
and exact pinned x/sys/windows v0.47.0 bindings were also checked (Context7 plus
installed source). Native UI/capability proof is unavailable; strongest feasible
proof is portable actual-cancel wiring RED→GREEN, real owned fake child processes
including failures/deadlines/joins, exact source guards and Windows cross-compile.
This is one **diagnostic-only** candidate, not another functional import attempt.
R4 argv stays byte-identical, one unique absent-owned CA/CurrentUser Root only,
exact DER guard before network,120s total and independent20s cleanup unchanged.

Choose one directly owned **Go test subprocess** for the snapshot instead of a
PowerShell/Add-Type observer: existing compiled test executable avoids a nested
PowerShell/compiler lifecycle, needs no install and allows cross-compiling the
actual Win32 call sites. Win32 Toolhelp read-only THREAD snapshot is documented
as a system numeric thread table; filter OwnerProcessID to certutil **before any
logging or window query**, and never retain/report foreign thread data. Enumerate
only those owned thread IDs with EnumThreadWindows (nonchild windows, no global
window enumeration/visibility heuristic). Recheck GetWindowThreadProcessId equals
owned PID/thread before **each** class/caption read, reject observer's own PID,
use fixed buffers/quoted output, and inspect only presence of dialog IDs6/7
without messages/actions. PID/session/thread IDs/class/title are fixture-public
metadata only. No WCT/custom ABI/stack/memory/debugger/suspension/remote injection,
no foreign text, global screenshot, environment/key dump, SendMessage, button
click, autoapproval, elevation, policy, registry, LocalMachine or TLS change.
Categorical thread wait reasons are **UNKNOWN/not queried**, not guessed.

Reserve8s **within** existing120s: import cancellation112s, snapshot at most6s
also ending no later than matrix deadline minus2s, then1s snapshot WaitDelay and
1s original import WaitDelay. Wrap Cmd.Cancel only: Go calls it after Start has
set Process; read PID there, synchronously run/join bounded snapshot, always
invoke original Cancel/Kill afterward, and preserve its result. Cmd.Run joins
watchCtx/output before returning, so no Process pointer read race, detached
logger or observation after test end. No repeated probes or import retry.
Missing APIs, races, empty/partial snapshot or deadline are explicitly UNKNOWN;
a positive owned window may identify a dialog but is not automatic proof of
causality or consent authority. If empty/unavailable, owner needs interactive
Windows evidence, not a new workaround. Any consent/scope change requires owner
decision. All16oncePASS/zero skips and all11actual verified-HTTPS modes remain
required; no runtime success or release acceptance is inferred from observation.

### Round-5 implementation and measured verification

`certutil_diagnostic_test.go` provides only the fixture import context, Cancel
observer and private snapshot-command constructor plus portable tests.
`certutil_diagnostic_windows_test.go` is the private subprocess entry and scoped
Win32 snapshot. The native caller uses these seams without changing R4 argv,
preflight/arming/DER/store/cleanup programs or any11mode assertion. No source in
production, helper, Unix, native16name list, installer C# or release fields changes.
Snapshot uses pinned library-provided THREADENTRY32 and typed owner/class/session
bindings; only EnumThreadWindows, GetWindowTextW and GetDlgItem use primitive
stdcall DLL calls with official signatures. There is **no custom native struct,
WCT or reflective/PInvoke framework**, PowerShell child or compiler subprocess.
Toolhelp THREAD-only handle closes; PID/owner/thread checks precede each text
read, observer PID is rejected, UTF16buffers64(class)/128(caption),32owned threads/
16window callbacks, quoted captions and existing1024-byte partial-line cap bound
output. Availability, owner-query failure/rejection, traversal errors, cap hits,
empty/false enumeration and partial caption are explicit, inconclusive metadata.
No thread-wait category is inferred; all results are observation-only.

Portable RED extracted the old1s import reservation and join behavior into the
actual seams **without** the observer. `diagnostic-red.log`,05:14:13→05:14:14UTC,
exit1: budget expected8s but got1s; five cancellation cases show kill-import then
import-joined with PID0/no snapshot, while normal exit already passes. Then the
minimal Cancel observer/reservation implementation gives `diagnostic-green.log`,
05:18:02→05:18:09 exit0. The same budget/lifecycle tests are GREEN; additional
command/source-scope and original-Cancel-error tests are characterizations, not
falsely claimed as their own observed RED. Actual owned Go children exercise
snapshot success, exit7, blocking until6s cancellation, unavailable factory,
start failure and normal import. Assertions require snapshot/output join BEFORE
original kill BEFORE import join, checked owned PID/deadlines, original cancel
result, no snapshot on normal exit,1s each WaitDelay and no lingering callbacks.
This is actual shared wiring and process lifecycle, not only source substring
proof. Windows API/runtime/UI observation remains unexecuted locally.

| Check / evidence | UTC start→end, 2026-11-16 | Result |
| --- | --- | --- |
| Focused portable diagnostic GREEN (`diagnostic-green.log`) | 05:18:02→05:18:09 | PASS; includes actual prior RED regressions |
| `go test -race ./internal/upgrade -run '^(TestCertutilFixture\|TestPowerShellFixture)' -count=1 -v` (`diagnostic-race.log`) | 05:18:09→05:18:20 | PASS real cancellation/kill/join/failure paths |
| `go test -json ./... -count=1 -timeout=180s` (`full-go.log`) | 05:21:14→05:21:41 | PASS802 top-level tests,3existing skips |
| `go test -race -json ./internal/upgrade ./internal/client/... -count=1 -timeout=180s` (`upgrade-client-race.log`) | 05:21:14→05:21:33 | PASS347 top-level tests,1existing skip |
| `go vet ./...` (`vet.log`) | 05:21:33→05:21:33 | PASS |
| `bash scripts/test-installers.sh` (`installers.log`) | 05:21:14→05:21:21 | PASS offline fixtures, not live installation |
| `python3 scripts/installers_test.py` (`installer-https.log`) | 05:21:21→05:21:24 | PASS four actual-curl/private verified-TLS matrices |
| `python3 -m unittest discover -s scripts/ci -v` (`ci-contracts.log`) | 05:21:24→05:21:26 | PASS12offline contracts/fake publication only |
| Existing private actionlint1.7.12 (`actionlint.log`) | 05:21:26→05:21:26 | PASS; optional shellcheck/pyflakes unavailable, disabled |
| Final source scope contract (`final-scope.log`) | 05:25:15→05:25:15 | PASS |
| Windows/amd64/CGO0 upgrade-test cross-compile (`windows-compile-current.log`) | 05:25:15→05:25:15 | PASS actual Go Win32 call sites, **not execution** |
| Windows/amd64/CGO0 `go vet ./internal/upgrade` (`windows-vet-current.log`) | 05:25:16→05:25:16 | PASS |

All tests use exactGo1.26.11/TMPDIRvar-tmp/bytecode-off; argv/UTC/exits/environment
are in `commands.jsonl`, actual top-level counts/skips in `test-summary.json`.
Four new portable top-level tests explain802versus798. Existing skips are the two
opt-in browser fixture servers and privileged Unix wrong-owner; affected race
skips only wrong-owner. No added skip, assertion relaxation, passing-rerun waiver,
production delay change or total budget increase. Bounded self-review added only
Win-only owner-query failure/rejection counters after the full/race runs; Linux
build inputs were unchanged, final source contract and Windows compile/vet were
freshly checked. Earlier compile/vet also passed; never executed the Windows binary.
Previous parent whole terminal race25/required server-store-client race/production
HTTPS integration proofs are explicitly **reused**, not new R5 runs, with unchanged
source/log hashes in `reuse-evidence.json`. Latest hosted Linux entire-pipeline
success is separate and does not establish native matrix success. Initial read-only
hosted parser shadowed built-in `all` with a list and errored before repo edits;
corrected parsing and the failure note are retained, no faulty result accepted.

### Round-5 review boundary and next observation

Complete **original9a12611→current** bundle:
`/var/tmp/warden-windows-r5-review.diff`, `.json`, `.sha256`. Includes all6task
paths/two new Go files and the **whole new ignored-ledger delta**, baseline/current
safe input hashes, actual hosted JSON/logs/metadata, official API bytes/versioned
binding evidence, final diagnostic sources/runtime args and budgets, compile-only
binary/tool metadata, measured commands and reused proofs. Protected `mise.toml`
content is excluded **before** reads/copies/hashes; unrelated cache/private
evidence preserved. Report/ledger prefix, exact original baseline/HEAD/index,
version0.23.0×3, formatting/whitespace, unchanged production/helper/Unix/C#/
all preflight+main+cleanup programs, native names, hashes and nonapplying reverse
patch are verified in bounded self-review, not independent acceptance.

**Diagnostic candidate implemented; native observation still UNKNOWN/UNRUN.**
No root operation performed locally. Parent independent review/fresh checks before
at most one new **observational** automatic-PR run. No new import mechanism,
arg variant, retry, timeout inflation or functional candidate. If owned class/
caption/ID6/7 evidence suggests a consent dialog, owner MUST decide before any
scope/GUI change; this worker has no autoapproval authority. If unavailable/
empty/ambiguous, report UNKNOWN/need interactive Windows evidence, not no-UI or
another workaround. All16nativeoncePASS/zero skips, successful owned import/DER
postcondition before network, actual11mode good bytes/full negatives/CDN/request/
forbiddenHTTP assertions and exact CA removal/absence remain mandatory. Genuine
PRF/production trust, privileged Unix owner, hosted artifact/OIDC/signatures and
manual signing authority remain open/unanswered; narrow T16 risk is no waiver.
No staging/commit/push/PR/CI/manual dispatch/global tool/service/install/deploy/
signing/merge/release action. Stop after self-review; parent controls next step.

Closing self-review05:33:28UTC exit0 (`self-review.log`):6task paths,
463safe tracked inputs plus2new Go sources=465total, format/link/version/prefix/
byte-preservation/nonapplying reverse checks PASS. Full45KB patch read in bounded
self-review. Closing prose only after runtime checks; no runtime source change.
Final package refreshed after recorder closes to bind immutable logs/commands;
`verify.py` verifies465inputs/6tasks/69evidence files/reused hashes, complete ledger
delta/prefix, expected RED-only nonzero exit, counts, HEAD/index and bundle digests.
No self-review result is independent approval or native runtime acceptance.

### R5 parent local acceptance checkpoint

Independent reviewer `01a1e1ea-4a07-7503-b4c7-e7dc96ff6f22` found no issues in the bounded diagnostic patch against `9a12611`. Review inspected the retained evidence; it did not execute tests, replay RED or perform native operations. Parent inspected both new sources and integration, verified all 6 task/465 input/69 evidence hashes, and freshly executed:

- `TMPDIR=/var/tmp GOTOOLCHAIN=go1.26.11 go test -count=1 -race ./internal/upgrade ./internal/client/...`: PASS, `/var/tmp/warden-windows-r5-parent-fresh-race.log`. The earlier `/var/tmp/warden-windows-r5-parent-race.log` reused client-package cache; the explicit `-count=1` run is the fresh execution proof.
- Full `go vet ./...`: PASS, `/var/tmp/warden-windows-r5-parent-vet.log`.
- Windows amd64 upgrade-test compilation and Windows-target upgrade vet: PASS, `/var/tmp/warden-r5-upgrade-windows.test.exe` and `/var/tmp/warden-windows-r5-parent-windows-vet.log`; **neither is native execution**.

Reviewed task hashes still matched before this prose-only append. Fresh fetched approved base remains `0.22.1`; existing release `0.23.0` remains unchanged. This accepts only the diagnostic candidate for one authorized automatic PR observation. Native metadata, root cause, functional import, all eleven download modes and all16 acceptance remain unproven. Empty or unavailable metadata remains UNKNOWN. Any consent evidence requires an owner decision before GUI action or trust-scope changes. No manual dispatch, signing, merge or release is authorized.

## Round 6 — owned certificate-control observation checkpoint (2026-11-16)

### Before code edits: native exception and narrow consent authorization

Baseline d22e9ce05da72f93cb92a77d1713786353c38576, same branch/sole writer.
Independently reconciled actual three R5 JSONL streams: run43812138655attempt1,
merge5b71d693ee34aa4c5221faf59b34ec49701a7e6c,16unique names once,
**15PASS/1FAIL/0SKIP**. Helper all4native PASS; Linux pipeline PASS. Owned
PID8384/session2/TID3196 had class`#32770`, caption`Security Warning`, ID6/7
present; observation joined in18ms before certutil deadline/join. Independent
exact-CA absence PASS, all6network counts0; import/DER/all11modes never ran.
This is positive owned-window evidence, not sole-root-cause proof.

Owner was asked: “Do you authorize fixture-only automated consent for this
 test-generated certificate? It would require exact generated-certificate
 identity checks, fail closed on ambiguity, retain CurrentUser-only trust and
 exact-DER verification/cleanup, and use no global SendKeys or blanket
 trust-policy changes. The risk is misidentifying a security prompt and approving
 the wrong certificate. The safer alternative is manual approval and validation
 in a disposable interactive Windows environment, which is not currently
 available here.” Owner replied exactly **`approve`**. This supersedes no-GUI-action
 only for safely identified consent for this single generated CA; it is not
 blanket UI/trust/signing authority.

**Actual child-control labels, IDs, classes and certificate text have NOT been
observed.** This candidate uses the explicitly permitted fail-closed observational
checkpoint, not a guessed clickable layout. No BM_CLICK/Invoke/action path will
be added. Proactively start one owned observer during import, bind live PID plus
creation identity and immutable public CA DER SHA256/full SHA1 thumbprint/random
CN, collect bounded owned standard-control text with WM_GETTEXT via documented
SendMessageTimeoutW, then decline consent even if identity-only evidence matches.
A parent-controlled observational checkpoint is required before a recognized
native action contract can be implemented. No passing native result is expected
from a warning that requires consent. No speculative action framework is needed.

Windows/UI runtime is unavailable locally: native UI integration is a **pre-edit
TDD exception**, not a proof waiver. Portable tests must first fail against the
old shared lifecycle (no proactive observer), then exercise actual shared
identity checks/cancellation/output joins with real owned disposable Go children.
Sanitized identity samples test strict logic only, not actual native layout;
exact-match/one-approval action tests remain pending because this checkpoint has
**zero approvals for every input**. Strongest native checks: official API and
pinned x/sys0.47.0/Go1.26.11 source inspection, bounded source guards, Windows
compile+vet only. Preserve R4 argv, preflight-before-cleanup arming, exact DER
postcondition before any Download, both cleanup programs, all11modes/native16,
production/helper/Unix/version0.23.0. Shared120s TOTAL, existing8s import reserve,
observer at most6s/end by matrix-minus2s,1s each output join, independent20s cleanup;
no retries, detached observers, global windows/text/actions, trust/TLS/policy or
release operation. Record complete ledger delta under private `/var/tmp/ww6`.

### Implemented checkpoint and proof boundaries

New `certutil_control_test.go` owns immutable value-only public CA identity,
bounded DER/CN/full-thumbprint validation, cloned target-envelope construction,
identity-only evidence matching and the proactive import/observer lifecycle.
New `certutil_control_windows_test.go` owns the private Windows entry and scoped
Win32 reads. The caller additionally checks the generated CA DER SHA256/CN/full
thumbprint before starting certutil. Parent captures live creation FILETIME after
Start and before Wait can release the owned handle; the child pins a limited-query
plus SYNCHRONIZE handle and repeatedly checks creation/liveness/PID/TID. No
process memory, debugger, privileges or global window enumeration. Toolhelp THREAD
numeric table is owner-filtered before windows; caps4096table entries/32owned
threads/16window callbacks/32controls/32polls at100ms, child5s inside parent6s.
Only one unambiguous owned `#32770`/`Security Warning` permits child metadata;
unknown/duplicate warning refuses child reads. These parent facts come from R5,
not a guessed native certificate-control layout.

Nonzero owned parent/descendant membership, process/thread, class, control ID and
parent identity are checked around text reads. Only standard Static/Button text
is read with **WM_GETTEXT**, one specific HWND, SendMessageTimeoutW100ms,
BLOCK|ABORTIFHUNG|ERRORONEXIT; no non-timeout flag/broadcast or action message.
Unknown classes/IDs, incomplete/raced/truncated/failed reads remain UNKNOWN.
Text buffer1024UTF16; quoted120-rune chunks preserve bounded public certificate
text under the existing1024-byte streaming line bound. A whole-field full SHA1
thumbprint (ASCII whitespace/case normalization only) and exact random CN can
establish **identity evidence only**. Combined labels, abbreviations, unknown
classes/parents/owners, missing/conflicting/duplicate identities are not a native
consent contract. Synthetic IDs101/102 in tests are explicitly sanitized examples,
never native expected IDs. Native labels/layout remain unobserved.

The observer deliberately exits3 even for identity-only matches: **zero approvals
for every input**. There is no clickable callback/BM_CLICK/Invoke path or pending
action scaffold. Its process/output join precedes original owned kill; Cmd.Cancel
cancels/joins that observer exactly once and preserves original cancel result.
Normal/early process exit cancels/joins the observer; factory/nil/start/failure,
blocked/deadline/cancel paths cannot leave a child or logging thread behind.
A clearly naturally completed import still needs the original exact-DER store
postcondition before downloads. Ambiguous completion stays failed closed.
All existing R5 snapshot code/tests remain unchanged. No import variant/retry,
production/helper/Unix/C#/mode/assertion/native16/version change.

Official Microsoft SendMessageTimeoutW/WM_GETTEXT/EnumChildWindows/IsChild/
GetParent/GetDlgCtrlID/OpenProcess/GetProcessTimes/WaitForSingleObject docs were
read before their API coding; the official process-ID lifetime article explains
handle-pinned reuse protection. Exact x/sys0.47.0 bindings and Go1.26.11 sources
were checked alongside Context7 `ctx7:docs:386bcd0c610955d0fca57aad`; master snippets
alone are not pinned-version proof. Ten full official pages and eight binding/Go
sources archived subsequently in `api-evidence.json` (timestamps are archival,
not native execution). These documented APIs prove no particular native layout.

### Actual RED/GREEN, checks and retained failures

- `control-red.log`,06:23:33UTC exit1: actual extracted R5 PID-only builder accepts
  zero/self/missing creation/CN/partial/wrong thumbprint/DER/file/inherited target;
  lacks the full public-identity envelope. This was a command-construction test,
  not local certutil execution. First combined run pattern selected this test
  only; lifecycle has its own explicit RED command, not an assumed execution.
- `lifecycle-red.log`,06:23:57→06:24:04 exit1: real Go child cases complete/mismatch/
  cancel call the old factory only after cancellation; normal/early exit never
  calls it. Actual old Cancel observer/kill/output joins are under test, not
  substring-only checks. A400ms disposable-child watchdog bounds old behavior.
- `identity-red.log`,06:27:17→06:27:18 exit1: fail-closed missing-capability baseline
  rejects the two complete synthetic identity samples. Negative identity cases
  already reject; they are NOT claimed to have independently failed RED.
- `control-green.log`,06:30:44→06:30:45 PASS actual shared helpers;10×race06:37:32→
  06:37:42 PASS. Follow-up startup/deadline/ID/clone/original-cancel/source-scope
  characterizations are not separate claimed REDs. Final focused/shared process
  tests06:49:24→06:49:33 PASS; final25×control race06:49:33→06:50:01 PASS. Ownership,
  full/missing/partial/wrong/conflicting/duplicate identities, PID/TID/process/
  parent/class, no target/start failure, no observer, exit7, block, normal/early
  exit, cancellation/deadline, kill-once/result and joined logging are covered.

| Check (all exact argv/UTC/exits retained) | Result |
| --- | --- |
| Initial full Go with test-child umask077,06:51:40→06:52:29 | **FAIL801PASS/5FAIL/3existing skips**; existing fixture permission assumptions |
| Initial affected race with test-child umask077,06:51:40→06:52:08 | **FAIL348PASS/3FAIL/1existing skip**, same mode assumptions |
| Focused unchanged `TestUpgradeReplacesExecutable` umask077 then022,06:54:06→06:54:09 | Deterministic FAIL0700 versus expected0755, then PASS with only child umask corrected; no source change |
| Full Go child-only normal fixture umask022,06:56:33→06:57:27 | PASS806top-level/3existing skips |
| Affected upgrade/client race child-only umask022,06:57:27→06:57:53 | PASS351top-level/1existing skip |
| Full vet06:52:08→06:52:09 | PASS |
| Final Windows amd64 compile06:52:09→06:52:11, Windows vet06:52:11 | PASS, **never executed locally** |
| Offline installers06:51:40→06:52:00 | PASS, no live installation |
| Four-test real-curl/source-contract suite06:52:01→06:52:04 | **FAIL** server CDN positive case deadline |
| Same unchanged suite isolated06:56:29→06:56:33 | **FAIL** client and server CDN positive deadlines; not only concurrent worker load |
| Twelve offline CI contracts06:52:04→06:52:10 | PASS, fake publication only |
| Existing private actionlint1.7.12,06:52:10 | PASS; optional shellcheck/pyflakes unavailable, disabled |

All wrappers retain TMPDIRvar-tmp/Go1.26.11/bytecode-off, private evidence root700,
parent umask077/logs600. The initial broad mode failures are caused by fixtures
using os.WriteFile with0755/0640 etc and assuming unmasked modes, not new code:
server refusal, CLI/SFTP preservation and upgrade executable cases. Controlled
child-only umask022 leaves testing.TempDir roots700/evidence private and changes
no process-global system policy, assertions, production or Unix code. Both
original failed commands and A/B proof remain visible, not a passing-rerun waiver.
Existing skips remain two opt-in browser fixtures and privileged wrong-owner;
affected race skips wrong-owner only. Four new portable tests explain806vs802.

**Required curl check is still FAILED, not waived.** Its unchanged fixture uses
connect0.1s/total0.25s. The isolated failure falsifies a worker-concurrency-only
explanation; root cause is UNKNOWN. Do not change the frozen installer, limits,
assertions or claim successful current four-matrix proof. Parent must resolve or
explicitly adjudicate this separate validation blocker before publication/CI.
All failed logs/commands are retained. No further unrelated debugging/code changes
or passing-rerun acceptance. Exact hashes reuse unchanged parent terminal/component
and latest hosted whole SSH/DB race25 evidence, explicitly NOT fresh execution.

### R6 review boundary — checkpoint only, acceptance blocked

Complete originald22e9ce→current review bundle:
`/var/tmp/warden-windows-r6-review.diff`, `.json`, `.sha256`; all6task paths,
2new Go sources, full new ignored-ledger delta and unchanged prefix, safe inputs,
actual R5 raw evidence, official API/bindings, runtime source/args/budgets,
compile-only binary, all new successes AND failures and exact-hash reused proofs.
Protected `mise.toml` excluded before reads/hashes/copies; unrelated cache and
private evidence preserved. No staged/committed/pushed/CI-dispatched/trust/signing/
service/deployment action. Version0.23.0×3 and frozen sources remain unchanged.

This implements only the permitted **fail-closed observational prerequisite**.
It does not implement native approval, the exact-match/one-approval action test,
or resolve the HTTPS import. Parent independent review/fresh affected race/vet/
Windows compile and the outstanding curl-validation decision precede any new
parent-controlled observational automatic PR run. Capture actual owned controls;
if unavailable/ambiguous, stop for interactive evidence rather than relaxing
identity. Only after an actual recognized native contract can consent be safely
implemented under the existing narrow approval. All16oncePASS/zero skips and all
11real verified-HTTPS modes still required; latest native remains15/1/0. Genuine
PRF/production trust, privileged Unix owner, hosted artifact/OIDC/signature gates
remain open; public signing remains unanswered/unauthorized. No acceptance waiver.

Closing bounded self-review: first07:22:15UTC check caught a trailing blank line
at report EOF; fixed that documentation newline only, retained failed log. Final
07:23:17→07:23:18 check PASS:6task paths/467safe inputs, format/whitespace/doc links,
report+ledger prefixes, exact HEAD/empty index/versions, import-only caller seam,
frozen sources/native16/programs/C# and nonapplying reverse patch. Entire68KB
patch read in bounded self-review, not independent acceptance. No runtime-source
change after final tests/compile. Final package refresh follows recorder closure
so logs/commands have immutable hashes; `verify.py` rechecks all inputs/evidence/
reused proofs/whole ledger delta and bundle checksums, including retained failures.
Stop: no native approval or all16 success, and curl validation remains blocked.

### R6 continuation — causal curl investigation, before fixture edits

Parent returned the same R6 outcome because the two curl failures block review
readiness; they are not waived. Same d22e9ce/sole writer, no Windows checkpoint,
installer, budgets or assertion changes. Original bundle/evidence and complete
ledger prefixes are preserved; continuation evidence is private `/var/tmp/ww6/curl`.
Systematic debugging inspected the actual identical extracted downloader and
fixture request/header/TLS/server lifecycle. Scoped traces include only public
loopback requests and whitelisted protocol/deadline state, not environment dumps.

Two bounded comparisons showed each Nagle-enabled persistent TLS response's
roughly40ms delay between server header write and curl receipt. Four sequential
requests (origin302/target200 for binary and checksum) consume most of250ms before
process startup/polling. TCP_NODELAY on the accepted fixture socket removes these
stalls without forcing Connection:close or changing CA/TLS/HTTP semantics. A
separate case-local-cleanup comparison reduced31/64active threads to1 before CDN
but left the per-response stalls; cleanup accumulation alone is NOT established
as the cause and will not be changed. Instrumented old cases sometimes passed
near250ms; that does not waive the original two actual deadline failures. Exact
kernel ACK internals were not packet-captured; the socket-option/latency causal
comparison is the evidence. Direct curl traces show TLS1.3 certificate/SAN
verification and direct loopback connections, no proxy CONNECT. Budgets are
correctly seconds: connect0.1, shared total0.25, four decreasing --max-time values.

Before edits: choose only the fixture's standard StreamRequestHandler
`disable_nagle_algorithm` setting. Read pinned Python3.12.15 socketserver setup
source plus Context7 `ctx7:docs:61259771e3a92f0d221192d1` and curl trace/deadline
documentation (refreshed reference `ctx7:docs:be70dd3b3d0175cb7fd6b756`). These
upstream excerpts are cross-checked against installed Python3.12.15 and actual
curl8.18.0 TLS traces, not treated as pinned dependency execution proof. No
production defect inferred. Test-first add
an actual-socket regression for both extracted installers: four verified TLS
HTTP/1.1 responses with normal Content-Length and persistent connection state,
TCP_NODELAY enabled on every accepted socket. Observe RED against existing
misconfigured sockets, then change one fixture class attribute and GREEN under
the same deadlines; all negatives/full suite must still pass. No native exception
for this portable test, no relaxed timeout or assertion, no global network option.

### R6 continuation — fixture correction and fresh proof

The only fixture behavior edit is `Peer.disable_nagle_algorithm = True`; Target
inherits it. This sets TCP_NODELAY on each accepted fixture socket, not a global
network option. HTTP/1.1, normal Content-Length, no forced Connection:close,
OpenSSL/TLS chain/hostname checking, actual curl, downloader code, byte limits,
connect/total budgets and every original negative assertion remain unchanged.
New `test_cdn_persistent_tls_socket_configuration` observes the actual accepted
SSLSocket/header/connection state for both extracted installers, asserting all
four origin302/target200 binary/checksum responses, persistence and TCP_NODELAY.
It does not set the socket option or substitute a downloader/curl result.

`curl-fixture-red.log`07:45:42->07:45:43 EXIT1: both script subtests receive the
real bytes but observe socket option0 !=1. This is deterministic fixture
misconfiguration RED, NOT falsely described as another naturally reproduced
timeout. One class attribute correction, then `curl-fixture-green.log`
07:46:22 EXIT0. Fresh complete suite07:46:22->07:46:25 PASS5/zero skips: all four
original tests including32 client/server streaming scenarios and their unchanged
negative checks, plus the new real-socket regression. Predetermined five complete
suites07:48:49->07:49:00 PASS25/zero skips/zero errors while related offline/CI
checks ran; this is bounded postfix stress, not retry-until-pass.

For exact deadline discrimination, private probes preserve old fixture and
actual installer source. An extra20ms server-work-before-headers hypothesis
failed its assertion (`curl-deadline-causal-reproduction.log`07:55:18 EXIT1): both
cases passed because work overlaps the post-handshake coalescing wait. This
negative finding/log is retained, not a validation success or hidden rerun.
Based on that phase evidence, one final bounded20ms-before-each-spawn comparison
(`curl-deadline-scheduler-comparison.log`07:57:30->07:57:31 EXIT0) keeps identical
real curl argv/CA/consumer code/budgets/scheduling delay in both variants. Original
Nagle0 reproduces the exact extracted `fetch` line64 TimeoutError at fourth CDN
checksum request: operation_left=-0.000950s, headers_left=+0.076722s. Shared total,
NOT per-hop connect/headers, expires. Socket-local TCP_NODELAY=1 variant succeeds
in0.114s with all four verified HTTPS requests. BrokenPipe after cancellation is
an observation/consequence, not the cause. Original exact host scheduling cannot
be reconstructed retrospectively; this controlled same-symptom reproduction,
wire latency comparison and real-socket RED/GREEN establish the fixture's missing
low-latency precondition under its deliberately reduced250ms operation budget.
No higher timeout, scheduler shim or probe instrumentation enters repository code.

Fresh related offline installers07:48:49->07:48:54 PASS, all12CI contracts
07:48:54->07:48:57 PASS, actionlint1.7.12 PASS (optional ShellCheck/Pyflakes still
unavailable/disabled). All Go, production scripts, workflow, build/embedding,
module and Windows source inputs are exactly the preceding R6 bundle hashes;
`curl/reuse-current-r6.json` binds the unchanged safe inputs/logs/command-prefix.
Existing R6 fullGo806PASS/3existing skips, affected race351PASS/1existing skip,
control race25, vet and Windows compile/vet are REUSED, NOT fresh continuation
execution; no Go source reads/calls this Python fixture. Parent terminal/component
and hosted SSH/DB race25 reuse remains separately bound. All original077 Go
failures, original curl failures, self-review failure and failed probe stay intact.

Curl gate is now causally corrected with fresh full proof, ready for independent
review of this SAME authorized observational checkpoint; no waiver or parent
acceptance claimed. Existing R6 owned-control sources are unchanged. Latest native
remains15PASS/1FAIL/0SKIP, current observation UNRUN, actual native child layout and
certificate-bearing controls UNKNOWN, action unimplemented/always no-click.
All16oncePASS/zero skips/all11verifiedHTTPS modes/exact cleanup still required.
External genuine PRF/production trust/privileged Unix/artifact-OIDC-signature gates
and signing authorization stay open. Original baseline/branch/index/0.23.0fields,
protected exclusions and whole original ledger prefix/delta remain fixed. Refresh
same review paths only after recorder closure; preserve previous bundle in
`curl/r6-before-curl-review.*`. Independent parent review owns publication/CI;
no worker staging/commit/push/dispatch/trust/live install/service/global tool/
signing/release/merge action. Stop at this bounded handoff.

### R7 before code — approved single-fixture consent, captured producer contract

Separate queued outcome now authorized at local HEAD
`238411d31722e8b57ea6dad25374494dcba7236c`, same branch/sole writer/initial HIGH,
no model override. Linux blocked-flush fix independently reviewed/fresh checked
and locally committed, NOT pushed; freeze it. Remote PR45 still71b6c2a and hosted
run43831002522attempt1/merge02bccd2 remains failed. No worker Git/PR/CI dispatch,
live install/service/trust/GUI execution/global tools/signing/release/worktree.
Three0.23.0fields fixed; protected content excluded BEFORE reads/copies/hashes,
unrelated cache/all private evidence retained. Private `/var/tmp/ww7`0700/077,
original task ledger prefix captured; test children alone use normal022 and exact
TMPDIR=/var/tmp/GOTOOLCHAIN=go1.26.11/PYTHONDONTWRITEBYTECODE=1.

Owner's exact `approve` remains authorization ONLY for one safely identified
owned fixture-CA prompt: full expected generated DER/CN/full UI SHA1, live creation
identity/PID/TID/parent/control revalidation immediately before one scoped action,
CurrentUser only/exact DER postcondition before Download/exact cleanup. Wrong-CA
approval risk was explained; safer manual interactive validation unavailable.
No blanket trust, global keystrokes/focus, foreign UI, policy/elevation/LocalMachine,
TLS bypass or signing authority. No new observation-only substitute absent a new
material safety gap.

Captured R6 control producer: owned PID8852/TID4240/creation134392911558098992,
root327800 `#32770`/`Security Warning`; exactly direct Button6 `&Yes`, Button7
`&No`, Static20 empty, Static65535 complete806rune warning. Body references the
same random CN three times and includes one grouped40hex `Thumbprint (sha1)`.
Canonical captured English body/layout with CRLF-only normalization supersedes
our preliminary standalone-field assumption, NOT exact identity. Sanitized actual
capture will be a golden fixture; positive tests replace its observed CN/full
fingerprint with values from the test's pinned generated DER, not derive expected
text from the implementation. Old expected DER was NOT printed, so do not claim
the historical observed identity already matched DER. UI SHA1 identifies this
public native root only; release payload verification remains SHA256.

PRE-EDIT native TDD exception: Windows UI runtime unavailable locally. Portable
real-helper guard/action-state/process lifecycle RED→GREEN, exact capture and
adversarial cases, race25, pinned API/source inspection, Windows compile/vet are
possible but NOT native action/import evidence. Native acceptance still requires
all16oncePASS/zero skips/all11actualverifiedHTTPS modes and both cleanup proofs.

Before uncertain action APIs, read official BM_CLICK (Microsoft commit
2ec0df659644a793ed4f6160f238a95c9d9a9dcf) and SendMessageTimeoutW (metadata commit
fa53641576e3603fa7b66d3a4ad969d3ce49d6f3). BM_CLICK has zero parameters and no
message return value; SendMessageTimeout function's nonzero result indicates
dispatch completion, NOT button LRESULT/nonzero acceptance. A nonactive dialog
might not act: do NOT activate/focus it or claim success; exact DER postcondition
must independently establish import. Choose one specific-owned-Yes HWND BM_CLICK
0x00F5, bounded100ms SMTO_BLOCK|ABORTIFHUNG(0x3); unlike read flags0x23, avoid
ERRORONEXIT's documented false failure on normal button/dialog destruction during
processing. No NOTIMEOUT/broadcast/unbounded SendMessage/PostMessage/retry. API
failure/timeout consumes the attempt and fails closed. Context7
`ctx7:docs:170425ac2c3c1871cc073968` cross-checked against actual x/sys v0.47.0
LazyProc.Call: error always nonnil/possibly stale, primary API result decides.

Lifecycle plan: keep child5s/parent6s inside shared120s/import reserve8s/cleanup20s;
join observer/output before original exactly-once kill and all waits before return.
Do not cancel a finishing observer when normal certutil exits immediately after
click; let bounded observer finalize. Helper0 only after guarded dispatch, never
proof of OS acceptance. Explicit no-action import-already-completed result may
allow naturally completed exit0 to reach unchanged exact-DER postcondition, but
wrong identity/guard/action error cannot authorize Download even if main exits0.
No second prompt/action; matching snapshots/DER and fresh ownership must agree.

### R6 parent local acceptance checkpoint

Independent reviewer `01a1e1ea-4a07-7503-b4c7-e7dc96ff6f22` resumed after a provider quota interruption and completed with no issues in the exact R6 observation/curl fixture patch against `d22e9ce`. The interrupted attempt was not approval. Completed review inspected evidence but executed no tests or native operations. Parent inspected the actual owned-control sources, lifecycle integration, curl regression and causal timing evidence; all 7 task/467 input/145 evidence hashes matched.

Fresh parent checks, with child-only umask `022` and `TMPDIR=/var/tmp`:

- `python3 scripts/installers_test.py`: all **5 PASS**, `/var/tmp/warden-windows-r6-parent-installer-https.log`.
- `GOTOOLCHAIN=go1.26.11 go test -count=1 -race ./internal/upgrade ./internal/client/...`: PASS, `/var/tmp/warden-windows-r6-parent-fresh-race.log`.
- Full `go vet ./...`: PASS, `/var/tmp/warden-windows-r6-parent-vet.log`.
- Windows amd64 upgrade-test compilation and Windows-target upgrade vet: PASS, `/var/tmp/warden-r6-upgrade-windows.test.exe` and `/var/tmp/warden-windows-r6-parent-windows-vet.log`; **not native execution**.

Reviewed task hashes remained unchanged until this prose-only append. Fresh approved base remains `0.22.1`; existing three `0.23.0` fields remain unchanged. This accepts only the no-click observation and causal fixture correction for the authorized automatic PR checkpoint. Actual native control layout, exact UI identity match and consent action remain unverified/unimplemented; all16/native HTTPS and external gates remain open. The next run is observational and must not be described as consent delivery or a native fix.

## Round 7 — guarded single-fixture consent implemented, NATIVE UNRUN

This supersedes the older current-state UNKNOWN/UNIMPLEMENTED statements only;
all original checkpoints/failures remain historical evidence. The R7 before-code
exception and owner scope above were recorded before native API changes. Baseline
is local `238411d31722e8b57ea6dad25374494dcba7236c`: accepted Linux fixture fix is
frozen and NOT pushed. Remote/hosted authoritative R6 outcome is still
run43831002522attempt1/merge02bccd2,16once15PASS/1FAIL/0SKIP and zero HTTPS modes.
No R7 Windows execution, trust-store or GUI action occurred locally.

### Implementation and non-negotiable limits

- `certutil_control_test.go` now matches exactly the captured English combined
  warning, not substring/standalone-field heuristics. Exactly four unique direct
  child handles/IDs/classes/texts are required, including Yes6 `&Yes`, No7 `&No`,
  empty Static20 and full Static65535. CRLF→LF is the only normalization. All
  three CN occurrences and the single grouped full40hex SHA1 must be the same
  identity derived from the pinned public DER; every extra/missing/partial/wrong
  or conflicting identity/body/control/dialog/locale is rejected.
- New `certutil_consent_test.go` owns canonical body and single-attempt state.
  Initial match, full fresh snapshot, unchanged handle/evidence comparison,
  fresh public DER validation and cancellation checks precede dispatch. The
  allowance is consumed before the dispatcher, including errors/timeouts; no
  retry is possible. Its golden `testdata/certutil-security-warning.txt` is the
  actual public capture with ONLY CRLF normalized. Tests independently replace
  historical CN/thumbprint using their generated DER, not implementation text.
- Native reader pins the process handle/creation, filters owned numeric threads,
  reads only the exact owned warning, and repeats complete process/window/child
  snapshots again at the native action seam. Root/Yes PID/TID/class/parent/ID are
  checked immediately before the sole100ms specifically-targeted BM_CLICK site.
  The only tolerated non-dialog top-level classes are the actually R5-observed
  `CertUtil`, `MSCTFIME UI`, `IME`; unknown classes fail closed. Original thread,
  window, control, UTF16/text-chunk and poll caps remain. Only a fully matched
  fixture's public text is logged; no foreign/unknown text or environment dump.
- Official BM_CLICK/SendMessageTimeout/EnumThreadWindows/EnumChildWindows docs
  and installed x/sys0.47.0 are archived in `/var/tmp/ww7/api/` and metadata.
  EnumThreadWindows zero also means no windows; EnumChildWindows' return is
  unused, so callback ownership/error/cap checks remain decisive. Read flags0x23
  are unchanged; action uses BLOCK|ABORTIFHUNG0x3,100ms, no ERRORONEXIT because
  normal click processing may destroy its button. Nonzero FUNCTION result, NOT
  LRESULT, establishes dispatch only. Inactive dialogs may ignore the click;
  no focus/activation/global input workaround or success guarantee is claimed.
- Helper0 only means guarded dispatch. A separate4 result means the pinned
  import completed before any action, NOT consent; parent must still obtain
  actual normal certutil exit/context and exact DER-store postcondition. Every
  identity/guard/action error fails even if main exits0. Normal main exit does
  not cancel a finishing observer. Cancellation cancels/joins observer/output
  before the original exactly-once kill/result; import Wait/output are joined.
  Even test watchdog callbacks are explicitly stopped/joined, not detached.
- `installer_https_windows_test.go` logs expected public CN/full SHA1/DER-SHA256
  before import and uses the corrected lifecycle. Its actual argv remains
  `-user -f -addstore Root CAfile`, CurrentUser only; absence preflight BEFORE
  cleanup arming, exclusive public DER/random128 serial/CN, exact DER-store
  postcondition BEFORE Download, all11 actual modes and both cleanup paths are
  unchanged. Shared120s total/import reserve8s/observer child5s-parent6s/cleanup20s
  are unchanged. Production installers/C#/true-null helper/Unix/Linux fixture/
  storage/auth/crypto/modules/workflows/three0.23.0 fields are frozen.

### Measured RED→GREEN and final fresh validation

Private evidence root `/var/tmp/ww7`0700; recorder parent077/logs0600, test children
alone normal022. All recorded commands use TMPDIR=/var/tmp,
GOTOOLCHAIN=go1.26.11, PYTHONDONTWRITEBYTECODE=1; no model/thinking override.

1. Guard/action RED09:29:13→09:29:14: actual captured compound CRLF and LF text
   rejected by old standalone matcher; zero reads/actions. After canonical guard,
   action RED09:31:21→09:31:22: explicit no-action checkpoint still prevents the
   expected one attempt/API-failure consumption. GREEN09:32:19→09:32:19 exercises
   actual shared matcher/guard/state, including zero-action adversarial cases.
2. Real fake-owned-process lifecycle RED09:35:11→09:35:12: old observer0 path
   kills consent-success import; handshake forces normal import Wait to precede
   observer final report, exposing observer cancellation. New tests use actual
   child PIDs/exec/Wait/context/output and file handshakes, not source contains.
3. Retained first GREEN failure09:37:54: test wrongly demanded a redundant kill
   after an already-joined natural nonzero import exit. Corrected expected count
   to0 for that case, still exactly1 on guard/cancel failures. Retained09:47:58
   failure: LF golden normalization made the bare-CR test mutation a no-op;
   corrected the mutation to actually introduce bare CR. No production waiver.
4. Self-review tightened test watchdog callback joins. All affected Go proofs
   were freshly repeated AFTER that change, not reused as current:

| Final check | UTC window | Result |
| --- | --- | --- |
| Focused guard/action/real-process race25 |10:01:21→10:01:40|6names each25,150top/2475all-level PASS,zero skips |
| Uncached fullGo |10:01:40→10:02:10|811PASS/3existing skips |
| Fullrace `./...` |10:01:21→10:02:52|811PASS/3existing skips |
| Required server/store/client included in fullrace |same|657PASS/3existing skips |
| Affected upgrade/client included in fullrace |same|355PASS/1existing skip |
| Fullvet + Windows amd64 compile/vet |10:01:21→10:01:23|PASS, compile-only NOT native |
| Offline installers |09:53:34→09:53:45|PASS |
| Actual curl HTTPS suite |09:53:45→09:53:48|5PASS/zero skips |
| CI contracts |09:53:48→09:53:50|12PASS/zero skips |
| actionlint1.7.12 |09:53:50|PASS, unavailable ShellCheck/Pyflakes explicitly disabled |
| Production HTTPS runner Go section |09:56:43→09:56:54|fresh private trimpath binaries + actual HTTPS/import/agent lifecycle/4runner contracts PASS |

Broad skips are unchanged opt-in browser setup/runtime fixtures and privileged
Unix wrong-owner fixture; NOT waived acceptance. Exact current source and all13
production distribution assets are hash-bound; no frontend rebuild/test/audit or
whole `scripts/test.sh` invocation is claimed. HTTPS uses synthetic TEST-ONLY PRF,
not genuine authenticator or production trust. Whole SSHDBrace25/source scan were
not rerun here and no clean-module/full-hosted-pipeline claim is made.

### Bounded review handoff, NOT native acceptance

Deliver `/var/tmp/warden-windows-r7-review.{diff,json,sha256}` against238411d with
all9task paths, complete pre-R7 ledger prefix/full delta, current safe inputs,
actual captured producer/raw hosted evidence, API archives, fresh UTC argv/exits,
all failures/dispositions/RED-GREEN/race25, nested HTTPS commands, current13asset
hashes and nonapplying reverse-patch check. Protected content excluded before
reads/copies/hashes; unrelated cache/private originals untouched. Index empty,
HEAD fixed, Linux source/report unchanged. No worker stage/commit/push/PR/dispatch/
GUI/trust/install/service/global-tool/signing/tag/release/merge/worktree action.

Parent independently reviews, freshly checks and locally commits R7; only then
publish both accepted Linux and Windows fixes together for one automatic CI run.
Do NOT push Linux alone or rerun the unchanged no-action checkpoint. Native
acceptance still requires all16 exact names once PASS/zero skips, all11 verified
HTTPS modes and both exact cleanup proofs. Old expected DER/body equality remains
unproved; dispatch is not import acceptance. Genuine PRF/production trust,
privileged Unix, hosted artifact/OIDC/signature and public-signing authority gates
remain open. STOP at this bounded handoff.

### R7 parent local acceptance checkpoint

Independent reviewer `01a1e1ea-4a07-7503-b4c7-e7dc96ff6f22` found no issues in the exact R7 patch against held Linux-fix commit `238411d`; review ran no tests or native operations. Parent inspected the actual exact-body guard, single-attempt dispatcher, native targeting and integration, and verified all 9 task/471 input/72 evidence hashes and 13 production assets.

Fresh parent checks used child-only umask `022`, `TMPDIR=/var/tmp` and Go `1.26.11`:

- Uncached full Go: PASS, `/var/tmp/warden-windows-r7-parent-full.log`.
- Uncached full Go race, covering both Linux and Windows-test-helper inputs: PASS, `/var/tmp/warden-windows-r7-parent-full-race.log`.
- New consent tests race25: PASS, `/var/tmp/warden-windows-r7-parent-consent-race25.log`.
- Full vet, Windows amd64 test compilation and Windows-target vet: PASS, `/var/tmp/warden-windows-r7-parent-vet.log`, `/var/tmp/warden-r7-upgrade-windows.test.exe`, `/var/tmp/warden-windows-r7-parent-windows-vet.log`. Compilation/vet are not native execution.
- Actual curl suite: **5/5 PASS**, `/var/tmp/warden-windows-r7-parent-curl.log`.

Reviewed task hashes remained unchanged before this prose-only append. Fresh approved base remains `0.22.1`; three existing `0.23.0` fields remain unchanged. This accepts a local R7 commit and joint push with `238411d` for one authorized automatic PR run. It does not prove native dispatch, import, DER postcondition, any HTTPS mode or cleanup. Historical expected DER remains unlogged; no retrospective matching claim. All native/external acceptance and separate signing-authority limits remain in force.
