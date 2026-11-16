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
