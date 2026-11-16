# Native Windows follow-up — PR #45

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
