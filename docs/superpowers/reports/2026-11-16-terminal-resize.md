# Unix terminal resize delivery and Restore ownership — 2026-11-16

## Parent local verification checkpoint

Independent review found no issues, inspecting actual sender/closer ownership,
consumer compatibility, causal RED/GREEN and the matching review snapshot.
It verified 5 task paths, 461 inputs, 13 assets and 32 evidence files; it did not
execute tests or independently replay historical RED source.
Parent separately freshly passed the original broad upgrade/client race,
full Go, required server/store/client race, vet, whole terminal race25 and the
actual disposable HTTPS runner (including clean frontend install/tests/build/
audit0). Logs: `/var/tmp/warden-terminal-parent-{original-race,full,required-race,vet,race25,integration}.log`.
These results close the local terminal blocker against the current source,
including the committed native R3 candidate. They do not establish native
Windows, genuine PRF/production trust or hosted-signing acceptance. The next
checkpoint is the authorized PR update and its automatic read-only native CI,
not merge, release or manual signing.

## Scope and baseline

Bounded local bugfix on `hieudmg/security-hardening`, original HEAD
`df6d3aa874266d7a39b468cce032a52cbedf25b4`. Parent owns requirements,
independent acceptance, commit and publication. No staging, commit, push, remote
edit, dispatch/rerun, signing, release, installation, live service operation,
privileged fixture or global tool/configuration change was performed. Protected
untracked `mise.toml` was excluded before content reads/copies/hashes; unrelated
Python cache and all previous private evidence were preserved. Release remains
0.23.0 in the three already-approved fields, with no new version/dependency edit.

Read AGENTS, debugging/TDD skills, approved plan T12/T15/T17 and lifecycle/spec
boundaries, ledger, Session interface, both platform implementations, Unix tests,
and actual SSH/picker consumers before implementing. No new initiative or
public contract was introduced.

> 🧠 **From Hindsight memory (Conventions and patterns)** — Project checkpoints distinguish local implementation/checks from independent and external/native acceptance; this was verified against the current approved plan and retained here.

Private evidence root: `/var/tmp/wtr.HpTp`. Original failing evidence remains
`/var/tmp/ww3.9hre/upgrade-client-race.log`; it is not overwritten or waived.
Complete **original df6d3aa-to-current** review artifacts are separate from all
native-R3 artifacts: `/var/tmp/warden-terminal-review.diff`, `.json`, `.sha256`.
They include both changed Go files, this new report, plan append, and the entire
new ignored ledger delta. The manifest binds exact current and baseline source
inputs, emitted assets, command logs, original failing log, and ledger
prefix/full/delta. Private artifacts are not release signatures.

## Failure evidence and causal limits

The original exact-Go broad race check had 338 top-level passes, one failure and
one skip. `TestResizeEventsPropagate` failed its unchanged two-second assertion,
then the detector reported `Restore` closing events at terminal_unix.go:87 versus
`startResize` sending at :113 after releasing the mutex. The raw stack, not just
the summary, was inspected. Baseline equality did not excuse this real race.

Three independently established defects/paths:

1. **Send/close ownership:** a done check under the mutex does not protect a
   later send after unlocking. Restore closed events without joining the sole
   sender or its signal subscription. The original detector proves overlap.
2. **Notification delivery:** the events channel was unbuffered, and the worker
   used a nonblocking send. A consumed SIGWINCH disappeared whenever the receiver
   had not yet started receiving (including the interval after `Kill` but before
   the test's select). A controlled-channel regression forces exactly that
   ordering and loses the event on the old logic. This establishes a real
   timeout-producing path, not a load explanation. **The original run did not
   instrument signal arrival/receiver readiness, so its exact native scheduling
   is not retrospectively proven.** The regression isolates the causal path;
   repeated native passes alone would not do so.
3. **Partial fixture lifetime:** production initializes stopResize, whereas the
   existing tests often constructed only `in` and sometimes `events`. With a nil
   stop channel, Restore could not wake a worker waiting for SIGWINCH. That is a
   separate resource-lifetime defect, not proof that it caused the original
   notification timeout. Raw entry now establishes all owned resize resources.

No relationship to the older Ctrl-C/Ctrl-D shell acknowledgment fixture defect
is asserted. Its original T12/T15 failures and diagnoses remain historical.

## Minimal implementation and preserved behavior

- Keep the existing one-element `os/signal` input channel and unbuffered public
  events channel. No new queue, buffering API, platform-wide coalescing policy,
  unbounded storage or public seam. Existing OS/Go signal coalescing cannot count
  arbitrary physical resize bursts; this change does not redefine the Session
  contract to permit lost notifications. It removes the extra avoidable loss
  between consuming a signal and finding a ready public receiver.
- The sole worker forwards each consumed signal by selecting between delivery
  and stop, instead of discarding it when no receiver is currently ready. The
  signal producer remains nonblocking through the unchanged buffered Notify
  input. A consumer may be absent indefinitely without blocking Restore.
- Raw entry initializes missing stop/events channels for partial sessions and
  creates a completion channel for its one worker. Repeated EnterRaw starts no
  additional worker. Native raw entry/restoration and Size ioctls are unchanged.
- Restore serializes under the existing mutex, restores terminal state, marks
  done, closes stop, joins the worker **through deferred signal.Stop**, then
  closes public events. The worker never takes that mutex, so a pending send
  cannot deadlock the join. The done flag replaces the redundant stopOnce under
  the same mutex. Repeated Restore and Restore-before-raw remain safe; re-entry
  after Restore still errors.
- A small private `forwardResize` method separates signal subscription from the
  channel-forwarding loop. It is used by production, not a public/test hook.
  `signal.Notify`/`Stop` remain in the actual production worker wrapper. Windows,
  Session API text, SSH/input pump, PTY control bytes, picker, authentication,
  network code, native R3 helper/certificate candidate and resource ceilings are
  untouched.

Installed Go1.26.11 `go doc os/signal.Notify`, `Stop` and `testing/synctest`
were read before implementing the channel tests: Notify does not block, buffer1
is documented for a single signal value; Stop guarantees no further deliveries
when it returns. No new third-party API/import was introduced or altered.

## Test-first evidence

First extracted the existing worker loop without changing its old done-check /
unlock / nonblocking-send behavior; added a completion channel closed after its
existing deferred Stop, not yet joined by Restore. This source-local organization
allowed controlled input and a controlled worker-retirement tail. Then added:

- `TestUnixResizeWaitsForReceiver`: an unbuffered controlled signal input and
  `synctest.Wait` ensure the worker consumes each signal before the test becomes
  a public event receiver. Three sequential notifications must each arrive;
  original two-second bound retained (virtual time in this isolated test).
- `TestUnixRestoreJoinsResizeBeforeClosingEvents`: hold the retirement tail after
  the loop exits, start Restore with a pending notification and no consumer,
  assert it has neither returned nor closed events, then release retirement and
  assert bounded join, closure and idempotence. The tail models Stop; it does
  not claim to intercept the native os/signal internal implementation.

`regression-red.log`, exit1 at 03:37:39Z: first test reports consumed SIGWINCH
lost; second reports Restore returned and events closed before worker retirement.
This is deterministic missing-behavior evidence, not a probabilistic stress RED.
It does not reproduce the exact old native check/send instruction interleaving;
that race is independently established by the retained original detector stack.

After the minimal fix, the same regressions pass (`regression-green.log`, exit0
03:38:28Z). `TestUnixResizeLifecycle` is additional characterization of full and
partial initialization, Restore-before-raw, raw resource ownership, repeated raw
entry, worker completion before Restore returns, closure, repeated restoration
and rejected re-entry. Existing real-process SIGWINCH propagation and PTY echo,
raw Ctrl-C byte, Size, readiness/EINTR tests remain, with their bounds unchanged.
No recover/panic suppression, signal-test skip, assertion weakening or timeout
inflation was added.

## Measured validation

All recorded Go commands use **GOTOOLCHAIN=go1.26.11**, **TMPDIR=/var/tmp**;
Python bytecode disabled. Environment: Go1.26.11 linux/amd64, Linux
7.0.0-43-generic x86_64, Node26.12.1/npm11.20.0, Python3.12.15. Ordinary test
umask022; evidence created under a private directory. Exact argv, UTC start/end,
duration, exit and relevant environment are in `commands.jsonl`; raw test output
and parsed top-level counts/reasons are in the named logs and `test-summary.json`.

| Check | Result / time / evidence |
| --- | --- |
| Two controlled regressions before fix | **RED exit1**, 03:37:39Z, `regression-red.log` |
| Controlled regressions + lifecycle | **GREEN exit0**, 03:38:28Z, `regression-green.log` |
| Focused resize/Restore race25, timeout60s | PASS 1.40s, `focused-race.log` |
| Original whole `go test -json -race ./internal/upgrade ./internal/client/... -count=1 -timeout=180s` | **PASS 22.99s, 342 top-level passes / one explicit skip**, `original-broad-race.log` |
| Full `go test -json ./... -count=1 -timeout=180s` | PASS 31.23s, **797 passes / three explicit skips**, `full-go.log` |
| Entire terminal `-race -count=25 -timeout=180s` | PASS 53.01s, **325 top-level passes / zero skips**, `terminal-race25.log` |
| Required server/... + store + client/... race count1 / timeout180s | PASS 87.65s, **656 passes / three skips**, `required-race.log` |
| CLI race count1 / timeout180s | PASS 3.21s, **59 passes / zero skips**, `cli-race.log` |
| `go vet ./...` | PASS 0.43s, `vet.log` |
| Whole SSH/DB `-race -count=25 -timeout=180s -failfast` | PASS 100.26s, **2,275 top-level passes / zero skips**, `ssh-db-race25.log` |
| Actual `bash scripts/test.sh` | PASS 19.34s, `integration.log`: fresh include-dev ci, 279 frontend +13 dist tests, production assets/build, audit0, both actual binaries, signed disposable HTTPS composed lifecycle, separate preservation/agent/real SSH contracts, four runner contracts |
| Offline `bash scripts/test-installers.sh` | PASS 5.29s, `offline-installers.log`; no live installation |
| Focused resize/Restore normal25 | PASS 0.13s, `focused-normal25.log` |

The only skips in full/required race are the two explicit opt-in browser server
fixtures and `TestRuntimeUnixRejectsWrongOwner` (requires chown privilege). The
original broad scope contains only the wrong-owner skip. A real browser journey
was **not** rerun in this task; production frontend tests and real binary HTTPS
composition are not a genuine PRF browser substitute. Windows build-tag tests
are not Linux passes; no native execution/CI dispatch occurred. No resource-bound
failure or new unrelated failure was observed. The historical native Windows
14/16 two-failure run and R3's native-unrun candidate are not superseded here.

A final test-only cleanup guard was added to the lifecycle characterization;
final current-test-source rechecks and self-review are recorded below. Earlier
logs remain accurate snapshots, not relabeled reruns.

## Remaining gates and handoff

The local terminal validation blocker is corrected with deterministic RED/GREEN
and fresh integrated checks; parent independent review and fresh exact-state
verification remain required. No checkbox, release or overall security acceptance
is claimed. Genuine authenticator PRF + production trust, native Windows all16
once with zero skips (including the committed df6d3aa helper/certutil candidate),
privileged Unix cross-owner and hosted artifact/downstream/OIDC/signature gates
remain open. T16 acceptance is limited to the specified trusted-service/proxy
Undici and DSSE/PAE residuals, not all findings. Permission for a manual public
signing workflow remains unanswered: nothing implemented/dispatched/signed.

## Closing current-state verification and self-review

After the test-only deferred cleanup guard, current-source checks passed again:
`focused-current.log` race25 exit0 (1.39s), `full-go-current.log` exit0 at
03:47:00Z (34.80s, 797 passes/three skips), `original-broad-race-current.log`
exit0 at03:46:46Z (20.12s, 342 passes/one skip), `vet-current.log` exit0,
`terminal-race25-current.log` exit0 at03:49:30Z (52.92s, 325 passes/zero skips),
and `required-race-current.log` exit0 at03:50:29Z (111.24s, 656 passes/three
skips). Whole SSH/DB race25, CLI and the real HTTPS runner precede only that
new terminal test cleanup guard; their production/consumer/native R3 source
inputs are identical to current. They are not mislabeled as rerun afterward.
No production changes followed the original GREEN.

Self-review inspected sender/closer ordering, mutex/join dependency, Stop defer
order, constructor versus partial ownership, unbuffered pending send/cancel,
idempotence/re-entry and unchanged consumer/Windows contracts. The private
hygiene validator's first attempt (`self-review.log`, exit1 03:52:19Z) named
nonexistent `internal/upgrade/lifecycle_test.go`; this was an evidence-validator
path error, not a Go/runtime failure. It was corrected to the actual
`upgrade_test.go`, `replace_windows_test.go` and `installer_https_windows_test.go`.
The first private packaging pass also pointed at nonexistent `web/dist` (zero
assets); before handoff it was corrected to Vite's actual `internal/web/dist`
and expanded to all461 safe tracked inputs. These incomplete intermediate
manifests were not acceptance evidence. Both corrections change only private
validation scripts, not repository tests or production behavior.

`self-review-current.log` exit0 at03:53:35Z checks exact HEAD/branch, empty index,
whitespace, gofmt, unchanged native/API/Windows/consumer/version bytes, release
field parity, complete original ledger prefix, local Markdown links, measured
counts and all recorded exits including intentional RED and the validator error.
Private packaging checks all **five task files, 461 safe tracked inputs, 13
actual emitted assets and evidence hashes**, plus the complete ignored ledger
append, and a **nonapplying reverse `git apply --check`** of the whole review
patch. Artifacts are mode0600, protected content excluded before reads/hashes.
Only closing report/ledger prose and evidence packaging follow these runtime
checks; the final manifest/checksum is refreshed for that exact state. No staging
or application of the patch occurred. Stop at self-review; parent review and
fresh validation remain separate.
