# Import-success toast test: controlled ambiguity correction

## Scope and boundary

Baseline `15c93b8a89241fd3b69f9c015d7ad527eee4f12e`, branch
`hieudmg/security-hardening`. This is a test-only correction plus this report,
an appended plan entry, and the ignored append-only ledger. No runtime,
accessibility, dependency, workflow, timeout-global, Windows, installer, or
release changes. The approved base remains 0.22.1 and all three existing 0.23.0
version fields remain frozen. No staging, commits, publication, CI dispatch,
installation, global configuration, trust/GUI, signing, or service changes.

Hindsight Conventions and patterns informed the fixture-first investigation and
separation of local verification from external acceptance; current source and
actual logs, not historical passing results, establish the findings below.

## Actual failure and mechanism

Automatic R8 run `43860842587`, expected head `15c93b8`, actual merge
`be0bf8fcb09c64371c712e83a828222ca144fe1d`, failed its second frontend invocation:
278 PASS / 1 FAIL. The first frontend invocation passed all 279. Raw evidence:
`/var/tmp/warden-pr45-native-r8/linux.log:10925-11002` shows the original
`screen.findByRole("status")` finding BOTH:

- the real toast `li`, `role=status`, `aria-live=polite`, title `Success`, message
  `Imported data successfully.`;
- Radix's visually hidden announcer `span`, `role=status`, containing
  `Notification SuccessImported data successfully.`.

Installed `@radix-ui/react-toast` **1.2.23**, reached through `radix-ui`, implements
this in `web/node_modules/@radix-ui/react-toast/dist/index.mjs`: `ToastImpl`
creates a separate `ToastAnnounce` with `role=status`; it portals a VisuallyHidden
span outside the viewport region. Its text is populated on the next animation
frames and it is removed by a one-second timer. The visible toast is portaled
into the viewport. Warden's existing viewport exposes the named
`Notifications (F8)` region. Warden's toast itself retains its existing status
role and polite live region. No production accessibility defect is inferred or
corrected by this task.

The test incorrectly required document-wide uniqueness of a role legitimately
shared by those elements. The hosted DOM directly establishes the ambiguity;
the exact scheduling that made that hosted query exhaust its retry window is
not retrospectively known. This is not a claim that every unscoped query always
fails, nor a passing-rerun waiver.

Installed Testing Library React 16.3.2 and DOM query implementations were
inspected; Context7 documentation for React Testing Library 16.3.2 was also
retrieved (`ctx7:docs:5e9f90062418674fc5e3b646`). No package changes/install.

## RED → minimal GREEN (UTC, 2026-11-16)

1. **12:03:42, observation, not RED:** the existing successful-import test was
   made to await the real announcer's exact text and role before the original
   document-wide assertion. This passed: the default async query can wait until
   the announcer disappears. Its log and command are retained as
   `unbounded-observation*`; it is not counted as evidence of a fix.
2. **12:04:30–12:04:33, genuine RED, exit 1:** retain that real-component
   precondition, but bound the original document-wide status query to **250 ms**,
   below the announcer's one-second lifetime and below the previous default
   query budget. It fails with `Found multiple elements with the role "status"`,
   showing the same actual toast and announcer as hosted CI. `app.red.tsx` and
   `red.log` preserve the exact failing test source and DOM. This is a controlled
   reproduction of the query mechanism, not an exact historical timing replay.
3. **12:04:59–12:05:01, GREEN, exit 0:** change only the query scope to
   `within(screen.getByRole("region", { name: "Notifications (F8)" }))`; retain
   the same 250 ms bound. Assert the announcer is outside that region and still
   mounted after the toast checks. Assert the uniquely selected status toast,
   exact import-success message, and `Success` title are visible. Preserve
   all five original `toHaveBeenCalledTimes(2)` checks and their existing waits:
   SSH, DB, groups, projects, key pairs. No arbitrary first match, hidden-role
   filtering, fake timers, mocked announcer, sleeps, skips, or extended bounds.

The regression strengthens the existing test; no test was removed or added.
All **279** Vitest tests remain. The 250 ms budget prevents retry-until-announcer-
removal from concealing ambiguity; the final mounted-announcer assertion makes
that condition explicit even if a slow host runs past the intended window.

## Fresh local verification

Exact argv, UTC starts/ends and exits are retained in `/var/tmp/wft/commands.jsonl`
and separate RED/GREEN command JSON. Test subprocesses use umask 022,
`TMPDIR=/var/tmp`, and `NODE_ENV=test`; the build uses `NODE_ENV=production`.
Private recorder files use 0600 inside a 0700 directory.

| Check | Result |
| --- | --- |
| Focused existing import test | Controlled RED exit 1; minimal GREEN exit 0 |
| Predetermined 25 independent focused invocations, 12:06:03–12:06:56 | 25/25 PASS, each executing the real-announcer precondition and all five refresh checks; 25 other app tests per invocation are deselected by `-t`, not acceptance-suite skips |
| `npm --prefix web test`, twice, 12:06:03–12:06:23 | Each: 17 files / 279 Vitest PASS, plus 13 node:test distribution contracts PASS, zero suite skips |
| `NODE_ENV=production npm --prefix web run build`, 12:06:23–12:06:24 | PASS; existing >500 kB chunk warning only; distribution verification PASS |
| `npm --prefix web audit --include=dev`, 12:06:24–12:06:25 | PASS, 0 vulnerabilities; no install/fallback or package changes |
| Remaining integrated runner commands, 12:07:57–12:08:02 | PASS with actual freshly built production binaries, exact Go 1.26.11; named composed HTTPS lifecycle, preservation/import/rollback suites, four permanent-agent/SSH graph characterizations, and four runner declaration contracts |
| Source/asset/diff checks | All non-task tracked inputs unchanged; all 13 emitted production assets byte-identical before/after build; empty index; whitespace check PASS |

The frontend argv above is the original `scripts/test.sh` frontend invocation,
including `NODE_ENV=test`. **The whole script was not executed verbatim**:
its mandatory `npm ci --include=dev` is prohibited by this task's no-install
boundary. The exact suffix beginning at `mkdir "$WORK/bin"` was extracted into
private `integration-remainder.sh`, with disposable work/trap and original
Go/TMPDIR/environment/umask setup. It runs the unchanged build and Go/Python
commands after the separately executed frontend/build/audit steps. This is
fresh integrated remainder coverage, NOT a claim that dependency installation
or a verbatim end-to-end `scripts/test.sh` invocation was verified.

Two harness failures are retained, not silently discarded:

- The first private Python recorder launch had a quoting SyntaxError before
  any tests ran. The erroneous script and both launch logs are preserved;
  correcting only its quoting allowed the predetermined runs to execute.
- The first integrated remainder failed compiling standard packages:
  `go1.25.14` did not match tool version `go1.26.11`. A controlled shell comparison
  showed that, despite resolving the exact 1.26.11 executable, without explicit
  child `GOROOT` the shell resolved the 1.25.14 source/tool root; with explicit
  child `GOROOT` both roots resolved to 1.26.11. Setting that variable only in
  the private runner environment made the unchanged integrated commands pass.
  The failure log, comparison, and both execution records are retained. No
  global Go configuration, source, cache purge, or tool installation changed.

Full Go/full-race/vet/SSH-DB-race25 were not freshly repeated for this isolated
TS-test change. The supplied R8 results for those checks are historical, not
fresh local evidence here. The selected production-path Go checks above are
fresh; synthetic PRF fixtures are not genuine authenticator acceptance.

## Review and remaining gates

Private review bundle: `/var/tmp/warden-import-toast-review.{diff,json,sha256}`.
It binds the exact baseline, task bytes and patches (including the entire ignored
ledger delta), unchanged safe tracked source inputs, installed source evidence,
original and RED test snapshots, raw hosted failure reference, all recorded
command outputs, and before/after production-asset hashes. The protected
untracked `mise.toml` is excluded from explicit collection paths; unrelated
cache/private artifacts are not modified. No source-runtime changes are made.

This is a tested local candidate for independent review, not parent approval,
hosted rerun success, or release acceptance. Existing R8 Windows status remains
15 PASS / 1 FAIL / 0 SKIP; both cleanup absence proofs and final counters remain
pending. No removal consent, GUI/trust action, or Windows change was attempted.
Genuine PRF/production trust, privileged Unix acceptance, hosted artifacts/OIDC/
signatures, and signing authorization remain open. Stop at the review boundary;
publication and any further external actions belong to the owner/parent.

## Parent local acceptance

Independent reviewer `01a1e1ea-4a07-7503-b4c7-e7dc96ff6f22` found no issues in the exact four-task patch. Its verification was read-only, not a test execution. Parent inspected the actual test diff and hosted duplicate-role DOM; all four task hashes, 473 current safe inputs, 61 evidence hashes and 13 emitted assets matched before this prose append. Parent freshly ran the full frontend (279 Vitest plus 13 distribution contracts, zero skips), production build and include-dev audit (zero vulnerabilities): `/var/tmp/warden-import-toast-parent-{frontend,build,audit}.log`. Production assets remain byte-identical. No fresh full Go/race/vet, native run or verbatim `scripts/test.sh` is claimed.

Accept only a local test-correction checkpoint. Hold the next push/automatic native validation pending the separately requested removal-confirmation decision, rather than repeating unchanged Windows diagnostics. No removal GUI action is authorized; native absence proofs, final counter assertions and the other external acceptance gates remain open.
