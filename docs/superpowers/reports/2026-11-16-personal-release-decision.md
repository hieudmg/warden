# 0.23.0 limited personal release — owner decision

## Authority and limits

The sole user/developer explicitly approved releasing 0.23.0 for personal daily
use after disclosure of the outstanding risks. This decision supersedes the
prior release/push hold and BLOCK disposition **as release authority only**; the
historical reports and failures remain valid evidence. Deferred checks are
**NOT PASS**, and this is not a claim of general production security acceptance.
Windows validation is owner-owned. Independent review of this bounded change and
the parent's hosted Linux checks after push remain pending.

The existing post-merge release workflow, including public attestations, is
allowed as part of normal publication. No separate manual signing workflow is
needed. The parent owns Git staging/commit/push, PR/merge, and publication; this
worker performs none of them. No live install, migration, service cutover,
certificate-store operation, GUI action, or global-tool change is authorized here.

## Known deferred evidence

- Latest native Windows result remains **15 PASS / 1 FAIL / 0 SKIP**. Both owned
  CurrentUser Root removal dialogs were observed; removal completion, absence
  after **both** cleanup attempts, and the final Go counter assertions remain
  unproven. The cause is not established. R8 diagnostics are not a cleanup fix.
  No removal-consent automation is added or authorized by this CI refactor.
- Genuine authenticator PRF, production certificate trust, privileged Unix
  cross-owner validation, and hosted release artifact/OIDC/signature provenance
  validation remain unverified/deferred, not passed. Synthetic PRF, compilation,
  fixture consent dispatch, or local tests do not substitute for these proofs.
- The previous hosted Linux import-toast failure has a reviewed local test-only
  correction at `419dc588a8077e26b5f1a6f29d8c7a94967d1eab`. Its local evidence is
  recorded in `2026-11-16-import-toast-test.md`; a fresh hosted Linux pipeline for
  the combined state has not run in this task.

## Bounded CI change

`.github/workflows/test.yml` retains only the original Linux job, with its bytes,
PR/`workflow_call` triggers, checks, time bounds and read-only permissions
unchanged. `release.yml` is byte-identical and still calls that Linux workflow
before build and isolated publication. Build/publisher isolation, provenance
validation, pinned Actions and all existing T16 guards are unchanged.

The original Windows job moves byte-for-byte to
`.github/workflows/test-windows.yml`, triggered **only** by owner-invoked
`workflow_dispatch`, with `contents: read`. All 16 named tests, the unchanged
`scripts/ci/test-windows.ps1`, Desktop PowerShell, fixture environment, pinned
Actions, 20-minute job bound and seven-day failure-evidence retention remain.
There is no automatic Windows dependency, new privilege, test skip, fabricated
pass, or change to product security, existing guarded GUI automation, trust
checks, cleanup assertions, or native acceptance requirements. No Windows run was
started by the worker.

## Local validation and self-review

- Test-first: the updated workflow contracts failed before configuration changes
  because the manual workflow was missing and the automated workflow still had
  a Windows job (seven tests, five expected failures). The earlier six-test RED
  is also retained; the final split contracts independently expose both changes.
- GREEN: `python3 -m unittest discover -s scripts/ci -v`: **14 PASS**, no skips,
  including the unchanged executable synthetic publisher/provenance guards.
- Existing `actionlint` v1.7.12: PASS across workflows, with ShellCheck and Pyflakes
  explicitly disabled (`-shellcheck= -pyflakes=`), not claimed as checked.
  Installed actionlint parser source, linked to official GitHub workflow syntax,
  confirms the empty `workflow_dispatch:` mapping; installed PyYAML 6.0.3 source
  confirms the existing `load(..., Loader=BaseLoader)` API. No dependencies added.
- Exact extraction/source-freeze comparisons cover Linux, the moved Windows job,
  `release.yml`, the Windows harness and other tracked inputs outside this task.
  Child checks use umask 022, `TMPDIR=/var/tmp`, and `GOTOOLCHAIN=go1.26.11`;
  the exact Go compiler version is recorded, but no Go suite is rerun for this
  workflow/documentation-only change. No frontend rerun is claimed.
- Private evidence root `/var/tmp/wpr` is 0700, evidence files 0600. Review bundle:
  `/var/tmp/warden-personal-release-review.{diff,json,sha256}`. It binds the small
  task scope, RED/GREEN logs, source-freeze results and full append-only ledger
  delta. This is self-review, not independent approval or hosted acceptance.

## Publication handoff — retain in release notes

0.22.1 → 0.23.0 is a **breaking authentication/encrypted-storage transition**;
all three already-bumped 0.23.0 version fields are unchanged. Preserve the legacy
migration guidance: **export legacy v1 data using the old release, freshly
initialize the new release, then import**. Do not imply an in-place automatic
migration. The parent's release notes must retain this breaking-change warning,
legacy export/fresh-init/import instructions, and the limited personal-release
exception with the deferred checks above; the frozen workflow's generic generated
notes are not a substitute. Existing migration/recovery documentation remains.

Stop for independent review of this exact bounded patch. The owner accepts the
limited personal-release risk; no deferred validation has been relabeled passed.
