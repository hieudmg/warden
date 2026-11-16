# T16 — unprivileged CI and source-bound publication

## Parent review checkpoint and owner disposition

Independent rereview closed the repository-selection P1 and exposure-assessment
finding, with no new issues. Parent freshly ran all 12 offline contracts,
actionlint and Bash syntax successfully; logs are
`/var/tmp/warden-t16-parent-fixed-{contracts,actionlint}.log`.
The owner explicitly accepted the narrowly documented enabled trusted-service/
proxy Undici risks and Sigstore DSSE/PAE type-binding limitation while awaiting
upstream fixes. See [the precise disposition](2026-11-14-t16-action-runtime-risk.md).
This is not blanket audit acceptance or remediation. Native Windows, actual
artifact-service/OIDC/signature evidence and other external acceptance gates
remain pending. No manual signing workflow, dispatch or public test-attestation
write was authorized. The original worker authority and historical statuses
below describe their respective checkpoints, not new parent restrictions or
current risk-decision status.

## Authority and pre-edit CONFIG-TDD exception

T16 only on `hieudmg/security-hardening`, baseline
`96e2ed4986f3423f423942d817c0f220470f15e9`. Bounded implementation and local
self-check, **not independent acceptance, hosted/native execution, M1 or release
acceptance**. Sole writer; no children/worktree, staging/commit/push/PR/tag/release/
deployment, live workflow dispatch, real installer/upgrade/service operation,
global tool/default change, or protected `mise.toml` content access.
All three release fields remain **0.22.1**; T17 owns 0.23.0.

Intentional same-version force-tag/clobber and executable-only/manual-restart
policies are preserved. No immutability or anti-rollback claim is made. Isolation
needs no further mutable-publication policy decision.

**Recorded before workflow/build configuration edits:** declarations, action
pins and test-tool configuration use the plan's CONFIG-TDD exception. Strongest
alternative: first run offline contracts against the actual old workflows;
record wrong permissions/unpinned actions/missing web and integration/native
checks/source-bound publication as RED; then validate edited YAML, pinned action
interfaces, actual build bytes and offline publisher execution. Artifact runtime
validation is tested, not waived. New Windows code is test-only: native RED/GREEN
cannot be executed on this Linux host, and is explicitly **UNRUN**. No hosted CI
is possible before an authorized parent push/PR; no workflow was dispatched.

Private evidence: **`/var/tmp/w16.Bmqg`**, pointer
`/var/tmp/warden-t16-evidence-path`. Local commands use `TMPDIR=/var/tmp`, explicit
`GOTOOLCHAIN=go1.26.11`, Node26.12.1/npm11.20.0, and shell-local umask022 for Go
checks. Tools/venv/source copies are private. The ignored ledger was snapshotted
before task edits (`ledger-before.md`). Historical T14/T15 reports and the plan,
specification, root AGENTS and current sources were read before editing.

## Action/runtime/API grounding

All action pins were resolved from official GitHub **tag refs to actual commit
objects**, including annotated-tag dereferencing where needed; exact pinned
README/action/source files are retained. No SHA was invented or copied from an
unverified example. `scripts/ci/action-pins.json` is the offline fixture allowlist.

| Repository | Verified tag | Commit |
| --- | --- | --- |
| actions/checkout | v7.0.1 | `3d3c42e5aac5ba805825da76410c181273ba90b1` |
| actions/setup-go | v7.0.0 | `b7ad1dad31e06c5925ef5d2fc7ad053ef454303e` |
| actions/setup-node | v7.1.0 | `949feb2413d6458794dcd2491c4babbbce0c15c1` |
| actions/upload-artifact | v7.0.2 | `cf430e030ddbb5b0abf93d22962f4752f3646cd9` |
| actions/download-artifact | v8.0.2 | `9000827ccba6bdab643e8b6fd33ac0654aef8333` |
| actions/attest | v4.2.2 | `1e69f48acb82d1966a394da916b4c1698aa569d6` |

Initially the official composite attest-build-provenance v4.2.2
(`4d101475d8b20a2381f78447822ac1eab6504dd8`) transitively pinned attest v4.2.1
(`508db95dd578ae2727ebd6217d5ba78e4fbda05d`). Review follow-up independently
resolved the official newer attest v4.2.2 above and uses it **directly**, with its
supported default SLSA predicate, identical subject inputs/bundle guard/header
option and explicit no-registry/no-storage settings. No custom signing/fork.
Its locked `@actions/attest`3.2.0 and `csv-parse`7.0.1, and download's locked
`@actions/artifact`6.3.1 were inspected.
All three downloaded package archives passed their exact lock SHA-512 integrity
checks; no package lifecycle script or action bundle ran during this inspection.

Exact sources establish `archive: false` single-file upload, raw download with
`skip-decompress: true`, fatal `digest-mismatch: error`, upload outputs
`artifact-id`/`artifact-digest`, current-run runtime-token scoping with no
`github-token`/cross-run override, streamed subject hashing, SLSA source/run
claims and the bundle output schema. `push-to-registry: false` and
`create-storage-record: false` explicitly disable registry behavior. No extra actions-read permission is needed
for this same-run download. Context7 Actions/PyYAML references supplemented the
pinned official sources, rather than replacing them.

The official Node distribution index lists **26.12.1**, bundled **npm11.20.0**;
its npm engines support this Node. Actual private install/test/build passes.
The action runtime is its own **Node24**, not the application's Node26; the
checkout source documents minimum runner2.327.1. GitHub-hosted runners are the
supported target, not an unverified old self-hosted runner. Caching is disabled,
checkout credentials are not persisted, and setup-go reads **go.mod including
1.26.11**, with an explicit compiler check and exact GOTOOLCHAIN.

Official runner-images README currently maps **windows-latest** to x64 Windows
Server2025 / VS2026. Its matching inventory lists .NET Framework4.8/4.8.1, above
the supported4.7.2 minimum. The job checks actual Desktop PowerShell5.1, registry
Release>=461808, OS and exact Go at runtime; inventory is not execution proof.
Exact PS5.1 certificate-provider/Add-Type and Microsoft X509Store/.NET4.7.2
references were read before the fixture. Context7's newer PowerShell example
was not treated as proof of a PS5.1 API.

Actionlint v1.7.12's tag resolves to
`914e7df21a07ef503a81201c76d2b11c789d3fca`. It is installed at that full commit in
a **private GOBIN**, as is govulncheck v1.9.0 (built with exact Go1.26.11). No
application Go dependency, tool server or global executable was added.
The test-only PyYAML6.0.3 Python3.12 Linux wheel is PyPI-SHA256-pinned; its private
venv installation was actually checked. `BaseLoader` constructs only strings,
lists and maps, preserves `on`, and cannot instantiate executable YAML objects.
Neither parsing nor fixtures rewrite the workflow under test.

## Implementation and source binding

- `test.yml` runs for pull requests and as the reusable main-release check.
  Defaults and all Linux/native jobs have **contents-read only**, no publication
  secrets or write/id-token grant. No pull_request_target or workflow_run path.
  Linux runs explicit-include-dev ci/web tests/build/audit, full Go/race/vet,
  whole SSH/DB race25 bounded180s, offline installer fixtures, actual curl HTTPS
  matrix, signed TLS/proxy restart integration, offline CI contracts, actionlint
  and pinned source govulncheck. Jobs have20-minute bounds. T17's historical
  `scripts/test.sh` replacement is untouched. The separate old-serializer helper
  needs historical git/module-cache inputs, so is not silently called from a
  shallow checkout; existing real store/HTTPS integration is in the full suite.
- `release.yml` preserves the original **push to main** trigger and serialized
  `release-main`, cancel-in-progress=false. The read-only build depends on all
  reusable checks (including required native Windows). It checks out event SHA,
  verifies HEAD, builds, and rejects tracked/staged/nonignored-untracked source
  drift. No publication or OIDC token permission exists during checkout/npm/go.
- The existing build has exactly **three binaries**, not six new targets:
  Linux amd64 server/client, Windows amd64 client. Build script verifies actual
  Go1.26.11/Node26.12.1/npm11.20.0 before dependency installation, includes dev
  dependencies, never executes a target binary, and emits exact
  `<sha256>  ./<filename>\n` sums. No application behavior or dependency changed.
- `release_bundle.py` emits a bounded data-only ZIP_STORED handoff and manifest:
  exact names, sizes, per-asset SHA256, source/repository/event/ref/workflow,
  runID/attempt, release version and minimum Go. Trusted **job outputs separately
  carry manifest SHA, raw-archive SHA, source/run/attempt/version**; upload adds
  the fixed artifact ID and service digest. The publisher does not trust a
  self-rehashed manifest from the downloaded artifact.
- Only `publish` has **contents-write, attestations-write, id-token-write**.
  It performs no checkout, dependency install, repo-script or artifact-code
  execution. Pinned download uses the build output ID within this workflow run,
  raw mode, not a mutable name or a cross-workflow/fork artifact lookup. Static
  inline Python verifies current trusted repository/push/main/workflow, exact
  event SHA/run/attempt, all trusted digests (including the raw service digest),
  bounded archive entries, exact schema/list/size/hash and checksum bytes.
  Unexpected/missing/duplicate/unsafe entries fail; names are never evaluated.
  **Nothing is extracted until all inputs pass**, then only fixed names are
  created exclusively. Publisher-only retry after an old build attempt fails
  closed; rerun the complete workflow to produce this attempt's artifact.
- Attestation `subject-path` lists the **three actual binaries and SHA256SUMS**,
  not the transport ZIP/manifest. A second static inline guard reads the action's
  generated bundle and rehashes individual dist bytes, checks exact subjects,
  source Git commit, push/main/workflow/builder, run and attempt **before gh
  release/tag operations**. This is subject/source consistency, not independent
  Sigstore signature verification: the pinned action/service remains trusted.
  Artifact failures precede attestation as well as release; a generated-bundle
  failure necessarily occurs after the attestation action but before release.
- The original force=true tag update and `gh release upload --clobber` remain.
  No immutable-release/rollback protection, independent checksum authenticity,
  resistance to a compromised trusted build/action/runner, or installer
  attestation enforcement is claimed.

## Native Windows CI wiring — all hosted outcomes UNRUN

`test-windows.ps1` uses **powershell**, not pwsh; logs OS/PS/framework/compiler,
uses a short temporary root, and runs a16-name matrix: agent7, SFTP5, upgrade4.
It first checks `go test -list` equals each expected name list, then executes
`go test -json -count=1 -timeout=5m`. Every named top-level test must have exactly
one pass; **any skip (including a subtest) fails**. No continue-on-error, empty
regex pass, or whole Unix/PTTY suite on Windows. JSON logs are uploaded even on
failure with a separate read-only job artifact (never a publication input).

The matrix names cover malicious pipe/certificate exchange, wrong/stale pins,
relay confidentiality, native staging-unlink/ACL/owner rejection, reparse/reconnect,
SFTP native containment/private-at-creation/replacement/root spelling and hostile
real adapter listings; plus the existing updater stage/collision, atomic helper
success/locked failure, C# compile/private-files/HTTP-untrusted-TLS refusal tests.
These test fixtures include descriptor-owner rejection, not a claim to have
executed a second real Windows user account.

**New explicit fixture:**
`TestWindowsPowerShellTrustedHTTPSReleaseMatrix` in
`internal/upgrade/installer_https_windows_test.go`. It requires
`WARDEN_NATIVE_HTTPS_FIXTURE=1` **and** the disposable hosted Windows environment;
the CI job sets that opt-in. Without it the test skips, which the CI harness
would reject. No such fixture previously existed in the T14 source; merely
running the older compile/refusal tests would not prove trusted HTTPS.

It compiles the **unchanged actual embedded installer C#**, supplies a unique
one-hour fixture CA and leaf, serves a signed local CRL for ordinary platform
revocation validation, and trusts only that CA in **CurrentUser Root**. Cleanup
removes the exact thumbprint only after certificate-byte comparison; independent
Go-deferred PowerShell cleanup also runs if the main process is terminated.
Nothing touches LocalMachine or the local Linux host trust store. Private files
use the existing owner-DACL creation helper. No permissive TLS callback,
production trust bypass, lowered production constants, installer entry-point,
service/elevation or downloaded-code execution is used.

The11 native C# scenarios are verified-platform-trust exact success, verified
HTTPS CDN redirect success, downgrade and initial HTTP refusal with zero HTTP
payload hits, wrong/duplicate checksum, truncated body, streamed binary256MiB+1,
checksum1MiB+1, actual10s header timeout, and untrusted TLS refusal. Both streams
must reach each positive peer. No test-only shortened size/time constants.
Actual native compilation/execution/store cleanup/PS/.NET API compatibility,
5-minute cancellation behavior and full installer user-environment behavior are
not proven locally. Native job failure/capability absence must be investigated,
not hidden with skips or production weakening. Cross-compile evidence below is
**only compilation**.

## Measured RED / GREEN

| Check | Actual pre-change evidence | Current local evidence |
| --- | --- | --- |
| Workflow declarations | `contracts-red.log`: old contents-write, v4/v5 tags, missing test/native/isolated-publisher paths (8 failures plus one missing-job error across5 tests) | `contracts-final.log`, subsequently refreshed: all12 offline contracts pass |
| Artifact/runtime handoff | `publication-red.log`: missing byte-bound builder/publisher (18 failed subcases across5 tests) | Actual inline validator/gh shell executed with real synthetic files; tamper/missing/extra/traversal/digest/self-rehash/source/run/attempt/event/ref/fork/workflow/minimum/version cases rejected before release; fake gh checks create and force/clobber paths |
| Optimized Python | `builder-optimized-red.log`: PYTHONOPTIMIZE=1 bypassed initial assert-based checksum check and created bad ZIP | Explicit non-assert guards; optimized bad checksums fail before ZIP creation |
| Generated provenance guard | `provenance-red.log`: valid artifact reached missing post-action guard | Actual inline bundle guard passes upstream-generated subjects and rejects ZIP/wrong hash/source/attempt |
| Native Windows | No local native RED or GREEN possible | New fixture and all three test binaries compile; actual hosted/native **UNRUN** |

The unsigned fixture in `scripts/ci/fixtures/provenance.json` was initially
source-generated with official subject/digest/SLSA/in-toto functions. Review
follow-up regenerated it **byte-identically from actual shipped attest v4.2.2
dist**, including real glob expansion and default-predicate selection. The only
seams suppress the signing/upload entrypoint and substitute synthetic claims at
one OIDC retrieval boundary; HTTP(S) requests throw. The same bundled functions
hashed **all real release build bytes**, and current inline guards pass that
result. See fixture README and `r1/dist-provenance.log`, `real-byte-guards.log`.
This is not a model duplicating our validator, nor signed/hosted proof. Evidence
also reproduces the shipped DSSE PAE type collision; the actual guard rejects
that mutant type. Files/generator/dist/claims are evidence-hashed.

## Current-source validation

| Command / scope | Result |
| --- | --- |
| Private pinned PyYAML venv; `python3 -m unittest discover -s scripts/ci -v` | PASS12 tests, plus adversarial subcases; no real gh/network writes |
| Pinned private actionlint `-shellcheck= -pyflakes=`; `bash -n scripts/build-release.sh` | PASS; shellcheck/pyflakes unavailable, not claimed run |
| Private452-file source copy, `timeout 600s bash scripts/build-release.sh` | PASS24.48s; actual3 binaries/sums, peak RSS771056kB; no target execution |
| `sha256sum -c SHA256SUMS`, `go version -m` every binary; actual-byte bundle and provenance guards | PASS; exact compiler; simulated run1234/attempt2 with base HEAD plus uncommitted T16 inputs, **not hosted identity** |
| Private `ci --include=dev`, `ls --all --include=dev`, `audit --include=dev` | PASS, audit exit0 / zero findings |
| Private `NODE_ENV=test npm --prefix web test`; TypeScript/Vite build/verifier | PASS279 frontend +13 script tests; existing chunk warning only |
| Private build versus existing embedded distribution | All13 files byte-identical, including CSS/JS/fonts/manifest; no frontend source/asset change or fresh browser run claimed |
| `go test ./... -count=1 -timeout=180s` | PASS24.69s |
| `go test -race ./... -count=1 -timeout=180s` | PASS95.27s, peak RSS1516604kB |
| `go vet ./...` | PASS |
| Whole SSH/DB `-race -count=25 -timeout=180s -failfast -v` | PASS SSH102.577s, DB4.563s; no raised resource/exit bound |
| `bash scripts/test-installers.sh` | PASS offline sandbox; no real installation/service operation |
| `python3 scripts/installers_test.py` | PASS4 test methods/matrices2.618s, real curl + private verified TLS |
| Named signed HTTPS runtime restart integration, tls/proxy | PASS0.446s |
| Exact-Go source govulncheck1.9.0 text + JSON | Text exit0, **0 symbol /0 package /8 module-only** |
| Windows amd64 agent/SFTP/upgrade `go test -c`, `go build ./...` | PASS **compile only**, native UNRUN |

Real private asset digests (not release/publication identifiers):

| Asset | Bytes | SHA256 |
| --- | ---: | --- |
| warden-linux-amd64 | 8720546 | `5fdc9e5f71d97b62940f76de7f5e690a0c6b3d5a9f46e6d2ebe98a80e13bcc19` |
| warden-server-linux-amd64 | 14479522 | `02f21490a4c5d3ac73c3ebe92e9098061b0f2f10f3d7f8897b7a5126668be520` |
| warden.exe | 9176064 | `c8a4a20f73f340e9b36ff08de6d485c8683fe901d1a44e7d5c4ea268a53e1ab2` |
| SHA256SUMS | 260 | `fccefa257cc04d645de2dd28169614cb99b62f8643ff77c2d81c4e18e5ad18dd` |

### Scan precision limitation (not a silent green binary gate)

Source scan1.9.0 uses exact Go1.26.11 and DB2026-11-11T02:51:11Z. The eight
module-only IDs remain5932/6603/6610/6611/6612/6617/6860/6866, as T15; no general
module sweep was authorized. No source/package finding is waived.

Attempted scans of the **actual stripped release bytes** return text exit3 for
these8 IDs. Diagnosis, not a dependency fix: existing build flags `-s -w` remove
the symbol table (`go tool nm` fails), and scanner1.9.0's exact
`internal/vulncheck/binary.go:106–113` explicitly substitutes all known vulnerable
symbols at **go.mod-level precision** when no package symbols are available.
`buildinfo/additions_scan.go:87–90` confirms that fallback. Thus these results do
not establish newly imported OpenPGP/HTML/HTTP2 or eight reachable release paths,
and must not be advertised as a clean binary scan. JSON exit0 alone is not a gate.

Controlled same-source/compiler/trimpath unstripped CLI/server builds both scan
text exit0 (0 affected +8 module-only), corroborating that precision limitation;
they are **different bytes**, not evidence that stripped-binary scans passed.
All failed stripped scans/metadata/source/diagnostic counterparts are retained.
CI gates source scan, not a pretend clean stripped-binary result. Build flags and
server dependencies were not changed to hide this limitation.

### Official-action dependency audit — separate unresolved upstream risk

Initial `npm audit --include=dev --json` against each **exact official action's**
package/lock, in private directories, exited1. No action npm install, lifecycle
script, server dependency edit, patched action fork or audit-fix was performed.
Counts are affected package rows, not independent vulnerabilities. Follow-up
fresh audits reproduce all five non-attester counts; old attester is retained
chronologically alongside current attester:

| Action lock | critical/high/moderate/low | total |
| --- | --- | ---: |
| checkout | 1/4/8/8 | 21 |
| setup-go | 1/5/17/4 | 27 |
| setup-node | 1/1/20/2 | 24 |
| upload-artifact | 3/9/20/5 | 37 |
| download-artifact | 4/9/14/5 | 32 |
| old transitively pinned attest v4.2.1 | 1/8/27/5 | 41 |
| current direct official attest v4.2.2 (fresh follow-up) | 1/6/28/5 | 40 |

Do **not** describe these as all dev-only or as Warden's zero npm audit.
The follow-up [shipped-runtime assessment](2026-11-14-t16-action-runtime-risk.md)
records exact dist/package sources, advisory IDs/ranges, enabled function paths,
input origins, adversary prerequisites, likely consequences and alternatives.
In particular, attester's shipped Undici6.25.0 networking to GitHub is enabled:
GHSA-35p6-xmwp-9g52 response-queue poisoning and GHSA-xjj6-f33q-929c /
GHSA-qrxm-fqhp-jwvm response/TLS1.2 DoS require a malicious/compromised reached
service/proxy, not artifact manifest content. Shipped Sigstore core2.0.0 PAE
has GHSA-jfc7-64v2-mr8c; producer type is fixed ASCII and guard rejects mutation,
not a claim the library or downstream verification is fixed. OCI update fixes
GHSA-j63v-mwhm-56jx but that registry branch is disabled, not demonstrated enabled
exposure. Other parser/expansion/address advisories are individually conditioned
in the assessment; lodash lock findings alone did not demonstrate shipped
vulnerable methods. Static analysis is bounded, not unknown-callgraph proof.
There is no verified newer listed official fixed bundle. Recommendation: retain
the official partial fix, obtain **specific narrow owner disposition or await an
official patch** before publication acceptance, never a blanket lock/dev/pinning
waiver. No custom signing, fork or capability/architecture replacement is approved.

## Reviewer P1 fix pass — chronology and focused validation

Same writer/baseline, T16 only. Reviewer correctly found that a no-checkout
publisher cannot rely on Git remote discovery: GitHub CLI's documented override
is **GH_REPO**, not GITHUB_REPOSITORY. Tag API paths already named the repository
and could mutate before `gh release` failed. Exact installed gh2.103.2 help and
official source at verified tag commit
`4f2cfe92e3499f8581bf39db77e0a1431fa7b55c`,
`pkg/cmdutil/repo_override.go` / `pkg/cmd/release/release.go`, confirm inherited
`--repo` takes precedence over GH_REPO; Context7 manual corroborates it.

1. **Before production workflow edits**, strengthened actual fake-gh fixture
   to remove inherited GH_REPO and reject missing/wrong explicit repository.
   Ran with hostile inherited GH_REPO: `r1/repository-red.log` fails exactly
   `release command missing or wrong explicit repository` after the tag probe.
2. Added `--repo "$GITHUB_REPOSITORY"` to **each** edit/upload/create. Repository
   is already validated by the unconditional earlier guard. GREEN proves
   create/force/clobber paths in a private non-checkout directory. Six individual
   missing/wrong-target mutations (edit/upload/create separately) are refused;
   non-404 metadata failures still stop. Publication execution uses fake gh only;
   actual CLI invocations were help-only, never release/tag writes.
3. Independently verified official attester update/interfaces/source **before**
   production pin change; extended offline pin/default-predicate contract first.
   `r1/attest-pin-red.log` has two actual old-wrapper failures. Direct official
   update then GREEN, with identical default SLSA/byte/source/run/bundle behavior.
   This declaration uses the already recorded CONFIG-TDD exception, not a runtime
   waiver. Shipped-dist generation and packaged-source assessment are above.
4. Current **12 full offline contracts PASS**, including previous tampering,
   identity, optimization, fork/workflow and artifact attacks, added per-command
   repo mutations, Unicode-mutated envelope type, wrong predicate/workflow, and
   action pin/default guards (`r1/contracts-green.log`). Six additional private
   YAML mutations (wrong SHA/repository/mutable tag, broad permissions, removed
   web tests/integration) all fail the actual contracts without editing production
   (`r1/adversarial-workflow-contracts.log`). Private pinned actionlint and Bash
   syntax PASS. Actual private release-byte archive and new shipped-dist
   unsigned provenance pass both real inline guards. No source/fixture rewrite
   disguises a hosted signer test. No hosted action entrypoint or OIDC ran.
5. No Go/native-helper/application/build inputs changed **in this fix pass**.
   All380 validated compiled/frontend/build-input hashes still match, as do all13
   embedded files (`r1/hygiene.log`, `r1/unchanged-build-inputs.json`); earlier
   full Go/race/build/Windows compile results above remain historical evidence
   for unchanged inputs, not newly executed native/full/race proof.

Safe hosted validation route is **outline only** in the runtime assessment:
ordinary authorized parent push/PR can run read-only required native tests;
a separately approved trusted-main manual attestation-only verification purpose
could test artifact/OIDC before release, with no tag/release write, no build-time
write grants and distinct fail-closed identity expectations. It may still create
public attestations/transparency records, so neither code nor run is silently
authorized. No new workflow, dispatch, publication trigger or permissions added.
All16 native tests and actual artifact-service/OIDC/signing remain **UNRUN**.

## Handoff / remaining acceptance

Changed scope is workflows, build script, CI fixtures/pins/test-tool requirement,
one native Windows test-only file, this report and shipped-runtime assessment,
the T16 plan checkpoint and the
T16-only ignored-ledger append. No production Go/frontend/dependency/release
field changed. Private source/build hashes bind exact compiled inputs; no global
runtime/tool configuration or protected-file content was inspected/changed.

Exact unstaged review patch: **`/var/tmp/warden-t16-review.diff`**.
Manifest: **`/var/tmp/warden-t16-review.json`**, including all new task files,
whole T16 ledger delta, original ledger hash and private evidence hashes.
Checksum artifact: **`/var/tmp/warden-t16-review.sha256`** binds diff and manifest.
These are self-review artifacts, not independent approval.

**UNRUN:** hosted PR/reusable workflows, all16 native Windows tests and their
C# scenarios/CA cleanup, actual artifact-service upload/download, OIDC/Sigstore
signed provenance, and real release/tag operations (not authorized). Genuine
PRF-positive M1 and production-trust/browser/complete Windows installer acceptance
remain T17/external requirements. Existing synthetic PRF/browser success and
compile-only Windows do not close them. The upstream action audits and stripped
binary precision limitation above also remain explicit review items.

Final source/diff self-review and hygiene PASS: all16 task paths (including the
ignored ledger delta and every new fixture), formatting/whitespace/newlines,
380 compiled/frontend/build-input hashes still matching the validated private
copy, all13 embedded files identical, original ledger prefix preserved,
branch/HEAD unchanged, index empty, and all three release fields0.22.1. The
complete unstaged patch passes non-applying reverse `git apply --check`; its
manifest binds task and evidence hashes. Initial action/tool tag refs were
independently rechecked; follow-up separately resolved the new attester and CLI
tag commits and refreshed official release-tag lists. These checks do not upgrade
UNRUN hosted/native outcomes or count as independent review.

Stop at T16 implementation/self-review. Recommended next: independent parent
review of this exact diff and residuals; only after separately authorized parent
push/PR may hosted CI produce native evidence. Do not waive native failures,
mark M1/T16/security release accepted, start T17, bump versions or publish here.
