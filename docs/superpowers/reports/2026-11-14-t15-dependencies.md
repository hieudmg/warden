# T15 — dependency remediation, local tooling removal and validation

## Authority and status

Owner-authorized **T15 only**, branch `hieudmg/security-hardening`, baseline HEAD
`c0e77b744093b32db793b7835291bef85f86f7f5`. Sole writer; no children/worktrees,
staging, commits, pushes, deployment, release/version bump, SFTP fork or rsync.
Protected unrelated `mise.toml` is not read or changed. T16 is not started.

**Resumed with owner approval:** minimum build Go is now authorized to become
**1.26.11**, enforced by `go 1.26.11`, not merely a preferred toolchain. Every
resumed Go build/test/scan uses explicit `GOTOOLCHAIN=go1.26.11`; actual version
and scanner build metadata are checked. Binary runtime hosts do not need Go.
Host defaults and protected configuration remain untouched. The owner later
approved project-local shadcn CLI/MCP removal; its verified local dependency is
now removed while exact 4.19.0 static CSS and the full MIT notice/provenance are
retained. **Latest measured status:** fresh include-dev npm audit exits0 with
zero findings; fresh source/build-matched Go text gates exit0 with zero
symbol/package findings and **eight explicit module-only IDs**. The separately
authorized fixture-only correction passes whole SSH/DB race25. Bounded T15 is
implemented/self-reviewed, **not full independent/native/security-release
acceptance**. All earlier blockers, partial outcomes and failures below remain
historical; the latest owner-approved removal outcome supersedes their status.

**Pre-edit checkpoint (historical):** the dependency/documentation TDD exception
below still applies. Historical Go1.25 scan RED remains valid; a fresh pinned
Go1.26.11/v1.9.0 scanner run also exits 3 before x/crypto remediation. No
Warden behavior adapter has been written; one would require a focused actual RED.
The sections through “Validation limits and final checkpoint” below preserve the
**initial blocked preflight history**, not the resumed final status. Resumption
and the later owner-approved removal results are recorded separately below with
new exact-source evidence and checks.
Private resumed evidence: `/var/tmp/w15r.65nV`; initial evidence is preserved.

## Dependency-only TDD exception — recorded before dependency edits

Dependency declarations/lockfiles and evidence-only documentation have no useful
application-behavior RED by themselves. Retain fresh advisory JSON and a failing
vulnerability scan as dependency RED; validate any authorized compatible update
with the same supported, pinned toolchain and fresh scan, exact upstream patch
review, safely reproducible in-process vectors, full Go/race/vet, clean disposable
npm install/tests/build/emitted assets and a build-matched T9 browser journey.
No GREEN is claimed before that work. If an API migration changes Warden behavior,
its regression must run RED before production edits; this exception does not cover
such a migration. A material toolchain/security/product choice requires owner
authorization before implementation. No migration or runtime test was fabricated
merely to obtain RED for a dependency manifest.

Confirmed actual tools: `GOTOOLCHAIN=local go version` is
`go1.25.14 linux/amd64`; `go.mod` declares `go 1.25.0`; Node `v26.12.1`, npm
`11.20.0`. Commands use `TMPDIR=/var/tmp`, with private diagnostic evidence under
`/var/tmp/w15.utwz`. Scanner installation is private/pinned, never global, and
automatic toolchain selection is disabled. No real Warden endpoint is contacted.

## Initial official evidence

- [GO-2026-6354](https://vuln.go.dev/ID/GO-2026-6354.json), alias
  CVE-2026-78662: undecided-channel flooding deadlocks SSH; first fixed v0.56.0.
  Official patch reference: <https://go.dev/cl/826504>.
- [GO-2026-6355](https://vuln.go.dev/ID/GO-2026-6355.json), alias
  CVE-2026-56855: crafted established-channel messages deadlock SSH; first fixed
  v0.56.0. Official patch reference: <https://go.dev/cl/826524>.
- Both reviewed official records list `ssh.NewClientConn` among affected symbols.
  Current Warden pins x/crypto v0.55.0. Fresh local-toolchain reachability is
  reproduced below; parent automatic-Go-1.26 evidence is not local scan proof.
- Exact [v0.56.0 go.mod](https://proxy.golang.org/golang.org/x/crypto/@v/v0.56.0.mod)
  declares **`go 1.26.0`**, requiring an unapproved contract change.
- Official [Go release history/support policy](https://go.dev/doc/devel/release)
  supports a release until two newer major releases exist. Current download JSON
  lists Go 1.27.4 and 1.26.11 as stable supported lines. The complete official
  download list ends the 1.25 line at **1.25.14**, not a later security patch.
- Fresh baseline `npm --prefix web audit --json` exits 1: **20 affected packages
  (1 critical, 10 high, 8 moderate, 1 low)**. Baseline JSON and `npm explain` paths
  are retained privately; exact exposure and residuals are recorded below.

## Required decision

Authorize a new minimum/supported Go runtime (at least Go 1.26, with an explicit
supported patch policy) to permit x/crypto v0.56.0 and standard-library fixes, or
explicitly retain Go 1.25 and accept/defer the reachable advisories. Lowering an
upstream Go requirement, vendoring/backporting, a fork, and automatic Go 1.26
selection are not approved compatible updates. No such workaround is applied.

No supervisor-contact tool is available in this session; this report and the
handoff escalate that decision. **Stop before unsupported dependency edits.**
The owner may separately authorize bounded npm remediation while the Go decision
is pending; none was silently substituted for the requested complete T15 outcome.

## Fresh supported-contract Go scan: RED remains RED

Here “local/pinned” means the existing Warden Go contract, **not** that upstream
still supports Go 1.25. `GOTOOLCHAIN=local` was set for scanner installation,
source scans, binary builds and binary scans. The official module version list
and each candidate's exact go.mod establish:

| Scanner | Required Go | Disposition |
| --- | --- | --- |
| x/vuln v1.9.0 (latest) | 1.26.0 | Not installed or used |
| x/vuln v1.8.0 | 1.26.0 | Not installed or used |
| x/vuln **v1.7.0** | **1.25.0** | Privately installed and actually used |

`GOBIN=/var/tmp/w15.utwz/bin go install golang.org/x/vuln/cmd/govulncheck@v1.7.0`
PASS. `go version -m` confirms scanner **built with go1.25.14**; `-version`
reports govulncheck v1.7.0 and DB `https://vuln.go.dev`, updated
**2026-11-11T02:51:11Z**. No global installation, registry bypass or toolchain
auto-upgrade occurred. The scanner's exact installed `cmd/govulncheck/doc.go`
explains JSON mode exits zero even with findings; JSON exit zero is **not GREEN**.

Both initial and final runs:

```sh
TMPDIR=/var/tmp GOTOOLCHAIN=local /var/tmp/w15.utwz/bin/govulncheck -json ./...
TMPDIR=/var/tmp GOTOOLCHAIN=local /var/tmp/w15.utwz/bin/govulncheck ./...
```

JSON emits findings (exit 0 by design); text exits **3**, reporting **15
symbol-level advisories, plus 5 module-only advisories**. Initial/final finding
objects compare equal after order normalization. This is a successful scan
execution with an **unsuccessful vulnerability gate**, not infrastructure failure.

### Direct SSH call path and exact patch

Both GO-2026-6354 and GO-2026-6355 independently report:

```text
internal/client/ssh/graph.go:125 DialChain
  -> graph.go:213 dialNode
  -> graph.go:245 handshakeNode
  -> golang.org/x/crypto/ssh.NewClientConn (v0.55.0)
```

This direct call was checked against current source. Strict host-key checking
and cancellation/lifecycle tests do not remove the vulnerable protocol code;
a malicious authenticated/compromised SSH peer remains a residual threat.

Official tagged source and commit records were read (not a third-party summary):

- [a6cdac60840750226b15617ac8858be44361b36b](https://go.googlesource.com/crypto/+/a6cdac60840750226b15617ac8858be44361b36b),
  CL826504: `channel.established` atomic state; pre-establishment traffic other
  than open confirmation/failure is dropped before queue insertion.
- [86efde54dc7069251a8b007026c500d28e4239ce](https://go.googlesource.com/crypto/+/86efde54dc7069251a8b007026c500d28e4239ce),
  CL826524: established channels handle allowed messages explicitly and reject
  other message types rather than blocking on the pending-message queue.
- Exact v0.56.0 `ssh/channel.go` and `ssh/mux_test.go` contain
  `TestChannelUndecidedOutboundDropsTraffic`,
  `TestChannelUndecidedInboundDropsRequests`,
  `TestChannelRejectedInboundDropsTraffic`, and
  `TestChannelBogusMessageTearsDownMux`. These are bounded in-process upstream
  vector candidates using private mux/channel/packet APIs. They were **read, not
  run or ported**: the toolchain blocker precedes remediation. Safe Warden-level
  adaptation and backward-compatibility validation remain required upon resumption;
  this is not a claim that vectors are impossible or passing.
- The intervening official commit
  [c757c9851f77c470645455f548046ae0ce87ef8d](https://go.googlesource.com/crypto/+/c757c9851f77c470645455f548046ae0ce87ef8d)
  explicitly raises x/crypto's Go directive to 1.26 because Go 1.25 is no longer
  supported. The security commits occur after it.

A **private copy** of current go.mod/go.sum, not the checkout, reproduces the
compatibility failure with `GOTOOLCHAIN=local go get golang.org/x/crypto@v0.56.0`:

```text
golang.org/x/crypto@v0.56.0 requires go >= 1.26.0
(running go 1.25.14; GOTOOLCHAIN=local)
```

No dependency downgrade, main-module get, fork, replaced module, removed upstream
requirement, vendoring or custom SSH protocol mitigation was attempted.

### Standard-library and module inventory, unchanged before/after

Symbol reachability is scanner evidence, **not a reproduced exploit**. Broad
interface calls can overapproximate runtime paths. In particular, HTTP/2 server
findings are not proof that the current HTTP/1-only management listener enables
HTTP/2, and the Windows os.Root advisory is not a Linux exploit claim. None of
those qualifications makes the configured Go version clean.

| Advisory | Component / summary | First fix (Go1.26 line for stdlib) | Source scan |
| --- | --- | --- | --- |
| GO-2026-6354 | x/crypto SSH undecided channel deadlock | x/crypto v0.56.0 | Direct NewClientConn call |
| GO-2026-6355 | x/crypto SSH established channel deadlock | x/crypto v0.56.0 | Direct NewClientConn call |
| GO-2026-6603 | net/http HTTP/2 Trailer memory exhaustion | Go1.26.9 | Symbol match |
| GO-2026-6604 | os.Root Windows junction escape | Go1.26.9 | Symbol match; native relevance unverified |
| GO-2026-6605 | net/http rejected CONNECT desynchronization | Go1.26.9 | Symbol match |
| GO-2026-6607 | crypto/tls malformed ECH outer references | Go1.26.9 | Symbol match |
| GO-2026-6608 | net/textproto, mime/multipart header memory limit | Go1.26.9 | Symbol match |
| GO-2026-6609 | net/http Range header count | Go1.26.9 | Symbol match |
| GO-2026-6610 | net/http malformed HTTP/2 framing headers | Go1.26.9 | Symbol match |
| GO-2026-6611 | net/http repeated HTTP/2 initial windows | Go1.26.9 | Symbol match |
| GO-2026-6612 | net/http double HTTP/2 flow-control refund | Go1.26.9 | Symbol match |
| GO-2026-6613 | net/http server 2xx CONNECT desynchronization | Go1.26.9 | Symbol match |
| GO-2026-6617 | net/http HPACK encoder race | Go1.26.9 | Symbol match |
| GO-2026-6809 | crypto/x509 compromised intermediates | Go1.26.10 | Symbol match via WebAuthn ValidateMetadata |
| GO-2026-6859 | net/http MaxBytesReader header race | Go1.26.11 | Symbol match |
| GO-2026-6599 | html/template consecutive template context | Go1.26.9 | Module only |
| GO-2026-6600 | html/template yield/regexp context | Go1.26.9 | Module only |
| GO-2026-5932 | x/crypto unmaintained OpenPGP | v0.58.1-0.20261009181718-2f1f834330b2 | Module only; no OpenPGP call |
| GO-2026-6860 | x/net HTML text-node coalescing | x/net v0.62.0 | Module only |
| GO-2026-6866 | x/net HTML ancestor namespace transitions | x/net v0.62.0 | Module only |

Each ID resolves at `https://vuln.go.dev/ID/<ID>.json`. Five HTTP/2 IDs (6603,
6610, 6611, 6612, 6617) also match **x/net v0.57.0 at module level only**, first
fixed x/net v0.60.0; their reported source-symbol paths are in the **stdlib**.
Do not mistake the same advisory's module match for a separate x/net call trace.
Exact x/net v0.60.0 go.mod requires Go1.26.0 and x/crypto v0.57.0, x/sys v0.48.0,
x/term v0.46.0, x/text v0.42.0. x/net v0.62.0 likewise requires Go1.26.0 and
x/crypto v0.58.0, x/sys v0.49.0, x/term v0.47.0, x/text v0.43.0. These are
constraint evidence, **not selected updates**. A future compatible resolution
must handle the fresh x/net findings as well as the two initial SSH advisories.

Current WebAuthn v0.17.4 exact go.mod declares `go 1.25.0` and preferred
`toolchain go1.26.3`, with indirect x/crypto v0.52.0 and x/sys v0.45.0. Those are
not an already-required Go1.26 minimum for Warden: dependency toolchain preferences
do not replace the main module's selection. Warden currently selects x/crypto
v0.55.0 and x/sys v0.47.0; no WebAuthn upgrade is necessary merely to explain that
graph. Official [Go toolchain documentation](https://go.dev/doc/toolchain)
requires the main module's go line to be at least each dependency's **go line**.
An x/crypto update cannot legitimately keep `go 1.25.0` while using Go1.26-only
module metadata.

### Build-matched binary scan

Actual `GOTOOLCHAIN=local go build -o <private>/warden ./cmd/warden` and the
corresponding `warden-server` build PASS. `go version -m` for **both** confirms
Go1.25.14, revision c0e77b744093b32db793b7835291bef85f86f7f5, x/crypto v0.55.0 and
x/net v0.57.0. `vcs.modified=true` reflects checkout documentation/untracked state,
not a release bump. No real binary was installed or executed against Warden.

`govulncheck -mode=binary` runs on these exact artifacts in JSON and text modes.
Both text scans exit **3**. CLI: 13 symbol-level + 6 module-only IDs; server:
12 symbol-level + 7 module-only IDs. SSH6354/6355 are symbol-level in the CLI,
module-only in the server (which links other x/crypto packages, not this SSH path).
Binary scanning has no source call graph and is not independent exploit proof.
`build-versions.txt`, binary files, scan JSON/text and SHA-256 inventory are kept
in the private evidence directory. Source and binary builds use the same actual
Go version; no auto-Go1.26 result is presented as Go1.25 evidence.

## npm baseline/final: all 20 affected packages remain residual

Fresh initial and final `npm --prefix web audit --json` both exit **1** and JSON
objects are identical: **20 affected packages: 1 critical, 10 high, 8 moderate,
1 low**. Counts are affected packages, not distinct advisories. The installed
version may not be in every range aggregated into a package's `via` array;
retained JSON provides each exact range. No audit-force, suggested downgrade,
override, install, lock refresh or dependency change was applied.

Every GHSA identifier below is the canonical suffix at
`https://github.com/advisories/<GHSA-ID>`; all rows are **before = after,
unremediated**. Inherited rows add no independent advisory ID.

| Locked package/version | Audit severity | IDs / inherited paths |
| --- | --- | --- |
| `@hono/node-server` 2.1.1 | moderate | GHSA-rmxm-3fg6-px4f, GHSA-qv5m-9pm6-hqp3, GHSA-jpvv-r467-5p4w |
| `@modelcontextprotocol/sdk` 1.30.0 | high | GHSA-6qxp-vccf-f47h, GHSA-22jm-h49p-29qw, GHSA-46jr-4wx8-v453, GHSA-rvq5-wwqv-78pq, GHSA-f897-62hf-6gxq, GHSA-6prh-2h8m-c8cw |
| `@ts-morph/common` 0.27.0 | moderate | `minimatch` (inherited) |
| `body-parser` 2.3.0 | high | GHSA-27r3-jxmh-p828 |
| `brace-expansion` 5.0.9 | high | GHSA-q2hr-2g5m-vwhr, GHSA-qhr7-859c-m2p7, GHSA-6j4f-fj2g-mc7p |
| `deepmerge` 4.3.1 | low | GHSA-gcqx-w48m-w2h4 |
| `fast-uri` 3.1.6 | high | GHSA-qw65-cvwx-89v3, GHSA-58mr-gqgx-xq4g, GHSA-hrr3-gc8f-f4qj, GHSA-w74x-v6f9-j3xg, GHSA-xhq7-xmqj-769h, GHSA-wjr9-j795-jxcr, GHSA-333x-w4r6-6crp |
| `hono` 4.13.3 | moderate | GHSA-gqvv-2mrq-wpjv, GHSA-g6gw-c38x-mqfc, GHSA-crvj-82cr-hjcx, GHSA-hxh3-vqpv-xpqv, GHSA-5r4p-p66f-jhc7, GHSA-4m76-xfj5-7975, GHSA-h7mg-cq63-vhpq, GHSA-3gg2-335m-rxc6, GHSA-46wx-v44x-9hh2, GHSA-4h7h-rv7c-7m2v |
| `ip-address` 10.5.0 | moderate | GHSA-rpw4-54j3-4h4q, GHSA-2vr4-cq9g-pvrc, GHSA-j6r3-76f7-8jcv, GHSA-h3mg-xc3c-68pw, GHSA-rxp7-6hxx-x8q5 |
| `js-yaml` 4.3.1 | high | GHSA-2883-xcg3-v3hh |
| `minimatch` 10.2.6 | moderate | GHSA-g3hv-75wg-m249 |
| `postcss-selector-parser` 7.1.5 | moderate | GHSA-rj75-hqrm-r3gf |
| `proxy-addr` 2.0.7 | critical | GHSA-jqcg-44mw-7w3h |
| `qs` 6.15.3 | moderate | GHSA-x5fp-wj9c-mxmx, GHSA-4mjr-xmp4-gh2g, GHSA-6pq8-jhm2-2vcw |
| `shadcn` 4.19.0 | high | `deepmerge`, `ts-morph`, `zod` (inherited) |
| `source-map-js` 1.2.1 | high | GHSA-68fv-2mgg-jv7q |
| `systeminformation` 5.33.1 | high | GHSA-4vjg-vx72-qq4g, GHSA-7648-jmwf-vw7j, GHSA-3f7j-7jwc-fxfj |
| `ts-morph` 26.0.0 | moderate | `@ts-morph/common` (inherited) |
| `undici` 7.29.0 | high | GHSA-3wwx-pv8p-q78v, GHSA-pmjh-fq2x-6v4x, GHSA-r53p-7pc4-xj5r, GHSA-rfgv-xxqx-mfg5, GHSA-3xpg-4rpp-hhhm, GHSA-2jfj-6hjv-fm6j, GHSA-2gqq-gqf2-x968, GHSA-w293-vg96-wgc3, GHSA-8436-99hf-9mmv, GHSA-rx4f-c7p8-82vq, GHSA-4qv8-2p9j-2685, GHSA-f72v-6w45-q472, GHSA-xjj6-f33q-929c, GHSA-4w7w-5xrc-9h26, GHSA-2m5v-pch6-74hx, GHSA-qrxm-fqhp-jwvm, GHSA-9fm3-97px-rjf6, GHSA-55wc-3pg8-jfw6 |
| `zod` 3.25.76 | high | GHSA-mrhx-c7xc-m3w5 |

### Exact producer/consumer exposure paths

`npm explain` plus current lock paths establish the following (all unscoped names
below refer to `web/node_modules/<name>`). These are installed supply-chain paths,
not proof that Warden serves Node HTTP handlers:

- `shadcn@4.19.0 -> @modelcontextprotocol/sdk@1.30.0 -> express@5.2.1 ->
  proxy-addr@2.0.7`, body-parser@2.3.0 and qs@6.15.3. SDK also brings
  @hono/node-server@2.1.1, hono@4.13.3, express-rate-limit@8.6.2 ->
  ip-address@10.5.0, and ajv@8.20.0 -> fast-uri@3.1.6.
- `shadcn -> @dotenvx/dotenvx@1.75.1 -> systeminformation@5.33.1` and
  **`node_modules/@dotenvx/dotenvx/node_modules/undici@7.29.0`**;
  shadcn separately has **`node_modules/shadcn/node_modules/undici@7.29.0`**.
  dotenvx/conf/ajv is another fast-uri producer.
- `shadcn -> ts-morph@26.0.0 -> @ts-morph/common@0.27.0 -> minimatch@10.2.6
  -> brace-expansion@5.0.9`; shadcn directly brings deepmerge@4.3.1,
  zod@3.25.76, postcss-selector-parser@7.1.5 and
  cosmiconfig@9.0.2 -> js-yaml@4.3.1. socks is another ip-address producer.
- **`node_modules/undici@8.10.0`** is a different, dev-test instance from
  `jsdom@30.0.1 -> undici@^8.9.0`; it is **not listed by this fresh audit**.
  No undici major override behind jsdom was necessary or attempted.
- `source-map-js@1.2.1` has both shadcn/postcss and real build/test consumers:
  Vite8.2.2 -> postcss8.5.26; @tailwindcss/vite4.3.3 ->
  @tailwindcss/node4.3.3; jsdom30.0.1 -> css-tree3.2.1 (also through its selector
  helpers). Its lock entry lacks `dev` because it is shared; that is not browser
  execution evidence and not a reason to waive build/test exposure.

All 20 affected entries have non-dev lock paths, but the bundle inspection below
finds none of their JS in emitted browser code. That narrows exposure, not
remediation. Dependency install/build execution in privileged publishing remains
an explicit T16 risk; no CI/workflow change or dev-only waiver is made here.

### Actual emitted JS/CSS inspection (unchanged dependencies)

Read current `web/src/index.css`, Vite config, shadcn package exports/sideEffects
and exact installed CSS. `shadcn/tailwind.css` maps directly to
`dist/tailwind.css`, **not** the shadcn CLI/MCP JS entry. Thus blindly uninstalling
shadcn would break a production CSS input even though its Node CLI JS is absent
from runtime bundles.

A diagnostic build uses existing installed dependencies, current Vite8.2.2 and
unchanged config, with **private output only**:

```sh
(cd web && ./node_modules/.bin/vite build --outDir /var/tmp/w15.utwz/dist --sourcemap)
node web/scripts/verify-dist.mjs /var/tmp/w15.utwz/dist
```

Both PASS (existing >500-kB chunk warning). The actual source maps enumerate
**406 sources, 360 node_modules sources**, across all three JS chunks. Matching
all 20 audited package names against the emitted source list yields **zero JS
source hits**. `bundle-sources.json` retains the complete source inventory and
manifest. This is an instrumented baseline build, not a clean npm-ci installation,
the full tsc build command, a remediation build, or a real-browser CSP test.

Generated CSS `management-BwMqiByd.css` is **97,273 bytes**, SHA-256
`f169346ee329e8e7c1d76d8618b64a235b12be611b638dfcd4267604ba4627a3`, byte-identical
to the current embedded CSS. It contains the shadcn scroll-fade property output
and Geist font faces; the manifest retains all five font files and the verifier's
nine runtime assets. No CSS import or layout/style/font/dialog/CSP policy changed.
Source maps change diagnostic JS names; they were never copied into embedded dist
or treated as a browser acceptance run.

### Compatible remediation evaluation / separate residual decision

Registry metadata, not guessed package numbers, lists newest shadcn4 as **4.23.0**.
It moves to `@modelcontextprotocol/server ^2.3.1`, zod `^4.2.0`, undici
`^7.30.1` and postcss-selector-parser `^7.1.6`, but **still requires deepmerge
`^4.3.1` and ts-morph `^26.0.0`**. This is candidate metadata, not a tested upgrade
or assurance that all CLI APIs remain compatible. Registry deepmerge versions
end at **4.3.1**, within GHSA-gcqx-w48m-w2h4's affected range; no patched compatible
release exists in that evidence. @ts-morph/common0.27.0 requests minimatch
`^10.0.1`, while this advisory's fix starts at **11.0.1**, outside that range.
Latest shadcn4 therefore cannot alone yield a clean audit through ordinary
in-range updates. npm's suggested **shadcn1.0.0 major downgrade** is not approval.

If npm work resumes, prefer minimal in-range patched transitives/legitimate parent
releases with version-specific changelog/API evidence and producer/consumer tests.
For the unresolved shadcn-only tree, a bounded option for owner review is to retain
its MIT-licensed CSS locally (exact attribution/bytes, unchanged generated output,
fonts/dialog/CSP tests) and remove the installed generator/MCP dependency **only
if that tooling-capability tradeoff is explicitly accepted**. Alternatively retain
and explicitly accept/defer those precise toolchain advisories. No removal,
replacement UI framework, forced minimatch/undici major, or new tooling commitment
was chosen here. This option is a proposal, not an applied fix or an assertion
that minimal CSS relocation is always sufficient.

## Validation limits and final checkpoint

**Performed:** fresh initial/final govulncheck source JSON/text; build-matched
Go1.25.14 CLI/server binary JSON/text scans; official advisory/version/patch review;
private rejected update probe; fresh identical initial/final npm audit JSON;
all relevant npm explain paths; private source-map exposure build and emitted
verifier; final diff/manifest/documentation checks.

**Not run at this blocked preflight:** clean disposable `npm ci`, full frontend
tests/tsc production build, real build-matched T9 browser journey, full Go normal
or race tests, vet, repeated SSH/cancellation/TLS1.3 IPC/provider/HTTPS/upgrade
suites, new vulnerability vectors, or Windows cross-build/native execution.
There is no changed dependency or source behavior to validate yet; those required
remediation gates remain pending, not waived or claimed passing. No Playwright
dependency/config/service was added or used; browser skills will be read before
an actual browser run. Native Windows remains required/pending; synthetic PRF,
production-trust and genuine-authenticator acceptance remain separate and pending.
Parent T14/P1 closure and parent fresh suite passes are owner-supplied context,
not newly reproduced in this task or full T15 acceptance.

`go.mod`, `go.sum`, `web/package.json` and `web/package-lock.json` are unchanged;
all three Warden release fields remain **0.22.1**. No API adapter, production
source, test, build script or embedded distribution was changed. Only this report,
a narrow T15 plan checkpoint and the T15-only ignored ledger append are delivered.
No advisories were fixed; **all reported vulnerabilities remain residual**.

Exact task-only review patch: `/var/tmp/warden-t15-review.diff`.
Manifest: `/var/tmp/warden-t15-review.json`, including SHA-256 of every changed
file, pre-T15 ledger provenance/delta, manifest/release preservation and private
diagnostic evidence hashes. The protected file is excluded before content reads.
No staging is used to package new files. Stop at self-review / owner decision;
no T16 implementation, commit, publication or deployment.

## Superseding resumption — approved Go1.26.11 contract

This section supersedes the initial blocked checkpoint, not its historical RED
evidence. Actual resumed toolchain: **go1.26.11 linux/amd64**, explicitly selected
with `GOTOOLCHAIN=go1.26.11` for every Go build/test/scan, including private source
vectors, counterfactual tests and browser-runner Go children. Standard pinned
launcher/toolchain download only; no Go1.27 selection, global default/tool install
or protected-file access. Evidence root: **`/var/tmp/w15r.65nV`**. All commands use
`TMPDIR=/var/tmp`; ordinary Go checks below use shell-local **umask022**.

### Retained changes and exact-source grounding

- `go.mod` enforces **`go 1.26.11`**, not `go 1.26.0` or a preference-only
  toolchain directive. x/crypto **v0.55.0 -> v0.56.0** is the only Go module
  upgrade; its requirements need no other graph changes. `go.sum` replaces those
  two checksums. No replace/vendor/fork/backport or general update sweep.
- README/development instructions explain the minimum, explicit pinned launcher
  selection and lack of a Go requirement on binary runtime hosts. Release CI
  `setup-go@v5` reads **`go-version-file: go.mod`** instead of floating `1.26.x`.
  Exact v5 action README/source confirms patch selection; no action pin,
  permission/publishing isolation or other T16 change is included.
- Before dependency edits, a privately installed **govulncheck v1.9.0**, itself
  built with verified **go1.26.11**, reports **2 symbol-level SSH IDs + 8
  module-only IDs**, text exit **3** (`go126-before.txt/.json`). `go version -m`
  and scanner config identify v1.9.0, go1.26.11 and DB updated
  `2026-11-11T02:51:11Z`. This removes the old stdlib matches before the crypto
  change, independently of the historical Go1.25/v1.7.0 baseline.
- Context7 SSH/Vite/npm/Undici/Vitest and **version-pinned MCP SDK1.32.2** docs
  supplemented actual tagged/module/npm tarball sources. MCP1.32.2 official
  release notes and Undici7.30.1/8.12.2 release records, Vite8.2.4 changelog,
  parser/proxy/qs packaged changelogs, canonical advisory records, registry
  manifests/integrities and OSV advisory ranges are retained. GitHub API later
  rate-limited 11 of 66 advisory fetches; this is logged, not represented as
  complete independent retrieval. Undici release notes cover the remaining
  security fixes; the full npm audit is the final package inventory.

### Real compatibility REDs and narrow adaptations

The first pinned full suite (`go-full.log`) failed before any behavior adapter:

1. **`TestPosixRelMatchesFilepathRel`**: `posixRel("a", ".")` still returns
   `"../."`, but Go1.26.11 `filepath.Rel` now cleans it to `".."`. Exact
   Go1.25.14/1.26.11 `path/filepath/path.go` sources confirm the final-return
   change. Warden's explicit `TestPosixRelRetainsDotTargetComponent` already pins
   the historical remote POSIX spelling. Preserve that behavior: remove only the
   contradictory cross-stdlib comparison row and update its source comment;
   keep the independent explicit contract test. No SFTP logic or security policy
   changes. Focused old test fails before, both tests pass after
   (`posix-compat-red.log`, `posix-compat-green.log`).
2. **204 empty delivery**: the cross-origin boundary test reaches an allowed
   managed 204, then panics `http.ErrAbortHandler`. Exact Go1.26.11
   `httptest.ResponseRecorder.Write` returns `ErrBodyNotAllowed` even for empty
   bytes after 204/304; real net/http treats zero bytes as a no-op first.
   **Before editing `actions.go`**, added
   `TestManagedResponseEmptyBodyFlushesWithoutWrite`: actual RED observes an
   unnecessary 200 write and 204/304 aborts (`empty-response-red.log`). Delivery
   now skips `Write` only for an empty buffered body. Status/header copying,
   cancellation/deadlines, checked nonempty write/short-write, checked **flush**,
   abort propagation, buffer clearing and lease ownership remain unchanged.
   All three statuses pass afterward; existing real-socket pre-lock emission,
   blocked-flush/lease, cancellation and failure tests also pass. This is a
   focused Go compatibility adapter, not a dependency-only TDD waiver.

### Safe SSH advisory vectors — actual RED and GREEN

Warden's public `ssh.Conn`/`NewChannel` APIs cannot emit arbitrary malformed or
pre-establishment channel packets. Rather than expose private dependency APIs or
implement a new encrypted SSH peer, use the owner's permitted **exact upstream
in-process source-copy tests**. No production dependency source is patched, no
replace points Warden at a copy, and no real SSH endpoint is contacted.

Official v0.56.0 `ssh/mux_test.go` vectors assert:

- `TestChannelUndecidedOutboundDropsTraffic`: a channel-request flood leaves the
  request queue empty, and a premature CLOSE does not remove the undecided
  channel; the later open confirmation is processed and delivered. **This vector
  sends no channel DATA packets.**
- `TestChannelUndecidedInboundDropsRequests`: the inbound `NewChannel` is never
  received, accepted or rejected. Premature requests must not wedge the mux:
  closing the client makes the server observe EOF and return from `Wait`.
  **This proves shutdown progress, not normal inbound establishment.**
- `TestChannelRejectedInboundDropsTraffic`: reject transitions prevent subsequent
  traffic from stalling the mux.
- `TestChannelBogusMessageTearsDownMux`: an invalid established-channel message
  tears down the mux rather than waiting indefinitely.

Private fixed tree `crypto-fixed-vectors` is byte/hash-identical to the downloaded
v0.56.0 module (`upstream-copy-hashes.json`). Actual command:

```sh
cd /var/tmp/w15r.65nV/crypto-fixed-vectors
TMPDIR=/var/tmp GOTOOLCHAIN=go1.26.11 go test -race ./ssh \
  -run '^TestChannel(UndecidedOutboundDropsTraffic|UndecidedInboundDropsRequests|RejectedInboundDropsTraffic|BogusMessageTearsDownMux)$' \
  -count=25 -timeout=60s
```

**PASS**, `upstream-private-fixed-vectors.log` (also passed directly against the
unmodified downloaded tag). For sensitivity, `crypto-old-vectors` copies v0.55.0
production/test sources unchanged and adds only `advisory_sensitivity_test.go`:
package ssh, imports encoding/binary, strings, testing, and the **unaltered full
function bodies** of the outbound-undecided and bogus-message tests extracted
from the v0.56.0 file, each from its `func` through the next `func` boundary.
Run each independently with exact Go, `-run '^<name>$' -count=1 -timeout=2s`.
Both **FAIL by bounded timeout** in the expected protocol progress/teardown wait,
with stacks in the old mux/channel path. Logs:
`upstream-old-TestChannelUndecidedOutboundDropsTraffic.log` and
`upstream-old-TestChannelBogusMessageTearsDownMux.log`. This is upstream vector
sensitivity evidence, not a public-wire Warden exploit or production fork.

### Final Go scans and remaining module-only inventory

Fresh text and JSON source scans plus **build-matched CLI and server binary
scans** use the same v1.9.0 scanner and exact Go1.26.11. Both binaries are built
with `go build -trimpath -o <private>/build/<name> ./cmd/<name>`.
`build-versions-final.txt` records exact go1.26.11, crypto0.56.0, net0.57.0,
revision `c0e77b744093b32db793b7835291bef85f86f7f5`, modified=true. Go's dirty VCS
pseudo-version in metadata is not a Warden release-version edit. Binary hosts
were not upgraded or used; no real Warden service was run.

All **three text gates exit 0: 0 symbol, 0 package, 8 module-only IDs**.
JSON exit0 alone is not the proof; text gates and normalized findings are in
`source-final.{txt,json}`, `{warden,warden-server}-scan-final.{txt,json}` and
`scan-summary-final.json`. SSH6354/6355 and all former stdlib symbol findings are
absent. This is **not an all-modules-clean claim**:

| Remaining ID | Module / first fix | Exposure disposition |
| --- | --- | --- |
| GO-2026-5932 | x/crypto/openpgp; v0.58.1-0.20261009181718-2f1f834330b2 | No imported affected package/function; keep explicit residual, not an OpenPGP compatibility claim. |
| GO-2026-6603, 6610, 6611, 6612, 6617 | x/net HTTP/2; v0.60.0 | No imported affected package/function; these IDs no longer match the updated stdlib. |
| GO-2026-6860, 6866 | x/net HTML; v0.62.0 | No imported affected package/function. |

The selected minimal x/crypto0.56.0 target does not remove unrelated unused
packages. Advancing x/net0.62.0 also raises crypto to0.58.0 and sys/term/text as
recorded above; that still precedes the OpenPGP removal. No unsupported override
or broad module churn is substituted for this residual disposition. Further
module-only cleanup is separate from the reproduced reachable SSH remediation.
`go mod verify` passes. `go mod tidy -diff` was diagnostic only: besides obsolete
crypto checksums (removed), it proposes four baseline dependency-test checksum
lines (go-tpm-tools and go.uber/mock); no Go requirement changes. Those unrelated
checksum additions were not copied into this minimal update.

### npm: complete baseline, selected compatible fixes and residual decision

**Inventory qualification:** preserve the initial **20-package** audit as
historical evidence. This host's observed `npm config get omit` is `dev`
(inherited production environment), which may contribute to that inventory.
A later live audit of **original HEAD package/lock files in a separate private
directory**, explicitly using `npm audit --include=dev --json`, exits1 and
reports **23 affected packages: 1 critical, 11 high, 10 moderate, 1 low**
(`npm-full-before.json`). These were separate live advisory snapshots, not a
same-snapshot include/omit control: **omit=dev is not proven to be the sole cause
of the 20-versus-23 difference**, nor can registry changes be isolated as its
sole cause. The later explicit-include-dev audits provide the measured **23 -> 6**
comparison below. Neither the historical absence of root Undici8 from the
20-row inventory nor the tooling label establishes safety. Additional Vite and
Vitest/mocker findings and **jsdom's own Undici8 instance** are remediated, not
waived. Baseline files were not installed over the checkout.

All selected versions are published ordinary same-major patches/minors inside
producer ranges, apart from the deliberate exact direct dev-tool patch pins.
No permanent override, major substitution, npm-force/downgrade or package removal:

| Producer/consumer path | Locked before -> selected after |
| --- | --- |
| shadcn -> MCP SDK1 | 1.30.0 -> **1.32.2** |
| SDK -> @hono/node-server / hono | 2.1.1 -> **2.1.6** / 4.13.3 -> **4.13.16** |
| SDK/Express -> body-parser / proxy-addr / qs | 2.3.0 -> **2.4.0** / 2.0.7 -> **2.0.8** / 6.15.3 -> **6.16.1** |
| minimatch -> brace-expansion | 5.0.9 -> **5.0.12** (does not fix minimatch itself) |
| ajv (SDK/dotenvx/conf) -> fast-uri | 3.1.6 -> **3.1.9** |
| socks / express-rate-limit -> ip-address | 10.5.0 -> **10.7.4** |
| shadcn/cosmiconfig -> js-yaml | 4.3.1 -> **4.3.2** |
| shadcn -> postcss-selector-parser | 7.1.5 -> **7.1.6** |
| shared Vite/PostCSS/Tailwind/jsdom + shadcn -> source-map-js | 1.2.1 -> **1.2.2** |
| dotenvx -> systeminformation | 5.33.1 -> **5.33.16** |
| dotenvx + separate shadcn Undici7 | both 7.29.0 -> **7.30.1** |
| jsdom -> separate root Undici8 | 8.10.0 -> **8.12.2**, still satisfies ^8.9.0 |
| direct Vite | 8.2.2 -> **8.2.4** |
| direct Vitest + seven aligned @vitest packages | 4.1.11 -> **4.1.12** |

Version-specific security thresholds are in canonical records:
[source-map-js](https://github.com/advisories/GHSA-68fv-2mgg-jv7q),
[proxy-addr](https://github.com/advisories/GHSA-jqcg-44mw-7w3h),
[Undici7 release](https://github.com/nodejs/undici/releases/tag/v7.30.1),
[Undici8 release](https://github.com/nodejs/undici/releases/tag/v8.12.2),
[Vite8.2.4 changelog](https://github.com/vitejs/vite/blob/v8.2.4/packages/vite/CHANGELOG.md),
[Vitest mocker](https://github.com/advisories/GHSA-qxg6-89mg-rqv8) and
[second mocker fix](https://github.com/advisories/GHSA-xp26-3454-mjgp).
Vite8.2.3 is not published; 8.2.4 is the first available patched 8.2 release.
Exact SDK1.32.2 release/docs confirm the supported v1 transport API, not a v2
migration. Complete baseline GHSA arrays and final audit JSON retain all IDs.

Resolution was performed in disposable package/lock copies with `--ignore-scripts
--package-lock-only`. Broad trial resolution was rejected for unrelated churn;
a temporary **Undici-major-scoped** resolution selected only compatible versions.
An initial unscoped private trial would have forced Undici7 behind jsdom and was
**discarded before any install or checkout edit**. No such major substitution
exists in the final lock. Only npm-produced metadata for changed advisory nodes
was retained; unrelated optional WASI additions, chai/tinyrainbow upgrades and
root Undici latest-version drift were excluded. Final lock diff has **25 changed
existing package nodes + the root's two dev declarations**, no added/removed
nodes, and no override in either delivered package file. `npm ci --include=dev`
and complete `npm ls --all --include=dev` confirm the actual consumer graph
without those temporary resolver directives (`npm-lock-delta-final.json`).

Fresh final `npm audit --include=dev --json` still **exits1**, now **6 affected
packages: 0 critical, 2 high, 3 moderate, 1 low**. Seventeen affected package names
are no longer reported. Residuals, all Node shadcn authoring-tool paths:

| Exact residual path | Advisory / remaining constraint |
| --- | --- |
| shadcn4.19.0 -> deepmerge4.3.1 | **GHSA-gcqx-w48m-w2h4**, low; affected4.2.0–4.3.1, no published fixed version. |
| shadcn -> ts-morph26.0.0 -> @ts-morph/common0.27.0 -> minimatch10.2.6 | **GHSA-g3hv-75wg-m249**, moderate; first fixed11.0.1, outside common's ^10.0.1. Common and ts-morph are inherited affected rows. |
| shadcn -> zod3.25.76 | **GHSA-mrhx-c7xc-m3w5**, high; first fixed4.6.6, outside shadcn4.19's ^3.25.76. shadcn is the inherited high row. |

These are **three underlying advisory IDs, six affected package rows**, not six
independent exploits. Current registry newest shadcn4.23.0 still has unpatched
deepmerge and the ts-morph26/minimatch10 path. Its zod4/new MCP2 producer migration
is a larger parent-toolchain candidate, not a verified clean fix or an applied
change. No CLI/MCP capability is removed to make the audit green. Owner decision
remains whether to retain/accept or defer this exact residual tree, or explicitly
authorize a materially different authoring-tool replacement/removal and CSS
provenance plan. Go-minimum approval did **not** settle that choice.

### Clean install, producer/consumer, emitted assets and real browser

Private tracked-source copy `checkout` excludes the protected file before any
content access. Original checkout `node_modules` is not updated. The first clean
install inherited omit=dev: missing Vitest/type definitions caused test127/build1
(`npm-ci.log`, `web-test.log`, `web-build.log`). Rerun explicitly with **dev
included**, without changing npm/host configuration. Final fresh install and
complete `npm ls` both pass (`npm-ci-final.log`, `npm-ls-final.log`).

- `NODE_ENV=test npm --prefix <private>/checkout/web test`: **17 files / 279
  Vitest tests PASS**, plus **13/13 emitted-verifier tests**, no frontend skips.
  Final versions Vite8.2.4/Vitest4.1.12; `web-test-final.log`.
- Full `npm run build` (TypeScript + Vite + emitted verifier) **PASS**,
  `web-build-final.log`; only the existing >500-kB management chunk warning.
- Real CLI `shadcn --help` and `shadcn mcp --help` pass. A real installed
  **SDK1.32.2 Client + StdioClientTransport** spawns installed shadcn's `mcp`,
  connects/initializes, calls `listTools`, asserts **seven** tools, and closes.
  `mcp-consumer-final.log` names all seven. No init/add/generation mutation,
  registry fetch or real credential operation is needed for this consumer test.
  Actual dependency/range paths remain in `npm-explain-final.txt`.
- Source-map diagnostic build + verifier pass. Across three JS maps: **406
  sources / 360 node_modules sources, zero JS hits for all 23 baseline-audited
  package names** (`bundle-sources-final.json`). This narrows runtime exposure;
  it does not waive Node install/build/test/publish exposure.
- All **13 emitted distribution files are byte-identical** to the checkout's
  embedded distribution, including manifest/HTML/allowlist, JS/CSS and five Geist
  fonts (`dist-comparison-final.json`). CSS remains97,273 bytes/SHA256
  `f169346ee329e8e7c1d76d8618b64a235b12be611b638dfcd4267604ba4627a3`.
  Therefore no generated asset replacement is needed or claimed.
- Browser skills and shared-machine README read before execution. Existing
  `web/e2e/ui-privacy.cjs` runs against **that fresh built private distribution**
  with pinned-Go setup/runtime fixture children, real HTTPS, and the existing
  global headless Chromium151.0.7922.34 service/reference Playwright1.62.0.
  **1 complete journey PASS / 0 failed**; nine emitted runtime assets complete
  successfully; zero CSP violations/unexpected failures; zero implicit hostile
  image requests, exactly one after deliberate activation, no Referer/opener;
  actual locked/logged-out server states verified. No Playwright dependency,
  local launch fallback or service shutdown. HTML/artifacts:
  **`/var/tmp/w15r.65nV/browser-final/index.html`**, `result.json`, `trace.zip`,
  screenshots and `video/page-{0,1}.webm`. The earlier `browser/` run also passed,
  but the `browser-final/` run is authoritative after dev-tool patches.
  **Synthetic signed WebAuthn + injected PRF; test-only self-signed certificate
  exception. Not genuine PRF or production trust acceptance.**

### Initial post-remediation Go checks, stress failure and acceptance limits

All normal validation uses **TMPDIR=/var/tmp, GOTOOLCHAIN=go1.26.11, umask022**:

| Check / exact relevant scope | Measured result / log |
| --- | --- |
| `go test ./... -count=1 -timeout=180s` | **PASS**, `go-full-final-022.log` |
| `go test -race ./... -count=1 -timeout=180s` | **PASS**, `go-race-final-022.log` |
| `go vet ./...` | **PASS**, `go-vet-final.log` |
| `go test -race ./internal/client/ssh ./internal/client/db -run 'Cancel\|Graph\|Agent\|Auth\|Lifecycle' -count=25 -timeout=180s` | **PASS**, `ssh-lifecycle-race25.log` |
| `go test -race ./internal/client/agent ./internal/client/api ./internal/client/clienthttp ./internal/server/runtime -run 'TLS\|Authenticat\|Provider\|Redirect\|Cancel\|ManagedResponse\|GraphOwns\|PoolIdle' -count=10 -timeout=180s` | **PASS**, `tls-ipc-provider-race10.log` |
| `go test -race ./internal/upgrade -count=10 -timeout=180s` | **PASS**, `upgrade-race10-022.log` |
| Windowsamd64 `go test -c` for ssh/db/agent and `go build -o <private>/windows/ ./...` | **PASS, compile only**, `windows-cross-final.log`, private CLI/server/test artifacts and exact Go build metadata |
| Source/CLI/server vulnerability text gates | **exit0, no symbol/package findings; eight module-only IDs**, listed above |

**Failed diagnostics are retained, not silently rerun green:**

- A later diagnostic shell used umask077 for all commands, unlike the earlier
  passing normal/race run under022. Full normal/race then failed fixture
  expectations for0644/0640/0755 (actual0600/0700) in cp/SFTP/startup/upgrade;
  whole-upgrade race10 likewise failed the unchanged0755 expectation. Source
  fixtures create those modes without explicit chmod. Restoring **only the
  child-shell umask022**, not changing production/test logic, gives the final
  full normal/race and upgrade-race10 PASS above. Logs `go-{full,race}-final.log`
  and `upgrade-race10.log` are unsuccessful restricted-umask diagnostics, not
  newly fixed vulnerabilities or claimed arbitrary-umask acceptance.
- Extra **whole SSH package `-race -count=25`** fails
  `TestRunInteractiveCtrlCForwardsByte`'s PTY resource ceiling after repeated
  iterations (`ssh-db-race25.log`, ~99s). First observed ceiling:284 fds/514
  goroutines; later494/897. A separate private copy restores original HEAD
  go.mod/go.sum (crypto0.55.0), uses the **same exact Go1.26.11** and umask022,
  and repeats whole SSH25: **the same failure recurs**, first302 fds/547
  goroutines, later496/897 (`ssh-baseline-race25.log`, ~108s). No SSH source
  differs in that counterfactual. This is evidence the upgrade did not introduce
  the accumulated stress failure, **not a root-cause/leak fix or waiver**.
  Ordinary full normal/race and the dedicated auth/cancellation/graph/lifecycle25
  pass. **At that checkpoint**, whole-package growth still needed separate
  investigation; no ceiling increase or unexplained-failure waiver was applied.
  The explicitly authorized fixture-only follow-up below now supplies causal
  attribution, deterministic RED/GREEN and a passing whole-package stress run.
  These original failed logs and the old-crypto counterfactual remain evidence.

Ordinary Go package runs intentionally skip opt-in browser fixtures without the
private browser environment; the actual runner invokes them successfully.
Platform/root-only skips remain conditional (for example Unix wrong-owner tests
without root); native Windows execution is not substituted by cross-compilation.
Native Windows, genuine PRF-capable authenticator and production certificate
trust, independent acceptance and unresolved dependency residuals remain pending.
The initial SSH stress failure is superseded only by the authorized fixture
follow-up below, not by these earlier focused passes. This is **not full T15
acceptance or release readiness**.

### Final delivery / stop boundary

Release version stays **0.22.1 in all three fields**; the approved0.23.0 bump
belongs to T17. No staging/commits/pushes/publication/deploy, real install/upgrade,
SFTP fork/rsync or T16 changes. Protected `mise.toml` is excluded before reads.
Report/plan/spec and ledger distinguish original preflight from this resumption.
Exact **`/var/tmp/warden-t15-review.diff`** and
**`/var/tmp/warden-t15-review.json`** are deliberately regenerated, including every
changed/new task file and the **entire T15-only ledger delta from original
`/var/tmp/w15.utwz/ledger.before`**, not merely the resumed append. They bind final
file/evidence hashes and the actual failed/successful gates. Self-review checks
source/lock scope, preserved release versions, whitespace/local links/gofmt,
ledger-prefix preservation, staged-empty state and non-applying reverse-patch
validation. Stop after self-review; remaining capability/risk choices and the
new fixture diff return to owner/independent review, not T16 execution.

### Superseding authorized fixture-only stress correction

The parent authorized this follow-up only after the read-only diagnosis and
previous independent review completed. Review reported no P0/P1 production
finding and two P2 documentation corrections; that is a report about the
previous diff, **not independent approval of this new fixture diff or T15
acceptance**. No npm capability removal was authorized. All compatible dependency
updates, shadcn CLI/MCP/CSS, eight Go module-only findings, six npm rows/three
underlying advisories and all three 0.22.1 release fields remain unchanged.

**Causal evidence, not a PTY/runtime guess:**
`/var/tmp/warden-t15-ssh-stress-diagnosis.md` and its raw evidence under
`/var/tmp/w15d.n0Hr` identify five generic jump/proxy fixtures retaining **35
extra goroutines and 19 extra FDs after 32 seconds**. A completed client/channel
copy did not close upstream until both copies joined, while the reverse copy
waited for that upstream EOF. Listener-only cleanup left accepted connections
alive. The original fixed/old-crypto dumps contain the same persistent family
at **13x/14x** scale. First failure was the 512-goroutine ceiling (514), not
284 FDs exhausting the 512-FD ceiling. Direct, PTY and agent controls had zero
settled delta; no new agent API lifetime or production graph defect was found.
The source diagnosis also distinguished finite 30-second command/stalled-proxy
retention from the persistent relay cycle.

**Actual TDD chronology:** before editing existing fixture behavior,
`go test -race ./internal/client/ssh -run '^Test(SSHFixture|ProxyFixture)'
-count=1 -timeout=45s -v` exited1. The jump and all three proxy cases timed out
waiting for upstream EOF and copy completion; the accepted-connection cleanup
regression also timed out. Failure cleanup drained the relays. Evidence:
`/var/tmp/w15r.65nV/fixture-fix/relay-red.log` and `red-chronology.json`, which
binds unchanged pre-fix helper hashes and the new regression hash. The subsequent
context-argument adaptations and gofmt did not change those EOF/join assertions.
Only then was fixture behavior changed. Focused GREEN is `relay-green.log`.

The test-only correction follows T12's DB relay pattern: each completed copy
closes both owned endpoints **before** joining the reverse worker. The jump
handler is synchronous and joins its channel-request drainer. Generic SSH server
handlers join session/forward/request workers. A shared fixture listener owns
its cancellation context, accepted connections, accept loop and handlers;
shutdown cancels, closes the listener, **joins the accept loop before handler
Wait**, closes accepted transports and joins handlers. A controlled late-Accept
regression exercises that ordering without an Add-after-Wait race. Upstream
dials are context-bound; upstream-close cancellation callbacks are stopped or
joined. The coalesced-banner read is also abortable on fixture cancellation.

Fixture command execution now uses its owned context; the cancellation test
uses `exec sleep 30` to keep the synthetic sleeper in that owned process slot,
not an unowned shell descendant. The stalled-proxy fixture waits for its owned
context instead of leaving a 30-second sleeper. Its no-response/deadline behavior
and the cancellation test's 200ms context/five-second assertion are unchanged.
No production SSH/Graph/agent/TTY code, dependency or PTY fixture was changed.

The five original graph/jump/plain/authenticated/coalesced cases now assert
natural connection/worker completion **before forced fixture cleanup**.
`TestSSHFixtureChannelEOFClosesUpstreamAndJoins`,
`TestProxyFixtureClientEOFClosesUpstreamAndJoins`, and
`TestSSHFixtureCleanupClosesAcceptedConnection` cover EOF/cleanup boundaries;
`TestSSHFixtureListenerShutdownJoinsLateAcceptedHandler` controls shutdown's
late-Accept window. The Linux-only resource test reruns the five original paths
and logs before/after snapshots after their child cleanups. Counts supplement,
not replace, explicit EOF, handler and copy-join assertions.

**Authoritative post-fix checks** use **TMPDIR=/var/tmp,
GOTOOLCHAIN=go1.26.11, child-shell umask022**; logs below are all under
`/var/tmp/w15r.65nV/fixture-fix/`:

| Check | Measured result / evidence |
| --- | --- |
| Fixture EOF/join/ownership `-race -run '^Test(SSHFixture\|ProxyFixture)' -count=25 -timeout=60s -v` | **PASS**, `fixture-race25.log`, package1.509s |
| **Whole** SSH and DB `-race -count=25 -timeout=180s -failfast -v` | **PASS**, `whole-ssh-db-race25.log`; SSH100.486s, DB4.491s, wall100s; `whole-race25-summary.json` |
| `go test ./... -count=1 -timeout=180s` | **PASS**, `go-full.log`, wall22s |
| `go test -race ./... -count=1 -timeout=180s` | **PASS**, `go-race.log`, wall84s |
| `go vet ./...` | **PASS**, `go-vet.log` |
| Windowsamd64 SSH/DB/agent `go test -c` | **PASS, compile only**, `windows-cross.log`, `windows-ssh-version.txt`; new resource logger is Linux-suffixed, no native Windows execution |

Whole-package stress ran all tests, not only the earlier passing security
selector; failfast stops on a first failure rather than accumulating resources.
All **25** five-path observations showed **16 goroutines before and 16 after
joins/cleanup**, FD baseline **6 every iteration**, post-run FDs **10-18**, and
no failures or PTY ceiling hits. The focused resource test also returned to two
goroutines every iteration; its transient FD range was6-22. These are not
zero-FD claims: the exact Go runtime's `internal/poll/splice_linux.go` caches
completed splice pipes in a `sync.Pool`. No forced GC or stats-only acceptance
was used. The deterministic EOF/joins establish the fixture contract; counts
show the former repeated persistent growth did not recur. The 100-second whole
run remains within its original180s bound; no claim of a ten-second package run
or increased timeout is made.

The PTY safety ceilings remain exactly **512 FDs / 512 goroutines / 256MiB heap**;
its ten-second exit assertion and source are unchanged. Historical stress
failures, restricted-umask errors and read-only diagnosis remain preserved.

**Documentation corrections:** the outbound upstream vector sends requests and
premature CLOSE, then confirmation, **not channel DATA**; the undecided inbound
vector never accepts its channel and proves EOF/shutdown progress, **not normal
establishment**. The historical20 versus later23 npm audits were separate live
snapshots: observed omit=dev may contribute, but no sole-cause attribution is
proved. Later explicit-include-dev **23 -> 6** is the measured comparison.
Plan/spec are corrected and the ledger appends this qualification without
erasing prior chronology.

Production-source/module/frontend-input byte comparisons preserve the prior
build-matched scan, frontend, emitted-dist, MCP consumer and browser evidence;
those checks were **not rerun in this fixture-only pass**. Exact Go/build and
scanner metadata remain those recorded above; new Go tests bind current fixture
source, not a new vulnerability inventory or native-platform claim. No new npm
install/audit/browser run, CLI/MCP/CSS removal, dependency change, host-tool
change, staging/commit/publication or T16 work occurred. Closing source/diff/doc
self-review and hygiene pass: **21 task paths, 10 gofmt-clean Go files, 48 local
Markdown targets**, append-only ledger with its original pre-T15 prefix, staged
empty, unchanged branch/HEAD/release fields, and non-applying complete-patch
reverse validation. Exact `/var/tmp/warden-t15-review.diff` and `.json` are
refreshed with all T15 paths, the entire ledger delta from the original pre-T15
baseline, and old/new diagnostic/validation evidence hashes. Stop for independent
review of this new fixture diff and the pending owner npm decision; no full T15
acceptance is claimed.

### Owner-approved project-local CLI/MCP removal — pre-edit checkpoint

The owner now approves removing shadcn CLI/MCP **if it is a local dependency**.
Inspection confirms `web/package.json` installs shadcn^4.19.0 and
`web/src/index.css` imports its CSS export; the condition is met. This supersedes
only the earlier retain-local-CLI/MCP constraint. Shared/global tools, generated
UI components, Base UI/Radix dependencies, aliases and authoring metadata are
outside this removal. The completed fixture fix and its race25 evidence remain
preserved, not undone or needlessly repeated.

**Before configuration/CSS edits, record the TDD exception:** removing one local
package and copying an unchanged static stylesheet/license are configuration,
static-asset and documentation changes with no intended UI behavior change.
No new behavior helper/guard is planned and no fabricated behavior RED is
claimed. Strongest required verification is exact source/license hashes,
necessary-only npm lock pruning, clean private include-dev install/ls/audit,
all frontend tests/build/verifier, emitted asset byte comparison, a fresh
build-matched HTTPS browser journey, and exact-Go full normal/race plus fresh
source/build-matched binary vulnerability gates. Outcomes are pending below.

The inspected installed package is **shadcn4.19.0**, MIT copyright2023 shadcn.
Its `dist/tailwind.css` is16041bytes, SHA256
`bc7d83425702955b4cb67cb14ede9d603f9d912376d57a2d81d661094d2a782a`;
its full `LICENSE.md` is1063bytes, SHA256
`1564074e13439397221ffd522e2e504d56561994a23d371aa5e3ad43e4f5423f`.
`/var/tmp/w15r.65nV/local-tool-removal/before.json` preserves the package's exact
resolved tarball/integrity, inspected bytes and all checkpoint source hashes.
Retain these static bytes and notice with explicit provenance, not a maintained
library fork, fetcher or automatic future tooling install. Historical audits20
and later23->6 remain separate live snapshots;6->0 is not assumed before audit.

### Project-local removal — measured final outcome

**Owner condition met and applied:** remove only `dependencies.shadcn` from the
project manifest. npm-produced pruning removes **292 nodes (656 -> 364)** and
updates **39 retained nodes' dev/peer/devOptional reachability metadata**. No
retained version, integrity or dependency range changes; no node additions,
new overrides, forced majors or unrelated upgrades. The initial private npm
output also hydrated six unrelated optional WASI bundled-node entries; those
were excluded, retaining only the necessary npm-produced pruning/metadata.
`lock-prune-unfiltered.json` and `lock-prune-summary.json` preserve that decision.
Clean `npm ci` leaves the selected lock bytes unchanged and complete `npm ls`
passes. Checkout `node_modules` was not mutated; clean private installations,
not stale ignored files there, establish the new installed graph. Shared/global
MCP/Pi/youtrack and other repository tools were never uninstalled or changed.

The exact published shadcn4.19.0 tarball SHA512 integrity and its CSS/license
members were independently compared before copying. Retained files are
`web/vendor/shadcn-4.19.0/{tailwind.css,LICENSE.md,README.md}`; the README records
version, source URL/integrity, lengths, SHA256s and copyright2023 shadcn. The
CSS and full MIT license are **byte-identical** to those inspected members.
The app imports that CSS directly and excludes its vendor directory from
Tailwind class discovery, preventing provenance/license prose becoming utility
candidates. No generated UI component, Base UI/Radix dependency, alias or
`components.json` metadata changed; no fetcher, maintained-library-fork claim
or automatic authoring-tool reinstall was introduced. Development guidance
explains the local removal and independent future authoring-tool choice.

**All new evidence** is under `/var/tmp/w15r.65nV/local-tool-removal/`:

| Check | Actual result / evidence |
| --- | --- |
| Clean private `npm ci --include=dev` | **PASS**, `npm-ci.log`; lock bytes unchanged |
| `npm ls --all --include=dev` | **PASS**, `npm-ls.log`; no shadcn package or binary in the clean install |
| Fresh `npm audit --include=dev --json` | **exit0, 0 critical/high/moderate/low/info**, `npm-audit.json`, `audit-gate.json`; measured prior6 -> current0, not assumed |
| Full frontend / emitted verifier tests | **279 tests/17 files +13 verifier tests PASS**, `web-test.log` |
| TypeScript/Vite build / emitted graph verifier | **PASS**, `web-build.log`; only the existing >500kB chunk warning |
| Emitted distribution versus preceding embedded distribution | **All13 files byte-identical**, `dist-comparison.json`: CSS97273bytes/hashf169346ee329e8e7c1d76d8618b64a235b12be611b638dfcd4267604ba4627a3, all five fonts, JS/HTML/manifest unchanged; no generated asset replacement |
| Build-matched real HTTPS/CSP browser journey through shared Chromium151.0.7922.34 | **1 journey PASS /0 failed**, nine body-complete runtime assets, zero CSP/unexpected failures; zero implicit hostile-image hits and one deliberate activation, no Referer/opener; verified lock/logout. `browser/index.html`, `result.json`, `trace.zip`, screenshots, `video/page-{0,1}.webm` |
| Fresh exact-Go source/CLI/server vulnerability text gates | **All exit0; each0 symbol/0 package/8 module-only**, `{source,warden,warden-server}-scan.{txt,json}`, `scan-summary.json` |
| Fresh full Go normal / full Go race / vet | **All PASS**, `go-full.log`, `go-race.log`, `go-vet.log`; wall26s/105s/0s, `go-exits.txt` |

The new browser run uses the private freshly emitted distribution and exact
Go1.26.11 child fixtures; global service/reference packages are read-only.
**Synthetic signed WebAuthn/injected PRF and a test-only self-signed trust
exception remain explicit: not genuine PRF or production certificate trust.**
No project Playwright dependency, local-launch fallback or shared-service stop.

New CLI/server binaries are built `-trimpath` with exact Go1.26.11 and this
checkout's byte-matched embedded assets; `build-versions.txt` binds revision
c0e77b7/modified=true, crypto0.56.0 and net0.57.0. Dirty Go pseudo-version metadata
is not a release bump. Fresh scanner metadata is govulncheckv1.9.0 **built with
Go1.26.11**, DB2026-11-11T02:51:11Z. The eight module-only IDs/first-fix/exposure
dispositions above remain unchanged; none is silently waived by npm's zero.
All Go commands and browser fixture children use **GOTOOLCHAIN=go1.26.11,
TMPDIR=/var/tmp, child-shell umask022**. No host defaults/global tools changed.

The completed fixture correction is preserved byte-for-byte across all six SSH
test files, as are production Go/module sources and PTY thresholds. Its actual
RED/GREEN, whole-SSH/DB race25, controlled joins and Windows compile-only evidence
above therefore remain applicable; race25 was not needlessly duplicated. Fresh
full Go normal/race cover the final state. New asset evidence supersedes the
previously retained frontend/browser/scan cohort; previous logs stay historical.
Audit20 versus later23->6 retains its separate-live-snapshot qualification; the
new observed6->0 does not retroactively establish sole omit=dev causality.

**Current open gates:** eight Go module-only residual IDs and their disposition,
independent review of the combined T15/fixture/removal diff, native Windows,
genuine PRF-capable authenticator and production certificate trust/overall
acceptance. The local CLI/MCP capability decision is now resolved, not pending;
zero known npm findings is not a general supply-chain safety or release claim.
All three release fields remain0.22.1. No T16/staging/commit/push/publication,
real install/upgrade/deploy, protected-file content access, SFTP fork or rsync.
Refresh the exact full T15 review artifacts, including the original-to-current
ledger delta and the new provenance/removal evidence, then stop at self-review.

**Closing combined self-review:** 25 T15 task paths, ten gofmt-clean Go files
and 50 local Markdown targets pass hygiene; actual package/CSS/development and
structured lock diffs were inspected. All **364 Go/module/web source inputs**
match their freshly validated private copy; six SSH fixture hashes match the
completed stress25 cohort. Rechecked the exact archive SHA512 against the old
lock integrity and tar members against the retained stylesheet/full notice.
The necessary-only prune, complete clean-install graph and byte-identical
13-file distribution are independently checked. Original pre-T15 and
pre-removal ledger prefixes remain intact. The complete original-baseline diff
passes non-applying reverse validation, and its manifest binds all task/new
vendor files, prior failures and new private evidence with SHA256s. Final
source/evidence hashes are independently reverified after packaging. Branch,
HEAD, staging-empty and three0.22.1 release fields remain unchanged. This closes
bounded source/doc self-review only; the independent/residual/native/PRF/trust
acceptance gates above remain open. No further task or publication started.
