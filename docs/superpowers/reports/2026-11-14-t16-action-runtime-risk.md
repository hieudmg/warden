# T16 review follow-up — official action runtime risk

## Owner disposition

After reviewing the specific residual risks summarized below, the owner explicitly
accepted retaining the pinned official Actions while awaiting upstream fixes.
Acceptance covers the enabled Undici trusted-service/terminating-proxy response
and transport risks and the Sigstore DSSE/PAE type-binding limitation. It is not
a blanket waiver of action audit findings, a claim of remediation, or approval
of downstream verifier behavior. Keep the exact ASCII type and byte/source/run
guards. Native Windows and hosted artifact/OIDC/signature checks remain required.
No manual verification workflow, dispatch or public attestation/transparency
record creation was authorized by this decision.

## Scope, method and decision boundary

This is the bounded T16 writer follow-up, not independent approval or a blanket
upstream-dependency waiver. Evidence root: `/var/tmp/w16.Bmqg/r1`; the enclosing
T16 manifest hashes the evidence. No action entrypoint, signer, network write,
installer, tag, release or hosted workflow ran. No third-party dist was rebuilt,
patched for deployment, or replaced by a fork. Static inspection cannot prove an
unknown call graph safe; the inventory prioritizes the **privileged downloader
and attester**, their parsers, credential-bearing networking and signing path.
It does not exhaustively audit every function in all six action distributions.

Official tag-ref/tag-list GETs independently resolved:

- `actions/attest` **v4.2.2** =
  `1e69f48acb82d1966a394da916b4c1698aa569d6` (commit object).
- Latest listed `attest-build-provenance` v4.2.2 remains
  `4d101475d8b20a2381f78447822ac1eab6504dd8`; its actual `action.yml` pins
  **attest v4.2.1**, `508db95dd578ae2727ebd6217d5ba78e4fbda05d`.
- Latest listed checkout/setup-go/setup-node/upload/download releases still match
  `scripts/ci/action-pins.json`. No newer listed official release closes the
  residual publisher findings below. This is a point-in-time check, not a promise
  that upstream cannot subsequently publish a fix.

The ordinary supported choice is direct **official `actions/attest` v4.2.2**,
not a fork, manual signer or custom predicate generator. Exact pinned README,
`action.yml`, `src/{main,detect,provenance,attest,subject}.ts` and shipped
`dist/index.js` were inspected before switching. With no SBOM/custom-predicate
inputs, `detectAttestationType` returns `provenance`; `getPredicateForType` calls
`generateProvenancePredicate` / `buildSLSAProvenancePredicate`. Same `bundle-path`
output/schema, same individual subject paths, same `NODE_OPTIONS` header option.
Registry push and storage-record creation are explicitly false. No new token
permission, endpoint, external trigger or signing purpose was introduced.

## Dist evidence, not merely lock attribution

Downloaded exact official **shipped** distributions, without executing their
entrypoints:

| Action | Official path | Private evidence path relative to `r1/` |
| --- | --- | --- |
| attest v4.2.2 | `dist/index.js` | `attest-dist-index.js` |
| old attest v4.2.1 | `dist/index.js` | `attest-old-dist.js` |
| download v8.0.2 | `dist/index.js` | `actions-download-artifact-dist.js` |
| upload v7.0.2 | `dist/upload/index.js` | `actions-upload-artifact-dist-upload-index.js` |
| checkout v7.0.1 | `dist/index.js` | `actions-checkout-dist.js` |
| setup-go v7.0.0 | `dist/setup/index.js` | `actions-setup-go-dist.js` |
| setup-node v7.1.0 | `dist/setup/index.js` | `actions-setup-node-dist.js` |

`packaged-source-inventory.json` records exact non-dev lock nodes, versions,
resolved package-archive integrity and SHA256. Eleven selected npm archives were
fetched as data and checked against their exact lock integrity, not installed.
`packages/*.sources.json` contains bounded archive-member reads (no extraction
or lifecycle scripts). `shipped-source-matches.json` corroborates version
attribution: complete Undici `Agent` and `Request` source bodies in both relevant
versions and complete Sigstore DSSE code match dist after only whitespace,
require-ID and ncc module-preamble normalization. Other full-source comparisons
are explicitly false, **not silently treated as matches**. Their named module
markers/function bodies and vulnerable operations were inspected in the actual
dist instead; version attribution is lock plus source corroboration, not a
reproducible-build claim or proof that a body uniquely identifies one version.
`{attest,download}-bundle-anchors.json` records exact lines and snippets.

`exercise-attest-dist.mjs` loads the actual dist in a private VM, suppresses its
signing/upload entrypoint and substitutes synthetic claims at exactly one OIDC
retrieval boundary. HTTP(S) requests throw. It executes real default-predicate
selection, glob expansion, streamed file hashing, SLSA and in-toto generation.
The unsigned synthetic fixture regenerated **byte-identically**; every actual
private release asset was independently rehashed. Current inline guards pass
that real-byte result (`real-byte-guards.log`). This does **not** exercise hosted
OIDC, certificate issuance, signing, attestation upload or artifact service.

## What the official update actually fixes

- **GHSA-j63v-mwhm-56jx**, `@sigstore/oci <=0.7.1`: old bundle/lock 0.7.1 ->
  shipped 0.7.2. Dist now has origin-scoped `#securedFetch` / manual redirect
  policy stripping sensitive headers after leaving the registry origin
  (`attest-dist-index.js:63458+`). This fixes a real packaged credential-flow
  defect. **The OCI branch is disabled here**: four subjects and
  `push-to-registry: false`; do not call it demonstrated enabled exposure.
- Brace expansion updates: direct glob chain 5.0.7 -> **5.0.9**, cache chain
  5.0.6 -> **5.0.9**, other glob chain 2.1.0 -> **2.1.4**. These close older
  expansion/OOM advisories including GHSA-mh99-v99m-4gvg and
  GHSA-rgw5-rvv9-x895 for those nodes. Newer residual advisories still apply.
- `ip-address` **10.2.0 -> 10.4.0** closes
  **GHSA-mwp4-54f8-5fhr** (`<=10.3.0`), **GHSA-4xrf-jv44-h6hh**
  (`>=10.1.1 <=10.2.1`) and **GHSA-22jq-vg5j-6vgg** (`>=10.1.1 <=10.2.0`).
  Newer classifier/parser advisories still apply to 10.4.0.

Fresh exact-lock `npm audit --include=dev --json` for new attest exits **1**:
**40 affected package rows: 1 critical /6 high /28 moderate /5 low**. Historical
old attest was 41 (1/8/27/5); these are not independent-advisory or shipped-function
counts. Fresh follow-up audits of the other five exact action locks also exit1
and reproduce 21/27/24/37/32 for checkout/setup-go/setup-node/upload/download,
respectively (`r1/audit-current-summary.json`). Project npm audit0
is a separate result and does not waive action risk. No audit-fix was run.

## Specific remaining publisher/runtime exposures

Advisory JSON snapshots are `r1/GHSA-*.json`; ranges below are from the official
advisory or exact audit, not inferred from severity labels. **Enabled** means
source wiring enables that operation, not that a hosted exploit was observed.

| Advisory / packaged version and range | Actual function, enabled path and input origin | Adversary prerequisites, likely consequence and disposition |
| --- | --- | --- |
| **GHSA-35p6-xmwp-9g52**; Undici **6.25.0** attest, **6.23.0** download; `<6.27.0` | Shipped HTTP/1.1 idle-socket/keep-alive parser. Attest `writeAttestation` -> `getOctokit` -> `getProxyFetch` -> bundled `undici.fetch` -> repository attestation API. Dist `116739–116771`, `120731–120742`, `121080+`. This is enabled for attestation upload, not just a dev dependency. | Control/compromise the authenticated upstream HTTP/1.1 endpoint (or trusted terminating proxy), plus socket reuse, to inject an unsolicited response. Response/request association poisoning, potentially false service metadata or job failure; no demonstrated asset-integrity bypass. Artifact payload bytes alone do not control this peer. Recommend narrow owner disposition of **this trusted-service network risk**, or wait for official update; not blanket acceptance. |
| **GHSA-xjj6-f33q-929c**; same shipped Undici; `>=6.23.0 <6.29.1` | Bundled `fetch` response handling creates its stream before the excessive content-coding check (`attest` lines20451/47910 and surrounding code). Enabled on attester's Octokit service responses. | A reached malicious/compromised trusted HTTPS endpoint sends >5 content codings and closes early; one crafted response can terminate the Node process despite caught rejection. Main likely cost: failed attestation/publication job. No public artifact-content route into response headers identified. Official package fixes exist; no newer listed official action bundle found. |
| **GHSA-qrxm-fqhp-jwvm**; same Undici; `>=4.2.1 <6.29.1` | Actual dist retains socket assertions rejecting `ERR_TLS_CERT_ALTNAME_INVALID`; enabled Undici transport permits ordinary negotiated TLS (no workflow TLS1.3-only restriction). | A reached endpoint negotiates TLS1.2, then renegotiates to a different CA-trusted certificate with the wrong hostname. Uncaught assertion/DoS; TLS1.3 cannot renegotiate. Requires control of the reached trusted endpoint/proxy and valid certificates, not merely a PR or uploaded manifest. No hosted negotiation/proxy behavior was measured. |
| **GHSA-jfc7-64v2-mr8c**; `@sigstore/core` **2.0.0**, affected `<=3.2.0` | Shipped `preAuthEncoding`, `attest-dist-index.js:61444`, truncates payloadType to ASCII low bytes. `@sigstore/sign` **3.1.0** DSSE builder calls it (`65529`). Actual packaged function reproduces equal PAE for ASCII and Unicode-mutated types (`dist-provenance.log`). | An attacker who can mutate a signed bundle's type can exploit type confusion in a consumer accepting such a type. **Our producer always supplies literal ASCII in-toto type**; guard requires that exact type and SLSA URI, and the new mutant-type fixture is refused. No malicious payloadType input from assets is enabled; no signature forgery/publication exploit demonstrated. Producer patch remains desirable; downstream verification must not be inferred safe from this local consistency guard. |
| **GHSA-2m5v-pch6-74hx**; Undici6.25.0/6.23.0, `>=4.0.0 <6.29.1` | Vulnerable shipped `Agent` clones options with `JSON.parse(JSON.stringify(...))`. Exact package Agent source matches dist. | **Requires function-valued `tls.checkServerIdentity` passed through Agent**. No such custom pin callback is configured by this workflow's ordinary Octokit client; default platform hostname/chain validation remains. Not evidence of a default TLS verification bypass. Remove neither TLS verification nor default trust to work around it. |
| **GHSA-2mjp-6q6p-2qxm**; download's Undici **6.23.0**, `>=6.0.0 <6.24.0`; attester6.25.0 outside this range | Packaged low-level `Request` permits conflicting case-variant Content-Length in flat header arrays. Exact Request source matches dist. Current downloader's same-run path uses `ArtifactHttpClient` and native HTTP client POST/GET, **not public cross-run Octokit download**. | Requires attacker-controlled flat header arrays plus disagreeing intermediary parsers. Fixed literal header objects and no public API download token here; enabled attacker header path not identified. Do not generalize this as all Undici findings unreachable: attester's three response risks above are enabled. |

### JSON, XML, registry, globs and address parsing

- **JSON / OIDC / signing:** same-run downloader `ArtifactHttpClient`
  (`actions-download-artifact-dist.js:82601–82757`) reads service response bodies
  and `JSON.parse`s them before generated protobuf JSON conversion. Blob download
  uses native `@actions/http-client`, raw mode, no Azure SDK XML parsing or ZIP
  extraction. Attest OIDC/JWKS uses Actions HTTP client and **jose5.10.0**
  verification; sign uses `@sigstore/sign3.1.0`, its make-fetch-happen14.0.3
  network client, and Sigstore bundle/protobuf parsing. Octokit uses native JSON
  decoding of trusted API responses, **not eval**. These are real non-dev
  networking/parser surfaces. A compromised service can deliver oversized or
  malformed responses before our artifact bounds; finite job timeout is not a
  memory bound or proof of parser safety. No artifact manifest becomes JavaScript,
  a predicate input, request headers, endpoint, glob, SBOM or evaluated code.
  This assessment found no separate advisory for the built-in JSON parser; it
  does not certify all parser/crypto paths or hosted token validation.
- **GHSA-8cw4-87c7-c6xx**, **csv-parse7.0.1**, `<7.0.2`: bundled duplicate-column
  branch can replace a parsed record's prototype with `columns:true` and
  `group_columns_by_name:true`. `subjectPath` is parsed with only
  `relaxColumnCount:true`, `skipEmptyLines:true` (`attest`128738+); both vulnerable
  options are absent, and all four paths are literals created exclusively after
  verification. Prerequisites are not enabled. This is not a statement that the
  package or prototype-mutation function is absent from dist.
- **fast-xml-parser5.3.4** is genuinely shipped in download/upload Azure SDK code,
  including `DocTypeReader` and entity replacement, not just a dev lock entry.
  **GHSA-m7jm-9gc2-mpf2** (`>=5.0.0 <5.3.5`) raw entity-name regex and
  **GHSA-jmr7-xgp7-cmfj** (`>=5.0.0 <5.3.6`) unbounded entity expansion are present
  (`download`92174–92204,93123+). **GHSA-474x-hrwr-fgx4** (`<=5.11.2`) additionally
  needs non-default `stopNodes`. Downloader's fixed current-run raw path does
  **not** call Azure XML parse; upload's Azure response deserialization can, in
  the **read-only build job**, never with publication/OIDC write grants. Malicious
  Azure/proxy XML could consume CPU/memory there; XSS additionally needs an HTML
  rendering sink, not established here. No artifact manifest-to-XML path found.
- **lodash4.17.23** is a non-dev download lock node. **GHSA-r5fr-rjxr-66jc**
  (`>=4.0.0 <=4.17.23`) needs `template` with malicious imports-key names;
  **GHSA-f23m-r3pf-42rh** (`=4.17.23`) needs array-path `unset`/`omit`/`pullAt`.
  No `template` or `baseUnset` implementation was found in that exact dist.
  Other similarly named `omit` helpers are not proof the vulnerable lodash
  method ships. Classified **not demonstrated shipped/enabled**, not a confirmed
  privileged code-injection route based on the lock's critical label.
- **brace-expansion5.0.9/2.1.4** remain affected by
  **GHSA-6j4f-fj2g-mc7p** (`>=4.0.0 <5.0.10`, `>=2.0.0 <2.1.5`),
  **GHSA-qhr7-859c-m2p7** (`<5.0.11` / `<2.1.6` in those branches), and
  **GHSA-q2hr-2g5m-vwhr** (`<5.0.12` / `<2.1.7`).
  **minimatch10.2.5** has **GHSA-g3hv-75wg-m249** (`>=7 <11.0.1`). Glob matching
  really runs during subject hashing, but only on fixed literal paths, not
  braces/extglobs from a release manifest. Adversarial expansion/amplification
  input would require changing trusted workflow inputs/action/runner. Download
  is fixed artifact ID, not an attacker-supplied name/pattern.
- **ip-address10.4.0** remains affected by **GHSA-rpw4-54j3-4h4q** (`<=10.5.0`),
  **GHSA-2vr4-cq9g-pvrc** (`>=10.2.0 <=10.5.0`),
  **GHSA-j6r3-76f7-8jcv** (`<=10.7.0`), **GHSA-h3mg-xc3c-68pw** (`<=10.7.0`),
  **GHSA-rxp7-6hxx-x8q5** (`<=10.7.3`). Code is shipped through SOCKS support;
  observed callers serialize proxy address bytes, not policy-allowlist classifiers.
  No attacker-controlled SOCKS destination/long zone string from artifact data is
  configured here. Classifier advisories need policy use and hostile addresses;
  parser DoS needs hostile address input. An operator-controlled hostile proxy or
  compromised endpoint remains a different prerequisite, not eliminated risk.

Undici cookie helpers, WebSocket, EventSource, retry/dump/cache interceptors have
additional exact audit entries. The workflow does not enable those capabilities;
Octokit retries are not evidence it uses Undici's retry interceptor. No bounded
inspection can prove every unknown branch absent. Checkout/setup/tool download
and upload bundle residuals are not accepted wholesale because their jobs are
read-only: malicious dependency/build code can still affect build outputs. They
cannot obtain publication permission/secrets by this workflow's declarations.

## Recommendation and hosted proof plan — not executed

Keep the independently verified **official direct attester** update and explicit
repository fix. Retain all byte/source/predicate guards. Do not rebuild an action
fork, perform custom signing, drop attestations, weaken TLS, or pretend pinning
remediates vulnerable code. The owner has explicitly accepted the **enabled trusted-service response risks**
and producer DSSE limitation above while awaiting official fixes. Repeat this
inventory when adopting a patched action, and complete the outstanding hosted
checks before claiming publication acceptance. There is currently no verified newer listed
fixed official bundle. Removing the capability or replacing artifact/signing
architecture is consequential, outside this ordinary fix; not implemented.
A narrow disposition may distinguish service/proxy compromise prerequisites and
availability versus type-binding effects; it must not waive all lock findings.

**Hosted evidence is still UNRUN:** all16 required native Windows tests including
trusted HTTPS/PS5.1/.NET and exact CA cleanup, actual artifact upload/download,
OIDC/Sigstore signature/identity, and full Windows installer acceptance. Existing
PR workflow is read-only and is the ordinary validation route after an authorized
parent push/PR; no dispatch or hosted write was performed. It cannot establish
the privileged release attester path before merge.

**Outline only, requires explicit owner approval before implementation/run:** a
separate manual non-release verification workflow at a reviewed trusted main
workflow ref, hard repository/ref/actor guards and an explicit expected source SHA
that **must equal github.sha at the dispatched reviewed main ref** (refuse a
mismatching historical checkout; the default predicate describes event SHA).
Read-only build/check jobs checkout that SHA, run dependencies/tests and produce
same-run ID/digest-bound release-shaped bytes; no write/OIDC secrets during build.
A separate attestation-only job receives just required attestations/id-token
permissions (contents-read, no tag/release write), uses official action and static
byte/source guards, and never checks out, installs, runs artifact code or issues
`gh release`/tag API mutations. Because dispatch event/workflow identity differs,
use purpose-specific explicit identity expectations rather than loosening the
release push/main guard. Reuse data-validation logic only after independent review
of the distinct purpose. Verify actual signed bundle with trusted official
verification tooling: exact subject digests of all retained bytes, signer workflow
ref/commit, source SHA, repository, event, run/attempt, chain and transparency-log
policy; retain artifact API IDs/digests and native logs/cleanup evidence. A signing
run on a public repository may create **public attestations/transparency records**
even without a release: obtain explicit owner authorization for that write first.
No new workflow/trigger/permission or synthetic release was added for this outline.
