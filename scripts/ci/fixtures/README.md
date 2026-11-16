# Offline provenance data (NOT a signed attestation)

`provenance.json` is deliberately unsigned (empty signatures). It tests the actual
workflow's post-action subject/source guard, not Sigstore/OIDC authentication.
It was initially generated from v4.2.1 source functions, then regenerated
**byte-identically from the actual shipped `dist/index.js`** of official
`actions/attest` v4.2.2, commit
`1e69f48acb82d1966a394da916b4c1698aa569d6`:

- `subjectFromInputs`, real glob expansion and streamed `digestFile`.
- Default provenance detection / `getPredicateForType` with all SBOM/custom
  predicate inputs absent.
- Bundled `@actions/attest` **3.2.0** `buildSLSAProvenancePredicate` and
  `buildIntotoStatement`.

Regeneration used Node26.12.1's VM loader in private evidence. The only seams
suppress the signing/upload entrypoint and substitute synthetic claims at the
OIDC retrieval boundary. All subject glob/hash, default predicate selection,
SLSA and in-toto code comes from the downloaded dist, not a rebuilt bundle.
HTTP(S) requests throw if attempted. The same functions hashed every actual
private release asset. No signer, certificate, network token retrieval,
attestation upload or GitHub write ran. The generator,
exact downloaded sources, statement and hashes are in the T16 private evidence
manifest. This is executable upstream subject/predicate generation evidence, not
a locally invented subject-verification model or native/hosted acceptance.

Fixture inputs are independently defined in `test_release.py`: each binary is
UTF-8 `NONEXECUTABLE synthetic release bytes: <filename>`, without a final newline.
SHA256SUMS has the three lexically ordered binary names in the exact T14 format
`<sha256>  ./<filename>\n`. Synthetic claims identify `hieudmg/warden`, push/main,
source `96e2ed4986f3423f423942d817c0f220470f15e9`, run1234/attempt2. Tests unpack
this generated statement, execute the real inline workflow guard against actual
verified files, and reject wrong subject, digest, source and attempt. Actual
signed hosted provenance creation remains UNRUN; any hosted signing-only
validation route requires separate owner approval and must not publish a release.
