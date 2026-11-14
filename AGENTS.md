# Warden contributor instructions

## Pull requests and release versions

Every new PR must include a release version increment in the same PR, including
CLI, server, web, documentation, and maintenance changes. Do not wait for the
user to request a version bump.

- Honor an explicit version or increment specified by the user. If it conflicts
  with compatibility requirements or the current base version, ask before
  proceeding.
- Otherwise, judge the complete PR scope and choose the appropriate SemVer bump:
  - **Minor** (`x.y.z` -> `x.(y+1).0`): backward-compatible new features or
    capabilities.
  - **Patch** (`x.y.z` -> `x.y.(z+1)`): backward-compatible bug fixes,
    documentation/help improvements, refactors, dependency updates, and other
    maintenance that adds no new capability.
  - For mixed changes, use minor if any change warrants minor. Assess dependency
    updates by their actual effect on Warden's public behavior, not just the
    dependency's version number.
- Do not silently fit a breaking change into minor or patch. Explain the
  compatibility impact and obtain the user's decision on the release version
  before opening the PR; do not automatically choose a major increment.

### Version source and synchronized files

The Warden release workflow (`.github/workflows/release.yml`) reads
`web/package.json` and uses `v<version>` as the release tag. Despite its location,
this is the release version for Warden, not only the web frontend.

Update these fields together, using a plain `MAJOR.MINOR.PATCH` value without a
`v` prefix:

1. `web/package.json`: `version`.
2. `web/package-lock.json`: top-level `version`.
3. `web/package-lock.json`: `packages[""].version`.

Do not change dependency versions or regenerate unrelated lockfile data just to
bump the Warden release version.

### Before opening or updating a PR

- Calculate the increment from the latest approved base branch version. On a
  new PR, include the bump before opening it. When updating an existing PR,
  retain its bump unless the scope or base version changes; do not increment
  again for every commit or review fix.
- If the base advances before merge, recheck the version against the updated
  base and adjust it so the PR still introduces the intended increment.
- Verify all three fields match, the value is valid `MAJOR.MINOR.PATCH`, and the
  diff contains no unintended dependency changes.
- State the old version, new version, increment type, and rationale in the PR
  description and completion summary.
- Including a version bump does not authorize merging, manually publishing a
  release, or creating/pushing tags. Keep publication within the user's approved
  scope; the existing release workflow handles releases after merge.
