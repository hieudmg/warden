# Development

## Requirements

- Go **1.26.11 or newer**, enforced by the minimum in `go.mod`
- Node `^20.19.0 || >=22.12.0`
- npm `>=10`
- Linux integrated acceptance requires Bash 4+ and Python 3 (standard-library
  controlling-PTY fixture); offline installer checks additionally need curl.
  The separate browser runner needs openssl and the already-provisioned shared
  Chromium/Playwright service, not a browser/global install.

The server embeds the generated Vite distribution. Clean-checkout server
builds and tests therefore build the frontend first through Make targets.

## Local development

The validated build/test toolchain is Go 1.26.11. Select it explicitly without
changing your installed default (the standard Go launcher can download it):

```bash
export GOTOOLCHAIN=go1.26.11
go version
```

This is a source-build requirement, not a Go installation requirement for binary
runtime hosts. CI reads the exact patch from `go.mod`.

```bash
make build
make test
make test-race
make vet
bash scripts/test.sh
```

`make test` runs frontend tests, installer smoke tests, and Go tests.
`scripts/test.sh` **replaces** the obsolete unauthenticated HTTP/key-file flow.
It installs include-dev frontend dependencies, runs all web tests/build/audit,
builds actual init/serve/CLI executables embedding those assets, and runs
`TestSecurityLifecycleHTTPS` and `TestAccountSecurityLifecycleHTTPS`. Setup uses an actual controlling PTY/CSPRNG password,
private-CA-verified HTTPS and signed WebAuthn fixtures, never a production auth
bypass. Fixture subprocesses strip inherited `WARDEN_*` overrides; explicit
config files alone would not isolate per-field environment settings. The journey
also tests conflicting disposable ambient settings are ignored.
One composed journey carries the installation through logout versus
lock, locked restart, recovery/replacement, pairing, persistent server verifier,
deterministic graph TTL versus same-agent custody, actual agent termination and
reapproval, revocation and fresh export/import to another initialized vault.

**Test substitutions:** PRF results are synthetic; the composed graph TTL uses an
in-process production agent with an injected clock and synthetic graph, not a
remote SSH handshake. The separate real-SSH graph fixture and permanent-agent
fake-clock suites run too. `LegacyRefusalAndRollback` separately runs preserved
config/DB/key/WAL/SHM and importer fault/identity/retry tests; it is not part of
the single composed journey. No live credentials/state, fallback keys, real
installers, services, public signing or release writes are used. Runner contracts
are checked by `python3 scripts/test_integration_runner.py`; read-only CI invokes
the same runner, not only a differently named discrete suite.

Separate real-browser privacy/CSP validation, using the existing shared Chromium
(build production assets first). The account runner covers setup, recovery reentry,
login+unlock, nested fresh export, recovery rotation, global lock/re-unlock,
locked restart, logout and restricted password replacement, asserting no access
to `navigator.credentials` or PRF:

```sh
TMPDIR=/var/tmp WARDEN_ACCOUNT_ARTIFACTS=/var/tmp/warden-account-private-artifacts \
  node web/e2e/account-lifecycle.cjs
```

Passkey privacy/CSP coverage is retained separately:

```sh
GOTOOLCHAIN=go1.26.11 TMPDIR=/var/tmp \
  WARDEN_UI_ARTIFACTS=/var/tmp/warden-ui-private-artifacts \
  node web/e2e/ui-privacy.cjs
```

This uses signed synthetic WebAuthn/injected PRF and a **test-only certificate
exception**. It records body-complete asset/network/CSP evidence, not genuine
PRF, production trust or the whole composed lifecycle. Do not install browsers or
silently use local-launch fallback. Keep traces/video/recovery screenshots private.
Native Windows requires actual execution of `scripts/ci/test-windows.ps1`, not
`GOOS=windows` compilation. See [the T17 acceptance matrix](superpowers/reports/2026-11-14-t17-integration.md)
for remaining gates and exact local evidence.

The generated frontend distribution at `internal/web/dist/` is gitignored.

## UI component authoring and retained CSS

The project does not install or bundle the shadcn CLI/MCP server. Existing
components, Base UI/Radix runtime dependencies, aliases and `web/components.json`
authoring metadata remain in place; metadata is not an installed generator.
Future component-authoring tools are a separate owner choice, not an implicit
package download or a requirement for building this repository. This removal
does not uninstall shared/global MCP, Pi, or tools used by other repositories.

The app imports the unmodified shadcn **4.19.0** stylesheet from
`web/vendor/shadcn-4.19.0/tailwind.css`, with its full upstream MIT notice and
[source hashes/provenance](../web/vendor/shadcn-4.19.0/README.md). This is a retained
static asset, not a maintained library fork. Keep that notice with the CSS.
The vendor directory is excluded from Tailwind class-source discovery so its
license/provenance prose does not generate utilities.

For a clean source-build installation including build/test dependencies:

```bash
npm --prefix web ci --include=dev
npm --prefix web audit --include=dev
```

## Release artifacts

```bash
bash scripts/build-release.sh
```

This creates `dist/` artifacts:

- `warden-server-linux-amd64`
- `warden-linux-amd64`
- `warden.exe`
- `SHA256SUMS`

Release builds use `CGO_ENABLED=0`, `-trimpath`, stripped symbols, and the
frontend production build. GitHub release automation reads the version from
`web/package.json`.

`warden upgrade` and `warden-server upgrade` consume these assets and pick the
one matching the running binary and platform:

| Binary | Target | Asset |
| --- | --- | --- |
| `warden` | linux/amd64 | `warden-linux-amd64` |
| `warden` | windows/amd64 | `warden.exe` |
| `warden-server` | linux/amd64 | `warden-server-linux-amd64` |

Other combinations fail before the installed executable is touched. Point the
commands at an alternate verified-HTTPS release with `WARDEN_REPO` and
`WARDEN_RELEASE_BASE_URL`; the release layout must include `SHA256SUMS` beside
the asset.

## Windows client build

The client does not import the embedded web package and can be built without
the frontend toolchain:

```bash
GOOS=windows GOARCH=amd64 go build -o warden.exe ./cmd/warden
make build-client-windows
```

## Installer tests

```bash
make installer-test
bash scripts/test-installers.sh
```

The smoke test uses local fake release assets and verifies checksum handling,
interactive defaults, custom config paths, upgrades, state preservation, and
generated systemd units. Actual installer downloads/service changes are not run.
Windows fixtures require native Windows PowerShell Desktop 5.1/.NET Framework
4.7.2+; PowerShell Core/Linux mocks or cross-builds are not native evidence.
