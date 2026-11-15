# Development

## Requirements

- Go **1.26.11 or newer**, enforced by the minimum in `go.mod`
- Node `^20.19.0 || >=22.12.0`
- npm `>=10`
- Linux end-to-end tests also require Bash 4+, `curl`, `openssl`, and `jq`

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
`scripts/test.sh` starts an ephemeral local server and exercises the API and
CLI without using real credentials or persistent state.

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
commands at a local or alternate release with `WARDEN_REPO` and
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
generated systemd units. PowerShell execution requires a Windows or PowerShell
host.
