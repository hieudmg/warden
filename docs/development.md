# Development

## Requirements

- Go toolchain from `go.mod`
- Node `^20.19.0 || >=22.12.0`
- npm `>=10`
- Linux end-to-end tests also require Bash 4+, `curl`, `openssl`, and `jq`

The server embeds the generated Vite distribution. Clean-checkout server
builds and tests therefore build the frontend first through Make targets.

## Local development

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
