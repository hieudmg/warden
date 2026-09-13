# Self-upgrade commands design

## Goal

Add self-upgrade commands for the client and server:

- `warden upgrade`
- `warden-server upgrade`

Each command downloads the latest suitable release binary, verifies it using the
release checksum file, and replaces only its own executable. Existing settings
and state must be preserved without prompts.

## Release contract

The updater uses the release layout already consumed by the installers:

- repository: `WARDEN_REPO`, default `hieudmg/warden`
- download base: `WARDEN_RELEASE_BASE_URL`, default
  `https://github.com/<repo>/releases/latest/download`
- checksum file: `SHA256SUMS`

Asset selection is based on the binary kind and `runtime.GOOS`/`runtime.GOARCH`:

| Binary | Supported target | Asset |
| --- | --- | --- |
| client | linux/amd64 | `warden-linux-amd64` |
| client | windows/amd64 | `warden.exe` |
| server | linux/amd64 | `warden-server-linux-amd64` |

Unsupported targets and missing assets are errors. No fallback asset is used.
The downloaded asset is fully written to a temporary file and its SHA-256 digest
must match the corresponding entry in `SHA256SUMS` before replacement starts.

## Shared updater

Create `internal/upgrade` with a public operation that accepts binary kind and
an injectable HTTP client/filesystem boundary for tests. It owns:

1. Asset selection and unsupported-target validation.
2. Release URL construction and download.
3. SHA-256 checksum parsing and verification.
4. Executable path resolution and replacement.

The command packages remain responsible for argument parsing, user-facing
messages, and server restart guidance. They call the shared package through a
package-level function variable so command tests can isolate parsing and output.

The updater uses `os.Executable` and creates temporary files beside the target
executable so replacement remains on the same filesystem. It preserves the
existing executable mode on Unix and does not alter any adjacent file.

## Replacement behavior

On Unix, close the downloaded file, apply executable permissions, and atomically
rename it over the current executable. A failure leaves the existing executable
untouched.

On Windows, the running client executable cannot be overwritten. Download and
verify the replacement first, then launch a `cmd.exe` helper that waits for the
parent process to exit and moves the temporary file over the target. The command
reports that replacement was scheduled; the helper cleans up its temporary file
on success or failure.

The server command is currently Linux-only. It replaces the binary but never
restarts a service or changes `server.json`, `warden.db`, `master.key`, or the
service unit. It prints the existing user-scope and system-scope daemon-reload,
restart, and status commands.

## Versioning and documentation

Bump `web/package.json` and the root metadata in `web/package-lock.json` from
`0.17.0` to `0.18.0`. The existing release workflow will publish `v0.18.0` and
its existing four assets.

Document both commands, the no-prompt/state-preservation guarantee, supported
platforms, checksum verification, and the server manual-restart requirement in
the CLI, deployment, and development documentation.

## Error handling

Errors must identify the operation and preserve the old binary. Important cases
include:

- unsupported OS/architecture or binary kind;
- release download failure or unavailable suitable asset;
- missing checksum entry;
- checksum mismatch;
- inability to resolve, write beside, or replace the executable;
- inability to launch the Windows replacement helper.

No success message is printed until verification succeeds. A Windows scheduled
replacement is the exception: it reports scheduling only after the helper starts.

## Testing

Unit tests cover:

- asset selection for each supported binary/target and unsupported targets;
- download and checksum success;
- missing asset/checksum and checksum mismatch failures;
- replacement failure leaving the original executable intact;
- successful replacement using a temporary executable path;
- command argument validation and output;
- server restart guidance;
- absence of prompts and preservation of representative config/state files.

Run the full Go suite, vet, frontend tests, and installer smoke tests where the
environment supports them.
