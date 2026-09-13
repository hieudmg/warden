# Self-upgrade Commands Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add prompt-free `warden upgrade` and `warden-server upgrade` commands that download, checksum-verify, and replace the latest suitable executable while preserving all settings and state.

**Architecture:** A shared `internal/upgrade` package will select the release asset, download and verify it, and delegate executable replacement to OS-specific files. The client and server command packages will validate arguments, pass release environment overrides, print concise results, and keep server restart guidance separate from replacement. The existing GitHub latest-release and `SHA256SUMS` contract remains unchanged.

**Tech Stack:** Go 1.25, `net/http`, `crypto/sha256`, `runtime`, `os`, `os/exec`, `httptest`, existing Bash/PowerShell release installers, npm package metadata.

**Spec:** `docs/superpowers/specs/2026-09-13-self-upgrade-design.md`

## Global Constraints

- Preserve all client/server settings and state; upgrade commands must not prompt or rewrite configuration, database, key, or service files.
- Use `WARDEN_REPO` with default `hieudmg/warden` and `WARDEN_RELEASE_BASE_URL` with default `https://github.com/<repo>/releases/latest/download`.
- Verify the selected binary against `SHA256SUMS` before replacing the installed executable.
- Support only the published `linux/amd64` and `windows/amd64` client/server assets; fail clearly when no suitable binary exists.
- Use `warden-linux-amd64`, `warden.exe`, and `warden-server-linux-amd64` for the matching binary/target.
- Replace only the executable; do not restart `warden-server` automatically.
- Bump release metadata from `0.17.0` to `0.18.0`.
- Do not add third-party dependencies.

---

## File map

- Create `internal/upgrade/upgrade.go`: release configuration, asset selection, download, checksum parsing, and orchestration.
- Create `internal/upgrade/replace_unix.go`: atomic Unix executable replacement.
- Create `internal/upgrade/replace_windows.go`: deferred Windows replacement helper launch.
- Create `internal/upgrade/upgrade_test.go`: deterministic HTTP, checksum, selection, and preservation tests.
- Modify `cmd/warden/main.go`: register `upgrade`, validate arguments, invoke shared updater, and print client result.
- Modify `cmd/warden/main_test.go`: command validation/output tests with an injected updater.
- Modify `cmd/warden-server/main.go`: register `upgrade`, invoke shared updater, and print restart guidance.
- Modify `cmd/warden-server/main_test.go`: command validation/output tests and restart-guide assertions.
- Modify `web/package.json` and `web/package-lock.json`: set release version to `0.18.0`.
- Modify `README.md`, `docs/cli.md`, `docs/deployment.md`, and `docs/development.md`: document commands, supported assets, preserved settings, checksums, and manual server restart.

## Interfaces

The shared package will expose these exact interfaces:

```go
package upgrade

type Kind uint8

const (
    Client Kind = iota
    Server
)

type Doer interface {
    Do(*http.Request) (*http.Response, error)
}

type Options struct {
    Repo             string
    ReleaseBaseURL   string
    HTTPClient       Doer
    GOOS             string
    GOARCH           string
    ExecutablePath   string
    Replace          func(tempPath, executablePath string, mode fs.FileMode) (scheduled bool, err error)
}

type Result struct {
    Asset          string
    ExecutablePath string
    Scheduled      bool
}

func Upgrade(ctx context.Context, kind Kind, opts Options) (Result, error)
```

Empty `Repo`, `ReleaseBaseURL`, `HTTPClient`, `GOOS`, `GOARCH`, and
`ExecutablePath` values use the production defaults (`hieudmg/warden`, the
GitHub latest-download URL, `http.DefaultClient`, `runtime.GOOS`,
`runtime.GOARCH`, and `os.Executable()`). `Replace` defaults to the
OS-specific `replaceExecutable` implementation. Tests set all relevant values
explicitly.

## Task 1: Build the shared release updater core

**Files:**
- Create: `internal/upgrade/upgrade.go`
- Create: `internal/upgrade/upgrade_test.go`

- [ ] **Step 1: Write failing asset-selection tests**

Add table-driven tests for `assetName` covering:

```go
func TestAssetName(t *testing.T) {
    tests := []struct {
        name       string
        kind       Kind
        goos       string
        goarch     string
        want       string
        wantErr    string
    }{
        {name: "linux client", kind: Client, goos: "linux", goarch: "amd64", want: "warden-linux-amd64"},
        {name: "windows client", kind: Client, goos: "windows", goarch: "amd64", want: "warden.exe"},
        {name: "linux server", kind: Server, goos: "linux", goarch: "amd64", want: "warden-server-linux-amd64"},
        {name: "windows server unavailable", kind: Server, goos: "windows", goarch: "amd64", wantErr: "no suitable release binary"},
        {name: "linux arm unavailable", kind: Client, goos: "linux", goarch: "arm64", wantErr: "no suitable release binary"},
    }
    // Call assetName(tc.kind, tc.goos, tc.goarch) and assert exact asset/error text.
}
```

- [ ] **Step 2: Run the focused tests and confirm they fail**

Run:

```bash
go test ./internal/upgrade -run '^TestAssetName$' -count=1
```

Expected: FAIL because `internal/upgrade` and `assetName` do not exist.

- [ ] **Step 3: Implement release defaults and asset selection**

Define `Kind`, `Options`, `Result`, and `assetName`. Build the default release
base as `https://github.com/<repo>/releases/latest/download`; trim a trailing
slash from explicit bases. Reject invalid kinds and unsupported target pairs
with an error containing `no suitable release binary`.

- [ ] **Step 4: Add failing checksum/download tests**

Use `httptest.Server` to serve an asset and `SHA256SUMS`. Add tests named
`TestUpgradeDownloadsAndVerifies`, `TestUpgradeRejectsChecksumMismatch`,
`TestUpgradeRejectsMissingChecksum`, and `TestUpgradeRejectsUnavailableAsset`.
Inject `HTTPClient`, `GOOS`, `GOARCH`, `ExecutablePath`, and `Replace`. Assert:

- requests use `/<asset>` and `/SHA256SUMS`;
- a valid checksum calls `Replace` once with the selected asset content;
- mismatch, missing checksum, and HTTP 404 return errors and never call `Replace`;
- the original executable file remains byte-for-byte unchanged after failures.

The checksum fixture must use the same format as the release script:

```text
<sha256>  warden-linux-amd64
```

- [ ] **Step 5: Run the checksum/download tests and confirm they fail**

Run:

```bash
go test ./internal/upgrade -run '^TestUpgrade(DownloadsAndVerifies|Rejects)' -count=1
```

Expected: FAIL because download, checksum, and orchestration are not implemented.

- [ ] **Step 6: Implement download, checksum verification, and cleanup**

Implement `Upgrade` to validate the asset before any network request, resolve
the executable path, create a temporary file in the executable directory, GET
the selected asset, GET `SHA256SUMS`, parse the first matching checksum entry
for the exact asset name, compare a lowercase hexadecimal SHA-256 digest, close
the file, and call `Replace`. Use `defer` cleanup so failed verification or
replacement never leaves a temporary file. Treat non-2xx responses as errors
that include the asset or checksum URL. Do not call `Replace` before checksum
verification succeeds.

- [ ] **Step 7: Run the focused updater tests and confirm they pass**

Run:

```bash
gofmt -w internal/upgrade/upgrade.go internal/upgrade/upgrade_test.go
go test ./internal/upgrade -count=1
```

Expected: PASS for selection and all download/checksum cases.

- [ ] **Step 8: Commit the shared updater core**

```bash
git add internal/upgrade/upgrade.go internal/upgrade/upgrade_test.go
 git commit -m "Add release asset download and verification"
```

## Task 2: Add safe executable replacement for Unix and Windows

**Files:**
- Create: `internal/upgrade/replace_unix.go`
- Create: `internal/upgrade/replace_windows.go`
- Modify: `internal/upgrade/upgrade.go`
- Modify: `internal/upgrade/upgrade_test.go`

**Interfaces:**

```go
// replace_unix.go
func replaceExecutable(tempPath, executablePath string, mode fs.FileMode) (bool, error)

// replace_windows.go
func replaceExecutable(tempPath, executablePath string, mode fs.FileMode) (bool, error)
```

- [ ] **Step 1: Write failing Unix replacement tests**

Add `TestReplaceExecutable` using a temporary directory and files named
`current` and `download`. Assert that a successful replacement changes the
current file to the downloaded bytes, retains the original executable mode,
returns `scheduled == false`, and removes the temporary source. Add a failure
case using a destination in a non-writable/missing parent and assert the old
file remains unchanged.

- [ ] **Step 2: Run the replacement test and confirm it fails**

Run:

```bash
go test ./internal/upgrade -run '^TestReplaceExecutable$' -count=1
```

Expected: FAIL because the OS-specific replacement function is not defined.

- [ ] **Step 3: Implement Unix atomic replacement**

In `replace_unix.go` with `//go:build !windows`, chmod the temporary file to
the supplied mode (falling back to `0755` when mode has no permission bits),
rename it over the target with `os.Rename`, and return `(false, nil)`. Return
wrapped errors without deleting or modifying the target when chmod/rename fails.

- [ ] **Step 4: Add Windows replacement implementation**

In `replace_windows.go` with `//go:build windows`, create a detached
`powershell.exe` helper with an encoded, static command. Pass the temporary and
target paths through environment variables and use `Move-Item -LiteralPath` and
`Remove-Item -LiteralPath`, so `%`, quotes, and command metacharacters remain
data. The helper waits for the parent process to exit, retries the move while the
executable is locked, and cleans up only after terminal failure. Return
`(true, nil)` only after `Start` succeeds, and return a wrapped error if
`powershell.exe` cannot be started. Do not attempt to replace the locked
executable in the current process.

- [ ] **Step 5: Wire the default replacement function**

Have `Upgrade` use `replaceExecutable` when `Options.Replace == nil`. Preserve
the existing executable mode by statting the target before download; if stat
fails, return an error before downloading. Pass that mode to the replacement
function. Keep `Scheduled` from the replacement result in `Result`.

- [ ] **Step 6: Add successful replacement integration coverage**

Add `TestUpgradeReplacesExecutable` that injects the real replacement function
on the current platform, serves a valid fixture, and asserts the target bytes
change and no temporary files matching the updater prefix remain. Add
`TestUpgradePreservesAdjacentState` with `client.json`, `server.json`,
`warden.db`, `master.key`, and `warden-server.service` fixtures; assert every
file is unchanged after upgrading the target binary.

- [ ] **Step 7: Run replacement and integration tests**

Run:

```bash
gofmt -w internal/upgrade/replace_unix.go internal/upgrade/replace_windows.go internal/upgrade/upgrade.go internal/upgrade/upgrade_test.go
go test ./internal/upgrade -count=1
GOOS=windows GOARCH=amd64 go test -c ./internal/upgrade -o /tmp/warden-upgrade-windows.test.exe
rm -f /tmp/warden-upgrade-windows.test.exe
```

Expected: PASS on the host and successful Windows cross-compilation.

- [ ] **Step 8: Commit platform replacement**

```bash
git add internal/upgrade
 git commit -m "Replace upgraded executables safely per platform"
```

## Task 3: Wire `warden upgrade` and `warden-server upgrade`

**Files:**
- Modify: `cmd/warden/main.go`
- Modify: `cmd/warden/main_test.go`
- Modify: `cmd/warden-server/main.go`
- Modify: `cmd/warden-server/main_test.go`
- Modify: `internal/upgrade/upgrade.go` only if command-facing option helpers are needed

**Interfaces:**

```go
// client command package
var runUpgrade = upgrade.Upgrade
func runClientUpgrade(args []string, stdout, stderr io.Writer, lookupEnv func(string) (string, bool)) int

// server command package
var runUpgrade = upgrade.Upgrade
func runServerUpgrade(args []string, stdout, stderr io.Writer, lookupEnv func(string) (string, bool)) int
```

If both command packages use the same variable name, keep them package-local;
the packages are separate Go programs.

- [ ] **Step 1: Write failing client command tests**

Add `TestRunClientUpgradeRejectsArguments` and
`TestRunClientUpgradeReportsSuccess`. Stub the package-level updater and assert
that positional arguments return exit code 2 without invoking it, while
`run([]string{"upgrade"}, ...)` invokes the client kind and prints the resolved
asset/path. Set `WARDEN_REPO` and `WARDEN_RELEASE_BASE_URL` through the injected
lookup function and assert they are passed through without prompting.

- [ ] **Step 2: Run the client command tests and confirm they fail**

Run:

```bash
go test ./cmd/warden -run '^TestRun(ClientUpgrade|Rejects)' -count=1
```

Expected: FAIL because the upgrade command is not registered.

- [ ] **Step 3: Implement client command registration and output**

Add `case "upgrade"` to the client root switch. Require zero arguments and
print `usage: warden upgrade` on invalid input. Pass `upgrade.Client` and the
release environment values into the shared operation. Print a success message
only after `Upgrade` returns nil; distinguish scheduled Windows replacement
from immediate replacement. Wrap failures as `warden upgrade: ...` and return
exit code 1. Do not load client config or prompt for an endpoint.

- [ ] **Step 4: Write failing server command tests**

Add `TestRunServerUpgradeRejectsArguments`, `TestRunServerUpgradeReportsSuccess`,
and `TestRunServerUpgradePrintsRestartGuide`. Stub the updater, assert it is
called with `upgrade.Server`, and require output containing both:

```text
systemctl --user daemon-reload
systemctl --user restart warden-server
sudo systemctl daemon-reload
sudo systemctl restart warden-server
```

Assert that upgrade does not enter `serve`, load the server config, or start a
listener.

- [ ] **Step 5: Run the server command tests and confirm they fail**

Run:

```bash
go test ./cmd/warden-server -run '^TestRunServerUpgrade' -count=1
```

Expected: FAIL because the upgrade command is not registered.

- [ ] **Step 6: Implement server command registration and restart guide**

Add `case "upgrade"` to the server root switch. Require zero arguments and
print `usage: warden-server upgrade` on invalid input. Invoke the shared updater
with `upgrade.Server`, print success and the existing user/system manual restart
commands, and never call service-management commands itself. Return exit code 1
on updater errors.

- [ ] **Step 7: Update command usage text and run focused tests**

Add both commands to `printUsage`. Run:

```bash
gofmt -w cmd/warden/main.go cmd/warden/main_test.go cmd/warden-server/main.go cmd/warden-server/main_test.go
go test ./cmd/warden ./cmd/warden-server -run 'Upgrade|Usage' -count=1
```

Expected: PASS, with no prompt or config/state mutation.

- [ ] **Step 8: Commit command wiring**

```bash
git add cmd/warden/main.go cmd/warden/main_test.go cmd/warden-server/main.go cmd/warden-server/main_test.go
 git commit -m "Add client and server upgrade commands"
```

## Task 4: Bump minor release and document the commands

**Files:**
- Modify: `web/package.json`
- Modify: `web/package-lock.json`
- Modify: `README.md`
- Modify: `docs/cli.md`
- Modify: `docs/deployment.md`
- Modify: `docs/development.md`

- [ ] **Step 1: Write the version/documentation changes**

Set the root package version and its lockfile package version from `0.17.0` to
`0.18.0`. Add usage examples:

```text
warden upgrade
warden-server upgrade
```

Explain that each command downloads the latest suitable checksum-verified
release binary, changes no settings/state, and requires no prompt. Document
that the server command replaces only the binary and prints manual systemd
restart commands; it does not restart the service. List the currently supported
asset targets and the `WARDEN_REPO`/`WARDEN_RELEASE_BASE_URL` test/override
variables.

- [ ] **Step 2: Validate metadata and documentation**

Run:

```bash
node -e "const p=require('./web/package.json'); if (p.version !== '0.18.0') process.exit(1)"
node -e "const p=require('./web/package-lock.json'); if (p.version !== '0.18.0' || p.packages[''].version !== '0.18.0') process.exit(1)"
git diff --check
```

Expected: all commands succeed.

- [ ] **Step 3: Commit release metadata and docs**

```bash
git add web/package.json web/package-lock.json README.md docs/cli.md docs/deployment.md docs/development.md
git commit -m "Bump release to v0.18.0 and document upgrades"
```

## Task 5: Full verification and integration review

**Files:**
- No new files; inspect all implementation and test files above.

- [ ] **Step 1: Run all Go tests and vet**

```bash
go test ./...
go vet ./...
```

Expected: both exit successfully.

- [ ] **Step 2: Run frontend and installer checks**

```bash
npm --prefix web ci
npm --prefix web test
bash scripts/test-installers.sh
```

Expected: frontend tests and installer smoke tests pass. If a required tool is
missing, record the exact skipped command and reason rather than claiming it
passed.

- [ ] **Step 3: Compile release targets**

```bash
GOOS=linux GOARCH=amd64 go build ./cmd/warden ./cmd/warden-server
GOOS=windows GOARCH=amd64 go build ./cmd/warden
```

Expected: all published release targets compile successfully.

- [ ] **Step 4: Review the final diff and repository state**

```bash
git diff origin/main...HEAD --check
git diff origin/main...HEAD --stat
git status --short --branch
```

Confirm only the updater, commands, tests, version metadata, docs, and approved
spec/plan commits are present; confirm no config/database/key/service fixture
was modified in the working tree.

- [ ] **Step 5: Commit any verification-only fixes separately**

If verification reveals a defect, add a focused test first, fix the defect, rerun
the failing check and the full relevant suite, then commit with an action-first
message. Do not amend unrelated commits or stage generated build artifacts.
