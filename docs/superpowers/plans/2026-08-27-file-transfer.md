# File Transfer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `warden cp` to recursively copy local and configured-SSH files and directories through SFTP.

**Architecture:** `internal/client/sftp` supplies endpoint-independent local/SFTP filesystem adapters and recursive copy logic. The CLI parses endpoints, resolves remote profiles and bundles, then creates SFTP clients over Warden's existing SSH graph; two remote endpoints stream every file through local Warden process.

**Tech Stack:** Go 1.25, `golang.org/x/crypto/ssh`, `github.com/pkg/sftp` v1.13.11, in-process `httptest` and SSH/SFTP fixtures.

**Spec:** `docs/superpowers/specs/2026-08-27-file-transfer-design.md`

## Global Constraints

- Command is exactly `warden cp <source> <destination>`; add no flags.
- At least one endpoint must be remote; reject local-to-local with exit code 2.
- `<connection>:<path>` is remote; Windows volume paths (`C:\...`) remain local.
- File copies overwrite by default; directory copies recursively merge, following standard `cp` placement.
- Never invoke native `ssh`, `scp`, or `rsync`; use SFTP over Warden-dialed SSH clients.
- Remote-to-remote transfers relay through local Warden process.
- Create parents, preserve mode bits, write files to a temporary sibling before rename, and clean temporary files best-effort on failure.
- Reject source symlinks/special files and directory self-copy. Do not preserve owner or timestamps.
- Preserve strict known-host behavior and close every target and jump SSH client.
- Use `make test`, `make test-race`, and `make vet` for final repository validation.

---

## File Structure

- `internal/client/sftp/filesystem.go` — filesystem interface plus local and `pkg/sftp` adapters, with platform-correct path operations.
- `internal/client/sftp/transfer.go` — destination placement, source validation, recursive directory traversal, temporary replacement, and byte-stream copy.
- `internal/client/sftp/remote.go` — `DialChain`/SFTP construction and idempotent close of SFTP and every SSH client in a remote endpoint.
- `internal/client/sftp/transfer_test.go` — local adapter unit tests for placement, overwrite, mode, self-copy, symlink rejection, and cleanup.
- `internal/client/sftp/remote_test.go` — in-process authenticated SSH+SFTP fixture and local↔remote/remote↔remote transport tests including connection closure.
- `cmd/warden/main.go` — `cp` dispatch, endpoint parser/profile resolution, command handler, and usage text.
- `cmd/warden/main_test.go` — CLI help, argument/profile errors, and end-to-end API + SSH/SFTP transfer tests.
- `go.mod`, `go.sum` — direct SFTP dependency and checksums.
- `README.md` — `cp` syntax and local/remote examples.

## Task 1: Add dependency and filesystem boundaries

**Files:**
- Modify: `go.mod`
- Modify: `go.sum`
- Create: `internal/client/sftp/filesystem.go`
- Create: `internal/client/sftp/transfer_test.go`

**Interfaces:**
- Produces `Filesystem`, `Endpoint`, `NewLocalFilesystem`, and `NewRemoteFilesystem` used by Tasks 2 and 3.
- `Filesystem` supports `Lstat`, `Stat`, `ReadDir`, `Open`, `Create`, `MkdirAll`, `Chmod`, `Rename`, `Remove`, `Join`, `Dir`, and `Base`.

- [ ] **Step 1: Add exact SFTP dependency**

Run:
```bash
go get github.com/pkg/sftp@v1.13.11
git diff -- go.mod go.sum
```

Expected: `go.mod` gains direct `github.com/pkg/sftp v1.13.11`; no dependency downgrades.

- [ ] **Step 2: Write adapter contract tests**

Create `internal/client/sftp/transfer_test.go` with a temporary local root. Assert these operations through `NewLocalFilesystem()`:

```go
func TestLocalFilesystemPathOperations(t *testing.T) {
    fs := NewLocalFilesystem()
    if got := fs.Join("root", "child"); got != filepath.Join("root", "child") { t.Fatal(got) }
    if got := fs.Base(filepath.Join("root", "child")); got != "child" { t.Fatal(got) }
}
```

Also assert `Lstat` sees a created symlink as `ModeSymlink`, `ReadDir` returns direct children, and `Create`/`Chmod` operate through the interface.

- [ ] **Step 3: Run adapter test before implementation**

Run:
```bash
go test ./internal/client/sftp -run 'TestLocalFilesystemPathOperations' -count=1
```

Expected: FAIL because package/types do not exist.

- [ ] **Step 4: Implement filesystem adapters**

Create `internal/client/sftp/filesystem.go`:

```go
type Filesystem interface {
    Lstat(string) (os.FileInfo, error)
    Stat(string) (os.FileInfo, error)
    ReadDir(string) ([]os.FileInfo, error)
    Open(string) (io.ReadCloser, error)
    Create(string) (io.WriteCloser, error)
    MkdirAll(string, os.FileMode) error
    Chmod(string, os.FileMode) error
    Rename(string, string) error
    Remove(string) error
    Join(...string) string
    Dir(string) string
    Base(string) string
}

type Endpoint struct { FS Filesystem; Path string }
func NewLocalFilesystem() Filesystem
func NewRemoteFilesystem(client *pkgsftp.Client) Filesystem
```

Use `filepath` for the local adapter and `path` for the remote adapter. Wrap `os` and `*pkgsftp.Client` methods directly; alias import `github.com/pkg/sftp` as `pkgsftp` to avoid collision with this package name.

- [ ] **Step 5: Run adapter tests**

Run:
```bash
go test ./internal/client/sftp -run 'TestLocalFilesystemPathOperations' -count=1
```

Expected: PASS.

- [ ] **Step 6: Commit adapter boundary**

```bash
git add go.mod go.sum internal/client/sftp/filesystem.go internal/client/sftp/transfer_test.go
git commit -m "feat: add SFTP filesystem adapters"
```

## Task 2: Implement recursive, safe copy core

**Files:**
- Create: `internal/client/sftp/transfer.go`
- Modify: `internal/client/sftp/transfer_test.go`

**Interfaces:**
- Consumes `Filesystem` and `Endpoint` from Task 1.
- Produces `Copy(source, destination Endpoint) error` for Task 3.

- [ ] **Step 1: Write failing copy-semantics tests**

Add table-driven tests rooted in separate temporary directories. Cover:

```go
func TestCopyFileOverwritesDestination(t *testing.T)
func TestCopyDirectoryIntoExistingDirectoryUsesSourceBase(t *testing.T)
func TestCopyDirectoryToMissingDestinationCreatesRoot(t *testing.T)
func TestCopyRejectsLocalDirectoryIntoItself(t *testing.T)
func TestCopyRejectsSourceSymlink(t *testing.T)
func TestCopyRemovesTemporaryFileAfterWriteFailure(t *testing.T)
func TestCopyAppliesSourceMode(t *testing.T)
```

For `TestCopyRemovesTemporaryFileAfterWriteFailure`, wrap local `Filesystem.Create` with a writer that returns `errors.New("write failed")` after its first write; assert destination remains unchanged and globbing `target + ".warden-cp-*"` is empty.

- [ ] **Step 2: Run copy tests before implementation**

Run:
```bash
go test ./internal/client/sftp -run '^TestCopy' -count=1
```

Expected: FAIL because `Copy` is undefined.

- [ ] **Step 3: Implement placement and source validation**

Create `internal/client/sftp/transfer.go` with:

```go
func Copy(source, destination Endpoint) error
func destinationPath(source, destination Endpoint, sourceInfo os.FileInfo) (string, error)
func validateSource(fs Filesystem, name string) (os.FileInfo, error)
```

Use `Lstat` in `validateSource`; return errors for `ModeSymlink`, non-regular non-directory modes, and missing source. In `destinationPath`, append `source.FS.Base(source.Path)` when destination `Stat` succeeds and is a directory. For local same-filesystem directories, reject `filepath.Rel(source.Path, target)` equal to `.` or not beginning `..`.

- [ ] **Step 4: Implement file and directory copying**

Add these helpers:

```go
func copyFile(source, destination Filesystem, sourcePath, targetPath string, mode os.FileMode) error
func copyDirectory(source, destination Filesystem, sourceRoot, targetRoot string) error
func temporarySibling(fs Filesystem, target string) string
```

`copyFile` must create target parent, read source, write unique `target + ".warden-cp-<random>"`, `io.Copy`, close reader and writer, `Chmod` mode bits, then rename only after both closes succeed. On every post-create error, call `Remove(temp)` and return the original error. `copyDirectory` must create/chmod every directory, use `ReadDir`, reject symlink/special children through `validateSource`, and recurse using each adapter's `Join`.

- [ ] **Step 5: Run copy tests**

Run:
```bash
go test ./internal/client/sftp -run '^TestCopy' -count=1
```

Expected: PASS.

- [ ] **Step 6: Commit copy core**

```bash
git add internal/client/sftp/transfer.go internal/client/sftp/transfer_test.go
git commit -m "feat: add recursive SFTP copy core"
```

## Task 3: Add remote lifecycle and transfer integration tests

**Files:**
- Create: `internal/client/sftp/remote.go`
- Create: `internal/client/sftp/remote_test.go`
- Modify: `internal/client/sftp/transfer.go`

**Interfaces:**
- Consumes `Endpoint`, `Filesystem`, and `Copy` from Tasks 1–2; `model.SSHBundle` and `clientssh.DialChain` from existing packages.
- Produces `Dial(ctx, bundle) (*Remote, error)`, `(*Remote).Endpoint(path string) Endpoint`, and `(*Remote).Close() error` for Task 4.

- [ ] **Step 1: Write failing remote tests and fixture**

In `remote_test.go`, create an in-process password-authenticated SSH server that handles session channel `subsystem` requests where payload name is `sftp`. Serve an isolated `t.TempDir()` using `pkgsftp.NewServer(channel, pkgsftp.WithServerWorkingDirectory(root))`; run `Serve()` in a goroutine and close server/channel on return.

Write:

```go
func TestCopyLocalToRemoteAndBack(t *testing.T)
func TestCopyRemoteToRemoteRelaysThroughClient(t *testing.T)
func TestRemoteCloseClosesWholeJumpChain(t *testing.T)
```

Use remote `Lstat`/`os.ReadFile` assertions to verify bytes, directory placement, overwrite, and modes. Give the source and destination different fixture roots in the relay test. Track accepted SSH connections with an atomic counter and wait until it returns to zero after `Close`.

- [ ] **Step 2: Run remote tests before implementation**

Run:
```bash
go test ./internal/client/sftp -run '^(TestCopyLocalToRemoteAndBack|TestCopyRemoteToRemoteRelaysThroughClient|TestRemoteCloseClosesWholeJumpChain)$' -count=1
```

Expected: FAIL because `Dial` and `Remote` do not exist.

- [ ] **Step 3: Implement SFTP dial and close ownership**

Create `internal/client/sftp/remote.go`:

```go
type Remote struct {
    client *pkgsftp.Client
    target *ssh.Client
    chain  []*ssh.Client
    mu     sync.Mutex
}
func Dial(ctx context.Context, bundle model.SSHBundle) (*Remote, error)
func (r *Remote) Endpoint(name string) Endpoint
func (r *Remote) Close() error
```

`Dial` calls `clientssh.DialChain(ctx, bundle, clientssh.DialOptions{})`, then `pkgsftp.NewClient(target)`. If SFTP setup fails, close every chain client before returning. `Close` is idempotent: close SFTP first, then every element of `chain`, retaining first error. `Endpoint` wraps `NewRemoteFilesystem(r.client)`.

- [ ] **Step 4: Run remote tests**

Run:
```bash
go test ./internal/client/sftp -run '^(TestCopyLocalToRemoteAndBack|TestCopyRemoteToRemoteRelaysThroughClient|TestRemoteCloseClosesWholeJumpChain)$' -count=1
```

Expected: PASS.

- [ ] **Step 5: Commit remote transport**

```bash
git add internal/client/sftp/remote.go internal/client/sftp/remote_test.go internal/client/sftp/transfer.go
git commit -m "feat: connect file copies over SFTP"
```

## Task 4: Add CLI endpoint parsing and command handler

**Files:**
- Modify: `cmd/warden/main.go`
- Modify: `cmd/warden/main_test.go`

**Interfaces:**
- Consumes `clienttransfer.Dial`, `clienttransfer.Copy`, `clienttransfer.NewLocalFilesystem`, and `clienttransfer.Endpoint` from Tasks 1–3.
- Produces `runCP(args, configPath, configPathSet, stdout, stderr, lookupEnv) int` and `parseCPEndpoint(raw string, connections []model.SSHConnection) (cpEndpoint, error)`.

- [ ] **Step 1: Write failing parser and handler tests**

Add tests for:

```go
func TestRunCPHelp(t *testing.T)
func TestRunCPRejectsWrongArgumentCount(t *testing.T)
func TestRunCPRejectsLocalToLocal(t *testing.T)
func TestParseCPEndpointRecognizesWindowsVolume(t *testing.T)
func TestRunCPRejectsUnknownConnection(t *testing.T)
```

Assert `cp --help` prints `warden cp <source> <destination>` to stdout with exit 0; invalid operand count/local-to-local returns 2; `C:\\tmp\\file` is local; `missing:/tmp/file` returns exit 1 with `cp: connection "missing" not found`.

- [ ] **Step 2: Run CLI unit tests before implementation**

Run:
```bash
go test ./cmd/warden -run '^(TestRunCP|TestParseCPEndpoint)' -count=1
```

Expected: FAIL because `cp` dispatch and parser do not exist.

- [ ] **Step 3: Implement endpoint parsing and resolution**

In `cmd/warden/main.go`, add `case "cp": return runCP(...)` to `run`. Add:

```go
type cpEndpoint struct {
    path       string
    connection *model.SSHConnection
}
func parseCPEndpoint(raw string, connections []model.SSHConnection) (cpEndpoint, error)
func runCP(args []string, configPath string, configPathSet bool, stdout, stderr io.Writer, lookupEnv func(string) (string, bool)) int
func printCPUsage(w io.Writer)
```

Recognize a Windows volume with `filepath.VolumeName(raw) != ""` before splitting on the first `:`. For all other operands containing `:`, reject empty name/path, find an exact profile name, and report an unknown name. Operands without `:` are local. `runCP` validates two operands, loads client config, lists profiles once, parses both endpoints, rejects two local endpoints, fetches a bundle and calls `clienttransfer.Dial` for every remote endpoint, defers each close, converts local endpoints with `NewLocalFilesystem`, then calls `clienttransfer.Copy`. Prefix runtime errors with `cp:` and return 1.

- [ ] **Step 4: Add root and command help**

Add to `printUsage` and a dedicated printer:

```text
warden [--config path] cp <source> <destination>

Usage:
  warden cp <source> <destination>
```

Do not create a flag set: the command has no flags.

- [ ] **Step 5: Run CLI unit tests**

Run:
```bash
go test ./cmd/warden -run '^(TestRunCP|TestParseCPEndpoint)' -count=1
```

Expected: PASS.

- [ ] **Step 6: Commit CLI contract**

```bash
git add cmd/warden/main.go cmd/warden/main_test.go
git commit -m "feat: add cp command"
```

## Task 5: Verify CLI against real SSH/SFTP and document it

**Files:**
- Modify: `cmd/warden/main_test.go`
- Modify: `README.md`

**Interfaces:**
- Consumes the fully wired `run` and `cp` command from Task 4.
- Produces end-to-end coverage of API profile resolution plus SFTP transfer, and user-facing command documentation.

- [ ] **Step 1: Write failing CLI end-to-end test**

Extend the command-package SSH fixture to accept `subsystem=sftp` and serve `t.TempDir()` using `pkgsftp.NewServer`. Add `TestRunCPEndToEnd` that:

1. writes a known host entry under the test `HOME`;
2. serves one or two SSH connection records plus matching `/api/v1/transport/ssh/<id>` bundle JSON from `httptest.Server`;
3. runs local→remote, remote→local, and remote→remote `cp` invocations;
4. verifies recursive placement, destination overwrite, mode bits, no stdout, and connection closure.

- [ ] **Step 2: Run the end-to-end test before fixture/handler updates**

Run:
```bash
go test ./cmd/warden -run '^TestRunCPEndToEnd$' -count=1
```

Expected: FAIL because existing fixture rejects SFTP subsystem channels.

- [ ] **Step 3: Implement SFTP support in CLI fixture**

Update `newCLITestSSHServer`/its connection handler so its session handler reads a `subsystem` request payload, replies true only for `sftp`, and runs `pkgsftp.NewServer` rooted in the server test directory. Keep current exec request behavior unchanged so SSH command tests remain valid.

- [ ] **Step 4: Document public semantics**

Add to `README.md` CLI examples:

```text
warden cp ./release.tar prod:/srv/releases/
warden cp prod:/var/log/app ./app-logs
warden cp source:/srv/export destination:/srv/import
```

Document that transfers recurse for directories, overwrite files by default, place a source directory beneath an existing destination directory, require at least one configured host, and relay host-to-host bytes through local Warden client.

- [ ] **Step 5: Run focused command validation**

Run:
```bash
go test ./cmd/warden -count=1
go test ./internal/client/sftp -count=1
```

Expected: PASS.

- [ ] **Step 6: Commit integration and docs**

```bash
git add cmd/warden/main_test.go README.md
git commit -m "test: cover SFTP file transfers"
```

## Task 6: Run full verification and inspect final change

**Files:**
- Modify only if a command reveals a defect in prior tasks.

**Interfaces:**
- Consumes complete feature and test suite.
- Produces validation evidence for review/PR.

- [ ] **Step 1: Format all modified Go files**

Run:
```bash
gofmt -w cmd/warden/main.go cmd/warden/main_test.go internal/client/sftp/*.go
git diff --check
```

Expected: no formatting or whitespace errors.

- [ ] **Step 2: Run repository test suite**

Run:
```bash
make test
```

Expected: PASS.

- [ ] **Step 3: Run race and static analysis suites**

Run:
```bash
make test-race
make vet
```

Expected: both PASS.

- [ ] **Step 4: Inspect intended final diff**

Run:
```bash
git status --short
git diff origin/main...HEAD --check
git diff origin/main...HEAD --stat
```

Expected: only SFTP dependency, transfer implementation/tests, CLI/docs, approved spec, and this plan.

- [ ] **Step 5: Commit any verification fixes**

If Steps 1–3 changed files:

```bash
git add cmd/warden/main.go cmd/warden/main_test.go internal/client/sftp go.mod go.sum README.md
git commit -m "fix: finalize file transfer validation"
```

If no files changed, make no commit.

## Plan Self-Review

- Spec coverage: Tasks 1–5 implement all endpoint modes, recursive placement, overwrite, temporary replacement, modes, source rejection, strict SSH reuse, jump-chain closure, CLI contract, tests, and README documentation. Task 6 validates repository-wide compatibility.
- Placeholder scan: no deferred implementation labels or undefined test requirements remain.
- Type consistency: `Filesystem`/`Endpoint` originate in Task 1; `Copy` in Task 2; `Remote` in Task 3; CLI uses only those exported interfaces in Tasks 4–5.
