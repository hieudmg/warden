# SSH Connection Agent Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Transparently reuse SSH graphs for noninteractive SSH, SFTP copy, and SSH-tunneled DB commands through a self-terminating, cross-platform per-user client agent.

**Architecture:** The CLI keeps server-side profile resolution but sends resolved bundles to an authenticated local agent over framed IPC. Agent pool leases `ssh.Graph` instances keyed by full-bundle SHA-256, retains inactive graphs for ten minutes, and exposes operation adapters that create per-operation SSH sessions, SFTP clients, and DB tunnel channels without closing pooled transport.

**Tech Stack:** Go 1.25, `golang.org/x/crypto/ssh`, `github.com/pkg/sftp`, `github.com/go-sql-driver/mysql`, `github.com/Microsoft/go-winio v0.6.2`, `encoding/json`, `net`, OS build tags.

**Spec:** `docs/superpowers/specs/2026-08-28-ssh-connection-agent-design.md`

## Global Constraints

- Support Linux, macOS, and Windows client builds; Unix uses private socket mode `0600`, Windows uses `go-winio` named pipe with current-owner SDDL `D:P(A;;GA;;;OW)`.
- Do not change public CLI syntax, client config, server APIs, host-key validation, or `xssh` behavior.
- Agent execution applies only to `ssh`, remote `cp`, and DB bundles whose `SSH` field is non-nil; direct DB stays in CLI.
- Persist no credentials, private keys, SQL, shell commands, transfer paths, or transport bundle. Token state contains only protocol version, endpoint identity, and random 256-bit token.
- Cache key is SHA-256 of deterministic complete `model.SSHBundle` encoding, including secret fields; cache stores only hash as key.
- TTL is ten minutes after final operation releases a graph. Never expire graph with active leases; terminate agent only after pool is empty and no handler runs.
- Never automatically replay an operation after it may have started remotely. Retire failed graphs before future lease acquisition.
- Preserve `ssh` stdin/stdout/stderr and remote exit-status propagation; preserve existing `cp` validation and DB secret sanitization.
- Use test-first changes. Stage only intended files with NUL pathspec files, review staged diff, and commit every task with `git commit -F <file> --`.

---

## File Structure

| Path | Responsibility |
| --- | --- |
| `internal/client/ssh/graph.go` | Own a reusable SSH jump graph and expose target client safely. |
| `internal/client/ssh/exec.go` | Run command against borrowed graph target without closing graph. |
| `internal/client/ssh/graph_test.go`, `internal/client/ssh/exec_test.go` | Graph lifetime, close order, and execution reuse tests. |
| `internal/client/sftp/remote.go` | Open operation-scoped SFTP client on borrowed graph target. |
| `internal/client/sftp/remote_test.go` | Verify borrowed SFTP close leaves graph alive. |
| `internal/client/db/tunnel.go`, `internal/client/db/mysql.go` | Separate borrowed tunnel from one-shot graph ownership and run query with injected dialer. |
| `internal/client/db/tunnel_test.go`, `internal/client/db/mysql_test.go` | Verify borrowed tunnels and query reuse. |
| `internal/client/agent/protocol.go` | Versioned length-prefixed JSON frame types and codec. |
| `internal/client/agent/pool.go` | Bundle fingerprinting, single-flight graph acquisition, lease/retire/expiry lifecycle. |
| `internal/client/agent/server.go` | Authenticated IPC listener, operation dispatch, stream forwarding, self-shutdown. |
| `internal/client/agent/client.go` | Connect/start/retry agent and relay frames to CLI streams. |
| `internal/client/agent/runtime.go` | Common private state, token, endpoint, and detached self-launch lifecycle. |
| `internal/client/agent/runtime_unix.go` | Unix-socket listener/dial and permissions (`!windows`). |
| `internal/client/agent/runtime_windows.go` | Named-pipe listener/dial with `go-winio` (`windows`). |
| `internal/client/agent/*_test.go` | Protocol, pool clock, authentication, startup race, stream, and operation integration tests. |
| `cmd/warden/main.go`, `cmd/warden/main_test.go` | Hidden agent dispatch and CLI routing to agent adapters. |
| `go.mod`, `go.sum` | Pin `github.com/Microsoft/go-winio v0.6.2`. |
| `README.md` | Explain transparent cache scope, TTL, self-exit, exclusions. |

## Task 1: Introduce reusable SSH graph ownership

**Files:**
- Modify: `internal/client/ssh/graph.go`
- Modify: `internal/client/ssh/exec.go`
- Modify: `internal/client/ssh/exec_test.go`
- Create: `internal/client/ssh/graph_test.go`

**Interfaces:**
- Produces `func DialGraph(ctx context.Context, bundle model.SSHBundle, opts DialOptions) (*Graph, error)`.
- Produces `type Graph struct` with `Target() *golangssh.Client`, `Close() error`, and idempotent target-to-jump closure.
- Produces `func RunCommandOnClient(ctx context.Context, client *golangssh.Client, command string, streams Streams) error`.
- Existing `DialTarget`, `DialChain`, and `RunCommand` remain source-compatible wrappers.

- [ ] **Step 1: Write failing graph lifetime and borrowed-command tests**

Add tests that use `newTestSSHServer` and direct a target plus jump chain. Test that `DialGraph` returns its final client, `RunCommandOnClient` runs two separate commands successfully on the same graph, and graph `Close` disconnects every server connection. Include an idempotent second close assertion.

```go
graph, err := DialGraph(context.Background(), model.SSHBundle{Target: target, Jumps: []model.SSHNode{jump}}, testOptions())
if err != nil { t.Fatalf("DialGraph: %v", err) }
if err := RunCommandOnClient(context.Background(), graph.Target(), "echo first", Streams{Stdout: &out}); err != nil { t.Fatal(err) }
if err := RunCommandOnClient(context.Background(), graph.Target(), "echo second", Streams{Stdout: &out}); err != nil { t.Fatal(err) }
if err := graph.Close(); err != nil { t.Fatal(err) }
if err := graph.Close(); err != nil { t.Fatal(err) }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/client/ssh -run 'TestDialGraph|TestRunCommandOnClient' -count=1`

Expected: FAIL because `Graph`, `DialGraph`, and `RunCommandOnClient` do not exist.

- [ ] **Step 3: Implement graph wrapper and execution split**

Define graph ownership around existing `DialChain`; move target-to-jump closing into `Graph.Close` under `sync.Once`, clear `clientAgents` as each client closes, and preserve all current failure cleanup. Export borrowed execution by renaming existing `runOnClient` and retain private alias only if current tests require it. Make one-shot `RunCommand` dial graph, defer `Close`, then call borrowed execution.

```go
type Graph struct {
    target *golangssh.Client
    chain  []*golangssh.Client
    once   sync.Once
    err    error
}

func (g *Graph) Close() error {
    g.once.Do(func() {
        for i := len(g.chain) - 1; i >= 0; i-- {
            if err := g.chain[i].Close(); err != nil && g.err == nil { g.err = err }
            clientAgents.Delete(g.chain[i])
        }
    })
    return g.err
}
```

- [ ] **Step 4: Run SSH tests**

Run: `go test ./internal/client/ssh -count=1`

Expected: PASS, including existing host-key, proxy, jump-chain, cancellation, and interactive tests.

- [ ] **Step 5: Commit graph abstraction**

Stage only listed Task 1 paths. Commit message file content:

```text
refactor: add reusable SSH graph

Separate SSH graph ownership from operation-specific sessions.
```

## Task 2: Allow SFTP and DB operations to borrow a graph

**Files:**
- Modify: `internal/client/sftp/remote.go`
- Modify: `internal/client/sftp/remote_test.go`
- Modify: `internal/client/db/tunnel.go`
- Modify: `internal/client/db/tunnel_test.go`
- Modify: `internal/client/db/mysql.go`
- Modify: `internal/client/db/mysql_test.go`

**Interfaces:**
- Consumes `ssh.Graph.Target()` from Task 1.
- Produces `func Open(target *golangssh.Client, bundle model.SSHBundle) (*Remote, error)`; its `Close` closes SFTP only.
- Produces `func NewBorrowedTunnelDialer(target *golangssh.Client, dbAddr string) *TunnelDialer`; its `Close` disables future dials but never closes target.
- Produces `type DialContextFunc func(context.Context, string, string) (net.Conn, error)` and `func RunQueryWithDialContext(ctx context.Context, bundle model.DBBundle, sqlText string, out io.Writer, dial DialContextFunc) error`.

- [ ] **Step 1: Write failing borrowed-resource tests**

Add one SFTP test that calls `Open(graph.Target(), bundle)`, performs a remote filesystem operation, closes `Remote`, then runs `RunCommandOnClient` on same graph. Add DB tunnel test that calls `NewBorrowedTunnelDialer`, closes dialer after a direct-tcpip exchange, then opens a new SSH session through same graph. Add MySQL test that uses injected borrowed dial function and confirms table output.

```go
remote, err := Open(graph.Target(), bundle)
if err != nil { t.Fatal(err) }
if err := remote.Close(); err != nil { t.Fatal(err) }
if err := ssh.RunCommandOnClient(ctx, graph.Target(), "true", ssh.Streams{}); err != nil { t.Fatal(err) }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/client/sftp ./internal/client/db -run 'TestOpenBorrowed|TestBorrowedTunnel|TestRunQueryWithDialContext' -count=1`

Expected: FAIL because borrowed constructors and injected DB query path do not exist.

- [ ] **Step 3: Implement resource ownership split**

Keep `sftp.Dial` as one-shot compatibility API: dial `ssh.Graph`, call `Open`, and attach graph closure only to this owned variant. `Open` builds `pkgsftp.NewClient(target)`, keeps profile/host identities, and its close cannot close borrowed target.

Make `TunnelDialer` have optional `closeGraph func() error`; one-shot constructor sets it from `graph.Close`, borrowed constructor leaves it nil. Factor current `RunQuery` validation, connector setup, query, formatting, and sanitization through the injected-dial function so direct queries pass nil and existing one-shot tunneled queries preserve behavior.

```go
func NewBorrowedTunnelDialer(target *golangssh.Client, dbAddr string) *TunnelDialer {
    return &TunnelDialer{target: target, dbAddr: dbAddr}
}

func RunQueryWithDialContext(ctx context.Context, b model.DBBundle, sql string, out io.Writer, dial DialContextFunc) error {
    // retain maxSQLBytes validation and set cfg.DialFunc only when dial != nil
}
```

- [ ] **Step 4: Run affected package tests**

Run: `go test ./internal/client/sftp ./internal/client/db -count=1`

Expected: PASS, including transfer safety, same-host checks, direct DB, tunneled DB, and cancellation tests.

- [ ] **Step 5: Commit borrowed operation resources**

Stage only listed Task 2 paths. Commit message file content:

```text
refactor: share SSH graphs with SFTP and DB

Keep operation resources short-lived while retaining transport graph ownership.
```

## Task 3: Build cross-platform private IPC runtime and frame protocol

**Files:**
- Modify: `go.mod`
- Modify: `go.sum`
- Create: `internal/client/agent/protocol.go`
- Create: `internal/client/agent/protocol_test.go`
- Create: `internal/client/agent/runtime.go`
- Create: `internal/client/agent/runtime_test.go`
- Create: `internal/client/agent/runtime_unix.go`
- Create: `internal/client/agent/runtime_unix_test.go`
- Create: `internal/client/agent/runtime_windows.go`

**Interfaces:**
- Produces protocol constant `Version = 1`, `Frame`, `Request`, `Response`, `ReadFrame(io.Reader)`, and `WriteFrame(io.Writer, Frame)`.
- Produces `Runtime` with `Listen() (net.Listener, error)`, `Dial(context.Context) (net.Conn, error)`, `ReadToken() ([]byte, error)`, `CreateToken() ([]byte, error)`, and `Cleanup() error`.
- Uses `winio.ListenPipe(path, &winio.PipeConfig{SecurityDescriptor: "D:P(A;;GA;;;OW)"})` and `winio.DialPipeContext` under `//go:build windows`.

- [ ] **Step 1: Add failing protocol and runtime tests**

Test round-trip request/output/final frames through `net.Pipe`, reject declared frame length greater than `1<<20`, reject unknown version before payload dispatch, and reject token mismatch. On Unix, create runtime in test cache directory, call `Listen`, then assert socket mode equals `0600` and parent directory mode is `0700`; call `Cleanup` and assert socket/token absence.

```go
if err := WriteFrame(client, Frame{Version: Version, Kind: FrameStdout, Data: []byte("ok")}); err != nil { t.Fatal(err) }
got, err := ReadFrame(server)
if err != nil || string(got.Data) != "ok" { t.Fatalf("ReadFrame() = %#v, %v", got, err) }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/client/agent -run 'TestFrame|TestRuntime' -count=1`

Expected: FAIL because package and protocol/runtime symbols do not exist.

- [ ] **Step 3: Add dependency and implement runtime/protocol**

Run `go get github.com/Microsoft/go-winio@v0.6.2`, then implement a 4-byte big-endian size prefix plus JSON frame body with a hard 1 MiB frame maximum. Do not permit callers to bypass version/token frame validation. State lives under `os.UserCacheDir()/warden/agent`; create parent directory mode `0700`, create token atomically with `O_CREATE|O_EXCL` mode `0600`, and use `crypto/rand.Read` for 32 bytes. Derive Unix socket path inside this directory, remove only a stale socket owned by this runtime directory, and chmod socket `0600`. Keep Windows import and named-pipe use solely in windows-tagged file so Linux/macOS builds contain no Windows symbols.

```go
func WriteFrame(w io.Writer, f Frame) error {
    body, err := json.Marshal(f)
    if err != nil || len(body) > maxFrameBytes { return errFrameTooLarge }
    var size [4]byte
    binary.BigEndian.PutUint32(size[:], uint32(len(body)))
    if _, err := w.Write(size[:]); err != nil { return err }
    _, err = w.Write(body)
    return err
}
```

- [ ] **Step 4: Run runtime tests and cross-compile**

Run:

```bash
go test ./internal/client/agent -count=1
go test ./internal/client/agent -run TestRuntime -count=1
go build ./cmd/warden
gofmt -w $(find internal/client/agent -type f -name '*.go' -print)
go mod tidy
git diff --check
GOOS=windows GOARCH=amd64 go build ./cmd/warden
GOOS=darwin GOARCH=arm64 go build ./cmd/warden
```

Expected: PASS. Remove generated `warden`/`warden.exe` binaries before staging.

- [ ] **Step 5: Commit private IPC foundation**

Stage only Task 3 paths. Commit message file content:

```text
feat: add private cross-platform agent IPC

Add authenticated framed local transport and OS-specific endpoints.
```

## Task 4: Implement pooled graph agent server and client operations

**Files:**
- Create: `internal/client/agent/pool.go`
- Create: `internal/client/agent/pool_test.go`
- Create: `internal/client/agent/server.go`
- Create: `internal/client/agent/server_test.go`
- Create: `internal/client/agent/client.go`
- Create: `internal/client/agent/client_test.go`

**Interfaces:**
- Consumes `ssh.DialGraph`, `ssh.Graph`, `sftp.Open`, `db.NewBorrowedTunnelDialer`, and `db.RunQueryWithDialContext`.
- Produces `type Pool`, `func NewPool(dial GraphDialer, now func() time.Time, ttl time.Duration) *Pool`, `func (p *Pool) Acquire(context.Context, model.SSHBundle) (*Lease, error)`, and `func (l *Lease) Release()`.
- Produces `type Server` with `Serve(context.Context) error`; server closes listener and returns when `Pool.Empty()` after TTL cleanup.
- Produces client functions `RunSSH`, `RunCopy`, and `RunTunneledDB` that relay frames to provided `ssh.Streams`/writers.

- [ ] **Step 1: Write failing pool and server integration tests**

Use fake clock and fake graph dialer to prove: same bundle has one dial across two leases; a lease blocks expiry; final release expires precisely after ten minutes; changed password produces second SHA-256 key; `Retire` makes next acquisition dial replacement; concurrent acquisition waits for one in-progress dial; last removal signals server shutdown.

Use `net.Pipe` for server tests: wrong token returns final authentication error without invoking handler; two sequential SSH RPCs against test SSH server result in one accepted SSH connection; stdout/stderr/stdin and exit status frames retain exact bytes; malformed oversized and unknown-version frames close request without panic.

```go
clock.Advance(10 * time.Minute)
pool.Expire()
if !pool.Empty() { t.Fatal("pool retained expired graph") }
if got := graph.CloseCalls(); got != 1 { t.Fatalf("CloseCalls = %d, want 1", got) }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/client/agent -run 'TestPool|TestServer|TestClient' -count=1`

Expected: FAIL because pool/server/client symbols do not exist.

- [ ] **Step 3: Implement pool lifecycle**

Fingerprint `SSHBundle` by JSON-marshaling concrete struct then hashing with `sha256.Sum256`; struct has no maps, so encoding is deterministic for its declared field sequence. Use one pool mutex plus per-entry ready channel: first acquire sets `dialing`, dials without pool lock, then publishes graph or error; followers wait on ready channel or context cancellation. Lease increments `active`; release records `lastUsed`, and timer sweep retires only `active == 0 && now.Sub(lastUsed) >= ttl`. Retired entry is removed from map immediately but closed only after active count reaches zero. Close concrete graph target-to-jump outside pool lock.

```go
type entry struct {
    graph *ssh.Graph
    active int
    lastUsed time.Time
    retired bool
    ready chan struct{}
    dialErr error
}
```

- [ ] **Step 4: Implement framed server dispatch and client relay**

Authenticate first frame before reading operation fields. Dispatch SSH by acquiring one lease and calling `ssh.RunCommandOnClient`; use synchronized frame writer for stdout/stderr while a reader goroutine forwards stdin until EOF. Dispatch copy by acquiring each unique remote bundle lease, opening `sftp.Open` per remote endpoint, invoking `sftp.Copy`, and closing remotes before lease releases. Dispatch tunneled DB by acquiring bundle SSH lease, constructing `db.NewBorrowedTunnelDialer(lease.Target(), dbAddr)`, invoking injected query runner, then closing DB/tunnel resources. Convert operation errors to final frames with a separate remote-status field; do not serialize raw Go error chains or secrets.

Client first dials existing endpoint, then starts detached self with `exec.Command(os.Executable(), "agent", "serve")`, all stdio nil, `Start`, and `Process.Release` on absent endpoint. Retry read token/dial within five seconds. On all operations, preserve output byte order per stream, pass stdin only for SSH, and return `*ssh.ExitStatusError` for final remote status.

- [ ] **Step 5: Run agent and package tests**

Run:

```bash
gofmt -w internal/client/agent
go test ./internal/client/agent -count=1
go test ./internal/client/ssh ./internal/client/sftp ./internal/client/db -count=1
git diff --check
```

Expected: PASS.

- [ ] **Step 6: Commit pooled agent implementation**

Stage only Task 4 paths. Commit message file content:

```text
feat: pool SSH graphs in local agent

Reuse authenticated transport through authenticated IPC with idle expiry.
```

## Task 5: Route CLI noninteractive transport commands through agent

**Files:**
- Modify: `cmd/warden/main.go`
- Modify: `cmd/warden/main_test.go`

**Interfaces:**
- Consumes `agent.Serve`, `agent.RunSSH`, `agent.RunCopy`, and `agent.RunTunneledDB`.
- Produces hidden `agent serve` branch that is absent from `printUsage`.
- Existing `runSSH`, `runCP`, and `runDB` preserve validation/API lookup and call agent only after a resolved SSH bundle is available.

- [ ] **Step 1: Write failing CLI routing tests**

Add test seam for agent executor functions. Verify `runSSH` resolves list/bundle then passes name’s bundle and exact command to agent. Verify `runCP` retains malformed/local/same-host behavior before agent, resolves both remote bundles, converts a relative local path to absolute with `filepath.Abs`, and submits agent copy request. Verify DB uses direct runner with nil SSH but submits `RunTunneledDB` when `bundle.SSH != nil`. Verify `run([]string{"agent", "serve"}, ...)` invokes server and `printUsage` contains no `agent` line. Keep existing command end-to-end tests and update fixture expectations only where agent startup is intentionally injected.

```go
if got := executor.copy.Source.Path; !filepath.IsAbs(got) {
    t.Fatalf("local source path = %q, want absolute", got)
}
if directCalls != 1 || tunneledCalls != 0 { t.Fatalf("direct=%d tunneled=%d", directCalls, tunneledCalls) }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./cmd/warden -run 'TestRunSSHUsesAgent|TestRunCPUsesAgent|TestRunDBRoutesTunnel|TestAgentServeHidden' -count=1`

Expected: FAIL because command routing still invokes one-shot transport directly.

- [ ] **Step 3: Implement CLI routing with narrow seams**

Add package-level function variables initialized to agent operations only to permit deterministic tests; production logic must call concrete agent package. Route after API/bundle resolution so user-visible list/lookup errors retain exact prefix/exit codes. For CP, replace `resolveCPEndpoint` execution ownership with request construction that preserves profile identity, host identity, paths, and existing copy validations. For SSH DB bundle, send query and writer to agent; retain direct `clientdb.RunQuery` for nil SSH. Add internal branch `case "agent": return runAgent(...)`, accept only `serve`, and avoid public usage text.

- [ ] **Step 4: Run CLI tests and race detector**

Run:

```bash
gofmt -w cmd/warden/main.go cmd/warden/main_test.go
go test ./cmd/warden -count=1
go test -race ./internal/client/agent ./cmd/warden -count=1
git diff --check
```

Expected: PASS, with no agent subcommand in user help and no data races in pool/client seams.

- [ ] **Step 5: Commit CLI integration**

Stage only Task 5 paths. Commit message file content:

```text
feat: route noninteractive SSH operations through agent

Keep CLI validation while reusing local SSH transport graphs.
```

## Task 6: Document behavior and complete verification

**Files:**
- Modify: `README.md`
- Modify: `docs/superpowers/plans/2026-08-28-ssh-connection-agent.md`

**Interfaces:**
- Documents implementation behavior from prior tasks; no runtime interface changes.

- [x] **Step 1: Add documentation assertions first**

Add/update README CLI behavior text stating: `ssh`, remote `cp`, and SSH-backed `db` reuse per-user connections; each connection is closed ten minutes after final operation; agent exits when last cached connection closes; credentials never persist; `xssh` and direct DB bypass cache. Add a plan completion checklist marking only tasks whose test output has passed.

- [x] **Step 2: Verify docs and full Go test suite**

Run:

```bash
gofmt -w $(find internal/client/ssh internal/client/sftp internal/client/db internal/client/agent -type f -name '*.go' -print) cmd/warden/main.go cmd/warden/main_test.go
git diff --check
go test ./... -count=1
GOOS=windows GOARCH=amd64 go build ./cmd/warden
GOOS=darwin GOARCH=arm64 go build ./cmd/warden
rm -f warden warden.exe
git status --short
```

Expected: all tests and cross-platform client builds PASS; status lists only intended README/plan changes before staging.

- [x] **Step 3: Commit documentation and plan record**

Stage only `README.md` and plan file. Commit message file content:

```text
docs: describe SSH connection agent lifecycle

Document transparent connection reuse, expiry, and exclusions.
```

## Completion checklist

- [x] Task 1 — SSH graph tests are covered by the passing full Go test suite.
- [x] Task 2 — SFTP and DB borrowing tests are covered by the passing full Go test suite.
- [x] Task 3 — Agent IPC tests and client cross-builds passed.
- [x] Task 4 — Agent pool, server, and client tests are covered by the passing full Go test suite.
- [x] Task 5 — CLI routing tests are covered by the passing full Go test suite.
- [x] Task 6 — Documentation checks, the full Go test suite, and both client cross-builds passed.

## Plan Self-Review

- **Spec coverage:** Task 1 covers graph ownership; Task 2 covers SFTP/DB borrowing; Task 3 covers cross-platform authenticated IPC; Task 4 covers cache, TTL, self-exit, stream protocol, and resilience; Task 5 preserves CLI semantics; Task 6 documents and verifies all requirements.
- **Placeholder scan:** No incomplete or unspecified implementation actions. Interfaces, test commands, failure expectations, dependency version, security descriptor, TTL, and commit content are explicit.
- **Type consistency:** `ssh.Graph` feeds `sftp.Open`, `db.NewBorrowedTunnelDialer`, and agent `Lease.Target`; agent package exposes `RunSSH`, `RunCopy`, `RunTunneledDB`, and `Serve` for CLI integration.
