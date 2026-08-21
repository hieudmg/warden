# Warden Hub Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a Linux Warden server and Linux/Windows Warden client that share one HTTP API for encrypted connection profiles, local SSH/MySQL execution, interactive SSH, and release-style project reports.

**Architecture:** `warden-server` is the only SQLite/master-key owner and serves embedded web UI plus `/api/v1` JSON on one configured listener. `warden` is an API-only client: it retrieves redacted metadata or explicit short-lived-in-memory transport bundles, then executes SSH/MySQL locally with Go libraries; `xssh` owns the caller's terminal directly. Jump routes are syntactically validated JSON integer arrays on `ssh_connections` and logically resolved only at transport-query time.

**Tech Stack:** Go module; standard `net/http`, `database/sql`, `crypto/aes`, `crypto/cipher`, `crypto/rand`, `encoding/json`; SQLite driver selected after current documentation check; `golang.org/x/crypto/ssh` and `golang.org/x/crypto/ssh/knownhosts`; Go MySQL/MariaDB driver; platform-specific terminal packages selected and documented for Linux x86-64 and Windows x86-64; embedded static web UI.

**Spec:** `docs/superpowers/specs/2026-08-21-warden-hub-design.md`

## Global Constraints

- Server target: Linux x86-64 only; client targets: Linux x86-64 and Windows x86-64.
- One server listener serves `/` and `/api/v1/...`; no application authentication; tailnet is the trust boundary.
- `warden-server` is the sole SQLite and master-key reader; clients never read SQLite or server config files.
- Stored secrets use AES-256-GCM with a random 32-byte key file, no bcrypt, no salt, no password KDF, fresh random 12-byte nonce per value, and BLOB storage.
- Secret BLOB format is `[format version: 1 byte][nonce: 12 bytes][ciphertext + GCM tag]`.
- Master key is exactly 32 random bytes in a separate Unix file, owned by service user and mode `0600`; unsafe/missing key fails startup.
- Ordinary profile reads redact secrets; explicit transport-profile responses decrypt complete bundles, set `Cache-Control: no-store`, and never log response bodies.
- SSH jump routes are syntactically valid JSON arrays of integer IDs; missing IDs, self-reference, and cycles are allowed on write but fail during transport resolution before network connection.
- SSH deletion is allowed; CLI/web warn and list dependents first, but stored dependent JSON is not rewritten.
- Client uses Go SSH/MySQL/HTTP implementations; no native `ssh`, `sshpass`, `mysql`, `fzf`, or `nc` dependencies.
- Reports contain only `project`, `title`, `summary`, `agent_model`, and server-generated UTC `created_at`; reports are immutable and append-only.
- Never log or return passwords, private keys, SQL text, remote command text, secret paths, or secret-bearing response bodies.
- Use parameterized SQL, strict JSON decoding, request/field size limits, context cancellation, foreign keys, WAL mode, busy timeout, and local SQLite storage only.
- Do not claim perfect Go memory zeroization; overwrite temporary byte buffers where practical and avoid credential caches.

## File Structure

Create focused packages with these ownership boundaries:

```text
cmd/warden-server/main.go              # server binary entrypoint
cmd/warden/main.go                     # client binary entrypoint
internal/config/                       # server/client config loading and defaults
internal/crypto/                       # master-key loading and AES-GCM BLOB codec
internal/store/                        # SQLite connection, migrations, repositories
internal/model/                        # API/domain structs shared by server and client
internal/server/                       # HTTP server, middleware, API routing
internal/server/profiles/              # profile CRUD and transport bundle resolution
internal/server/reports/               # project/report handlers and repository use
internal/server/audit/                 # safe audit event recording
internal/client/api/                   # HTTP client, JSON errors, redaction-safe decode
internal/client/ssh/                   # SSH graph resolution consumption and command mode
internal/client/db/                    # MySQL execution and SSH tunnel dialing
internal/client/terminal/               # Linux/Windows raw terminal, PTY, resize/signals
internal/client/report/                 # report CLI request construction
internal/web/                          # embedded management UI assets
migrations/                            # numbered SQLite migrations
scripts/                               # reproducible build/check scripts
README.md                              # setup, service, client, and tailnet deployment
```

Shared API/domain structs must not import server-only or client-only packages. Store repositories must return domain values, not HTTP types. Transport bundle responses must have separate secret-bearing types so ordinary list/detail handlers cannot accidentally serialize credentials.

---

### Task 1: Bootstrap Module, Targets, and Configuration

**Files:**
- Create: `go.mod`
- Create: `cmd/warden-server/main.go`
- Create: `cmd/warden/main.go`
- Create: `internal/config/config.go`
- Create: `internal/config/config_test.go`
- Create: `README.md`
- Create: `.gitignore`
- Create: `Makefile`

**Interfaces:**
- Produces `config.Server` with `ListenAddr`, `DBPath`, `MasterKeyPath`, `StaticFS` and `config.Client` with `APIBaseURL`, `Timeout`.
- Produces `cmd/warden-server` and `cmd/warden` binaries that parse subcommands and return nonzero on invalid configuration.

- [ ] **Step 1: Write failing config tests** for default paths, environment/config-file precedence, invalid listen address, invalid URL, and client timeout parsing.
- [ ] **Step 2: Run `go test ./internal/config` and confirm failure** because module/packages do not yet exist.
- [ ] **Step 3: Implement minimal module, config structs, strict JSON config loading, environment overrides, and `--help` command dispatch.** Keep server and client configuration separate; never load server master-key bytes in client binary.
- [ ] **Step 4: Add build commands and documentation** showing `go build ./cmd/warden-server` and `go build ./cmd/warden`, plus `GOOS=windows GOARCH=amd64 go build ./cmd/warden`.
- [ ] **Step 5: Run `go test ./...`, `go vet ./...`, and both Linux builds.** Record Windows cross-build result; do not claim PTY support until native Windows tests exist.

### Task 2: Master-Key Validation and AES-GCM Codec

**Files:**
- Create: `internal/crypto/keyfile.go`
- Create: `internal/crypto/keyfile_test.go`
- Create: `internal/crypto/gcm.go`
- Create: `internal/crypto/gcm_test.go`

**Interfaces:**
- `func LoadMasterKey(path string) ([32]byte, error)` validates exactly 32 bytes and Unix mode with no group/other bits.
- `type Codec struct { ... }` exposes `Encrypt(plaintext, aad []byte) ([]byte, error)` and `Decrypt(blob, aad []byte) ([]byte, error)`.
- Codec output is one-byte version `1`, 12-byte nonce, and AES-GCM ciphertext including 16-byte tag.

- [ ] **Step 1: Write failing tests** for valid key load, missing key, wrong length, unsafe permissions, round trip, unique nonce for repeated plaintext, tamper failure, wrong-key failure, malformed version/length, and AAD mismatch.
- [ ] **Step 2: Run `go test ./internal/crypto -v` and confirm failure.**
- [ ] **Step 3: Implement key-file validation** with `os.Stat`, permission checks on Linux, exact-length read, and no logging of key bytes.
- [ ] **Step 4: Implement AES-256-GCM** using `crypto/aes`, `cipher.NewGCM`, and `crypto/rand`; store binary BLOBs, not Base64; copy only necessary buffers.
- [ ] **Step 5: Run crypto tests plus a benchmark** for 64-byte, 1 KiB, and 16 KiB values. Verify no bcrypt/KDF dependency appears in `go.mod`.

### Task 3: SQLite Schema, Migrations, and Repositories

**Files:**
- Create: `migrations/001_initial.sql`
- Create: `internal/store/store.go`
- Create: `internal/store/migrations.go`
- Create: `internal/store/store_test.go`
- Create: `internal/store/profiles.go`
- Create: `internal/store/profiles_test.go`
- Create: `internal/store/reports.go`
- Create: `internal/store/reports_test.go`
- Create: `internal/store/audit.go`
- Create: `internal/store/audit_test.go`
- Create: `internal/model/profile.go`
- Create: `internal/model/report.go`
- Create: `internal/model/audit.go`

**Interfaces:**
- `func Open(ctx context.Context, path string) (*Store, error)` configures SQLite with foreign keys, WAL, busy timeout, and migrations.
- Profile repository methods: `CreateSSH`, `GetSSH`, `ListSSH`, `UpdateSSH`, `DeleteSSH`, `SSHDependents`, `CreateDB`, `GetDB`, `ListDB`, `UpdateDB`, `DeleteDB`.
- `jump_connection_ids` is stored as TEXT containing syntactically valid JSON integer array; repository validates JSON shape only.
- Report methods: `CreateProject`, `GetProjectByName`, `ListProjects`, `CreateReport`, `ListReports`.
- Audit method: `AppendAudit(ctx, AuditEvent) error`.

- [ ] **Step 1: Write migration and repository tests first** for schema creation, rerun-safe migration, foreign keys on reports/DB references, WAL/busy settings, CRUD, JSON syntax acceptance, malformed JSON rejection, deletion with dependents, report append-only behavior, and audit persistence.
- [ ] **Step 2: Run store tests and confirm failure.**
- [ ] **Step 3: Implement migration table and initial schema.** Include `ssh_connections`, `db_connections`, `projects`, `reports`, `audit_events`, and `schema_migrations`; use encrypted BLOB columns for every secret; use `ON DELETE RESTRICT` only where actual SQL foreign keys exist, while SSH jump JSON remains application data.
- [ ] **Step 4: Implement parameterized repository methods** and transaction-safe profile writes. Allocate SSH row ID before encrypting fields so AAD can include stable `warden/ssh/<id>/<field>`.
- [ ] **Step 5: Implement dependent lookup** by scanning valid JSON arrays in Go against listed SSH rows; report dependent SSH and DB names without rejecting deletion.
- [ ] **Step 6: Run `go test ./internal/store -race` and inspect migration/schema output** for secret columns and absent jump-edge table.

### Task 4: Profile API, Query-Time Graph Resolution, and Audit

**Files:**
- Create: `internal/server/server.go`
- Create: `internal/server/http_error.go`
- Create: `internal/server/profiles/handlers.go`
- Create: `internal/server/profiles/resolve.go`
- Create: `internal/server/profiles/resolve_test.go`
- Create: `internal/server/audit/audit.go`
- Create: `internal/server/profiles/handlers_test.go`
- Create: `internal/model/transport.go`
- Create: `internal/model/api.go`

**Interfaces:**
- `ResolveSSHBundle(ctx context.Context, id int64) (model.SSHBundle, error)` resolves target and ordered jump IDs recursively, detects missing IDs/self-reference/cycles, decrypts secrets, and returns no partial bundle on failure.
- `ResolveDBBundle(ctx context.Context, id int64) (model.DBBundle, error)` resolves DB credentials plus complete referenced SSH bundle.
- HTTP routes under `/api/v1/ssh-connections`, `/api/v1/db-connections`, `/api/v1/transport/ssh/{id}`, `/api/v1/transport/db/{id}`, and dependent-warning endpoints.
- Ordinary response structs contain redacted metadata only; transport response structs contain secrets.

- [ ] **Step 1: Write resolver tests** for linear chain, missing ID, self-reference, cycle, malformed stored JSON defense, DB-over-SSH resolution, decryption failure, and AAD mismatch.
- [ ] **Step 2: Write handler tests** for strict JSON decoding, size limits, redaction, `no-store`, stable JSON error codes, source metadata, and delete-with-warning behavior.
- [ ] **Step 3: Run resolver/handler tests and confirm failure.**
- [ ] **Step 4: Implement DFS resolution** with a visited stack and depth bound; validate all graph nodes before decrypting/returning secrets or initiating any transport.
- [ ] **Step 5: Implement CRUD handlers** with syntax-only jump JSON validation on writes, encrypted-field handling, parameterized repository calls, and safe error sanitization.
- [ ] **Step 6: Implement audit records** for CRUD, dependent lookup, transport retrieval, success/failure, source address, user-agent, and safe resource metadata; exclude SQL, commands, and secrets.
- [ ] **Step 7: Run API tests, `go test ./internal/server/... -race`, and an HTTP integration test** proving normal profile reads redact values and transport reads set `Cache-Control: no-store`.

### Task 5: API Client and Noninteractive SSH Transport

**Files:**
- Create: `internal/client/api/client.go`
- Create: `internal/client/api/client_test.go`
- Create: `internal/client/ssh/graph.go`
- Create: `internal/client/ssh/exec.go`
- Create: `internal/client/ssh/hostkey.go`
- Create: `internal/client/ssh/exec_test.go`
- Modify: `cmd/warden/main.go`

**Interfaces:**
- `api.Client` supports redacted list/get, transport bundle retrieval, dependent lookup, and report creation over JSON HTTP.
- `ssh.RunCommand(ctx context.Context, bundle model.SSHBundle, command string, io streams) error` streams remote output and returns remote exit status.
- `hostkey.Callback(path string, acceptNew bool, terminal io.ReadWriter) (ssh.HostKeyCallback, error)` uses platform-standard known-hosts path, rejects changed keys, and only accepts unknown keys interactively with explicit `--accept-new`.

- [ ] **Step 1: Write fake-HTTP-client tests** for URL construction, JSON errors, no-store transport response, timeouts, and response-body closure.
- [ ] **Step 2: Write SSH integration tests with an in-process test SSH server** for password/key authentication, command output, nonzero status, cancellation, jump chain, and proxy dialing.
- [ ] **Step 3: Run tests and confirm failure.**
- [ ] **Step 4: Implement API client** with strict decoding, bounded response bodies, no credential logging, and context-aware requests.
- [ ] **Step 5: Implement SSH graph dialing** using `golang.org/x/crypto/ssh`; connect jump hosts in route order with `ssh.Client.Dial`/`ssh.NewClientConn`; support optional HTTP CONNECT using Go `net/http`/`net.Dialer`.
- [ ] **Step 6: Implement command execution** with stdin/stdout/stderr streaming, remote exit status preservation, and sanitized errors.
- [ ] **Step 7: Wire `warden ssh <name> "<command>"`** to list/find the connection via redacted API metadata, retrieve bundle, execute locally, and return the correct process status.
- [ ] **Step 8: Run Linux tests, `go test ./internal/client/... -race`, and Linux/Windows client cross-builds.**

### Task 6: MySQL/MariaDB Client and SSH-Tunneled DB

**Files:**
- Create: `internal/client/db/mysql.go`
- Create: `internal/client/db/tunnel.go`
- Create: `internal/client/db/mysql_test.go`
- Create: `internal/client/db/tunnel_test.go`
- Modify: `cmd/warden/main.go`

**Interfaces:**
- `RunQuery(ctx context.Context, bundle model.DBBundle, sqlText string, out io.Writer) error` opens a Go MySQL/MariaDB connection locally and executes one SQL string.
- `TunnelDialer` exposes a `DialContext` compatible with the selected MySQL driver for DB-over-SSH without writing credentials to files or argv.

- [ ] **Step 1: Write tests** using a fake SQL driver/server for DSN construction, password non-disclosure, output formatting, DB errors, cancellation, and direct-vs-SSH profile selection.
- [ ] **Step 2: Write tunnel tests** against the test SSH server for local forwarding lifecycle, close-on-cancel, and failure before DB dial.
- [ ] **Step 3: Run tests and confirm failure.**
- [ ] **Step 4: Implement MySQL/MariaDB driver integration** with credentials held in memory, bounded command input, context cancellation, and stable tabular output.
- [ ] **Step 5: Implement SSH tunnel dialing** over resolved bundle, close all clients/listeners synchronously, and avoid loopback ephemeral-file/config dependencies.
- [ ] **Step 6: Wire `warden db <name> "<SQL>"`** through API retrieval and local execution; return driver/DB status without logging SQL or credentials.
- [ ] **Step 7: Run DB tests and Linux/Windows cross-builds.**

### Task 7: Cross-Platform Interactive `xssh`

**Files:**
- Create: `internal/client/terminal/terminal.go`
- Create: `internal/client/terminal/terminal_unix.go`
- Create: `internal/client/terminal/terminal_windows.go`
- Create: `internal/client/terminal/terminal_test.go`
- Create: `internal/client/ssh/interactive.go`
- Create: `internal/client/ssh/interactive_test.go`
- Modify: `cmd/warden/main.go`

**Interfaces:**
- `terminal.Session` exposes `EnterRaw`, `Restore`, `Size`, `ResizeEvents`, and `RunShell` primitives with platform implementations.
- `ssh.RunInteractive(ctx context.Context, bundle model.SSHBundle, term terminal.Session, acceptNew bool) error` requests remote PTY, starts optional `cd <default_dir>; exec $SHELL --login` safely as a remote command, copies terminal bytes, handles resize/signals, and closes all connections.

- [ ] **Step 1: Read current documentation for chosen Linux/Windows terminal packages** and record exact supported console/PTY APIs in `go.mod` and package comments.
- [ ] **Step 2: Write Linux and Windows-specific unit tests** for size detection, raw-mode restoration on error, Ctrl-C/Ctrl-D forwarding, resize event propagation, and cleanup.
- [ ] **Step 3: Implement Unix terminal handling** with raw mode, window-size ioctl, signal/resize notification, and deferred restoration.
- [ ] **Step 4: Implement Windows console handling** with console mode changes, input/output handles, resize events, and restoration on all exits.
- [ ] **Step 5: Implement interactive SSH PTY** using `ssh.Session.RequestPty`, `Setenv` only for nonsecret terminal metadata, stdin/stdout/stderr attachment, and remote shell lifecycle.
- [ ] **Step 6: Implement `warden xssh [name]`**; when name is omitted, fetch redacted profiles and provide a built-in searchable picker with no `fzf` dependency.
- [ ] **Step 7: Test native Linux interactive behavior manually and run Windows tests on a Windows runner**; verify terminal mode restoration after authentication, remote failure, Ctrl-C, and normal exit.

### Task 8: Reports, Projects, and CLI Changelog Commands

**Files:**
- Create: `internal/server/reports/handlers.go`
- Create: `internal/server/reports/handlers_test.go`
- Create: `internal/client/report/report.go`
- Create: `internal/client/report/report_test.go`
- Modify: `cmd/warden/main.go`

**Interfaces:**
- `POST /api/v1/projects` creates/gets stable project identifier.
- `POST /api/v1/reports` accepts `project`, `title`, `summary`, `agent_model`; server sets UTC `created_at`.
- `GET /api/v1/projects` and `GET /api/v1/projects/{name}/reports` list chronological entries.
- CLI command: `warden report create <project> --title ... --summary ... --agent-model ...`.

- [ ] **Step 1: Write handler tests** for exact required fields, arbitrary nonempty agent model, project/name limits, title/summary byte limits, server timestamp, append-only behavior, and safe errors.
- [ ] **Step 2: Write CLI tests** for flag parsing, missing values, API errors, and successful response output.
- [ ] **Step 3: Run tests and confirm failure.**
- [ ] **Step 4: Implement report/project handlers and repository calls** with strict decoding, UTC timestamps, parameterized SQL, and audit events that omit report contents if configured as sensitive.
- [ ] **Step 5: Implement API client report methods and CLI output** with no local persistence and nonzero failure status.
- [ ] **Step 6: Run report tests and full server/client package tests.**

### Task 9: Embedded Web Management UI

**Files:**
- Create: `internal/web/embed.go`
- Create: `internal/web/static/index.html`
- Create: `internal/web/static/app.js`
- Create: `internal/web/static/styles.css`
- Create: `internal/server/web.go`
- Create: `internal/server/web_test.go`

**Interfaces:**
- Root handler serves embedded static UI from `/` and delegates `/api/v1/...` to API handlers.
- UI uses only existing JSON API resources; no second backend or secret-bearing endpoint.

- [ ] **Step 1: Write route tests** for root asset serving, API/UI same listener, unknown route status, and cache headers.
- [ ] **Step 2: Implement minimal management UI** with connection list/redacted details, SSH/DB create/edit forms, dependent warning before delete, project report list, and audit list.
- [ ] **Step 3: Keep UI management-only**: no terminal, credential reveal, SQL execution, or remote command execution controls.
- [ ] **Step 4: Add responsive layout and explicit validation/error states** while keeping all actions API-backed.
- [ ] **Step 5: Run UI route tests and manually verify in browser through tailnet URL.**

### Task 10: Service Packaging, Documentation, and End-to-End Verification

**Files:**
- Create: `deploy/systemd/warden-server.service`
- Create: `deploy/systemd/README.md`
- Create: `scripts/test.sh`
- Create: `scripts/build-release.sh`
- Modify: `README.md`

**Interfaces:**
- Service runs `warden-server serve` as a dedicated Unix user with `DBPath` and `MasterKeyPath` configured outside the client.
- Release script outputs Linux server/client and Windows client x64 artifacts.

- [ ] **Step 1: Write end-to-end test script** that creates temporary key/DB, starts server on an ephemeral loopback port, invokes CLI API commands, and tears down with no leaked process.
- [ ] **Step 2: Implement systemd unit** with non-root user, restrictive state directory, `UMask=0077`, restart policy, and configured tailnet/loopback bind guidance; do not expose credentials through unit command arguments.
- [ ] **Step 3: Implement reproducible release builds** for `linux/amd64` server, `linux/amd64` client, and `windows/amd64` client; report checksums.
- [ ] **Step 4: Document key generation, permissions, SQLite backup plus separate key backup, API URL configuration, tailnet-only exposure, known-hosts behavior, CLI examples, and native Windows usage.**
- [ ] **Step 5: Run `go test ./...`, `go test -race ./...`, `go vet ./...`, build scripts, and end-to-end tests.**
- [ ] **Step 6: Verify with a clean temporary directory** that server startup rejects unsafe/missing key, normal reads redact secrets, transport retrieval works, deleted jump references fail at query time, reports persist, and no secret appears in captured logs/output.

## Execution Order and Review Gates

Execute Tasks 1-4 sequentially because all later work depends on stable models, storage, encryption, and API contracts. Tasks 5 and 6 can proceed after Task 4; Task 7 depends on the SSH bundle shape from Task 5. Task 8 can proceed after Task 4. Task 9 depends on API handlers from Tasks 4 and 8. Task 10 follows all feature tasks.

At each task boundary:

1. Run the task-specific tests and relevant full-package tests.
2. Inspect `git diff` or changed-file list when a repository exists; this workspace currently has no Git metadata, so do not claim commit evidence until a repository is initialized.
3. Check that no secrets, SQL, commands, or key material entered logs, fixtures, test output, or documentation.
4. Review API/domain type compatibility before starting the next task.

## Plan Self-Review

- **Spec coverage:** deployment/trust model is Task 10; binaries/config Task 1; encryption Task 2; SQLite/report/audit storage Task 3; API/redaction/query-time validation Task 4; SSH Task 5; MySQL and tunnels Task 6; xssh/PTY Task 7; reports Task 8; UI Task 9; testing/release/docs Task 10.
- **Placeholder scan:** no `TBD`, `TODO`, “implement later”, or unspecified “appropriate handling” steps remain. Library-specific terminal APIs are intentionally selected after reading current documentation in Task 7 before code is written.
- **Type consistency:** `model.SSHBundle` and `model.DBBundle` are introduced in Task 4 and consumed by Tasks 5-7; `api.Client` is introduced in Task 5 and extended by Tasks 6 and 8; repository method names are defined in Task 3 before handler use.
- **Scope check:** all approved MVP components remain in one implementation plan, but each task yields a separately testable deliverable with explicit interfaces.
