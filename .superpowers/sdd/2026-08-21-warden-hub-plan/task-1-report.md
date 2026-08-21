# Task 1 Report: Bootstrap Module, Targets, and Configuration

## Scope completed
- Established Go module and Task 1 file layout.
- Added separate server/client bootstrap entrypoints.
- Implemented strict JSON config loading with defaults and env overrides.
- Added config tests first, validated initial failure before module existed, then reran green.
- Added bootstrap README and Makefile.

## Changed files
- `go.mod`
- `cmd/warden-server/main.go`
- `cmd/warden/main.go`
- `internal/config/config.go`
- `internal/config/config_test.go`
- `README.md`
- `Makefile`
- `.superpowers/sdd/2026-08-21-warden-hub-plan/task-1-report.md`

## Commands run and outputs

### 1) TDD failure before module existed
Command:
```bash
go test ./internal/config
```
Output:
```text
go: cannot find main module, but found .git/config in /var/www/code/go/warden
	to create a module there, run:
	go mod init

Command exited with code 1
```

### 2) Config package tests after implementation
Command:
```bash
go test ./internal/config
```
Output:
```text
ok  	warden/internal/config	0.002s
```

### 3) Full test suite
Command:
```bash
go test ./...
```
Output:
```text
?   	warden/cmd/warden	[no test files]
?   	warden/cmd/warden-server	[no test files]
ok  	warden/internal/config	(cached)
```

### 4) Vet
Command:
```bash
go vet ./...
```
Output:
```text
(no output)
```

### 5) Linux builds
Command:
```bash
go build ./cmd/warden-server
```
Output:
```text
(no output)
```

Command:
```bash
go build ./cmd/warden
```
Output:
```text
(no output)
```

### 6) Windows client cross-build
Command:
```bash
GOOS=windows GOARCH=amd64 go build ./cmd/warden
```
Output:
```text
(no output)
```

### 7) Help dispatch and invalid-config exit behavior
Command:
```bash
go run ./cmd/warden-server --help
```
Output:
```text
Usage:
  warden-server serve [--config path]
  warden-server --help

Environment overrides:
  WARDEN_SERVER_CONFIG
  WARDEN_SERVER_LISTEN_ADDR
  WARDEN_SERVER_DB_PATH
  WARDEN_SERVER_MASTER_KEY_PATH
  WARDEN_SERVER_STATIC_FS
```

Command:
```bash
go run ./cmd/warden --help
```
Output:
```text
Usage:
  warden [--config path] ssh <connection> <command>
  warden [--config path] db <connection> <sql>
  warden [--config path] xssh [connection]
  warden [--config path] report create <project> --title <title> --summary <summary> --agent-model <name>
  warden [--config path] config list
  warden [--config path] config get <connection>
  warden --help

Environment overrides:
  WARDEN_CLIENT_CONFIG
  WARDEN_CLIENT_API_BASE_URL
  WARDEN_CLIENT_TIMEOUT
```

Command:
```bash
go run ./cmd/warden-server serve --config "$tmpdir/server.json"
```
Output:
```text
invalid server config: invalid listen address "localhost": address localhost: missing port in address
exit status 1
```
Observed shell exit:
```text
exit=1
```

Command:
```bash
go run ./cmd/warden --config "$tmpdir/client.json" config list
```
Output:
```text
invalid client config: invalid api base url "://bad": parse "://bad": missing protocol scheme
exit status 1
```
Observed shell exit:
```text
exit=1
```

## Commit
- `d987555324f7e918055af203e4c826c293b5d48e` - `Bootstrap Warden Hub config and entrypoints`

## Post-commit status
Command:
```bash
git status --short --branch
```
Output:
```text
## feature/warden-hub
```

## Decisions
- Used module path `warden`. No approved external repository path existed; local module path keeps Task 1 imports stable without guessing publication target.
- Server defaults:
  - `ListenAddr`: `127.0.0.1:8080`
  - `DBPath`: `/var/lib/warden/warden.db`
  - `MasterKeyPath`: `/etc/warden/master.key`
  - `StaticFS`: empty string
- Client defaults:
  - `APIBaseURL`: `http://127.0.0.1:8080`
  - `Timeout`: `30s`
- Precedence order: defaults < config file < environment overrides.
- Config files are strict JSON objects with unknown fields rejected.
- Client config stays limited to API settings only. No server DB path or master-key settings enter client config struct or entrypoint.
- Entry points stay bootstrap-only in Task 1: they validate config, parse subcommands/help, and avoid implementing HTTP, SQLite, crypto, SSH, DB, UI, or reports.
- Left existing `.gitignore` unchanged per task instruction.

## Concerns / residual risks
- Command handlers are intentionally stubs until later tasks wire real API, server, and transport behavior.
- Windows client cross-build passes, but no native Windows runtime or PTY behavior is claimed yet.
- Running raw `go build ./cmd/...` from repo root creates local binaries in repo root; those artifacts were removed after validation to keep workspace clean.

---

## Task 1 Fix Round 1: config-path rejection and help dispatch

### Scope completed
- Rejected blank `WARDEN_SERVER_CONFIG` and `WARDEN_CLIENT_CONFIG` values before any config-file read.
- Rejected explicit empty `--config=` values for both binaries.
- Added command-specific `--help` dispatch for `ssh`, `db`, `xssh`, `config list`, and `config get` before arity/config validation.
- Added regression coverage for config-path rejection and command help/config-flag behavior.

### Changed files
- `internal/config/config.go`
- `internal/config/config_test.go`
- `cmd/warden/main.go`
- `cmd/warden/main_test.go`
- `cmd/warden-server/main.go`
- `cmd/warden-server/main_test.go`
- `.superpowers/sdd/2026-08-21-warden-hub-plan/task-1-report.md`

### Commands run and outputs

#### 1) Regression tests before fix
Command:
```bash
go test ./internal/config ./cmd/warden ./cmd/warden-server
```
Output:
```text
--- FAIL: TestReadConfigFileRejectsEmptyRequiredPath (0.00s)
    config_test.go:200: readConfigFile() error = nil, want error
--- FAIL: TestLoadServerRejectsEmptyConfigPathEnvBeforeRead (0.00s)
    config_test.go:156: LoadServer() error = nil, want error
--- FAIL: TestLoadClientRejectsEmptyConfigPathEnvBeforeRead (0.00s)
    config_test.go:181: LoadClient() error = nil, want error
FAIL
FAIL	warden/internal/config	0.002s
--- FAIL: TestRunRejectsEmptyExplicitConfigFlag (0.00s)
    main_test.go:76: run() exitCode = 0, want 1, stdout="client bootstrap ready for ssh via http://127.0.0.1:8080\n" stderr=""
--- FAIL: TestRunHelpCommandsSkipArgAndConfigValidation (0.00s)
    --- FAIL: TestRunHelpCommandsSkipArgAndConfigValidation/ssh (0.00s)
        main_test.go:57: run([ssh --help]) exitCode = 2, want 0, stderr="usage: warden ssh <connection> <command>\n"
    --- FAIL: TestRunHelpCommandsSkipArgAndConfigValidation/config_get (0.00s)
        main_test.go:57: run([config get --help]) exitCode = 1, want 0, stderr="invalid client config: read config \"not-a-duration\": open not-a-duration: no such file or directory\n"
    --- FAIL: TestRunHelpCommandsSkipArgAndConfigValidation/config_list (0.00s)
        main_test.go:57: run([config list --help]) exitCode = 2, want 0, stderr="usage: warden config list\n"
    --- FAIL: TestRunHelpCommandsSkipArgAndConfigValidation/db (0.00s)
        main_test.go:57: run([db --help]) exitCode = 2, want 0, stderr="usage: warden db <connection> <sql>\n"
    --- FAIL: TestRunHelpCommandsSkipArgAndConfigValidation/xssh (0.00s)
        main_test.go:57: run([xssh --help]) exitCode = 1, want 0, stderr="invalid client config: read config \"not-a-duration\": open not-a-duration: no such file or directory\n"
FAIL
FAIL	warden/cmd/warden	0.002s
--- FAIL: TestRunServeRejectsEmptyExplicitConfigFlag (0.00s)
    main_test.go:16: run() exitCode = 0, want 1, stdout="server bootstrap ready on 127.0.0.1:8080 (db=/var/lib/warden/warden.db static_fs=)\n" stderr=""
FAIL
FAIL	warden/cmd/warden-server	0.002s
FAIL

Command exited with code 1
```

#### 2) Regression tests after fix
Command:
```bash
go test ./internal/config ./cmd/warden ./cmd/warden-server
```
Output:
```text
ok  	warden/internal/config	(cached)
ok  	warden/cmd/warden	0.002s
ok  	warden/cmd/warden-server	(cached)
```

#### 3) Full test suite
Command:
```bash
go test ./...
```
Output:
```text
ok  	warden/cmd/warden	(cached)
ok  	warden/cmd/warden-server	(cached)
ok  	warden/internal/config	(cached)
```

#### 4) Vet
Command:
```bash
go vet ./...
```
Output:
```text
(no output)
```

#### 5) Build
Command:
```bash
go build ./...
```
Output:
```text
(no output)
```

### Residual risks
- `config get --help` now prefers help output over treating `--help` as connection name; plain `help` still remains valid as positional data where command arity requires more arguments.
- Command bodies remain bootstrap stubs until later tasks add real transport behavior.
