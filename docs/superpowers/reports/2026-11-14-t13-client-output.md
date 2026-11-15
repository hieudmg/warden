# T13 — API redirect characterizations and terminal-safe diagnostics/headers

## Authorization and status

Owner-authorized **T13 only**, sole writer in `/var/www/code/go/warden`, branch
`hieudmg/security-hardening`, baseline HEAD
`7c3adc055e35c92dc938b8628346a32023d20631`. The owner reports T12 review closed and
fresh parent full Go/race passing; the historical T12 report is not rewritten.
No children/worktrees, staging, commits, push, deployment, version/dependency
changes, real credentials/data, T14/T15, rsync or external DB/proxy TLS changes.
Protected unrelated `mise.toml` was not read or changed. Temporary files/logs use
private `/var/tmp/wt13/`; Go uses `TMPDIR=/var/tmp` with ordinary test umask.
No other artifacts were cleaned.

**Implemented and self-checked; independent T13 review remains pending.** This is
not security-release, genuine PRF/browser/production-trust or native Windows
acceptance. No frontend files changed or frontend retest claimed.

## Actual changes and retained boundaries

### Redirects: passing-existing characterizations, not a fabricated fix

T4 already uses `clienthttp.Client` to own standard HTTP transports, strip unsafe
TLS/protocol delegates, copy the injected client, remove browser cookies, and
refuse **every** API redirect before another request. Unknown RoundTrippers fail
closed. `api.NewAgent` explicitly installs the owned IPC transport; it must not
be treated as generic unverified network injection. No production transport,
origin/capability allowlist, path/query/encoded-path or credential policy changed.
No final-response URL check was added or represented as leak prevention.

Expanded `api/TestAPIRedirectPolicyBeforeCredentialSend` and new
`agent/TestAPIRedirectPolicyBeforeCredentialSend` cover 100 cases each:
301/302/303/307/308 × GET/POST × cross-host/cross-port/subdomain/HTTPS-to-HTTP/
same-origin × normal/injected clients. Each fixture has an actual HTTPS origin
and HTTPS second peer, plus an HTTP downgrade receiver. The API test exercises
`ListSSH`/`PostJSON`; the agent test exercises the actual credential producer
`agentHTTP`, including its bearer header and exact POST body. The normal agent
client comes from `apiHTTPClient` with a public test-CA file; the normal API client
comes from `New(..., nil)`, with only its **owned test transport** given trusted
roots and an ordinary TCP route. Injected clients use guarded standard transports.

The TCP dialer routes `example.com` and subdomain authorities to loopback ports;
it does not perform TLS itself or override ServerName. Ordinary TLS verifies the
request hostname with trusted test roots. Before each guarded request, a
**credential/body-free positive probe** proves the exact redirect target is
reachable with those roots/routes (including subdomain and downgrade targets).
Counters are then reset. The origin must receive the request and return the
expected redirect status; agent-origin assertions require the actual bearer,
POST payload and expected TLS SNI. The guarded request must produce **zero target
HTTP requests, authorization bytes and body bytes**, including same-origin
replays. This does not claim zero TCP/TLS connections across the preceding probes.

Caller `Transport`, TLS-config/root pointers and values, redirect callback
identity, timeout, cookie-jar identity/content remain unchanged; the callback is
never invoked by the guarded request. Agent per-command timeout copies preserve
the enrolled/shared client timeout. Existing verified-origin/TLS-delegate/unknown-
RoundTripper/capability tests remain in the package runs. New
`TestNewAgentPreservesOwnedIPCAndCommandTimeout` characterizes the explicit owned
IPC constructor. Existing `TestAgentAPIMemoryLifetimeAndBoundedStreams` checks
actual IPC API streaming and per-command timeout changes, unchanged. Initial HTTP
configuration rejection is also passing-existing coverage, **not new TDD**.

### Diagnostics: actual RED → GREEN

New portable `internal/client/terminal/text.go` is a **diagnostic-only** boundary:
`EscapeErrorText` and `ErrorText` escape ESC, OSC initiators, C0/C1, DEL, CR/LF,
other nonprintables and malformed UTF-8; printable Unicode remains intact.
ESC is `\x1b`, CR/LF/tab are `\r`/`\n`/`\t`, other BMP nonprintables use `\uNNNN`,
and each malformed byte becomes visible `\ufffd`. Printable backslashes are not
escaped again. No global stdout/stderr wrapper or stream filtering was added.

`MaxErrorBytes = 1024` is an **encoded UTF-8 byte** limit including escape
expansion. It reuses the existing API message-size literal rather than inventing
an 8-MiB terminal limit. Truncation has no suffix and emits only complete Unicode
runes/generated escape tokens. The fixed CLI command prefix/final newline are
outside the limit; `APIError.Error()` includes its own `api: ...` prefix inside
it. Existing HTTP/IPC response limits are unchanged (agent HTTP response 4 MiB,
API successful body 4 MiB, error-envelope read 64 KiB); these are not display
limits. Parsed message fields retain their existing 1,024-byte bound, now cut
without invalid UTF-8.

`APIError.Error()` sanitizes the **whole** formatted error, including the
server-controlled code. `Code`, `StatusCode` and `Message` remain structured data;
formatting does not mutate them, replace JSON formatting, or erase typed error
identity. Ordinary JSON encoding/round-trip is tested, including C1 data; it is
not a claim that arbitrary raw JSON is safe to display unencoded on a terminal.
The CLI has no new JSON/CSV output interface. Existing TSV delimiters remain.

Every error-value rendering site in `cmd/warden/main.go` and `auth.go` now uses
`terminal.ErrorText`, after any `errors.As`/status classification. Inspection
inventory: config failures; login/begin/poll/status/logout; SSH list/bundle/agent
failure; DB selector/list/bundle/direct/agent failure; xssh picker/terminal/bundle/
interactive failure; report creation; config search; cp operand/resolve/transfer
failure; port-watch parse/API/watch failure; upgrade failure text only; agent
runtime/listen/token/serve failure. Usage/static strings and `%q` local names are
not raw server errors. Flag parsing handles local argv, not API-response text.
No updater/installer/network-policy work is hidden in diagnostic formatting.
No audit logging or raw-error persistence was added.

Generic relay errors are escaped only when rendered. Tests cover actual framed
agent relay diagnostics, byte streams and `ExitStatusError` classification;
CLI seams cover final relay errors and wrapped typed statuses. The original
error chain remains available for classification. This is **not broader secret
redaction**; existing DB password scrubbing and audit classifications remain.

### DB headers: table fix, existing TSV characterization

`writeTable` now copies column names and applies the existing `sanitizeCell`
before width measurement/output, as `writeTSVRow` already did. C0/C1/DEL and
multiline/tab controls become spaces; printable Unicode, existing byte-based
table widths and TSV separator tabs/record newlines remain unchanged. No new
header length truncation or pretty-printing redesign was added.

`TestDBHeadersSanitizedInTableAndTSV` uses the real synthetic MySQL producer:
`newFakeMySQLServer` → Protocol::ColumnDefinition41 **name** field → pinned
`go-sql-driver/mysql` parser → `database/sql.Rows.Columns` → normal query renderer.
It is not a manual mirror of the consumer. Table mode failed before the fix;
TSV mode already passed and was retained as a characterization. Tests require
exact TSV structure and printable `名`, `héllo世界`, `値` preservation.

API evidence: installed `github.com/go-sql-driver/mysql v1.10.0` `packets.go`
`readColumns` reads the fifth length-encoded string as `name`, and `rows.go`
`Columns` returns it unchanged with the current config. Existing producer
`testserver_test.go:columnDef` writes that exact field. Context7 could not resolve
the exact driver (only different libraries); no substitute driver API was used.
Official MySQL ColumnDefinition41 documentation was retrieved as
`ctx7:docs:83fc558f60cf5c9d0bbb4018`, confirming `name`/`org_name` field order and
length-encoded strings. No new third-party calls/imports or dependency changes.

### Stream preservation

SSH exec and interactive stdout/stderr are intentionally **not sanitized**.
CLI tests require exact NUL/invalid-UTF-8/ESC/OSC/CRLF/C1 stream bytes and wrapped
remote exit status 23. The xssh test passes the original terminal session through
unchanged. A real framed relay test checks both raw output streams and typed
final status/error handling; existing real SSH/PTY tests ran in full Go/race.
SFTP/binary transfer code is untouched and existing transfer tests ran normally
and under race. These are not claims about filtering arbitrary remote streams:
remote SSH output can intentionally control the terminal.

## Chronology and exact validation

All Go commands below use `TMPDIR=/var/tmp`, Go **go1.25.14 linux/amd64**.
Logs are in `/var/tmp/wt13/`. No historical T12 failure was silently waived.

1. Before production changes:
   - `go test ./internal/client/api -run '^TestAPIErrorTerminalControlsEscaped$' -count=1`
     **RED**, `api-red.log`: raw ESC/C1 in rendered errors, raw code/invalid UTF-8,
     and existing 1,024-byte slicing splitting Unicode. Initial assertions also
     attempted to require sanitized structured Message fields; those were
     narrowed to the approved presentation boundary to preserve machine meaning.
     The rendered-error and UTF-8 truncation failures remain genuine RED evidence.
   - `go test ./internal/client/db -run '^TestDBHeadersSanitizedInTableAndTSV$' -count=1`
     **RED**, `db-red.log`: raw hostile table headers; TSV already passing.
   - `go test ./cmd/warden -run '^TestCLIError' -count=1`
     **RED**, `cli-red.log`: login relay error reached stderr with malformed UTF-8
     and raw controls. An earlier setup attempt used the fixture's HTTP default;
     corrected to explicit HTTPS **before production edits**, then observed the
     intended diagnostic failure. Byte/status preservation already passed.
2. Minimal fixes followed those failures. The matching output set passed:
   `go test ./internal/client/api ./internal/client/db ./internal/client/terminal ./cmd/warden -run 'Test(APIErrorTerminalControlsEscaped|DBHeadersSanitizedInTableAndTSV|EscapeErrorTextEncodedByteLimit|CLIError)' -count=1`
   (`output-green.log`). Unit encoded-byte/token edges are supplemental coverage
   of the same already-RED behavior, not a separate fabricated missing-API RED.
3. Expanded redirect suite first ran **GREEN unchanged production policy**:
   `go test ./internal/client/api ./internal/client/agent -run '^TestAPIRedirectPolicyBeforeCredentialSend$' -count=1`
   (`redirect-characterization.log`). No new redirect production fix is claimed.
4. Help expectations were added before help edits:
   `go test ./cmd/warden -run '^TestClientHelpGuidesConsumers$' -count=1`
   **RED**, `help-red.log`, missing encoded-byte/stream/header documentation.
   After help edits, help+CLI checks passed (`help-cli-green.log`). Report/runbook/
   plan/ledger prose uses the documentation-only TDD exception and link/diff checks.
5. Final-assertion sensitivity check, **not a replacement for pre-edit RED**:
   `go test -overlay /var/tmp/wt13/api-baseline-overlay.json ./internal/client/api -run '^TestAPIErrorTerminalControlsEscaped$' -count=1`
   expected **FAIL**, `final-api-baseline-sensitivity.log`. Overlay uses the exact
   HEAD API source without changing checkout files; final presentation/UTF-8
   assertions still detect the old implementation.

### Final current-source commands — all PASS

- `go test ./... -count=1 -timeout=180s` — `final-full-go.log`.
- `go test -race ./... -count=1 -timeout=180s` — `final-full-race.log`.
- `go test ./internal/client/api ./internal/client/clienthttp ./internal/config ./cmd/warden ./internal/client/db ./internal/client/terminal ./internal/client/agent -count=1 -timeout=180s`
  — `final-focused.log`.
- `go vet ./...` — `final-vet.log`.
- `go test -race ./internal/client/api ./internal/client/agent -run '^TestAPIRedirectPolicyBeforeCredentialSend$' -count=10 -timeout=180s`
  — `final-redirect-race10.log` (2,000 matrix cases total).
- `go test -race ./internal/client/api ./internal/client/db ./internal/client/terminal ./internal/client/agent ./cmd/warden -run 'Test(APIErrorTerminalControlsEscaped|DBHeadersSanitizedInTableAndTSV|EscapeErrorTextEncodedByteLimit|CLIError|AgentRelayTerminalBoundary|NewAgentPreserves)' -count=25 -timeout=180s`
  — `final-output-race25.log`.
- `GOOS=windows GOARCH=amd64 go test -c -o /var/tmp/wt13/win-<package>.test.exe <package>`
  for API/clienthttp/DB/terminal/agent/config/CLI, then Windows `go build ./...`
  — `final-windows-cross.log`, **COMPILE ONLY**, no native execution proof.

No new unexplained test failures remain in these T13 checks. Historical/native/
genuine-PRF and production-browser/trust acceptance, and known dependency work,
are not resolved by these results.

## Review delivery and stop boundary

Changed-path inventory and per-file hashes:
`/var/tmp/warden-t13-review-manifest.json`. Exact review delta:
`/var/tmp/warden-t13-review.diff`. These are explicit-allowlist artifacts, with
tracked changes against HEAD and every known new task file included; no staging.
The ignored pre-existing ledger uses its saved pre-T13 baseline for a T13-only
delta, explicitly identified in the manifest (it does not exist in HEAD).
Protected `mise.toml` is excluded before content access.

Self-review covers all production rendering sites, complete new tests, retained
TLS/capability/IPC ownership and timeout behavior, DB producer/consumer field
order, raw stream/status preservation, encoded-byte/truncation behavior, final
commands and documentation consistency. Final formatting/whitespace/local links,
unchanged branch/HEAD and empty staged diff are checked before artifact creation.
No remaining concrete T13 finding identified by this self-review. Independent
review remains required; stop here, without T14, staging, commits or publication.
