# T14 — bounded HTTPS upgrades and state-preserving installers

## Status and authority

Bounded implementation and implementer self-check on `hieudmg/security-hardening`,
baseline HEAD `d6c437dabc25a26f5ed3b3b360f799cc1ef6f496`. **Not independent
acceptance, native Windows acceptance, or a security-release certification.**
Only T14 was authorized. T15 has not started.

The owner's policies remain unchanged: mutable same-version releases are
intentional; self-upgrade replaces only the executable, including service-managed
installations; the operator performs the restart/cutover. No service-managed
upgrade prohibition, forced stop/restart, automatic initialization, automatic
migration, key fallback, or new public origin was introduced.

Sole writer; no child agents, worktrees, staging, commits, push, deployment,
installed-binary upgrade, real installer execution, live data migration, service
commands, elevation, version bump, dependency change, or global trust mutation.
Protected unrelated `mise.toml` was excluded from content inspection and changes.
Commands used `TMPDIR=/var/tmp`; private evidence is under `/var/tmp/wt14` because
`/tmp` quota is exhausted. These temporary logs are not durable repository files.

References: [binding design](../specs/2026-11-14-security-hardening-design.md),
[T14 plan](../plans/2026-11-14-security-hardening.md#t14-upgradesinstallers-enforce-https-bounds-while-preserving-state-and-service-behavior),
[T1 initialization](2026-11-14-t1-initialization.md),
[T5 transfer preservation](2026-11-14-t5-transfer-preservation.md),
[T13 network/output boundary](2026-11-14-t13-client-output.md), and the chronological
ignored ledger `.superpowers/sdd/2026-11-14-security-hardening-7c97840ce693/ledger.md`.

## API/source preflight

The implementation consulted installed Go 1.25.14 official
`src/net/http/{client,transport}.go` for redirect ordering, request context,
transport cloning/configuration, TLS and timeout behavior, and existing T4 owned
transport code without importing its one-origin API policy. Native ACL calls
were checked against exact installed `golang.org/x/sys@v0.47.0/windows/` security
and syscall source and the existing T11 private-staging pattern; no dependency
version changed.

curl options were checked using its official documentation and the installed
`curl --manual` (`/var/tmp/wt14/curl-manual.txt`): `--disable` first,
`--proto '=https'`, `--proto-redir '=https'`, connect/max-time/max-filesize and
redirect behavior. `--retry-max-time` alone is not a hard shared outer deadline;
the monotonic supervisor owns that deadline instead.

Microsoft references consulted include Windows PowerShell 5.1
[Add-Type](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/add-type?view=powershell-5.1),
.NET Framework 4.7.2
[HttpClientHandler](https://learn.microsoft.com/en-us/dotnet/api/system.net.http.httpclienthandler?view=netframework-4.7.2),
[ResponseHeadersRead](https://learn.microsoft.com/en-us/dotnet/api/system.net.http.httpcompletionoption?view=netframework-4.7.2),
[Stream.ReadAsync](https://learn.microsoft.com/en-us/dotnet/api/system.io.stream.readasync?view=netframework-4.7.2),
[FileStream ACL-aware creation](https://learn.microsoft.com/en-us/dotnet/api/system.io.filestream.-ctor?view=netframework-4.7.2),
[Directory ACL-aware creation](https://learn.microsoft.com/en-us/dotnet/api/system.io.directory.createdirectory?view=netframework-4.7.2),
[File.Replace](https://learn.microsoft.com/en-us/dotnet/api/system.io.file.replace?view=netframework-4.7.2),
[AggregateException](https://learn.microsoft.com/en-us/dotnet/api/system.aggregateexception.-ctor?view=netframework-4.7.2),
and Microsoft's reference source for HttpClientHandler certificate callback
ownership. Context7 was consulted where available; installed source/official
Microsoft documentation supplied the needed version-specific detail. API
availability from documentation is not native C# compilation/runtime evidence.

## Implementation

### Go updater

- `internal/upgrade/http.go` owns a fresh standard HTTP transport. Initial and
  redirect URLs require HTTPS, a hostname, and no userinfo/fragment. Verified
  cross-host CDN redirects are permitted; T13's credential-bearing API refusal
  policy is deliberately **not** reused here.
- Caller configuration can supply public trust roots and ordinary TCP/proxy
  routing, not `InsecureSkipVerify`, TLS dialers, `ServerName`, ALPN/protocol
  delegates, arbitrary RoundTrippers, redirect callbacks, or cookie jars. Caller
  configuration is not mutated. Go TLS minimum is 1.3; standard HTTP/2 works.
- Complete connection establishment (TCP, proxy TLS, CONNECT, origin TLS and
  protocol setup) has one 10-second bound, enforced by an owned raw-socket abort
  timer until `GotConn`. Origin headers retain their 10-second bound. One
  5-minute context covers both
  downloads, redirects and standard transport retries; an earlier caller context
  wins. Byte admission is 256 MiB binary / 1 MiB checksum, counted while reading
  with a one-byte overflow probe, independent of Content-Length.
- The inspected publisher runs `sha256sum` over release assets and produces
  SHA256SUMS filename entries. Verification accepts exact asset names with
  optional `./` and the standard text/binary marker. It requires a 64-hex SHA-256
  digest and exactly one matching entry; malformed, ambiguous/duplicate,
  wrong-algorithm, missing and mismatching entries fail before replacement.
- The target must be a regular file, not a symlink. Identity is rechecked before
  replacement. Unix retains rename-based atomic replacement. Native Windows
  staging uses exclusive creation with a protected owner-only DACL, validated
  on the opened handle before payload bytes; no POSIX-mode privacy fallback.
- The Windows detached encoded helper now calls `File.Replace`, not `Move-Item`.
  It waits for the parent and retries locked-target replacement; exhaustion
  removes the owned verified stage and preserves the original. A successful
  launch is still reported as **scheduled**, not completed. The updater never
  opens config, DB/WAL/SHM, legacy key or service files. T1 runtime key policy and
  the retained descriptor-validating utility are unchanged; no T17 dead-code work.

### Standalone shell installers

- Bash + Python 3 + curl are now explicit prerequisites. The identical embedded
  Python drivers are narrow supervisors for the standalone scripts, not a new
  shared installation framework or product configuration surface.
- curl starts with `--disable`, restricts initial/redirect protocols to HTTPS,
  has a 10-second connection bound and a remaining-operation `--max-time`, and
  never follows redirects itself. Each Location is resolved and checked **before**
  the next request. A monotonic outer deadline covers both streams and all hops.
  curl is supervised and joined; signal/error cleanup owns only successfully
  created private files. There are no automatic transfer retries: rerun explicitly.
- Streams are counted in the driver; curl's additional max-filesize guard uses
  `limit+1` so an exact-limit chunked stream remains admissible. No certificate
  bypass is used. Destination stages are private/exclusive and published by
  rename only after complete checksum verification; symlink binary targets fail.
- Client configuration requires an explicit HTTPS origin for fresh installation.
  Existing timeout, CA path and other JSON settings survive endpoint selection.
  Both destination stages are prepared before publication. Private same-directory
  hard-link snapshots let a reported config publication failure roll back the
  binary; a failed fresh publication removes the newly installed binary. Signal
  cleanup uses inode identity rather than deleting arbitrary stage-name matches.
- Server publication now prepares both files before rename, retains a private
  original-binary hard-link snapshot, and rolls back on absent-unit publication
  failure. Exclusive `ln -T` does not overwrite or traverse competing units,
  including directory/symlink collisions. Rollback failure retains private
  recovery staging and reports its path; missing Python 3 fails before downloads
  or target publication.
- Server installation asks only for the directory. It never generates/reads
  `master.key`, writes server config, initializes storage, executes downloaded
  code, or runs service/setup commands. Existing initialized/legacy config,
  DB/WAL/SHM, key, modes and custom unit stay untouched. A hardened user unit is
  created only if absent. Output explains manual `init --config`, HTTPS/RP/TLS,
  recovery and old-release export → separate fresh init/import/verification →
  owner-managed cutover, plus user/system manual restart commands.

### Windows PowerShell installer — implementation, native evidence pending

- Supported target is **Windows PowerShell 5.1 / .NET Framework 4.7.2+**;
  PowerShell Core is explicitly rejected. No PowerShell/.NET runtime was installed.
- Embedded C# owns `HttpClientHandler`, disables automatic redirects/cookies,
  uses verified TLS 1.2 with revocation checks and strict `SslPolicyErrors.None`,
  and cannot inherit a permissive hosting-process certificate callback.
- Manual HTTPS redirects, `ResponseHeadersRead`, bounded streaming, linked
  header deadlines and one operation cancellation source replace unbounded
  downloads. Cancellation disposes active streams and async operations are
  awaited/joined, not abandoned as fire-and-forget workers.
- Directory/file ACLs are supplied at creation and validated before payload;
  exclusive stages and `File.Replace` publication preserve collision safety.
  Binary and config stages are prepared together; config publication errors
  roll back prior binary publication with private backups. User-scope PATH and
  environment behavior is retained.
- Linux source assertions and Windows Go cross-compilation **do not compile or
  execute this embedded C#**. Native compilation, ACL, cancellation, rollback,
  platform-trust HTTPS and actual installer/user-environment behavior remain
  required before acceptance.

### Deployment guidance

`README.md`, `docs/deployment.md`, and `deploy/systemd/README.md` now describe
manual fresh initialization, authenticated HTTPS, locked restarts and retained
legacy rollback artifacts, not generated disk vault keys or guessed HTTP hosts.
The reference unit explicitly passes `/etc/warden/server.json` and allows writes
to `/var/lib/warden`, retaining `UMask`, `NoNewPrivileges`, `ProtectSystem` and
scope/permission guidance. No daemon was started or reloaded. These documents
label the branch implementation, not an already published/accepted release.

## RED, GREEN and characterization evidence

### Actual focused RED before the corresponding fix

All commands below used `TMPDIR=/var/tmp`. Log names are relative to
`/var/tmp/wt14`.

| Regression / command | Actual RED evidence | GREEN |
| --- | --- | --- |
| `go test ./internal/upgrade -run 'TestUpgradeHTTPSRedirectAndTransportPolicy\|TestUpgradeChecksumExactEntry\|TestFetchChecksumRejectsMultipleMatchingEntries\|TestUpgradeRejectsSymlinkExecutable' -count=1` | `go-policy-corrected-red.log`: HTTP/downgrade requests, caller redirect callback, untrusted TLS acceptance, unsafe delegate invocation, malformed/ambiguous checksum and symlink behavior | Whole upgrade suite; final normal/race and repeated race below |
| `go test ./internal/upgrade -run TestUpgradeStreamLimitsTimeoutChecksumAndRollback -count=1` | `go-stream-corrected-red.log`: limit+1 binary/checksum, slow body and shared deadline were accepted | `go-first-green.log`, then final suites |
| `bash scripts/test-installers.sh` | `installers-red.log`: old curl invocation lacked owned config/protocol/time/size policy; `client-origin-red.log`: insecure/invalid endpoint accepted; `unit-static-red.log`: missing reference-unit declaration | `installers-final.log` |
| `python3 scripts/installers_test.py InstallerHTTPS.test_stage_collision_is_never_cleaned_as_owned` | `shell-collision-red.log`: both drivers deleted a file they never exclusively created | `network-final.log` |
| `go test ./internal/upgrade -run TestWindowsHelperWaitsAndRetriesMove -count=1` (historical test name) | `helper-static-red.log`: encoded helper still used Move-Item and lacked File.Replace | Final test renamed `TestWindowsHelperWaitsAndRetriesReplace`; normal/race pass; **source contract only** |
| `bash scripts/test-installers.sh` during self-review | `client-config-red.log`: `KeyError: ca_certificate`, proving settings dropped; `client-publication-red.log`: binary changed despite config publication failure; `client-authority-red.log`: empty host/invalid port authority accepted | Updated fixtures pass for existing and fresh installations, preserve original bytes, and leave no owned publication stages |

**TDD chronology correction:** streaming caps and the operation context were
initially coupled into the policy edit before stream tests existed. Those
portions were withdrawn, then the corrected stream test demonstrated actual RED
against unbounded copy/read/no operation context before reimplementation. This
is **not** claimed as pristine test-first chronology. The initial policy CDN
fixture also used a hostname absent from its certificate; it was corrected to a
certificate-valid CDN hostname and rerun before the policy implementation.

Other fixture corrections are not product security findings: a sorted shared
name slice, overwrite of a deliberately read-only fixture, extractor handling of
the background heredoc, and invalid TLS EOF framing. The corrected network
fixture uses valid chunked framing and a trusted disposable CA, never `-k`.
A missing-helper cross-compile failure is not native Windows behavioral RED.
Documentation/service declarations use static fixtures and prose review, not
fabricated runtime RED.

### Coverage and passing-existing characterization

- Go verified-HTTPS fixtures positively reach each permitted endpoint. The final
  matrix covers 301/302/303/307/308 CDN and downgrade paths; HTTP receivers get
  zero requests. Unsafe TLS/ALPN/registered protocol delegates cannot run;
  injected hostname overrides cannot authenticate the wrong host. A genuine
  standard HTTP/2 peer succeeds.
- Go stream tests cover exact limit and limit+1, absent Content-Length, truncated
  binary/checksum, bad digest, slow headers/body, shared and redirect deadlines,
  cancellation, replacement failure, private stage mode, original executable
  and adjacent config/DB/WAL/SHM/key/service bytes/modes, and cleanup.
  `http_test.go` additionally exercises a held TCP context and an actual stalled
  TLS handshake with short internal test budgets. New expansions that passed
  immediately are characterization/coverage, not newly claimed RED.
- Offline shell fixtures use controlled PATH wrappers for curl/id/mv and forbid
  sudo/systemctl/sysctl/tailscale/openssl/dd. Downloaded marker binaries are
  **never executed**. They inspect curl flags, checksum refusal, initialized and
  legacy preservation, root refusal, unit hardening, settings preservation,
  publication rollback, private files, and cleanup. The interruption test proves
  a blocked curl child is terminated/joined and originals remain unchanged; it
  passed newly implemented behavior initially and is **characterization**, not RED.
- `scripts/installers_test.py` extracts the **exact embedded drivers** and runs
  actual curl against disposable verified TLS fixtures with test-only trust.
  Matrices cover limits/chunking, checksum failures, slow/shared deadlines, HTTPS
  CDN, initial/downgraded HTTP and untrusted HTTPS refusal, and collision ownership.
  Its PowerShell assertions are explicitly static source contracts only.
- Native-only Go test sources cover Windows private creation/collisions, actual
  encoded helper replacement/locked-target cleanup, and PowerShell C# compilation,
  private files, HTTP/untrusted HTTPS refusal and config-failure rollback. They
  were cross-compiled only, not executed.

## Initial checkpoint validation (before independent P1 review)

These are the initial checkpoint results, not proof against the subsequently
reported P1 cases. The follow-up section below records current-source checks.

Actual local toolchain: Go 1.25.14 Linux/amd64, Python 3.12.15, curl 8.18.0
with OpenSSL 3.5.5. All commands use `TMPDIR=/var/tmp`; Python tests also set
`PYTHONDONTWRITEBYTECODE=1`.

| Check | Result / evidence |
| --- | --- |
| `go test ./... -count=1 -timeout=180s` | PASS all packages, including SFTP; `final-full-go.log` |
| `go test -race ./... -count=1 -timeout=180s` | PASS all packages; `final-full-race.log` |
| `go test ./internal/upgrade ./cmd/warden ./cmd/warden-server -count=1 -timeout=180s` | PASS; `focused.log` |
| Same focused command with `-race` | PASS; `focused-race.log` |
| `go test -race ./internal/upgrade -count=10 -timeout=90s` | PASS; `upgrade-race10.log` |
| `go vet ./...` | PASS; `final-vet.log` |
| `GOOS=windows GOARCH=amd64 go test -c -o /var/tmp/wt14/windows-upgrade.test.exe ./internal/upgrade` and `GOOS=windows GOARCH=amd64 go build ./...` | PASS **compile only**; `final-windows-cross.log` |
| `bash -n scripts/install-client.sh scripts/install-server.sh scripts/test-installers.sh` | PASS |
| `bash scripts/test-installers.sh` | PASS; `installers-final.log`; offline wrappers, not real curl network proof |
| `python3 scripts/installers_test.py` | PASS, four methods containing scenario matrices; `network-final.log`; actual curl network proof for embedded shell drivers |
| ShellCheck | Not installed; not run or claimed |

No frontend code changed; no frontend tests/build/browser retest claimed. No
native Windows, genuine PRF/production trust, live setup/migration, published
artifact, workflow execution or vulnerability-remediation acceptance is inferred
from these checks. Historical pre-T14 SFTP failure is not the current full-suite
result. Known dependency advisories remain separate T15 work.

## Initial self-review, artifacts and remaining limits

Self-review checks initial and redirect HTTPS admission before bytes, fresh
transport ownership, one deadline/stream counting, exact checksums before
replacement, private staging/collision ownership, failure preservation, helper
scheduling, config settings/rollback and nonexecution of service/setup commands.
Final task-only whitespace/newline/gofmt/local-link and inventory checks are
recorded in the ledger. Owned Python bytecode residue was removed; unrelated
artifacts were not cleaned.

Review deliverables, without staging:

- `/var/tmp/warden-t14-review.diff`: explicit allowlisted tracked baseline delta,
  full new untracked T14 files, and **only** the appended T14 ignored-ledger delta.
- `/var/tmp/warden-t14-review-manifest.json`: changed paths and SHA-256 hashes,
  baseline HEAD, ignored-ledger baseline provenance and review diff hash.
- Ignored-ledger baseline: `/var/tmp/wt14/ledger.before`; prior task history is
  unchanged and is not represented as new T14 work.

**Required/pending:** independent review and native Windows PowerShell 5.1 /
.NET Framework 4.7.2+ execution (C# compilation, explicit loaded HttpClient assembly reference, platform-trusted
HTTPS positive path and permissive-host certificate-hook isolation,
redirects/bounds/timeouts/cancellation, ACL-before-write, collision/locked
replacement/rollback/cleanup, updater encoded-helper execution and full
user-scope installer environment behavior). Linux/cross-build results do not
waive these checks. Per-file atomic rename/replacement and error rollback are
not a multi-file power-loss transaction or race-proof containment against a
same-user/privileged process replacing installation ancestors. If filesystem
permissions/I/O prevent rollback, private recovery staging is retained and the
failure is surfaced rather than deleting the old backup.

Same-release SHA-256 over verified HTTPS is integrity checking, not independent
signer/provenance or anti-rollback proof. Mutable release policy stays intentional.
No version/dependency/publication work was performed. Stop at this bounded T14
self-review; do not start T15 or perform real upgrade/deployment/cutover.

## Independent-review P1 follow-up — superseding implementation checkpoint

The owner authorized only the two reviewed P1 fixes at the same HEAD. The
initial full-suite passes above did **not** establish the missing behaviors.
No staging, commits, deployment, version/dependency changes, protected unrelated
file inspection, T15 work or real upgrade/installer/service effects were added.
Evidence below is under private `/var/tmp/wt14/p1`, with `TMPDIR=/var/tmp`.
Native Windows remains required/unavailable; this is not full T14 acceptance.

### P1a: bound the complete proxy/tunnel establishment

**Verified cause:** the old 10-second context only covered the TCP dial and was
canceled when the dial returned. Go 1.25.14's `net/http/transport.go:1855–1882`
uses a separate one-minute CONNECT write/read budget. Its origin response-header
timer starts after writing the origin request (`transport.go:2845`), not while
waiting for CONNECT. The five-minute operation context did not satisfy the
10-second establishment contract.

Before new API usage, inspected exact installed Go 1.25.14 source:

- `net/http/transport.go:1276–1282` (nil TCP result rejection), `1536` (HTTP/1
  GotConn), `1695–1807` (TLS and proxy sequencing), `1855–1882` (CONNECT close/join),
  and `2845` (origin response-header timer).
- `net/http/httptrace/trace.go` (hook composition, concurrency, readiness contract),
  `net/http/h2_bundle.go:10505–10519` (actual HTTP/2 GotConn), and
  `crypto/tls/conn.go:160–164` (NetConn, no direct TLS-underlying I/O).
- `time/sleep.go:94–111`: `AfterFunc` Stop(false) does **not** join its callback.

`internal/upgrade/establishment.go` now wraps only the updater-owned raw TCP
connection. Its abort timer uses the original dial deadline, including TCP time,
and remains active through proxy TLS, CONNECT, origin TLS and protocol setup.
It closes the raw socket to interrupt blocked reads/writes even when a permitted
TCP-routing fixture returns `ErrUnsupported` from deadline methods. Timeout
read/write errors retain timeout semantics. No SetDeadline success or reset is
assumed. The owned standard transport still strips unsafe TLS/hostname/ALPN/
protocol hooks and rejects unknown caller transports.

An owned request trace stops **and joins** the abort at GotConn, following both
TLS layers for HTTPS proxies, not the first TLSHandshakeDone. A stop-win after
the wall deadline still aborts; a once-completed readiness cannot re-arm or
late-close the connection on reuse. Normal close also joins and closes raw TCP
once. Default complete-establishment/header limits remain 10 seconds and the
shared operation context remains five minutes. External DB/proxy transports are
untouched.

**Actual RED before production changes:**

```sh
go test ./internal/upgrade -run '^TestUpgradeProxy(EstablishmentDeadline|EstablishedStreamAndReuse)$' -count=1 -timeout=25s
```

`proxy-red.log` records four silent-CONNECT failures: HTTP/HTTPS proxy × normal/
unsupported deadline methods. Actual CONNECT was received; the HTTPS proxy
completed verified TLS first. Each failure took approximately **900 ms** (the
operation budget), not the injected **80 ms** phase bound. Failure checks also
require raw TCP close, proxy EOF/handler join before fixture-forced cleanup,
original binary preservation and no temporary files.

The positive matrix already passed before the fix and is **characterization**:
HTTP/HTTPS proxies × actual origin HTTP/1 and HTTP/2, with unsupported socket
deadline methods. A streamed body lasts 360 ms, beyond its 120 ms establishment
budget; SHA256SUMS then reuses the same connection. It requires one dial/tunnel,
two origin requests, one reuse, both HTTPS-proxy/origin handshakes, and no raw
close before replacement. Both relay directions join before forced cleanup.
Passing helper coverage additionally holds a running abort callback until
released to prove readiness waits, and models delayed-timer late readiness versus
healthy reuse. These helper expansions are not separately claimed as pre-fix RED.

An intermediate whole-upgrade race10 failed the old TLS test's literal
`"TLS handshake timeout"` expectation (`upgrade-race10.log`): the stricter complete
establishment timer correctly reported `context deadline exceeded` first. The
test now requires `net.Error.Timeout()` and retains the short elapsed-time
assertion; no timeout bound or guard was weakened. Self-review also preserved
standard Go's nil-dial-result contract: `nil-dial-red.log` showed `(nil,nil)`
hidden inside a nonnil guard, bypassing the standard nil check; the owned dial
now returns an error before wrapping. Its direct regression passes in final runs.

### P1b: roll back binary publication if absent-unit publication fails

**Verified cause:** the old server installer renamed the verified binary before
creating/writing/chmodding/exclusively linking an absent unit. Its cleanup owned
only temporary files, so any later unit failure left the executable changed or
newly present.

The server now prepares both stages inside a private same-filesystem rollback
directory, retaining an original-binary hard link and a new-inode identity link
before publication. Binary rename precedes **exclusive file-target** unit
publication (`ln -T`); commit occurs only after both succeed. On failure, cleanup
restores original bytes/mode or removes only the owned fresh binary, and removes
an owned unit only when inode identity matches. Competing units are never
force-replaced or deleted. Failed rollback retains the private original snapshot
and reports the exact recovery-directory path rather than erasing the backup.
No config, DB/WAL/SHM, key, marker or service operation is performed.

**Actual RED before production changes:**

```sh
bash scripts/test-installers.sh server-publication
```

`server-publication-red.log` shows existing/fresh binary preservation failures
for unit temporary creation, write, chmod, link I/O, and concurrent regular-file/
symlink collisions; it also shows the missing retained backup after rollback
failure. Each case asserts the intended failure wrapper was reached after both
verified downloads, so these are not bad-fixture setup failures. Existing
executable mode 0711 and opaque initialized config/DB/WAL/SHM/key/marker mode 0400
are independently snapshotted. Fresh executable absence is independently checked.
Binary-rename failure and missing-Python3 refusal were passing characterizations.
The host's Python apport hook duplicated assertion tracebacks while handling
stdin-script failures; the original preservation assertions are the RED evidence.

During self-review, added directory/directory-symlink unit collisions. The first
transaction implementation still used plain `ln`, which could write the stage
**inside** a competing directory and report success (`server-directory-red.log`).
Installed `ln --help` confirms `-T` treats LINK_NAME as a file rather than a
directory; `ln -T` now makes all four cases fail safely without changing the
competing directory/target. Final fixtures exercise 18 existing/fresh publication
cases plus rollback-I/O recovery and missing-Python3 checks. They preserve custom
unit bytes/modes/symlinks and empty directories, clean owned stages, and retain
mode-0700 recovery staging only in the deliberately failed rollback case.

The sandbox adds controlled mktemp/cat/chmod/ln/mv failure wrappers; forbidden
sudo/systemctl/sysctl/tailscale commands remain blocked and uncalled. Fixture
binaries are not executed. Missing Python3 is tested with an isolated PATH and
must fail before any curl call or binary/unit publication. Documentation now
states this fail-before-publication prerequisite contract. No dependency installer
or new product configuration switch was added.

### Current-source validation after both fixes and self-review

All commands below passed; log names are relative to `/var/tmp/wt14/p1`:

| Command | Result/evidence |
| --- | --- |
| `go test ./... -count=1 -timeout=180s` | ALL PASS; `final-full-go.log` |
| `go test -race ./... -count=1 -timeout=180s` | ALL PASS; `final-full-race.log` |
| `go test ./internal/upgrade ./cmd/warden ./cmd/warden-server -count=1 -timeout=180s` | PASS; `final-focused.log` |
| Same focused command with `-race` | PASS; `final-focused-race.log` |
| `go test -race ./internal/upgrade -count=10 -timeout=90s` | PASS 32.545s, including proxy/stop-join/nil-dial checks; `final-upgrade-race10.log` |
| `go test -race ./internal/upgrade -run '^(TestUpgradeProxy\|TestEstablishment)' -count=10 -timeout=90s` | PASS 19.757s before the subsequent nil-dial-only guard/test; `proxy-race10.log`; final whole-package race10 supersedes it |
| `bash scripts/test-installers.sh server-publication` | PASS; `final-server-publication.log` |
| `bash scripts/test-installers.sh` | PASS; `final-installers.log` |
| `python3 scripts/installers_test.py` | PASS four methods/matrices, 2.747s; actual curl, `final-curl.log` |
| `bash -n scripts/install-client.sh scripts/install-server.sh scripts/test-installers.sh` | PASS |
| `go vet ./...` | PASS; `final-vet.log` |
| Windows/amd64 upgrade test cross-compile and `go build ./...` | PASS **compile only**; `final-windows-cross.log` |

A final current-source verbose run of proxy, establishment and nil-dial tests
also passes (`proxy-verbose-green.log`): each silent CONNECT fails at 0.08s;
established/reused streams complete at 0.36–0.37s, beyond the 0.12s phase budget.
Final hygiene covers 26 task files (11 tracked, 14 new untracked, one ignored
ledger), all 14 Go files formatted and 54 local Markdown targets present. The
complete patch passes reverse `git apply --check` without modifying the checkout.

The refreshed allowlisted review diff and manifest include the new establishment
source/tests and proxy fixtures, all original T14 task files, and only the T14
ignored-ledger delta. Final source hashes are verified after tests; protected
unrelated content is excluded before inspection. Current source/diff/hygiene
self-review is an implementer checkpoint, **not** independent P1 rereview or
native/full-T14/security-release acceptance. Native Windows PowerShell/.NET ACL,
helper and installer checks remain required/unavailable; ShellCheck remains
unavailable, with no global installation attempted. Per-file atomic operations
and error rollback still do not claim power-loss atomicity or race-proof rooting
against privileged/same-user ancestor substitution. Stop here; no T15.
