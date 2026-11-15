# T12 — SSH authentication, graph ownership and cancellable establishment

## Scope and status

Owner-authorized **T12 only**, `/var/www/code/go/warden`, branch
`hieudmg/security-hardening`, unchanged reviewed HEAD **`8541e6f`**. Sole writer;
no children/worktrees, staging, commits, push, deployment, dependency/version
changes, external TLS/profile changes, fork or rsync work. Protected untracked
`mise.toml` was not read or changed. Tests use isolated local sockets, synthetic
keys, SSH protocol peers and disposable runtime directories, not live agents,
servers, credentials or databases.

Implementation and self-review are retained, **not independent acceptance or a
security release**. The DB whole-chain failure has a reproduced and corrected
**fixture upstream-TCP leak**, not an assumed production graph bug. Latest
earlier all-pass handoffs were superseded by the parent's ordinary full-Go
**recurrence** in the Ctrl-C/Ctrl-D test at10.08s. The authorized test/fixture-only
sequencing correction and fresh implementer checks now pass as recorded in the
last section, including the disclosed TMPDIR environment correction. New
sequencing review and a fresh parent full run remain pending; this is not
unconditional T12 acceptance. Native Windows and
genuine PRF/production certificate-trust/browser acceptance remain pending.

**Current follow-up checkpoint:** after independent read-only review, the owner
authorized correction of P1 late-cancellation cleanup and P2 fixture request-drain
joins plus bounded PTY instrumentation/fixture regressions. Those corrections and
fresh final-source checks are recorded in **Follow-up after independent review**
below. Earlier chronology/checks remain historical, not the latest source. The
original timeout has now recurred; native PTY evidence demonstrates the invalid
EOF/SIGINT sequencing assumption independently, not the parent's exact syscall
ordering or a production input-pump bug. P1/P2 rereview is closed per the owner;
the new test-only correction is implemented and freshly checked below, with
independent sequencing review and fresh parent validation still pending.

## Implemented contract

### Authentication does not authorize forwarding

- `SSH_AUTH_SOCK` still supplies public-key authentication when no explicit
  password/key is configured. A real local agent/keyring and public-key-only
  SSH server verify authentication independently of forwarding acceptance.
- Removed implicit forwarding registration and requests from exec and
  interactive paths. There is no forwarding UI/profile option or new feature.
  Repeated commands on one graph and an interactive session authenticate while
  the server accepts **zero** `auth-agent-req@openssh.com` requests.
- Each node's client owns an exactly-once raw transport and optional agent
  socket. Graph closure closes clients in reverse order; interactive sessions
  now use that same graph owner. Failed partial chains also close in reverse
  logical order. A spontaneous SSH failure releases its agent socket too.
- Authentication is serial. The supported `agent.NewClient` ReadWriter-only
  path avoids the pinned library's unnecessary background pipeline reader;
  graph ownership still retains the actual closable socket. Socket cancellation
  unblocks a stalled synchronous Signers/authentication RPC. No agent forwarding
  registration or global client-to-agent map survives reuse.
- Normal closure is reverse ordered and idempotent. Cancellation/invalidation
  first **aborts the root network transport**, then performs reverse logical
  teardown: a channel Close can itself block writing through its parent.
  Ordinary Graph.Close has a 15-second root-abort escape for that case. This
  distinction is deliberate, not a claim that physical TCP abort waits for
  child channel acknowledgements. Once-wrapped sockets prevent double closes.

### Bounded network establishment, with joined cancellation

- Each node's establishment budget remains **15 seconds**, or the earlier
  caller deadline, covering TCP dial, optional CONNECT and SSH handshake.
  Direct TCP and local-agent socket establishment use `net.Dialer.DialContext`.
- Second-hop/proxy-hop/DB direct-tcpip opens execute synchronously under a joined
  context abort callback. They do **not** abandon an unbounded dial goroutine.
  Closing the owning root transport releases x/crypto's pending OpenChannel.
- SSH handshake and CONNECT have the same owned-transport abort protection.
  Real direct-tcpip connections return an error from SetDeadline; explicit
  injected deadline errors are also tested. Neither path relies on deadlines
  succeeding. Supported deadlines are cleared before successful publication;
  reset failure rejects/closes the transport rather than publishing a stale
  deadline.
- Cancellation callbacks are stopped **and joined before publication**, on
  error paths and before returning reusable connections. Late successful
  channel results are closed. No timed callback remains to close the next
  borrower. An elapsed deadline is recognized even in the scheduling interval
  before the context timer runs, avoiding a socket-timeout/context-error race.
- DB dialers cancel and join in-progress opens on Close. Healthy borrowed graphs
  remain owned by the pool; their ordinary Close still permits subsequent SSH
  operations. Cancellation during an **unconfirmed** channel open is different:
  the borrower must ask its owner to invalidate that transport.

### Explicit pooled ownership and the SSH protocol constraint

`db.BorrowedGraph` requires `Target()` and `Invalidate(reason)`. The agent passes
its actual pool lease, not an unowned target pointer. Invalidation records the
fixed reason **`SSH channel open canceled; connection-level abort required`**,
removes that entry from reuse and aborts its graph even while leases remain.

SSH v0.55.0 exposes no pre-confirmation channel ID/handle to cancel independently.
Consequently **other leases on that SAME graph fail too**. This is the required
connection-level abort of a stalled graph, not silent healthy-graph retirement.
Tests issue two simultaneous DB opens on one graph, cancel one, join both,
verify the exact reason, execute an unrelated healthy graph, acquire/execute a
replacement for the invalidated entry and release/expire every lease. Separate
healthy pool entries are preserved. Ordinary operation errors still use the
existing lease-safe Retire policy, not indiscriminate invalidation.

In-progress pool entries now retain a cancelable dial owner **before a Graph
exists**. Shutdown/Close/retirement cancel those owners. Owner and follower
publication paths recheck cancellation before handing out leases. A completed
real graph paused before publication is reclaimed if shutdown wins; the pool
retains no reservation or lease. Daemon termination aborts cached/retired active
graphs before joining handlers. Real authenticated IPC shutdown fixtures cover
first-hop SSH handshake, second-hop open, second-hop handshake and raw CONNECT,
and require remote handler completion **before fixture cleanup can force-close
anything**.

### Independent daemon/API-token lifetime preserved

T10/T4 already implement the fake-clock lifetime/auth-state contract. Their
existing tests pass unchanged: empty pools and TTL expiry, long idle, logout,
revocation, outage, server restart and vault lock do not terminate the daemon.
Pool eviction does not discard an approved memory-only API token. Only external
termination ends the daemon; actual restart still requires approval again.
Logout/revocation clear authorization as before. No API-token timer, expiry,
refresh, rotation, persistence or pairing-policy change was added. These are
**passing-existing characterizations**, not invented new RED cycles.

## DB whole-chain failure: verified cause, not an observer assumption

The parent log `/tmp/warden-t11-parent-full.log` really failed only
`TestTunnelCloseClosesWholeChain`, with one target SSH connection after **5s**.
Before editing, this command reproduced **two failures in 50 runs**:

```sh
go test ./internal/client/db -run '^TestTunnelCloseClosesWholeChain$' \
  -count=50 -timeout=180s
```

The old test relay waited for **both** `io.Copy` workers before closing either
endpoint. When the client's jump channel ended, channel-to-upstream copy could
return, but upstream-to-channel was still reading the target TCP socket. The
target SSH server, in turn, needed TCP EOF to end its connection. The upstream
socket was only closed in a defer **after the wait**. This is a real fixture
connection/worker leak, not just `open++`/`open--` observation timing.

First extracted that relay unchanged, then added a deterministic net.Pipe
regression. Closing only the channel peer left the target waiting for EOF and
both-worker join incomplete. Actual RED: `target did not receive EOF after
channel close: read pipe: i/o timeout`, then `relay did not join both copy
workers`. Forced failure cleanup closes all pipes and joins the relay; it is
not a passing leak waiver.

The relay now closes endpoints when a copy direction finishes, releasing the
other reader, and joins both copies and its request drain. The SSH fixture
registers accepted transports **before** starting handlers, tracks accepted and
completed counts including failures, joins forwarders/global request drains,
and signals completion. `waitClosed` retains its **5-second** bound, uses events
instead of sleeping/polling green, and requires balanced counters. Whole-chain
Close errors are checked, not swallowed to make the assertion pass. No
production SSH-disconnect error suppression or unrelated driver change was used.

The deterministic relay plus original whole-chain test passed 50 normal
repetitions immediately after this fix, and the final boundary set including
whole-chain closure passes **25 race repetitions**. Full Go passed three
repetitions at an earlier checkpoint and once again against final source. These
passes supplement the deterministic EOF proof; they are not the sole causal
evidence. Production cancellation fixes are separate from this fixture fix.

## Actual RED → GREEN chronology

Every production behavior slice below had focused RED before its corresponding
fix. Further boundary extensions/characterizations are distinguished explicitly.

| Focused test/command | Actual RED | GREEN / coverage |
| --- | --- | --- |
| `TestTunnelFixtureChannelEOFClosesUpstreamAndJoins` | Target EOF and relay join each timed out after channel close | Endpoint closure before join; original whole-chain test retained, balanced accepted/completed workers |
| `TestSecondHopDialAndHandshakeCancelWithoutDeadline` | Both channel-open and handshake remained blocked 200ms after cancellation; forced peer shutdown produced EOF/unexpected-channel error instead | Synchronous open + owned root abort; later added actual 250ms deadline cases, 1s outer safety bound |
| `TestProxyCONNECTCancelWithoutDeadline` | Raw and through-hop CONNECT stayed blocked after cancellation | Context abort on real TCP and unsupported-deadline SSH channel; later added timeout cases |
| `TestAgentAuthenticationDoesNotRequestForwarding` | Public-key auth succeeded but server accepted **2** implicit forwarding requests | Exec/repeated graph reuse and interactive all authenticate, zero requests |
| `TestPoolShutdownCancelsDialOwnerWithoutGraph` | Shutdown left an unpublished owner running | Entry retains cancelable dial context even without Graph value |
| `TestPoolCanceledOwnerCannotPublishLateGraph` | Canceled owner returned success and retained graph/reservation | Recheck before publication; late graph closed, no lease |
| `TestDBChannelOpenCancellationReclaimsLateResult` | Both owned/borrowed opens remained blocked against a peer that never confirmed | Owned abort / explicit pool-owner invalidation; operation and server handler join |
| `TestTunnelCloseJoinsPendingChannelOpenAndInvalidation` | Close returned while invalidation callback/open still blocked behind a barrier | Close cancels and joins opens; callback join precedes return |
| Self-review `TestBorrowedTunnelMissingTargetClosesWithoutWaiting` | New close/join state waited forever on an initially absent target, where old Close returned immediately | Initialize absent-target dialer as already closed; preserve fail-closed dial and prompt idempotent Close |
| Existing `TestChangedHostKeyRejected` / `TestUnknownHostKeyRejectedByDefault` in initial relevant suite | New deadline-reset error masked original strict host-key error on an already failed handshake | Preserve handshake failure, reset only successful transports; original host-key diagnostics pass |
| Initial boundary `-race -count=25`, direct CONNECT timeout subcase | Socket deadline fired before ctx timer; repeated `i/o timeout` instead of `context deadline exceeded` | Recognize actual elapsed context deadline; same set passes25 |
| `TestAuthenticationAgentDoesNotStartUnownedIdleReader` | NewClient started a reader without any agent RPC | Supported synchronous ReadWriter path, real agent-auth and stalled-agent cancellation still pass |

New tests after those primary REDs also cover reverse closure exactly once,
explicit deadline errors, reset failure, callback stop/join barriers, late channel
confirmation after abort, failed partial-chain agent cleanup, pool reuse/idle
agent cleanup, real completed-graph publication racing shutdown, multiple pooled
opens with independent healthy use, and all pending-establishment IPC shutdown
states. They are supplemental coverage, not a retroactive separate RED for each
case. The helper extractions for handshake/CONNECT and initial relay extraction
were behavior preserving. Documentation/report/checkpoint changes use the stated
documentation TDD exception, verified against source/results/links.

## Pinned API and source evidence

No dependency upgrade or fork. `go list -m golang.org/x/crypto` confirms
**v0.55.0**; go.mod/go.sum are unchanged.

Before production calls, retrieved Context7 SSH docs
`ctx7:docs:0481af1a079a00ef66c09c4d` and agent docs
`ctx7:docs:9b1f14877e3edd2023e7da8f`. Those public docs are not a version pin;
inspected exact installed official source under
`/home/hieudm/go/pkg/mod/golang.org/x/crypto@v0.55.0/ssh/`:

- `tcpip.go:372–405`: Client.DialContext launches a Dial goroutine and merely
  returns on ctx cancellation. It closes a result **only if Dial eventually
  returns**; a peer withholding channel confirmation can leave that goroutine
  indefinitely. Warden deliberately does not use that as its cancellation fix.
- `tcpip.go:409–547`: Dial builds direct-tcpip via OpenChannel; returned
  `chanConn.SetReadDeadline`/SetWriteDeadline explicitly return unsupported.
  Merely asserting the net.Conn deadline interface is not evidence of support.
- `mux.go:345–369`: OpenChannel sends, then waits on private `ch.msg`, with no
  caller-visible pre-confirmation channel handle/context/cancel operation.
  `mux.go` loop/Wait/Close and `channel.go:410–426` show root close terminating
  packet reads, dropping channels, closing pending message/request queues and
  unblocking readers/writers. `connection.go:95–99` closes underlying net.Conn.
- `client.go:53–93`: NewClient services request/channel streams; NewClientConn
  performs the synchronous handshake and closes raw I/O on failure. Its failed
  close is itself protected by the owned-root cancellation escape.
- `agent/client.go:335–355,955–1044`: closable I/O selects a pipeline reader;
  ReadWriter-only I/O selects serial RPCs. A pipeline can await its private
  pending queue after a reply. Authentication has no forwarding/concurrent-RPC
  need, so Warden selects serial behavior and retains socket ownership outside
  that wrapper. `agent/server.go:607–644`, keyring and Signers implementations
  ground the real local-agent test fixture.
- Installed Go **1.25.14** docs for `context.AfterFunc` explicitly say stop is
  **not** a join, and `net.Dialer.DialContext` bounds establishment without tying
  successful connection lifetime to later context cancellation. The code uses
  explicit callback completion channels and once-closed owned transports.

Previously recorded reachable x/crypto advisories **GO-2026-6354/6355** are **not
remediated here**. T15 owns dependency remediation; no dependency upgrade was
used to invent a missing channel-cancellation API, and no new govulncheck result
is claimed.

## Final checks and retained failure evidence

Toolchain: **Go1.25.14 linux/amd64**. Current-source commands:

```sh
go test ./internal/client/ssh ./internal/client/db ./internal/client/agent \
  ./cmd/warden -count=1 -timeout=180s
go test -race ./internal/client/ssh ./internal/client/db ./internal/client/agent \
  ./cmd/warden -count=1 -timeout=180s

go test -race ./internal/client/ssh ./internal/client/db ./internal/client/agent \
  -run '^Test(AuthenticationAgent|AgentAuthentication|GraphOwns|GraphCancellation|GraphCloses|SecondHop|ProxyCONNECT|NetworkNegotiation|ReusableHandshake|CancellationStop|DialTCPContext|DBChannel|BorrowedTunnelMissingTarget|TunnelClose|TunnelFixture|PoolShutdown|PoolCanceled|ServerExternalCancellation)' \
  -count=25 -timeout=180s

go test -race ./internal/client/agent \
  -run '^Test(SSHPoolIdleExpiryDoesNotEndAuthAgent|AuthAgentLivesUntilExternalCancellation|AgentAPIMemoryLifetimeAndBoundedStreams|AgentOwnsAPITokenInMemoryAndNeverPersistsOrReturnsIt)$' \
  -count=1 -v -timeout=90s

go test ./... -count=1 -timeout=180s
go vet ./...
```

All above **PASS against final source**. Logs:
`/tmp/warden-t12-final-source-{focused,race,boundary-race25,full,vet}.log` and
`/tmp/warden-t12-daemon-characterization.log`. Full Go includes SFTP passing;
there is no remaining waived SFTP baseline. Earlier full Go count3 also passed
(`/tmp/warden-t12-final-full-go.log`), before final fixture/serial-agent refinements.
Actual DB baseline/RED/GREEN logs:
`/tmp/warden-t12-db-{baseline,relay-red,relay-green,cancel-red,close-red}.log`;
SSH/pool REDs `/tmp/warden-t12-{cancel-red,forwarding-red,pool-red,agent-reader-red}.log`.
Closing absent-target regression `/tmp/warden-t12-nil-target-{red,green}.log`;
all final-source focused/race/boundary25/full/vet logs were refreshed after it.
Initial host-key and deadline-race failures are retained in
`/tmp/warden-t12-first-suites.log` and `/tmp/warden-t12-boundary-race25.log`.

**Unresolved PTY observation, not erased by PASS:** intermediate relevant normal
run `/tmp/warden-t12-handoff-focused.log` failed
`TestRunInteractiveCtrlCForwardsByte` at10.03s (`session did not end after Ctrl-D`).
No race/full command chained after that failed command was executed. Fifty
focused normal repeats passed (`/tmp/warden-t12-pty-reproduce.log`), then 25 whole
SSH-package race repetitions passed (`/tmp/warden-t12-ssh-package-race25.log`).
Subsequent final normal/race/full runs above pass. None reproduces or explains
that observation. Added only a mutex-safe output capture and diagnostic timeout
message reporting whether the fixture received Ctrl-D; the **10-second
assertion is unchanged**, with no retry, extra EOT, arbitrary sleep, signal or
production workaround. The fixture marks exec accepted before launching the
PTY child, but that is only a source observation, **not a verified root cause**.
Do not call the PTY failure fixed, preexisting, unrelated, or waived without
further evidence. It remains an open validation risk for independent review.

Windows amd64 `go test -c` for SSH/DB/agent/CLI and CLI `go build` **PASS**, artifacts
`/tmp/warden-t12-{ssh,db,agent,cli}.test.exe`, `/tmp/warden-t12-cli.exe`. An initial
cross-build correctly caught a Linux-only terminal helper reference; replaced it
with a portable in-memory fixture and reran successfully. **No native Windows
execution**. Unix SSH_AUTH_SOCK fixtures explicitly skip Windows. gofmt, diff
whitespace, local documentation links and unchanged module/staging checks are
part of closing self-review. No frontend/browser/genuine-authenticator test or
release publication was performed.

## Boundaries, risks and next step

- Same-graph disruption on canceled unconfirmed channel opens is unavoidable
  with this API/protocol; it is explicit, reasoned invalidation. Independent
  healthy graphs remain usable. Successful/previously completed channels do not
  retain cancellation callbacks.
- A net.Conn implementation must actually unblock I/O on Close, as standard TCP,
  Unix sockets and x/crypto's channel mux do after root abort. Arbitrary injected
  GraphDialers/host-key/progress callbacks that ignore cancellation or never
  return are not made preemptible. Production agent host-key checks are strict,
  noninteractive; a user-blocked local console confirmation/stdin reader is not
  an SSH network dial, and this work does not claim arbitrary-reader shutdown.
- Leak evidence is owned-transport closure, callback/open joins, endpoint EOF,
  balanced accepted/completed counters, worker/request drain and server-handler
  completion, **not loose runtime.NumGoroutine comparisons** or sleeping green.
  Tests do not prove all possible adversarial peer packet sequences.
- Existing external DB and HTTP CONNECT behavior is unchanged: Basic credentials
  and onward DB/proxy traffic may traverse plaintext outside SSH's encrypted
  segment. No external TLS profile/schema/export change or end-to-end
  confidentiality claim.
- Known dependency advisories remain T15 work. Native Windows, independent
  acceptance, genuine PRF and production-trust/browser acceptance remain pending;
  T9's prior synthetic PRF/test-certificate browser result is not promoted.
- The unexplained intermediate PTY timeout above remains unresolved despite
  current PASS. Further evidence-based triage is recommended before declaring
  T12 validation unconditionally complete. No T13 or commit follows this handoff.

Changed production seams: SSH `graph.go`, new `cancel.go`, `exec.go`,
`interactive.go`; DB `tunnel.go`; agent `pool.go` and the borrowed-DB constructor
call in `server.go`. Source-named SSH/DB/agent tests and fixture diagnostics,
security/IPC docs, narrow plan/spec checkpoint, this report and the ignored
execution ledger complete the bounded change. Self-review covers resource
ownership, reverse logical closure/root abort, exact-once sockets, callback
joining/deadline reset, publication races, same-graph versus independent-pool
behavior and unchanged authentication/token/host-key/TLS boundaries.

Closing hygiene: **25 task files** (including ignored ledger and new files) pass
explicit final-newline/trailing-whitespace/local-Markdown-target checks; **19 Go
files** are gofmt clean. `git diff --check`, unchanged module/release files and
empty staged diff pass. Branch/HEAD remain assigned. Protected `mise.toml` was
excluded before any content reads. No code or test behavior changed after the
final runtime checks; only measured evidence prose was completed.

## Follow-up after independent review

Same owner-authorized T12 scope, sole writer, branch/HEAD unchanged
`hieudmg/security-hardening` / `8541e6f`. Read reviewer
`01a1ddf1-1e80-7503-b4c7-e7366dc62826`'s complete final review and retained
read-only diagnosis `/tmp/warden-t12-pty-readonly-diagnosis.md`. No commits,
staging, dependency/version/fork/T13/publication operations or protected-file
content access. Parent's fresh `/tmp/warden-t12-parent-full.log` PASS is evidence
against the earlier source only, not proof of any follow-up fix. This subsection
supersedes earlier final-source checks/file counts, not the original failure
record or acceptance limits.

### P1: preserve exactly-once owner abort through canceled-result cleanup

Reviewer found a real source-supported ordering gap: `finish()` could successfully
stop its abort callback and THEN observe cancellation/an elapsed deadline. Closing
the late SSH channel could itself block writing a close packet, with the only
root-abort guard already gone. CONNECT had the same exposure after a stopped
callback, including cancellation observed during deadline reset.

**Actual RED before production edits:** new `cancel_cleanup_test.go` makes
channel/CONNECT Close **block until root-owner abort**, not the earlier always-nil
Close fake or an OpenChannel that only returns after abort. It covers:

- `TestDialTCPContextStoppedCallbackStillAbortsExpiredLateChannel`: OpenChannel
  confirms while timer delivery is held; callback stopping wins, elapsed deadline
  is observed, and cleanup remains blocked with **zero** owner abort calls.
- `TestCancellationStopWinThenCancelStillAbortsExactlyOnce`: a real cancelable
  context's custom AfterFunc stop succeeds, THEN its Err observation triggers
  cancellation. Observed abort calls0, expected1.
- `TestProxyCONNECTStoppedCallbackRetainsOwnerThroughCleanup`: both
  `elapsed-before-timer` and `cancel-during-reset` block closing the through-hop
  connection after callback stopping, without owner-root abort.

Clock seam: `heldDeadlineContext` supplies one immutable elapsed deadline while
its native cancellation delivery is explicitly held. This models the scheduling
gap before timer dispatch without waiting for a real timer or mutating a global
clock. The separate custom AfterFunc/Err wrapper deterministically exercises
stop-first/cancel-second. Its Value override prevents native cancelCtx unwrapping
from bypassing that test stop seam. Every failing close is released and joined
via explicit **failure cleanup**, not silently abandoned or called a pass.

First RED invocation had a test-setup error in the reset subcase: a context
without a deadline caused its *initial* zero SetDeadline to cancel before stop.
Corrected that setup to give it a future deadline **before production edits**;
all four intended paths then genuinely RED. Retained logs
`/tmp/warden-t12-followup-p1-{initial-red,red}.log`.

Minimal fix: `stopCancellation` shares a once-guarded owner abort between callback
and finisher. A finisher that observes cancellation after stopping executes that
abort synchronously **before late-channel Close**. Successful publication still
stops/joins and caches successful completion; later cancellation does not abort
a reused connection. Failed CONNECT retains a separate once-guarded root-first
abort through all cleanup, including reset errors/late cancellation after a
successful stop. Handshake's existing failed-result path already closes root
before its channel. No ignored context guard, detached Close goroutine or
connection-level cancellation API was invented. Exactly-once root/connection
close and existing stopped-callback reuse/join checks pass
(`/tmp/warden-t12-followup-p1-green.log`, race). The borrowed-lease invalidation
reason/concurrent same-graph disruption policy is unchanged, and the independent
healthy pooled graph/replacement integration still passes.

Pinned API evidence refreshed before edits: Context7 SSH
`ctx7:docs:02bb4fed77b59cef7c136b28`; exact x/crypto v0.55.0
`ssh/channel.go:227–246,611–617` confirms Close uses writePacket and can block
through parent/rekey. No dependency changes.

### P2: join fixture request drains before completion

Joined previously unowned DiscardRequests workers in second-hop/CONNECT SSH
fixtures, agent handshake/channel handlers and DB cancellation fixture. Agent
channel-drain registration uses the handler wait group **before** launching;
its exec handler also closes then synchronously drains remaining requests before
worker completion. There is no Add-after-parent-Wait race or competing reader
for an actively handled request stream. DB/SSH fixtures use explicit drain-done
channels, close before join and assert the drain is complete after the handler
signal, **before forced cleanup**. Agent tests require accepted/completed balance
and zero active request drains before cleanup. Existing joined global drains
remain joined. Audited other new lifecycle fixtures; old unrelated borrowed-DB
helper is not promoted to a new all-workers-quiescent proof.

This was a **fixture evidence gap**, not a separately demonstrated production
leak. No fabricated RED: the joined-boundary cases are characterization/coverage
refinement. Relevant SSH/DB/agent race cases PASS in
`/tmp/warden-t12-followup-p2-joins.log`, including independent healthy graph use,
replacement and external daemon cancellation. New PTY instrumentation also joins
its connection request drain, session workers and shell workers.

### PTY: measured fixture fixes, original timeout still not causally resolved

The read-only diagnosis above found no deterministic original10-second timeout.
It did prove weak pre-child readiness and retained masters/slaves. Follow-up
added **test-only bounded per-session events**: exec acceptance, PTY descriptors,
child PID/PGID/foreground group, canonical/signal flags and VINTR/VEOF; master
write start/result and actual forwarded control bytes; child Wait state/signal,
exit-status send, channel Close, endpoint closure, copy/drain completion and
joins. Buffer is capped at256 events and256 forwarded-input bytes, reporting
drops; write payloads are capped to first64 synthetic bytes. Timeout retains its
**10-second** assertion and now captures all goroutine stacks (bounded1MiB).
GOTRACEBACK=all alone does not make t.Fatal emit stacks. No live keys/credentials
were used; temporary logs/notes are owner-private, executable artifacts0700.

Separate actual RED→GREEN slices:

1. `TestInteractiveFixtureClosesPTYAndJoinsAfterChildExit`: child exited0 and
   client returned, but one copy and both endpoints remained retained after100ms.
   RED events show successful exit-status/channel Close followed by input-worker
   join, with output read still blocked. Parent now releases its slave after
   child Start and closes master before worker joins. Test requires actual closed
   os.File handles, zero copies, shell completion and the SSH handler/global
   request drain **before any fixture-forced cleanup**. Original assertion was
   not weakened. Logs `/tmp/warden-t12-followup-pty-leak-{red,green}.log`.
2. `TestInteractiveFixtureReadyRequiresInitializedForegroundShell`: a controlled
   before-Start barrier proves the old ready flag was true while child startup
   remained blocked. RED is deterministic, not a timing guess. Ready now requires
   a shell-generated marker after login initialization, its actual child-PID
   foreground group, ICANON/ISIG and VINTR03/VEOF04. A private octal-escaped
   bootstrap command cannot be satisfied by command echo; input is held until
   that handshake finishes so client bytes cannot interleave with bootstrap.
   `TestPTYReadinessMarkerRequiresOutputNotCommandEcho` also covers split markers
   and unchanged output. Ctrl-C test additionally waits for actual master-write
   completion, not only recordingReader's pre-write observation. Logs
   `/tmp/warden-t12-followup-pty-readiness-{red,green}.log`.
3. Closing self-review found that a PTY session registered after fixture cleanup's
   snapshot could otherwise start a late child and hold joins. A controlled
   canceled-start barrier reproduced a child still running with both copies
   after fixture cancellation. Bound child creation/lifetime to fixture context
   using Go1.25.14's CommandContext, and close the channel on early startup errors
   too. `TestInteractiveFixtureCanceledStartupCannotRetainLateChild` requires no
   published child/copy worker and joined session/handler after cancellation.
   Logs `/tmp/warden-t12-followup-pty-late-start-{red,green}.log`. These are fixture
   owner fixes, not daemon/process-control feature changes.

No production TTY/input/EOF logic or shell command contract changed. The fixture
still runs the real portable login-shell payload, but never signals its profile
subprocesses as a substitute for the initialized test subject. No arbitrary
startup sleep, extra client EOT, weakened EOF assertion, increased wait, retry,
SIGINT conversion or production workaround was added.

**Bounded instrumented final-source batch:** ordinary `go test` (the test binary
is NOT launched as a session leader, avoiding the proven diagnostic SIGHUP
artifact):

```sh
GOTRACEBACK=all GOMEMLIMIT=256MiB GORACE=halt_on_error=1 \
go test -race ./internal/client/ssh \
  -run '^Test(RunInteractiveCtrlCForwardsByte|InteractiveFixture|PTYReadinessMarker)' \
  -count=20 -cpu=1,2,4 -v -timeout=120s -failfast
```

**300 cases PASS**, including60 actual Ctrl-C cases, elapsed7.363s (package7.089s).
Per-case safety ceilings:512 FDs,512 goroutines,256MiB live Go heap; inherited
hard open-file2048/file-output64MiB limits. Supervisor samples test RSS/FDs and
would SIGQUIT at768MiB RSS/1024FD, with outer145/150s quit/kill bounds; none reached.
Sampled max13FD,51796KiB RSS, zero skipped samples in final run. These are **safety
ceilings, not leak proofs**; file closure/worker/drain joins supply ownership proof.
Artifacts `/tmp/warden-t12-followup-pty-bounded{.log,-resources.json}`.

An earlier sampler attempt hit /proc PermissionError during process inspection
and did not finish recording resource metadata; its native command nevertheless
completed300 PASS in7.368s. Retained as
`/tmp/warden-t12-followup-pty-sampler-error.log`, not used as complete monitoring
evidence. Corrected only the external supervisor to tolerate racing process
exit/non-inspectability and finally kill/join its owned command on exceptions;
one bounded corrected run above supplied complete metadata. No source mutation
or test retry loop was used to chase green. A preceding240-case instrumented
checkpoint (before the late-start fixture fix) also passed; it is superseded by
current-source300, not original-timeout causality.

**Required uncertainty remains:** neither the historical failure nor an equivalent
native10-second timeout was reproduced. No failed-state proof shows original EOT
loss, delayed SIGINT processing, profile stdin consumption, client Wait or close
stall. The resource leak is after exit-status/channel Close and therefore cannot
be asserted as its cause. Controlled readiness RED proves a distinct fixture
invariant, not the historical failure's provenance. The original observation is
still **PENDING for parent validation disposition**, not fixed, preexisting,
expected, unrelated or waived by these passes. No endless unchanged batches.

### Final-source commands and retained environment failure

An initial attempt to make logs private used shell-wide umask077. That also
changed CLI test-created source deep.txt from0644 to0600; `TestRunCPEndToEnd`
correctly failed its literal0644 expectation (main_test.go source creation at
mode0644). Retained `/tmp/warden-t12-followup-umask077-focused-failure.log`.
This was a validation-environment change, **not fixed by production/test edits**:
precreate logs0600, restore ordinary umask022 for tests. The single CLI mode case
then PASS (`/tmp/warden-t12-followup-umask022-cli-check.log`). Chained race/full
commands after the failing initial command did NOT run. All checks below were
then freshly run, and refreshed again after the final late-start fixture fix:

```sh
# Output files precreated/chmod0600; ordinary test umask022.
go test ./internal/client/ssh ./internal/client/db ./internal/client/agent \
  ./cmd/warden -count=1 -timeout=180s
go test -race ./internal/client/ssh ./internal/client/db ./internal/client/agent \
  ./cmd/warden -count=1 -timeout=180s

go test -race ./internal/client/ssh ./internal/client/db ./internal/client/agent \
  -run '^Test(AuthenticationAgent|AgentAuthentication|GraphOwns|GraphCancellation|GraphCloses|SecondHop|ProxyCONNECT|NetworkNegotiation|ReusableHandshake|CancellationStop|DialTCPContext|DBChannel|BorrowedTunnelMissingTarget|TunnelClose|TunnelFixture|PoolShutdown|PoolCanceled|ServerExternalCancellation|RunInteractiveCtrlCForwardsByte|InteractiveFixture|PTYReadinessMarker)' \
  -count=25 -timeout=180s

go test ./... -count=1 -timeout=180s
go vet ./...
```

All **PASS**. Focused normal SSH1.669s/DB0.063s/agent11.761s/CLI0.130s;
race4.994s/1.150s/15.469s/2.320s; boundary race25 SSH33.227s/DB2.232s/agent3.248s.
Full suite includes SSH1.839s/DB0.082s/SFTP0.105s/runtime17.739s. Logs
`/tmp/warden-t12-followup-final-{focused,race,boundary-race25,full,vet}.log`.
Existing daemon/API-token characterizations run as part of the agent suites;
no token timer, persistence, expiry, rotation or daemon-lifetime change.

Final-source Windows amd64 SSH/DB/agent/CLI test cross-compilation and CLI build
PASS, refreshed at closing; `/tmp/warden-t12-followup-{ssh,db,agent,cli}.test.exe`
and `/tmp/warden-t12-followup-cli.exe`. This is **not native Windows execution**. Context7 unix reference
`ctx7:docs:cfe57f15c1482999eb8f3132` plus exact installed x/sys v0.47.0
`unix/ioctl_unsigned.go:58–74` checked for typed termios/int getters; Go1.25.14
CommandContext docs/source checked before fixture API use. Module files unchanged.

Follow-up-only source files: `internal/client/ssh/{cancel.go,graph.go,
cancel_cleanup_test.go,lifecycle_test.go,interactive_test.go,pty_fixture_test.go}`,
`internal/client/agent/transport_lifecycle_test.go`, and
`internal/client/db/tunnel_cancel_test.go`. This report, narrow T12 plan checkpoint
and ignored ledger record the evidence. Closing self-review covers abort-before-
blocking-cleanup/once semantics and healthy reuse, all fixture drain registrations
and joins, actual initialized foreground readiness, endpoint lifetime and canceled
late-child ownership. **27 full-task files** (including ignored ledger/new files)
pass explicit final-newline/trailing-whitespace/local-Markdown-target checks;
**21 Go files** are gofmt clean. `git diff --check` PASS, modules/release fields
unchanged, staged diff empty, branch/HEAD unchanged. Protected file excluded
before content reads. No source change after final runtime checks, only measured
evidence prose. No T13 or commit. Parent decides PTY validation disposition;
native Windows, genuine PRF/production trust, independent acceptance and T15
advisory remediation remain pending.

## Recurring parent failure and authorized sequencing correction — before edits

This checkpoint supersedes the preceding “not reproduced” and final-pass status
without erasing those historical results. Parent command
`go test ./... -count=1 -timeout=180s` failed
`TestRunInteractiveCtrlCForwardsByte` at10.08s;
`/tmp/warden-t12-parent-fixed-full.log:11–1319` retains diagnostics/stacks.
Its chained race command did **not** execute. Master03 and04 writes both returned
n=1,nil at62.512ms/62.583ms (71us apart); initialized shell/foreground/termios
were verified, but child Wait had not ended and output stopped at `^C\r\n$ `.
This is not the separately proven direct-test-binary/session-leader artifact.

Read-only diagnosis `/tmp/warden-t12-parent-repro-readonly-diagnosis.md` verified
all27 checkout hashes unchanged. Two focused traced batches (60 and90 cases) and
one shell-traced full Go run passed but only exercised approximately19–22ms
Ctrl-C→Ctrl-D gaps; they do not establish a fix. A native SSH/Go-independent PTY
probe then used the same `sh -c 'exec "$SHELL" -l'`, SHELL=/bin/sh, bootstrap,
controlling group and `lflag=8a3b`/VINTR03/VEOF04. Both untraced and shell-traced
immediate-single-EOT cases stalled for the full10s with the same prompt suffix.
The traced case shows **read(0)=0 consuming EOT, then pending kernel SIGINT,
then dash's new prompt and another blocking read**. There is **no TCFLSH syscall**;
the earlier flush hypothesis is not the demonstrated mechanism. The contrast
case waited for the actual post-SIGINT prompt, sent one EOT and exited130.
Artifacts: `/tmp/warden-t12-pty-ordering-probe.py` and
`/tmp/warden-t12-pty-ordering-probe/{results.json,traced-immediate.strace,
traced-post-interrupt-prompt.strace}`. The parent had no shell trace, so its exact
syscall interleaving remains unproven; no production TTY defect is claimed.

Owner now authorizes the **same T12, test/fixture-only** correction after P1/P2
review closed: establish an unambiguous new shell prompt acknowledgment after
Ctrl-C, distinct from startup/command echo/kernel03 echo, before the test sends
its one EOT. First extract the unchanged input sequence and demonstrate a
barrier-controlled RED: held acknowledgment must prevent early EOT. Preserve
zero SSH-INT requests, actual03 forwarding, the10s EOF exit bound and all resource
joins. No arbitrary sleep, EOT retry, signal conversion, exit-command shortcut or
production input/shell-command change. Fresh normal full Go first, focused/race,
boundary25, final normal full Go, vet/hygiene and Windows compile-only are pending;
new sequencing review and independent/external acceptance remain pending.

## Test-only sequencing RED→GREEN and current-source checks

Only `internal/client/ssh/interactive_test.go`,
`internal/client/ssh/pty_fixture_test.go`, this report, the T12 plan checkpoint
and ledger changed relative to the read-only27-file snapshot. **All production
files remain byte-identical to that snapshot**, including the input pump and
portable login-shell command. No new imports/third-party API calls or dependency
changes; the fixture uses ordinary POSIX PS1 assignment/printf with the installed
`/bin/sh`, not a new trap or vendor-specific signal interpretation.

### Deterministic regression before the fix

Extracted the original input sequence unchanged into
`sendInteractiveInterruptThenEOF`: write03, require actual master delivery and
zero SSH-INT, then write04. Before adding the acknowledgment call,
`TestInteractiveCtrlCSequenceWaitsForShellAcknowledgment` ran against that helper
and failed immediately: **sequence event `input:04`, want
`awaiting-shell-ack`; EOT must wait while shell acknowledgment is held**.
`/tmp/warden-t12-sequencing-red.log` retains this actual RED, not a statistical
repetition or post-hoc claim. The acknowledgment callback is held by a channel
barrier; ordered progress events distinguish a driver waiting there from an
early EOT. A one-second progress deadline fails rather than falsely accepting a
stalled driver. Release permits exactly one EOT, then the driver is joined,
including failure cleanup. No negative assertion relies on a blind sleep.

### Minimal GREEN and acknowledgment proof

- Test fixture sets a control-delimited PS1 word containing its unique listening
  address **after login profiles**, via octal-escaped bootstrap syntax. Terminal
  command echo therefore cannot contain the raw prompt marker. Startup readiness
  marker remains distinct. No production shell payload was changed.
- The real client's output sink counts complete private PS1 markers with a
  bounded `len(marker)-1` tail and a mutex. It preserves output unchanged and
  counts only bytes accepted by the sink. The test first observes the entire
  initial prompt, saves its generation **before Ctrl-C**, then waits for a later
  generation after actual03 master delivery. This acknowledges a new shell
  prompt, not kernel03 echo, stale initial `$`, or the startup marker.
- Only then does the shared input driver write its one EOT. The existing10s
  termination assertion and nil/status130 contract remain unchanged. After real
  endpoint/copy/request-drain/SSH-handler joins, the test additionally requires
  exact forwarded input `03 04` and no SSH-INT. Existing post-child-exit closed-
  file/copy/handler assertions were extracted unchanged into a shared helper and
  now also cover the Ctrl-C integration, before fixture-forced cleanup.
- `TestPTYShellPromptGenerationsRejectEchoAndStalePrompt` covers escaped bootstrap
  echo, actual startup marker, kernel echo, stale/partial initial and subsequent
  prompts, another fixture's marker, split/coalesced markers, retained-tail
  non-recounting and byte-for-byte output preservation. This is supporting
  parser/phase coverage, not a second fabricated production RED.

Focused three-case normal GREEN is retained in
`/tmp/warden-t12-sequencing-green.log` (package0.045s). The native probe explains
why the old delivery-only sequencing was invalid; this correction removes that
fixture assumption, **not a claimed production TTY bug or proof of the parent's
unobserved exact syscall ordering**.

### Validation environment failures, retained rather than hidden

The requested first normal full-Go attempt ran before focused/race repetitions:
`/tmp/warden-t12-sequencing-full-first.log`. SSH passed1.801s, but runtime linking
failed **disk quota exceeded**, with SQLite disk-I/O failures elsewhere. `/tmp`
is a tmpfs with `usrquota`; overall disk space was not exhausted. No source or
assertion workaround was made.

Moving TMPDIR under a descriptive private `/var/tmp/warden-t12-sequencing-*`
root removed the quota error but exceeded existing Linux AF_UNIX path bounds;
retained `...-full-first-var-tmp.log`. A shorter11-byte root fixed direct socket
fixtures but runtime agent readiness still failed
(`...-full-first-short-tmp.log`); the worst-case nested subprocess socket path
calculates as110 bytes instead of103 under `/tmp`. No startup bound was
increased. Calculating those fixture paths established that **TMPDIR=/var/tmp** itself
(8 bytes) keeps the worst nested path107 bytes, within Linux's107-byte bound.
Go still creates private0700 test/build subdirectories and removes them. Ordinary
test umask022 is preserved; logs are precreated0600. The resulting full pass is
`...-full-first-var-tmp-root.log` (22.575s). Then minor self-review strengthened
final INT/input assertions to run after joins and guaranteed driver-failure
cleanup joins; all final-source checks below were freshly run after those edits.
These environment failures are not T12 GREEN results or source fixes.

### Stable final-source commands and outcomes

Each command below used **TMPDIR=/var/tmp**, ordinary `go test` launcher,
GOTRACEBACK=all, GOMEMLIMIT=256MiB and GORACE=halt_on_error=1. The runner is private
`/tmp/warden-t12-sequencing-run.py`, not repository scaffolding. Every batch is
bounded below3min: external QUIT145s/KILL150s,2048 hard FDs/64MiB file size,
1024-test-FD/768MiB-test-RSS safety ceilings. Resource counts are safety evidence,
not replacements for real file closure and worker/request-drain/handler joins.

```sh
# FIRST stable-source ordinary full Go, before focused/race repetition
TMPDIR=/var/tmp go test ./... -count=1 -timeout=180s

TMPDIR=/var/tmp go test ./internal/client/ssh \
  -run '^Test(InteractiveCtrlCSequenceWaitsForShellAcknowledgment|PTYShellPromptGenerationsRejectEchoAndStalePrompt|RunInteractiveCtrlCForwardsByte)$' \
  -count=1 -v -timeout=60s
TMPDIR=/var/tmp go test -race ./internal/client/ssh \
  -run '^Test(RunInteractiveCtrlCForwardsByte|InteractiveCtrlCSequence|InteractiveFixture|PTY)' \
  -count=20 -cpu=1,2,4 -v -timeout=120s -failfast

TMPDIR=/var/tmp go test ./internal/client/ssh ./internal/client/db \
  ./internal/client/agent ./cmd/warden -count=1 -timeout=180s
TMPDIR=/var/tmp go test -race ./internal/client/ssh ./internal/client/db \
  ./internal/client/agent ./cmd/warden -count=1 -timeout=180s
TMPDIR=/var/tmp go test -race ./internal/client/ssh ./internal/client/db \
  ./internal/client/agent \
  -run '^Test(AuthenticationAgent|AgentAuthentication|GraphOwns|GraphCancellation|GraphCloses|SecondHop|ProxyCONNECT|NetworkNegotiation|ReusableHandshake|CancellationStop|DialTCPContext|DBChannel|BorrowedTunnelMissingTarget|TunnelClose|TunnelFixture|PoolShutdown|PoolCanceled|ServerExternalCancellation|RunInteractiveCtrlCForwardsByte|InteractiveCtrlCSequence|InteractiveFixture|PTY)' \
  -count=25 -timeout=180s

# AGAIN, after the focused/race/boundary checks; no source changes between
TMPDIR=/var/tmp go test ./... -count=1 -timeout=180s
TMPDIR=/var/tmp go vet ./...
```

All **PASS** on stable source. Logs and per-batch resource metadata are
`/tmp/warden-t12-sequencing-<label>.{log,resources.json}`:

| Label | Outcome |
| --- | --- |
| `full-stable-first` |22.587s elapsed; SSH1.855s, DB0.108s, runtime20.831s |
| `green` |Three cases/package0.045s |
| `pty-bounded` |420 PASS including60 Ctrl-C cases; package7.171s/elapsed7.960s; max10FD/50128KiB RSS; no resource signal |
| `focused` |SSH1.657s/DB0.057s/agent11.764s/CLI0.116s |
| `race` |SSH4.949s/DB1.148s/agent15.544s/CLI2.325s |
| `boundary-race25` |SSH33.293s/DB2.214s/agent3.249s |
| `full-final` |22.606s elapsed; SSH1.769s/DB0.099s/SFTP0.132s/runtime20.894s |
| `vet` |PASS |

No resource signals in any batch. Existing daemon/API-token tests run unchanged
within the agent suites. Fresh Windows-amd64 SSH/DB/agent/CLI test cross-compiles
and CLI build PASS (`...-windows.log`); PE32+ artifacts0700 under
`/var/tmp/warden-t12-sequencing-windows-MVES8c/`, directory0700. They are
**compile-only**, not native Windows or Linux-only prompt-test execution.

Current status: implementation/self-review and the named implementer checks are
evidenced; **independent sequencing review and a fresh parent normal full run
remain pending**. Parent should account for the observed `/tmp` user quota without
changing tests. T12 checkbox remains open; native Windows, genuine PRF/production
trust/browser acceptance, independent overall acceptance and T15 advisories are
not promoted to PASS. No T13, staging, commit, dependency/version/profile changes
or protected-file access.

Closing self-review: all27 task files passed final-newline/trailing-whitespace
checks, all21 Go files are gofmt clean,39 local Markdown targets exist,
`git diff --check` passes, staged diff is empty, module/release fields and
branch/HEAD are unchanged. `/tmp/warden-t12-sequencing-hygiene.json` records the
five-file authorization delta. Source review checks the initial-before03/new-
prompt-after03 ordering, raw versus escaped marker bytes, bounded split-marker
state, held-ack deterministic progress/cleanup joins, exact one-EOT/no-SSH-INT
assertions after resource joins, and unchanged10s exit/production input behavior.
Only evidence prose changed after final runtime checks. Stop for the new
sequencing review and fresh parent checks, not T13 or unconditional acceptance.
