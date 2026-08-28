# SSH Connection Agent Design

## Goal

Make Warden reuse authenticated SSH transport graphs across separate noninteractive CLI invocations without changing command syntax. A background per-user agent owns those graphs in memory, expires an unused graph ten minutes after its last operation finishes, and exits when every graph has expired.

## Scope

The agent is transparent to callers of:

- `warden ssh <connection> <command>`
- `warden cp <source> <destination>` when either endpoint is remote
- `warden db <connection> <sql>` only when the resolved DB bundle includes SSH

`warden xssh` remains a direct interactive SSH process. Direct database connections, configuration lookup, reports, and all server behavior remain unchanged.

## Architecture

### Per-user agent and IPC

`warden agent serve` is an internal, undocumented command implemented by the same client executable. A normal noninteractive transport command attempts to authenticate to its current-user agent first. On no listener it starts `warden agent serve` detached, waits for readiness, then retries. Concurrent callers may all attempt startup; only process that creates local listener survives, and all clients attach to it.

The endpoint is OS-specific:

- Linux/macOS: socket under private per-user runtime directory, with directory mode `0700` and socket mode `0600`.
- Windows: named pipe scoped to current user, protected by a Windows security descriptor that permits only its owner.

Agent state contains a random 256-bit token. State and IPC endpoint are readable only by current OS user. Every request begins with protocol version and token authentication. Agent creates state atomically with the listener startup sequence; callers retry a short bounded interval while another process is initializing. Shutdown removes state and socket files. Nothing containing credentials, SQL, commands, or transfer paths is persisted.

Protocol uses length-prefixed JSON frames on one `net.Conn` per CLI call. Frames carry a versioned request envelope and byte payloads as JSON base64. Output frames stream stdout and stderr. SSH calls also stream stdin frames client-to-agent and an EOF frame; terminal frame contains success, remote exit status, or sanitized error. A framed protocol avoids concurrent write interleaving and supports full-duplex SSH sessions. The agent never writes request bodies or frames to logs.

### Bundle resolution and graph cache

The CLI continues its existing API list/profile lookup and retrieves a fresh resolved transport bundle for every invocation. It sends the bundle only over authenticated local IPC. The agent keys graphs by SHA-256 of a deterministic encoding of the full `model.SSHBundle`, including every hop, proxy setting, credential, and key material. Thus a server-side profile or credential change selects a new graph instead of silently reusing obsolete transport state. Only the fixed-length hash is retained as cache identity.

Introduce `ssh.Graph`, which owns target client plus ordered jump-client chain and provides safe concurrent access to target channels. `DialGraph` preserves existing strict host-key, jump, proxy, and ssh-agent-forwarding behavior. One-shot helpers continue to dial a graph, run, and close it. New helpers execute against an existing graph without closing it.

Agent pool leases one graph per operation. A lease increments active count before an operation opens any SSH session, SFTP channel, or DB tunnel. Releasing the final lease records `lastUsed` and schedules expiry at `lastUsed + 10 minutes`. Expiry never closes active graphs. On expiry the pool closes target-to-jump and removes the entry. When no entry or operation remains, agent shuts down itself. A fresh operation cancels/replaces its scheduled expiry.

If a graph cannot open a new channel/session, mark it retired and remove it from future lookup. In-flight leases finish or fail naturally; after their final release graph closes. Agent may establish a replacement before executing a not-yet-started operation. It never retries a command, SQL statement, or transfer after operation data may have reached remote endpoint.

### Operation adapters

Existing command parsing, validation, API errors, output formatting, and exit-code mapping remain in `cmd/warden`. Only execution moves to agent where SSH is involved.

- `ssh`: client sends command and stream frames. Agent leases target graph and creates an SSH session on it. It preserves stdin/stdout/stderr streaming and `ExitStatusError` mapping.
- `cp`: client resolves remote endpoint names and bundles. It converts local operand paths to absolute paths before IPC, because agent working directory belongs to original starter process and cannot represent subsequent client working directories. Agent opens an SFTP client per remote operation on leased graph(s), uses existing endpoint/filesystem and copy validation, and closes only SFTP clients when copy ends. It retains existing same-host and self-copy checks.
- `db`: direct DB bundle still calls `db.RunQuery` in CLI. SSH-backed DB request goes to agent, which leases graph and passes target client into tunnel dialer. MySQL connection and direct-tcpip channels close at operation end; leased graph remains cached.

Refactor SFTP and DB tunnel construction so their existing standalone paths remain ownership-safe: one-shot constructors own and close a newly dialed graph; agent constructors consume a borrowed graph/client and close only operation-specific SFTP/MySQL resources.

## Failure, lifecycle, and compatibility

A remote disconnect, failed `NewSession`, failed SFTP construction, or failed tunnel-channel creation evicts only that graph. Error text remains sanitized by existing SSH/DB behavior. A client failure to reach, authenticate to, or receive a valid protocol response from agent fails the invocation without printing secrets; an unavailable/stale agent is restarted once before returning its normal command error.

Long-running operations keep their lease and cannot trigger idle shutdown. Agent handles termination signals by stopping accepts, waiting only for active request cleanup, closing every graph target-to-jump, and deleting Unix state files. A crash leaves no credentials on disk; later client startup removes a stale Unix socket only from validated private runtime directory. Windows named-pipe instances vanish when their process exits.

No public command-line flag, client configuration setting, or server API changes. Existing help text excludes internal `agent serve`. Client and agent protocol version mismatch is detected before operation data; caller starts current executable only after stale agent has exited, otherwise reports a version error rather than sending a request to an unknown peer.

## Testing

Unit-test graph ownership and pool with injectable clock/dialer:

- same bundle reuses one authenticated graph across concurrent SSH session, SFTP, and DB tunnel creation;
- graph does not expire while leased, expires exactly ten minutes after final release, closes entire jump chain target-first, and agent ends after final graph removal;
- changed bundle fingerprint uses new graph;
- dead graph is retired and safe pre-execution replacement is used without replaying started work;
- pool startup races establish one listener and token authentication rejects absent/wrong tokens.

IPC integration tests verify frame order, stdin/stdout/stderr forwarding, exit status, malformed-frame rejection, and no protocol leakage in errors. CLI end-to-end tests use existing in-process SSH/MySQL fixtures to verify sequential `ssh`, `cp`, and tunneled `db` commands open one SSH connection, while direct DB and `xssh` bypass agent. OS-specific runtime tests cover Unix private socket permissions and Windows named-pipe compilation/security configuration.

## Documentation

README documents transparent reuse, included commands, strict host-key behavior remaining unchanged, ten-minute post-operation graph TTL, self-termination once idle, and explicit exclusion of `xssh` and direct DB connections.
