# Warden Hub Design

**Date:** 2026-08-21  
**Status:** Ready for user review

## 1. Goal

Build a personal central hub for LLM agents and human operators. Warden provides one API-backed source of truth for connection profiles, CLI transport operations, project changelog reports, and a web management plane.

The system preserves current Warden's security intent: prevent accidental credential disclosure in prompts, command arguments, shell history, and diagnostics. It is a personal tool, not a same-user process security boundary.

## 2. Scope

### In scope for first release

- Linux x86-64 Warden server binary.
- Linux x86-64 and Windows x86-64 Warden client binary.
- Single HTTP listener serving API and embedded web UI.
- Tailnet-only deployment; no application authentication.
- SQLite server database.
- Separate plaintext 32-byte master-key file, protected by Unix ownership and mode `0600`.
- AES-256-GCM encryption for stored secret fields; no password KDF and no salt.
- SSH connection profiles with key/password authentication, ports, optional HTTP CONNECT proxy, and named jump chains.
- MySQL/MariaDB connection profiles, including direct and SSH-tunneled execution.
- CLI-first API client commands for SSH, DB, interactive SSH, configuration management, and reports.
- Interactive `xssh` wrapper that retrieves a complete profile through API and executes an in-process Go SSH client locally.
- Release-style project changelog reports containing project, title, summary, agent model, and server-generated timestamp.
- Audit records for API operations and credential/profile retrieval.

### Explicitly out of scope

- Public Internet exposure, user accounts, application login, or per-user authorization.
- Browser-based terminal or WebSocket PTY proxy.
- Server-side execution of SSH or DB commands.
- Native `ssh`, `sshpass`, `mysql`, `fzf`, or `nc` dependencies for client transport.
- SQLite access by clients.
- PostgreSQL or hosted MySQL as Warden's application database.
- File transfer, command retries, SQL rewriting, query limits, dump/restore, and approval workflows.
- Line-level change capture or automatic Git diff collection.

## 3. Deployment and trust model

`warden-server` runs as a Linux service on a tailnet node. It binds one configured listener intended to be reachable only through the tailnet. The deployment must not bind publicly by default; documentation and service examples should use a tailnet address or loopback plus a tailnet proxy.

The server has no application authentication. Tailnet membership is treated as full trust for the API. Any reachable tailnet peer can manage profiles, retrieve credentials, invoke client operations, and submit reports. This is an explicit MVP trade-off, not an accidental omission.

The server is the sole owner of SQLite and the master key. Clients never read the DB or a server config directory.

## 4. Binaries and command model

Use one Go module with two named build targets because server and client have different platform and dependency requirements:

- `warden-server`: Linux x86-64 server/API/UI binary.
- `warden`: Linux x86-64 and Windows x86-64 client/API wrapper binary.

Commands:

```text
warden-server serve
warden ssh <connection> "<command>"
warden db <connection> "<SQL>"
warden xssh [connection]
warden report create <project> --title <title> --summary <summary> --agent-model <name>
warden config list
warden config get <connection>        # redact secrets by default
```

There is no server mode in the cross-platform `warden` client. Separating artifacts prevents Linux-only service/storage concerns from entering Windows builds while preserving one repository and shared API types.

Every client command calls the HTTP API. The client never opens SQLite or reads server-side profile files. `xssh` is API-backed for profile retrieval, then performs local transport as required for a real terminal.

## 5. HTTP API

Serve API and web UI from one listener:

```text
/                 embedded management UI
/api/v1/...       JSON API used by web UI and CLI
```

API should use explicit versioned resources and JSON errors with stable machine-readable codes. Initial resource groups:

- `/api/v1/ssh-connections`
- `/api/v1/db-connections`
- `/api/v1/projects`
- `/api/v1/reports`
- `/api/v1/audit-events`
- `/api/v1/transport/...` for profile retrieval

Profile list/get endpoints redact secret fields. A dedicated transport-profile response returns the complete resolved transport bundle only for an explicit operation, records an audit event, and is held in client memory only. An SSH bundle contains the target plus every referenced jump profile and proxy credential required for local execution. A tunneled DB bundle contains the DB profile plus its complete resolved SSH graph. Server and client both validate missing references and cycles. Secret-bearing responses set `Cache-Control: no-store`; HTTP response logging must never include their bodies.

Use request and response size limits, context cancellation, strict JSON decoding, and parameterized SQL. Since there is no application auth, do not claim audit identity stronger than source address, user-agent, client-supplied agent model, and operation metadata.

## 6. SQLite storage

SQLite stores:

- SSH and DB connection metadata and encrypted secret values.
- Ordered SSH jump ID lists stored as JSON on `ssh_connections`.
- Projects.
- Changelog reports.
- Audit events.
- Schema/migration metadata.

Enable foreign keys, WAL mode, busy timeout, and migrations at startup. Keep DB on local disk, not NFS/shared storage. Create DB and parent directories with restrictive permissions and document backup requirements.

Connection names use the current Warden-safe pattern `[A-Za-z0-9._-]+`. Validate all profile fields and reject control characters where values become transport arguments or generated files.

Each SSH connection stores its ordered jump route in `jump_connection_ids` as a JSON array of integer SSH connection IDs:

```json
[12, 4]
```

The route means target -> connection 12 -> connection 4. SQLite does not enforce foreign keys inside this JSON value. Write operations validate only that the value is a syntactically valid JSON array of integer IDs; they allow missing IDs, self-reference, and cycles. Transport-profile retrieval resolves and validates the complete graph before returning any credentials: missing references, self-reference, or cycles produce a clear error before the client opens a network connection. On SSH deletion, official CLI/web clients first query and display dependent SSH and DB profiles, then allow deletion after confirmation. Direct API deletion is also allowed and does not reject dependencies. Stored routes remain unchanged and may therefore become logically invalid until edited.

Report fields:

```text
id           integer primary key
project      text not null       # 1-100 bytes; [A-Za-z0-9._-]+
title        text not null       # 1-200 UTF-8 bytes
summary      text not null       # 1-16384 UTF-8 bytes
agent_model  text not null       # 1-200 UTF-8 bytes; arbitrary caller value
created_at   timestamp not null  # UTC, generated by server
```

Reports are immutable and append-only in MVP: create and read/list only, with no update or delete endpoint. No version field, file list, diff, or line-by-line history.

Audit fields should include operation, resource type/name, source address, result, timestamp, and safe metadata. Never persist credentials, private keys, passwords, SQL text, or arbitrary remote command text in audit rows by default.

## 7. Secret encryption

Use AES-256-GCM with a random 32-byte key loaded from a separate file. Do not use bcrypt: bcrypt is a one-way password hash and cannot recover credentials needed for SSH/DB operations. Do not derive the key from a password, so no salt or KDF is needed.

Key file requirements:

```text
/etc/warden/master.key
32 random bytes
owned by service user
mode 0600
```

The server must refuse startup when the key is missing, has the wrong length, or has unsafe group/other permissions. The key is never stored in SQLite, API responses, logs, environment variables, or backups of the DB.

Each encrypted field is stored as a binary BLOB:

```text
[format version: 1 byte][nonce: 12 bytes][ciphertext + GCM tag]
```

AES-GCM overhead is 28 bytes: 12-byte nonce plus 16-byte authentication tag, in addition to the one-byte format marker. Store BLOBs rather than Base64 to avoid expansion. Generate a fresh cryptographically random nonce for every encryption operation. The nonce is public and stored beside ciphertext; the key remains secret.

Use associated authenticated data binding a value to its logical location, for example `warden/ssh/<id>/password`, to prevent ciphertext swapping between records or fields. Decryption failure is an error and must not be returned with secret material.

Secret fields include SSH passwords, private-key contents, private-key passphrases, DB passwords, and proxy credentials. Decrypt only while constructing an explicit transport response. Do not promise perfect memory zeroization in Go; overwrite temporary byte buffers where practical and avoid long-lived caches.

## 8. Client transport

The client implements transport with Go libraries so Linux and Windows clients do not require installed native tools.

### SSH

Use `golang.org/x/crypto/ssh` with:

- key and password authentication;
- configured host, port, and username;
- named jump chains with cycle and missing-reference validation;
- HTTP CONNECT proxy support implemented in Go;
- remote command execution with streaming stdin/stdout/stderr;
- interactive PTY for `xssh`;
- terminal resize and interrupt/EOF handling per platform;
- host-key verification against the client's platform-standard `~/.ssh/known_hosts` file;
- unknown or changed host keys fail by default;
- an explicit `--accept-new` option may persist an unknown key after showing its SHA-256 fingerprint and receiving confirmation on an interactive terminal; it never accepts changed keys and never prompts in agent/noninteractive mode.

The current Warden behavior of SSH multiplexing can be replaced by in-process connections. Host-key verification must not be weakened for cross-platform transport. The same verification applies independently to each jump host and final target.

`warden ssh <name> "<command>"` sends exactly one command string, streams output locally, and returns the remote command exit status. It must not put credentials in argv, environment, logs, or errors.

`warden xssh [name]` retrieves a complete SSH bundle, attaches to the caller's terminal, opens a PTY, and starts an interactive shell in the profile's optional default directory. When `name` is omitted, it opens a built-in searchable picker listing connection names and non-secret metadata; this replaces the `fzf` dependency from `new-xssh.sh`. The hub does not proxy terminal bytes and does not implement a web terminal.

### MySQL/MariaDB

Use a Go MySQL/MariaDB driver. `warden db <name> "<SQL>"` retrieves a profile, decrypts credentials only in the client process, and executes one SQL string locally. Stream database output in a stable CLI format and return driver/DB status without exposing credentials.

For DB profiles referencing an SSH connection, create an in-process local listener or equivalent `net.Conn` dialer over the SSH transport. Close the tunnel synchronously on command completion or cancellation. Validate the complete jump graph before opening any transport.

## 9. Web management plane

The embedded web UI is management-only. It uses the same JSON API as the CLI and does not provide an interactive terminal.

MVP screens:

- connection list and redacted detail;
- create/edit SSH and DB profiles;
- jump-chain and dependency validation feedback;
- project list;
- chronological project changelog entries;
- audit event list with secrets and command contents omitted.

The UI never provides “test connection” or credential-reveal actions in MVP because execution is client-local and ordinary management reads are redacted. UI is not a separate backend.

## 10. Error handling and security boundaries

- Treat API transport failures, malformed profiles, crypto failures, SSH failures, DB failures, and remote nonzero exits as distinct error classes.
- Preserve child operation exit status where applicable.
- Sanitize errors before returning them; never include passwords, private keys, connection response bodies, or generated secret paths.
- Cancel all network operations on context cancellation.
- Do not log SQL or remote commands by default; if diagnostic command logging is added, make it explicit and redact sensitive arguments.
- Reject unsafe profile names and malformed jump graphs before network operations.
- Limit report and profile field sizes.
- Ensure temporary files are unnecessary for normal transport; if a future platform requires one, use restrictive permissions and synchronous cleanup.

## 11. Testing and validation

Unit tests:

- AES-GCM round trip, fresh nonce, tamper detection, wrong-key failure, AAD binding, malformed blob handling.
- SQLite migrations, foreign keys, profile CRUD, jump-ID JSON syntax validation, query-time graph validation, dependency warnings on deletion, report CRUD, audit insertion, concurrent access settings.
- API validation, redaction, transport-profile response, error codes, request limits.
- SSH profile syntax validation, query-time jump-chain expansion/cycle/missing-reference detection, proxy dialing, command exit propagation.
- MySQL direct and SSH-tunneled dialing using fakes or test servers.
- Report fields and server-generated timestamps.

Integration tests:

- Start server with temporary DB/key and call it through client.
- Verify secret-bearing responses use `Cache-Control: no-store` and ordinary profile reads are redacted.
- Verify client never needs SQLite or server config files.
- Verify `ssh`, `db`, `xssh`, and `report create` are API-backed.
- Verify secrets are absent from logs, normal output, and error text.
- Verify unknown SSH keys fail by default, explicit first-use acceptance persists a new key, and changed keys always fail.
- Verify Linux and Windows client builds; run platform-specific PTY tests on native/CI runners where available.

Performance tests should cover encryption/decryption for credential-sized values. AES-GCM with a random key and small payloads is expected to be negligible compared with SQLite and network operations; no bcrypt/KDF is used.

## 12. Delivery phases

1. Repository/bootstrap, build targets, configuration, SQLite migrations, key-file validation, and crypto package.
2. Profile CRUD API and CLI client with redacted listing.
3. Cross-platform SSH command transport and jump/proxy support.
4. MySQL direct and SSH-tunneled transport.
5. Interactive cross-platform `xssh` PTY support.
6. Report API/CLI and audit records.
7. Embedded web management UI.
8. Integration tests, Linux/Windows release builds, service/deployment documentation.

Phase boundaries keep transport correctness independent from UI work. No implementation should begin until this design is approved.
