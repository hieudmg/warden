# File-transfer design

## Goal

Add `warden cp <source> <destination>` for recursive file transfer between local filesystem paths and configured SSH connections. It follows ordinary `cp` placement and overwrite behavior without flags, while retaining Warden's existing credential, jump-chain, and host-key-verification model.

## Scope

- Copy one file or recursively copy one directory.
- Support local-to-remote, remote-to-local, and remote-to-remote paths.
- Require at least one remote endpoint. Local-to-local is rejected rather than duplicating operating-system `cp`.
- Overwrite existing files by default.
- Create missing destination directories.
- Use SFTP over SSH connections created by Warden; do not invoke a native `ssh`, `scp`, or `rsync` executable.

Out of scope: flags, delta transfer, resume, delete/synchronization semantics, ownership and timestamp preservation, and symlink or special-file transfer.

## CLI contract

```text
warden cp <source> <destination>
```

An endpoint in the form `<connection>:<path>` is remote; the connection must match a configured SSH profile. An endpoint without `:` is local. Windows volume paths (`C:\...`) are explicitly recognized as local paths.

Empty connection/path components and local-to-local copies are usage errors (exit 2). Connection lookup failures and transfer failures exit 1. Successful transfers write no stdout output; stderr provides contextual progress/error messages.

## Copy semantics

- A file source writes to the destination file, replacing it if present. If the destination names an existing directory, its basename is appended.
- A directory source is recursive. If destination is an existing directory, its basename is appended and its contents merge there. If destination does not exist, destination becomes the copied directory root.
- Missing parent directories are created.
- Source symlinks and special files fail rather than being followed or copied. A directory cannot be copied into itself.
- New/replaced files and directories receive source mode bits. Ownership and timestamps are not preserved.
- Files transfer through a temporary sibling at destination and rename into place only after the byte stream and close succeed. Failed transfers remove temporary files where possible.

## Architecture

Add `github.com/pkg/sftp` as a direct dependency. Its `NewClient(*ssh.Client)` API accepts Warden's already-dialed SSH client, preserving encrypted-profile credentials, local SSH-agent support, host-key policy, and jump chains.

Add an `internal/client/sftp` package with:

- endpoint-independent filesystem interfaces/adapters for local and SFTP operations;
- recursive source traversal and destination placement calculation;
- copy routines that stream files, create directories, apply mode bits, and perform temporary-file replacement;
- explicit close/cleanup ownership for SFTP clients and SSH dial chains.

`cmd/warden/main.go` adds `cp` dispatch, argument/help handling, endpoint parsing, SSH-profile resolution, bundle fetching, transfer invocation, and CLI-formatted errors. The existing `internal/client/ssh` dialer creates the SSH clients needed for each remote endpoint.

For remote-to-remote transfer, Warden opens independent source and destination SFTP clients and relays each file through the local Warden process. No remote shell command or trust relationship between remote hosts is required.

## Failure handling

Report contextual errors for inaccessible paths, unknown connections, incompatible existing destination types, directory self-copy, SFTP failures, and close/rename failures. Stop at the first error. Clean temporary destination files best-effort; never replace final destination after a failed stream.

## Verification

Add unit tests for endpoint parsing, invalid argument combinations, source/destination placement, recursive traversal, directory self-copy rejection, overwrite, mode application, and temporary-file cleanup.

Extend CLI/transport tests with in-process SSH/SFTP fixtures for local-to-remote, remote-to-local, and remote-to-remote file and directory copies; verify existing Warden host-key behavior and SSH-client closure. Update root help and `README.md` command examples.
