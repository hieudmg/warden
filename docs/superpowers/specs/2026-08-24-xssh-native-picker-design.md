# Native `xssh` picker design

## Goal

Replace `warden xssh`'s line-based picker with a cross-platform, fzf-style, full-screen terminal UI. It must remain part of the Warden executable: no `fzf` dependency or bundled platform binaries.

## Scope

`warden xssh` with no connection argument opens the picker. `warden xssh <connection>` keeps its current direct-connection behavior.

The picker provides:

- Case-insensitive search across connection profile name and hostname.
- Arrow-key selection, Enter to connect, Backspace to edit query, and Esc or Ctrl-C to abort.
- A two-column layout: searchable host list on left and selected profile configuration on right.
- A stacked layout on terminals narrower than 80 columns.
- Redraw on terminal resize.
- Colorized display: cyan title and borders, yellow search query, high-contrast selected row, and distinct labels and values.

## Preview redaction

The picker receives only `model.SSHConnection`, the existing redacted API representation. It renders every profile field. Sensitive values are never fetched or rendered; their presence booleans are displayed as `[configured]` or `[not configured]`:

- Password
- Private key
- Private-key passphrase
- Proxy password

All other fields are shown, including ID, host, port, username, proxy metadata, jump connection IDs, default directory, and timestamps.

## Architecture

Add an `internal/client/picker` package with isolated components for:

- Picker state: query, filtered connection indices, selected index, and selection result.
- Key decoding: printable characters, Backspace, arrows, Enter, Esc, and Ctrl-C.
- Rendering: ANSI screen lifecycle, responsive two-column/stacked layout, color styling, and redacted configuration formatting.
- Interaction loop: applies decoded keys, listens for terminal resize events, and redraws.

The package consumes the existing `internal/client/terminal.Session` interface. It adds no third-party terminal UI dependency.

## Data flow and terminal lifecycle

1. `runXSSH` loads the existing redacted SSH connection list.
2. With no explicit connection, it creates a terminal session for the picker.
3. Picker enters raw mode, switches to the alternate screen, hides cursor, and returns only a selected redacted connection ID or a clear error.
4. Picker cleanup always restores cursor, normal screen, and terminal mode.
5. Only after selection, `runXSSH` fetches the existing secret SSH bundle.
6. `runXSSH` creates a fresh terminal session for the existing interactive SSH transport. A second session is required because terminal sessions are single-use after `Restore`.

No credential values are introduced to picker memory or output.

## Compatibility and errors

Unix terminals and Windows consoles use Warden's existing raw-terminal implementations. Picker requires ANSI/VT rendering; an unsupported console must fail clearly rather than display corrupt escape sequences. Non-terminal input, no configured connections, cancellation, input failures, and rendering failures return actionable errors and always restore terminal state.

## Tests

- Unit tests for case-insensitive filtering, selection movement and bounds, and key decoding.
- Renderer tests for wide and narrow layouts, color output, redacted presence markers, and no secret-value output.
- Interaction tests with fake terminal sessions for Enter, cancellation, resize redraw, and terminal cleanup.
- Existing direct-connection and SSH integration tests remain.
- Run full Go test suite on Linux and cross-compile the Windows CLI target to detect platform interface regressions.

## Documentation

Update `README.md` with picker behavior, keys, search scope, colorized layout, responsive fallback, and preview redaction.
