# Native xssh Picker Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace `warden xssh`'s line-based connection prompt with a colorized, cross-platform, searchable two-pane terminal picker.

**Architecture:** Add a dependency-free `internal/client/picker` package that owns query state, raw key decoding, safe rendering, and picker lifecycle. `cmd/warden` supplies redacted `model.SSHConnection` records to it, restores its terminal session after a selection, then fetches the existing secret bundle and starts the existing interactive SSH transport in a new session.

**Tech Stack:** Go 1.25, standard library ANSI rendering, existing `golang.org/x/term`, `golang.org/x/sys`, and Warden `terminal.Session` abstraction.

**Spec:** `docs/superpowers/specs/2026-08-24-xssh-native-picker-design.md`

## Global Constraints

- Keep picker native to Warden: do not add `fzf`, Bubble Tea, or any other terminal UI dependency; do not bundle binaries.
- Support Unix terminals and Windows consoles through `internal/client/terminal`.
- Search case-insensitively across profile name and hostname.
- Keep `warden xssh <connection>` direct connection behavior unchanged.
- Render secret values only as `[configured]` or `[not configured]`; never fetch or print their values in picker.
- Show every field of redacted `model.SSHConnection`, including empty safe fields and presence markers.
- Use alternate screen, restore cursor/screen/raw mode on every picker outcome, and redraw on resize.
- Use two columns at widths >= 80 and a stacked layout below 80 columns.

---

## File structure

| Path | Responsibility |
| --- | --- |
| `internal/client/picker/picker.go` | Public picker entry point, state transitions, filter/selection rules, and typed picker result/errors. |
| `internal/client/picker/key.go` | Incremental raw-byte decoder for printable input, editing, navigation, confirmation, and cancellation. |
| `internal/client/picker/render.go` | ANSI screen lifecycle, safe value formatting, colors, wide/stacked layout, and output truncation. |
| `internal/client/picker/picker_test.go` | State, filtering, key-decoding, interaction, resize, cleanup, and redaction tests using a fake terminal. |
| `internal/client/terminal/terminal.go` | Extends session contract with ANSI capability reporting. |
| `internal/client/terminal/terminal_unix.go` | Reports ANSI support for Unix terminal session. |
| `internal/client/terminal/terminal_windows.go` | Tracks whether virtual-terminal output was enabled for Windows console session. |
| `internal/client/terminal/terminal_windows_test.go` | Covers Windows ANSI-capability state without a live Windows console. |
| `cmd/warden/main.go` | Replaces line picker invocation with native picker and creates separate picker/SSH sessions. |
| `cmd/warden/main_test.go` | Removes line-prompt behavior tests; preserves direct `xssh <connection>` coverage and adds picker error propagation seam if needed. |
| `README.md` | Documents interactive picker controls, layout, redaction, and Windows terminal requirement. |

## Task 1: Picker state and raw key decoder

**Files:**
- Create: `internal/client/picker/picker.go`
- Create: `internal/client/picker/key.go`
- Create: `internal/client/picker/picker_test.go`

**Interfaces:**
- Consumes: `model.SSHConnection` from `warden/internal/model`.
- Produces: `type State struct`, `func NewState([]model.SSHConnection) State`, `func (State) Filtered() []model.SSHConnection`, `func (State) Selected() (model.SSHConnection, bool)`, and `func (State) Apply(DecodedKey) State`.
- Produces: `type Key uint8`, constants `KeyRune`, `KeyBackspace`, `KeyUp`, `KeyDown`, `KeyEnter`, and `KeyCancel`; `func DecodeBytes([]byte) []DecodedKey` where `DecodedKey` carries `Kind Key` and `Rune rune`; and `type StreamDecoder` with `func (*StreamDecoder) Feed([]byte) []DecodedKey` plus `func (*StreamDecoder) Flush() []DecodedKey`.
- Later tasks rely on selection always being clamped to the filtered result count and the query matching lowercased `Name` or `Host`.

- [ ] **Step 1: Write failing state and decoder tests**

```go
func TestStateFiltersNameAndHostCaseInsensitively(t *testing.T) {
    conns := []model.SSHConnection{
        {ID: 1, Name: "prod-web", Host: "10.0.0.1"},
        {ID: 2, Name: "bastion", Host: "edge.example.test"},
    }
    state := NewState(conns)
    state = state.Apply(DecodedKey{Kind: KeyRune, Rune: 'E'})
    state = state.Apply(DecodedKey{Kind: KeyRune, Rune: 'D'})
    state = state.Apply(DecodedKey{Kind: KeyRune, Rune: 'G'})
    if got := state.Filtered(); len(got) != 1 || got[0].ID != 2 {
        t.Fatalf("Filtered() = %#v, want bastion", got)
    }
}

func TestStateNavigationAndQueryReset(t *testing.T) {
    state := NewState([]model.SSHConnection{{ID: 1, Name: "alpha"}, {ID: 2, Name: "beta"}})
    state = state.Apply(DecodedKey{Kind: KeyDown})
    selected, ok := state.Selected()
    if !ok || selected.ID != 2 { t.Fatalf("selected = %#v, %t; want beta, true", selected, ok) }
    state = state.Apply(DecodedKey{Kind: KeyRune, Rune: 'a'})
    state = state.Apply(DecodedKey{Kind: KeyBackspace})
    selected, ok = state.Selected()
    if !ok || selected.ID != 1 { t.Fatalf("selection after filter reset = %#v, %t; want alpha, true", selected, ok) }
}

func TestDecodeBytesRecognizesNavigationAndCancel(t *testing.T) {
    got := DecodeBytes([]byte("a\x7f\x1b[A\x1b[B\r\x03\x1b"))
    want := []DecodedKey{
        {Kind: KeyRune, Rune: 'a'}, {Kind: KeyBackspace}, {Kind: KeyUp},
        {Kind: KeyDown}, {Kind: KeyEnter}, {Kind: KeyCancel}, {Kind: KeyCancel},
    }
    if !reflect.DeepEqual(got, want) { t.Fatalf("DecodeBytes() = %#v, want %#v", got, want) }
}
```

- [ ] **Step 2: Run focused tests to verify failure**

Run: `go test ./internal/client/picker -run 'Test(State|Decode)' -count=1`

Expected: FAIL because package and exported state/decoder APIs do not exist.

- [ ] **Step 3: Implement minimal state and decoder**

In `picker.go`, retain original connection ordering. Store `query string`, `matches []int` (indexes into immutable source slice), and `selected int`. Rebuild matches after every rune/backspace by applying:

```go
needle := strings.ToLower(state.query)
if strings.Contains(strings.ToLower(c.Name), needle) ||
   strings.Contains(strings.ToLower(c.Host), needle) {
    state.matches = append(state.matches, index)
}
```

Set `selected = 0` after every query edit. For `KeyUp` and `KeyDown`, clamp within `0..len(matches)-1`; leave it at zero when no records match. `Selected` returns `(model.SSHConnection{}, false)` with no matches.

In `key.go`, decode bytes without dependencies:

- Printable UTF-8 runes become `KeyRune` events; ignore non-printable control bytes other than supported controls.
- `\b` and `0x7f` become `KeyBackspace`.
- `\r` and `\n` become `KeyEnter`.
- `0x03` becomes `KeyCancel`.
- `ESC [ A` becomes `KeyUp`, `ESC [ B` becomes `KeyDown`, and bare `ESC` becomes `KeyCancel`.

Implement `StreamDecoder` as the incremental decoder used by interaction loop. `Feed` retains incomplete `ESC` or `ESC [` bytes and emits events only when the full sequence arrives; `Flush` converts remaining lone `ESC` to `KeyCancel` and drops other incomplete sequences. `DecodeBytes` creates a `StreamDecoder`, calls `Feed`, then calls `Flush`, so unit tests can treat a final lone ESC as cancellation. Add `TestStreamDecoderBuffersPartialArrow` with `Feed([]byte("\\x1b["))` returning no keys and subsequent `Feed([]byte("A"))` returning `KeyUp`.

- [ ] **Step 4: Run focused tests to verify pass**

Run: `go test ./internal/client/picker -run 'Test(State|Decode)' -count=1`

Expected: PASS.

- [ ] **Step 5: Commit state and decoder**

```bash
git add internal/client/picker/picker.go internal/client/picker/key.go internal/client/picker/picker_test.go
git commit -m "Add xssh picker state and input decoding"
```

## Task 2: ANSI capability, renderer, and picker interaction loop

**Files:**
- Modify: `internal/client/terminal/terminal.go`
- Modify: `internal/client/terminal/terminal_unix.go`
- Modify: `internal/client/terminal/terminal_windows.go`
- Modify: `internal/client/terminal/terminal_windows_test.go`
- Modify: `internal/client/picker/picker.go`
- Modify: `internal/client/picker/key.go`
- Create: `internal/client/picker/render.go`
- Modify: `internal/client/picker/picker_test.go`

**Interfaces:**
- Consumes: `terminal.Session` methods `EnterRaw() error`, `Restore() error`, `Size() (int, int)`, `ResizeEvents() <-chan struct{}`, `Stdin() io.Reader`, and `Stdout() io.Writer`.
- Produces: `terminal.Session.SupportsANSI() bool` and `func Select(terminal.Session, []model.SSHConnection) (model.SSHConnection, error)`.
- Produces: `func Render(io.Writer, State, width, height int)` and `func FormatConnection(model.SSHConnection) []Field` where `Field` has `Label string` and `Value string`.
- Later task relies on `Select` returning selected redacted connection only after cleanup, or an error containing `selection aborted`, `no ssh connections configured`, or `does not support ANSI`.

- [ ] **Step 1: Write failing renderer, redaction, and interaction tests**

Create a `fakeSession` in `picker_test.go` implementing `terminal.Session` with `bytes.Reader` input, a mutex-protected `lockedBuffer` output (with `Write`, `String`, and `Count` methods), fixed `width`/`height`, `resize chan struct{}`, `ansi bool`, and counters for `EnterRaw`/`Restore`. Add a `fieldsText([]Field) string` test helper that joins each field's label and value.

```go
func TestFormatConnectionRedactsSecretsAndShowsAllFields(t *testing.T) {
    c := model.SSHConnection{
        ID: 7, Name: "prod", Host: "db.example.test", Port: 2222, Username: "deploy",
        HasPassword: true, HasPrivateKey: false, HasPrivateKeyPassphrase: true,
        ProxyHost: "proxy.example.test", ProxyPort: 8080, ProxyUsername: "proxy-user",
        HasProxyPassword: true, JumpConnectionIDs: "[1,2]", DefaultDir: "/srv/app",
    }
    output := fieldsText(FormatConnection(c))
    for _, want := range []string{"ID", "prod", "Host", "db.example.test", "Password", "[configured]", "Private key", "[not configured]", "Proxy password", "Jump connection IDs", "Default directory"} {
        if !strings.Contains(output, want) { t.Fatalf("preview missing %q: %q", want, output) }
    }
}

func TestRenderUsesWideAndStackedLayouts(t *testing.T) {
    state := NewState([]model.SSHConnection{{ID: 1, Name: "prod", Host: "host"}})
    var wide, narrow bytes.Buffer
    Render(&wide, state, 100, 20)
    Render(&narrow, state, 79, 20)
    if !strings.Contains(wide.String(), "│") { t.Fatalf("wide render lacks column separator: %q", wide.String()) }
    if strings.Contains(narrow.String(), "│") { t.Fatalf("narrow render has column separator: %q", narrow.String()) }
    if !strings.Contains(wide.String(), "\x1b[") { t.Fatalf("wide render lacks ANSI color: %q", wide.String()) }
}

func TestSelectRestoresTerminalAndReturnsHighlightedConnection(t *testing.T) {
    session := newFakeSession("\x1b[B\r", 100, 24, true)
    got, err := Select(session, []model.SSHConnection{{ID: 1, Name: "one"}, {ID: 2, Name: "two"}})
    if err != nil || got.ID != 2 { t.Fatalf("Select() = %#v, %v; want ID 2, nil", got, err) }
    if session.rawCalls != 1 || session.restoreCalls != 1 { t.Fatalf("raw/restore = %d/%d, want 1/1", session.rawCalls, session.restoreCalls) }
    if !strings.Contains(session.output.String(), "\x1b[?1049h") || !strings.Contains(session.output.String(), "\x1b[?1049l") { t.Fatal("alternate screen was not entered and restored") }
}
```

Also add tests that: an empty list errors before raw mode; `"\x03"` returns `selection aborted` and restores terminal; `ansi=false` returns an error containing `does not support ANSI`; and `sanitize` converts `\x1b`, `\r`, `\n`, and `\t` in profile fields into visible escaped text so config cannot inject terminal control sequences. Test resize by creating a fake session backed by `io.Pipe`: run `Select` in a goroutine, wait until initial render is written, record `before := output.Count("\\x1b[2J")`, send `session.resize <- struct{}{}`, wait until clear-screen count exceeds `before`, then write `\r` to pipe and assert `Select` returns. In `terminal_windows_test.go`, add `TestWindowsSessionReportsANSICapability` by toggling the new `ansi` field and asserting `SupportsANSI` returns its value.

- [ ] **Step 2: Run focused tests to verify failure**

Run: `go test ./internal/client/picker -run 'Test(Format|Render|Select)' -count=1`

Expected: FAIL because `Select`, `Render`, `FormatConnection`, and fake-session contract do not exist.

- [ ] **Step 3: Implement safe ANSI rendering and interaction**

First add `SupportsANSI() bool` to `terminal.Session`. Implement it as `return true` for `unixSession`. Add `ansi bool` to `windowsSession`; in `EnterRaw`, set it true only when `windows.SetConsoleMode(outH, s.origOut|winOutputVTExtra)` succeeds, and false when output mode cannot be read or VT mode cannot be enabled. Preserve existing interactive SSH behavior: VT setup remains best-effort, but only picker rejects an ANSI-incapable session.

Then implement `Select` with this lifecycle:

```go
if len(conns) == 0 { return model.SSHConnection{}, errors.New("no ssh connections configured") }
if err := session.EnterRaw(); err != nil { return model.SSHConnection{}, fmt.Errorf("enter picker raw mode: %w", err) }
defer session.Restore()
if !session.SupportsANSI() { return model.SSHConnection{}, errors.New("terminal does not support ANSI rendering; use a modern terminal") }
enterAlternateScreen(session.Stdout())
defer leaveAlternateScreen(session.Stdout())
```

`enterAlternateScreen` must write `\x1b[?1049h\x1b[2J\x1b[H\x1b[?25l`. `leaveAlternateScreen` must write `\x1b[?25h\x1b[?1049l`.

Keep all terminal input reads in `Select`'s calling goroutine: do not leave a blocked stdin-reader goroutine after selection, because it could consume keys from the subsequent SSH session. Use `bufio.Reader` over `session.Stdin()` and feed received bytes to `StreamDecoder`. For a leading ESC, inspect buffered bytes for the `[A`/`[B` continuation before calling `Flush`; a bare ESC cancels immediately. Unix and Windows VT arrow sequences are normally delivered as this buffered sequence.

Start one resize-render goroutine only. Guard `State` snapshots and writes to `session.Stdout()` with a mutex; it reads `ResizeEvents()`, locks, renders current state, and unlocks. Give it a `done` channel and `sync.WaitGroup`; on every exit, close `done`, wait for this goroutine, then leave alternate screen and restore raw mode. This guarantees no picker goroutine remains to consume SSH input. The calling goroutine renders once before input loop, renders after each state-changing key, and returns selection or cancellation.

Use ANSI SGR styles only through constants, for example:

```go
const (
    reset = "\x1b[0m"
    cyan = "\x1b[36m"
    yellow = "\x1b[33m"
    blue = "\x1b[34m"
    selected = "\x1b[7;36m"
)
```

Render a title, `Search: <query>` prompt, left list, and right selected `FormatConnection` fields. At width >= 80, split width into `leftWidth := width * 45 / 100` and the remaining right width with a visible `│` separator. At narrower widths, show list first and fields beneath it. Clamp each displayed line by rune count to its pane width and use `sanitize` before writing model values.

`FormatConnection` must always emit fields in this order: ID, Name, Host, Port, Username, Password, Private key, Private-key passphrase, Proxy host, Proxy port, Proxy username, Proxy password, Jump connection IDs, Default directory, Created at, Updated at. For each `Has*` field use exact marker strings `[configured]` and `[not configured]`. Format timestamps with `time.RFC3339`; show zero time as `(not set)`. Show empty safe string fields as `(not set)` and zero proxy port as `(not set)`.

- [ ] **Step 4: Run focused tests to verify pass**

Run: `go test ./internal/client/picker ./internal/client/terminal -count=1`

Expected: PASS, including state, decoder, redaction, wide/stacked layout, cancellation, cleanup, resize, and Unix terminal capability tests. Task 4 compiles the Windows-specific capability test without attempting to execute it on the host OS.

- [ ] **Step 5: Commit renderer and loop**

```bash
git add internal/client/terminal/terminal.go internal/client/terminal/terminal_unix.go internal/client/terminal/terminal_windows.go internal/client/terminal/terminal_windows_test.go internal/client/picker/picker.go internal/client/picker/key.go internal/client/picker/render.go internal/client/picker/picker_test.go
git commit -m "Add colorized xssh terminal picker"
```

## Task 3: Integrate native picker with `xssh`

**Files:**
- Modify: `cmd/warden/main.go`
- Modify: `cmd/warden/main_test.go`

**Interfaces:**
- Consumes: `picker.Select(terminal.Session, []model.SSHConnection) (model.SSHConnection, error)` and `terminal.Session.SupportsANSI() bool` from Task 2.
- Produces: `runXSSH` that creates one terminal session for selection and a fresh one for `clientssh.RunInteractive`.
- Existing `clientssh.RunInteractive(context.Context, model.SSHBundle, terminal.Session, bool)` remains unchanged.

- [ ] **Step 1: Write failing CLI integration tests**

Replace `TestPickConnectionSelectsByNumber`, `TestPickConnectionExactName`, `TestPickConnectionFilterNarrowsAndSelects`, and `TestPickConnectionAbort`: they test the deleted line-based interaction and must not survive as false requirements. Keep `TestPickConnectionEmptyList` as an equivalent `picker.Select` test in the picker package.

In `cmd/warden/main_test.go`, retain and run `TestRunXSSHUnknownConnection` and `TestRunXSSHRequiresInteractiveTerminal`. Add assertion that no explicit connection still reports the terminal creation error instead of falling back to buffered input when test stdin is not interactive:

```go
exitCode := run([]string{"xssh"}, &stdout, &stderr, lookupEnv)
if exitCode != 1 || !strings.Contains(stderr.String(), "interactive mode requires one") {
    t.Fatalf("xssh picker error = %d, %q", exitCode, stderr.String())
}
```

Use the same test API handler pattern as `TestRunXSSHRequiresInteractiveTerminal`, returning one redacted SSH connection from `/api/v1/ssh-connections` and failing if transport bundle is requested.

- [ ] **Step 2: Run focused tests to verify failure**

Run: `go test ./cmd/warden ./internal/client/terminal -run 'Test(RunXSSH|WindowsSessionReportsANSI)' -count=1`

Expected: FAIL because the CLI still invokes the deleted line-based picker rather than creating a native picker terminal session.

- [ ] **Step 3: Switch CLI path to native picker**

In `cmd/warden/main.go`:

- Remove `bufio`, `strconv`, and the old `pickConnection(stdin, stdout, conns)` function.
- Import `warden/internal/client/picker`.
- In the no-name branch, call `terminal.NewSession()`, then `picker.Select(pickerSession, conns)`.
- Do not defer picker restoration in `runXSSH`; `picker.Select` owns it and returns only after cleanup.
- Retain `cl.GetSSHBundle` after selection. Continue calling a new `terminal.NewSession()` for `clientssh.RunInteractive`, preserving explicit-name behavior and the terminal interface expected by SSH code.
- Remove `stdin io.Reader` from `runXSSH` and update its sole call in `run` accordingly.

- [ ] **Step 4: Run focused tests to verify pass**

Run: `go test ./cmd/warden ./internal/client/terminal ./internal/client/picker -count=1`

Expected: PASS. The command tests must prove explicit-name behavior and non-terminal picker failure remain safe; picker package tests prove interaction behavior.

- [ ] **Step 5: Commit terminal and CLI integration**

```bash
git add cmd/warden/main.go cmd/warden/main_test.go
git commit -m "Use native picker for interactive xssh selection"
```

## Task 4: Document behavior and validate cross-platform build

**Files:**
- Modify: `README.md`
- Modify: `docs/superpowers/plans/2026-08-24-xssh-native-picker.md`

**Interfaces:**
- Consumes: implemented `warden xssh` picker behavior from Tasks 1–3.
- Produces: user-facing picker documentation and recorded final validation output in this plan's task checklist.

- [ ] **Step 1: Write README acceptance text before editing**

Add this content beneath the interactive-shell CLI example, adapted to local README voice:

```markdown
When invoked without `<connection>`, `xssh` opens a colorized native terminal picker. Type to filter profile names and hostnames; use Up/Down to move, Enter to connect, and Esc or Ctrl-C to cancel. The right pane shows the selected profile; password, private-key, passphrase, and proxy-password values are never shown and instead display whether they are configured. Terminals narrower than 80 columns use a stacked layout. Use a modern ANSI/VT-capable terminal on Windows.
```

- [ ] **Step 2: Edit README with final picker usage documentation**

Place the text immediately after the `warden xssh [--accept-new] [connection]` example. Keep the existing native-Windows paragraph; append that the picker needs ANSI/VT rendering while interactive SSH retains current console behavior.

- [ ] **Step 3: Run full Go validation**

Run: `go test ./...`

Expected: PASS.

Run: `GOOS=windows GOARCH=amd64 go build -o /tmp/warden.exe ./cmd/warden`

Expected: PASS; `/tmp/warden.exe` exists. Remove it after command succeeds: `rm -f /tmp/warden.exe`.

Run: `GOOS=windows GOARCH=amd64 go test -c -o /tmp/terminal.test.exe ./internal/client/terminal`

Expected: PASS; the Windows-only terminal test compiles. Remove it after command succeeds: `rm -f /tmp/terminal.test.exe`.

Run: `go vet ./...`

Expected: PASS.

- [ ] **Step 4: Update task validation record in this plan**

Replace this exact unchecked item with command results after executing Step 3:

```markdown
- [ ] Validation results: `go test ./...`; Windows client build; Windows terminal-test compile; `go vet ./...`.
```

Use this completed form only with actual outputs:

```markdown
- [x] Validation results: `go test ./...` PASS; `GOOS=windows GOARCH=amd64 go build -o /tmp/warden.exe ./cmd/warden` PASS; `GOOS=windows GOARCH=amd64 go test -c -o /tmp/terminal.test.exe ./internal/client/terminal` PASS; `go vet ./...` PASS.
```

- [ ] **Step 5: Commit docs and validation record**

```bash
git add README.md docs/superpowers/plans/2026-08-24-xssh-native-picker.md
git commit -m "Document xssh native picker"
```

## Final verification

- [ ] Run `git diff origin/main...HEAD --check` and require no output.
- [ ] Run `git status --short`; verify only known pre-existing untracked `.cmdlog/` and `Master key path...` files, if still present, remain outside commits.
- [ ] Run `go test ./...`, `go vet ./...`, `GOOS=windows GOARCH=amd64 go build -o /tmp/warden.exe ./cmd/warden`, and `GOOS=windows GOARCH=amd64 go test -c -o /tmp/terminal.test.exe ./internal/client/terminal`; require all to pass and remove both `/tmp` Windows artifacts.
- [ ] Inspect `git log --oneline origin/main..HEAD` to confirm commits contain only design, picker implementation, integration, and docs.
