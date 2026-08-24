# React and shadcn/ui Frontend Design

**Date:** 2026-08-24
**Status:** Ready for user review

## 1. Goal

Replace Warden's vanilla JavaScript management UI with a self-contained React and shadcn/ui frontend. Organize existing modules into tabs, improve relationship editing with selectors backed by existing records, and give projects and reports a three-pane master-detail layout.

The server API, security boundary, and management-only scope remain unchanged. Browser code must never reveal credentials or execute SSH, SQL, or remote commands.

## 2. Scope

### In scope

- React and TypeScript application built with Vite.
- Local shadcn/ui component source and compiled Tailwind styles.
- Light theme as the default and only theme in this change.
- Tabs for SSH, Databases, and Projects & Reports.
- Existing SSH and DB CRUD flows, dependent warnings, projects, and immutable reports.
- Relationship selectors populated from existing API data.
- Responsive projects-and-reports layout.
- Frontend tests and updated Go static-serving tests.
- Build, test, release, and development documentation changes required by the frontend toolchain.

### Out of scope

- API or database schema changes.
- Application authentication or authorization.
- Credential reveal, browser terminals, SQL execution, or connection testing.
- Report update/delete support or project deletion.
- Client-side URL routing.
- Dark mode or a theme switcher.
- A new global state-management library.
- Committed generated HTML, JavaScript, CSS, or source maps.
- Playwright/E2E browser infrastructure.

## 3. Source and build architecture

Add a dedicated `web/` frontend project containing React, TypeScript, Vite configuration, Tailwind configuration, shadcn/ui configuration, application source, tests, and a committed npm lockfile. shadcn/ui components are source files owned by the repository; the running application has no CDN dependency.

Vite writes production output to generated `internal/web/dist/`. That directory is gitignored and must not be committed. The Go embed package embeds the generated distribution recursively, so frontend compilation must run before Go compilation from a clean checkout.

Supported workflows enforce this ordering:

1. Install exact frontend dependencies with the npm lockfile.
2. Run frontend tests where applicable.
3. Build the Vite production distribution.
4. Compile or test Go code.

Every supported command that compiles the server package performs the frontend phase first. This includes `make build`, `make build-server`, `make test`, new `make test-race` and `make vet` prerequisites, `scripts/test.sh`, and `scripts/build-release.sh`. Release builds use `npm ci` and stop immediately on install, test, or build failure. Client-only targets may skip frontend compilation because they do not import the embedded web package.

Documentation identifies Node and npm as build-time dependencies and replaces raw `go build ./cmd/warden-server`, `go test ./...`, `go test -race ./...`, and `go vet ./...` instructions with supported make/script commands. Direct Go commands that compile `internal/web` are explicitly unsupported from a clean checkout because generated assets are intentionally absent. Node and npm are never required by a released server binary.

The React entry point uses `createRoot`. One application shell owns shared resource data and notifications. Module components use React hooks and typed props; no client router or external state store is needed.

## 4. Embedded asset serving

Replace the current fixed three-file static contract with recursive Vite distribution serving.

- `/` and `/index.html` serve generated `index.html` with `Cache-Control: no-store`.
- Generated hashed assets serve from their emitted paths with correct content types, strong ETags, and immutable cache headers.
- `/api/...` remains delegated unchanged to the API handler.
- Unknown paths remain `404`; there is no SPA history fallback because the application has no client routes.
- Asset lookup validates paths and never exposes directory listings or files outside the distribution.

Both asset sources are normalized to an `fs.FS` root containing `index.html` directly: embedded assets use `fs.Sub` over the generated `dist` directory, while `static_fs` uses `os.DirFS(static_fs)` and therefore points directly at a Vite distribution directory. README and configuration comments must state this exact contract.

## 5. Application shell and module tabs

The application shell contains the Warden heading, trust-boundary subtitle, global notifications, and accessible shadcn Tabs. Tab order is:

1. SSH
2. Databases
3. Projects & Reports

SSH is initially active. Active-tab state is session-only; browser refresh returns to SSH. All three top-level resource lists load concurrently at application startup so relationship options are available without additional modal setup. Reports load only after project selection.

Each module renders distinct loading, empty, error, and loaded states. Load errors include a Retry action. Successful writes refresh affected resources while retaining the active tab and any selection that still exists.

## 6. SSH module

The SSH tab preserves the current connection table and create, edit, and delete dialogs. Secret inputs are always blank because list/get responses are redacted. Every blank secret input serializes as JSON `null` or is omitted—never as `""`. The API therefore retains stored values on edit and stores no value on create. This applies independently to password, private key, private-key passphrase, and proxy password.

Replace the raw jump-ID JSON input with an ordered relationship editor:

- An Add control selects an existing SSH profile by name and identifying host details.
- The profile being edited and profiles already in the route are excluded from Add options.
- Every selected entry has Move up, Move down, and Remove controls.
- Keyboard users can operate every control, and the current order is announced through accessible labels.
- Serialization preserves visible order in the existing `jump_connection_ids` JSON string format.

The API intentionally accepts any syntactically valid ordered integer sequence and postpones graph validation until transport resolution. The editor must preserve every stored entry and position during unrelated edits, including duplicates, self-references, cyclic routes, missing IDs, zero, and negative IDs. Existing valid IDs display their profile names; a self-reference is visibly marked; every unresolved integer displays as `Missing SSH #<id>`. Add options still exclude the edited profile and already-selected profiles, preventing creation of new self-references or duplicates through the UI. Existing exceptional entries remain unchanged unless the user explicitly moves or removes them.

SSH deletion retains the existing dependent lookup and warning. Confirmation distinguishes no dependents from references that will become invalid after deletion.

## 7. Database module

The Databases tab preserves the current DB table and create, edit, and delete dialogs.

Replace the numeric SSH connection ID field with an optional select containing:

- `Direct`, serialized as ID `0`.
- Existing SSH profiles, displayed by name with identifying host details.

If an existing DB profile references a deleted SSH ID, its edit dialog displays `Missing SSH #<id>` as the current value. Saving unrelated edits preserves that ID; selecting Direct or another profile replaces it.

DB deletion retains the existing confirmation behavior. Secret handling follows the SSH dialog rules.

## 8. Projects and reports module

Use a desktop three-column master-detail layout:

1. **Projects** — project list and New Project action.
2. **Reports** — reports for the selected project and Add Report action.
3. **Report content** — title, agent model, timestamp, and complete immutable summary for the selected report.

Selecting a project loads and displays its report list. Selecting a report displays its content in the third pane. Empty placeholders explain when no project, no report, or no report content is selected. On narrow screens, columns stack vertically in the same order; the UI does not introduce horizontal scrolling or separate drill-down routes.

The Add Report dialog preselects the active project but exposes a required select populated only from existing projects. The user may choose a different project before submission. After creation, the UI switches to the submitted project, reloads that project's reports, and selects the report returned by the create API so its content is immediately visible.

Reports remain immutable. No edit or delete actions are introduced.

## 9. Shared data and API behavior

Create a typed API client for existing endpoints and the stable JSON error envelope. API contracts and payload formats do not change.

Shared application state contains SSH profiles, DB profiles, projects, request status, and refresh functions. Reports remain scoped to selected projects. Relationship controls consume shared SSH/project records rather than fetching independent copies. Mutations trigger only affected refreshes, except an SSH mutation also refreshes data consumed by DB and SSH relationship displays.

Concurrent request results must not overwrite newer selection state. Components ignore stale responses after unmount or selection changes.

## 10. Dialogs, errors, and safety

Use accessible shadcn Dialog, form controls, Select/Popover-based relationship controls, Table, Tabs, Alert, and Button components as appropriate.

- Submitting disables relevant actions and prevents duplicate writes.
- A failed submission leaves the dialog and entered non-secret values intact.
- Validation, conflict, and malformed-request messages render inside the dialog.
- Unexpected errors use safe generic handling while preserving the server message when supplied by the stable error envelope.
- Dialog cancellation performs no write.
- Focus enters dialogs, remains trapped while open, returns to the trigger on close, and supports Escape.
- Success notifications identify the completed action.
- No credential enters browser storage, logs, list markup, relationship labels, or error notifications.

## 11. Visual behavior

Use shadcn/ui's neutral light tokens with Warden's green accent retained for primary actions and selection emphasis. Layout prioritizes data density appropriate for a management interface while keeping controls touch- and keyboard-usable.

Tables may scroll within their tab below the large breakpoint. Projects & Reports uses one column below Tailwind's `lg` breakpoint (`64rem`/1024 CSS pixels) and three columns at or above it. DOM order always remains Projects, Reports, Report content. Long names and report summaries wrap within their pane (`overflow-wrap: anywhere`; summaries preserve line breaks) and must not cause page-level horizontal overflow. Empty states, destructive actions, missing references, and API failures must be visually distinct without relying on color alone.

## 12. Testing and verification

### Frontend tests

Use Vitest and React Testing Library for behavior-focused tests covering:

- default SSH tab and tab switching;
- initial resource loading, empty states, load failures, and Retry;
- API error-envelope decoding;
- create/edit payload construction and duplicate-submit prevention;
- every SSH secret field and DB password serializing blank create/edit values as null or omission, never an empty string;
- ordered jump-route add, reorder, remove, exclusion, and serialization;
- preservation of duplicate, self, cyclic, missing, zero, and negative stored route entries during unrelated edits;
- Direct/existing/missing DB SSH selections;
- report project selection from existing projects;
- project selection loading reports and report selection showing content;
- Projects, Reports, and Report content DOM order plus the one-column/default and `lg` three-column class contract;
- long report content wrapping without a page-level overflow style;
- dialog cancellation, focus behavior, and accessible names.

Mock network boundaries rather than component internals. Avoid snapshots as primary assertions.

### Go tests

Update web-serving tests to discover generated hashed assets from `index.html` and verify:

- root and explicit index serving;
- `no-store` index policy;
- asset content types, ETags, and immutable caching;
- HEAD and conditional requests;
- API delegation;
- rejection of unknown and traversal-like paths;
- compatibility with embedded and override filesystems.

### End-to-end shell verification

Extend `scripts/test.sh` to build the frontend before server compilation, start the embedded server, and retain all existing API/CLI/security checks. Configure Vite to emit a manifest. Build verification walks every manifest entry, imported chunk, CSS file, and referenced asset, confirms each emitted file exists, and rejects external runtime script, stylesheet, font, and asset URLs. The live-server check requests every public emitted asset rather than sampling one file.

Before completion, run frontend tests and production build, Go tests, Go race tests, vet, end-to-end shell verification, and release build. Generated `internal/web/dist/` must remain ignored and absent from the committed diff.

## 13. Acceptance criteria

- Released `warden-server` serves React/shadcn UI without any network dependency.
- SSH, Databases, and Projects & Reports each occupy one tab.
- Projects & Reports follows the approved three-pane desktop layout and stacked narrow layout.
- Every relationship field uses existing records rather than raw IDs, while preserving all exceptional stored references—including missing, duplicate, self, cyclic, zero, and negative route entries—until explicitly changed.
- Ordered SSH jump routes remain manually reorderable and serialize correctly.
- Existing API behavior and credential-redaction guarantees remain intact.
- Default presentation is light theme.
- Every documented command that compiles the server package builds frontend first; unsupported raw Go commands are removed from documentation.
- Build verification proves all runtime frontend assets are local and embedded.
- No generated frontend distribution file is committed.
- Required frontend, Go, integration, race, vet, and release checks pass.
