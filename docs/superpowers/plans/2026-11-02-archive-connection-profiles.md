# Feature implementation plan: archive connection profiles

## Goal and approved behavior

Add a persisted archive state for SSH and database profiles. Existing profiles migrate as active. The web UI continues receiving all profiles, shows archived records in a separate section on each page, and supports archive/restore. Configuration search and the interactive `xssh` picker omit archived records. The server rejects attempts to use an archived profile as a direct SSH/DB target or as an SSH jump/tunnel hop, returning the same generic `404 connection not found` response used for missing transport profiles. Explicitly named `xssh` also goes through server enforcement.

Preserve archive state through data export/import; older imports without the field default to active. Profile editing, metadata visibility, and deletion remain available for archived records. No new CLI archive command is in scope.

## Design

Add a SQLite migration with `archived` defaulting to false for both connection tables. Carry the flag through domain/API and transfer models. Use an explicit archive-state API operation rather than editing a profile's connection fields. Keep list APIs inclusive for the web UI; filter only in configuration-search rendering and the `xssh` picker. Enforce transport denial in the resolver so every CLI transport consumer is covered, including direct calls and resolved jump routes. The web pages split inclusive results into active and archived tables and offer state-toggle actions.

## Execution

Repository: `/var/www/code/go/warden`, branch `hieudmg/archive-connection-profiles` (based on fetched `origin/main`). Keep the pre-existing untracked `mise.toml` untouched. Use one writer at a time; Task 2 depends on Task 1's API field and archive endpoint. Implement behavior test-first: focused failing tests before implementation, then focused passing checks.

### Task 1: Persist archive state and enforce server/CLI behavior

- Requirements: add migration and profile fields; preserve state through CRUD and data transfer; expose a state-toggle endpoint/client method; deny archived direct targets and archived jump/tunnel hops with generic transport not-found; hide archived profiles from config search and xssh picker, while preserving explicit-name server enforcement.
- Likely files: `migrations/007_archive_connections.up.sql`, `internal/model/{profile,api,transfer}.go`, `internal/store/{profiles,transfer}.go`, `internal/server/profiles/{handlers,resolve}.go`, `internal/client/api/client.go`, `cmd/warden/main.go`, and focused Go tests under the corresponding packages.
- Compatibility: old rows and old transfer JSON default to active; list APIs remain inclusive; archived profile GET/edit/delete remain available. Transport errors must not reveal whether an archived target or jump host exists.
- TDD/checks: first add and run failing migration/store/transport/API/CLI regression tests, then implement. Run focused tests for affected Go packages and `go test ./...` after integration.
- Escalate if a required API/security or data compatibility decision changes.
- [x] Implement and verify. Focused Go packages pass; full `go test ./...` is blocked only by the unrelated existing `internal/client/sftp/TestPosixRelMatchesFilepathRel` failure. Independent re-review accepted audit recording, migration/legacy transfer compatibility coverage, and invalid-state validation.

### Task 2: Add separate archived sections and controls to web pages

- Depends on Task 1's `archived` response field and archive-state endpoints.
- Requirements: show active SSH/DB profiles in their current sections, show archived profiles under separate headings, and allow archive/restore with reload and feedback. Keep edit/delete available for both states.
- Likely files: `web/src/api/{types,client}.ts`, `web/src/features/ssh/{ssh-tab.tsx,ssh-tab.test.tsx}`, and `web/src/features/db/{db-tab.tsx,db-tab.test.tsx}`.
- TDD/checks: add failing UI/API tests first; run focused Vitest files and TypeScript/Vite build.
- [x] Implement and verify. API/UI tests added before implementation; focused archive-detail assertion first failed on missing archived SSH metadata and passed after shared row rendering. Full web `npm test` (222 Vitest + 12 embedded-dist tests), `npm run build`, and `git diff --check` pass. Independent review found no issues.

## Final acceptance

Run the relevant Go and frontend test suites/build. Inspect the full diff and verify the unrelated `mise.toml` remains untouched. Independently review the transport denial and section separation against this plan. Commit only intended feature files if committing is authorized; do not push or open a PR without publication authorization.
