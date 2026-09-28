# Web Data Export/Import Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a web export/import flow that migrates every user-managed Warden record, including secrets, between servers with different master keys.

**Architecture:** Use a versioned JSON transfer DTO, with store-level snapshot export and transactional import that preserves record IDs and re-encrypts secrets under the destination key. Expose download/upload endpoints and add warned web controls that refresh resources after a successful import.

**Tech Stack:** Go 1.25, SQLite (`modernc.org/sqlite`), `net/http`, React 19, TypeScript, Vite, Vitest.

**Spec:** `docs/superpowers/specs/2026-09-28-web-data-transfer-design.md`

## Global Constraints

- Include SSH connections, DB connections, groups, SSH key pairs, projects, reports, every connection_notes row (including rows without an attached SSH/DB record), and all secret values.
- Exclude server configuration and internal audit history.
- Bundle is plaintext, versioned JSON; UI must warn on export and import.
- Import only into a destination with no managed records; reject any non-empty managed table without modifying data.
- Preserve IDs and timestamps; preserve dangling soft references (jump, tunnel, and key-pair) as stored.
- Encrypt imported secrets with the destination store's master key using existing row-bound AAD.
- Import is one transaction; any failure leaves managed tables unchanged.
- Reject bundle bodies larger than 50 MiB, including overflow encountered while checking trailing data; do not log or audit bundle contents or secrets.
- Do not commit, push, or publish without separate approval.

---

### Task 1: Versioned transfer format and atomic store operations

**Files:**
- Create: `internal/model/transfer.go`
- Create: `internal/store/transfer.go`
- Test: `internal/store/transfer_test.go`
- Modify only if needed: `internal/store/profiles.go`, `internal/store/key_pairs.go`, `internal/store/reports.go` (prefer existing validators/helpers; avoid unrelated edits)

**Interfaces:**
- Produces `model.DataBundle` with `format`, `version`, non-zero `exported_at`, and non-null arrays of transfer SSH connections, DB connections, groups, key pairs, projects, reports, and every `connection_notes` row.
- Produces `(*store.Store).ExportData(context.Context) (model.DataBundle, error)`.
- Produces `(*store.Store).ImportData(context.Context, model.DataBundle) error`.
- Transfer records contain original IDs/timestamps, JSON-safe secret strings, profile fields, and report `project_id`; notes are kept in a top-level `{connection_type, connection_id, note}` collection so even empty, orphaned, and unrecognized-type rows are preserved. DTO includes complete data but omits computed display-only names/counts.

- [ ] **Step 1: Add failing export/restore tests first.** Seed a store with groups, connections, notes, key pairs, reports, credentials, and a second empty store with a different 32-byte key. Assert bundle shape includes complete secret values, IDs, timestamps and report/project linkage; import into the second store and compare the restored records. Include dangling jump/tunnel/key-pair references and prove they survive unchanged. Insert empty, orphan, and unrecognized-type connection-note rows directly into the source DB and prove export/import preserves every row exactly. Add tests rejecting invalid version, missing/zero exported_at, each omitted/null top-level record array, duplicate IDs/names, invalid required fields, SSH password/key-pair conflicts, and malformed jump-route JSON.
- [ ] **Step 2: Run the focused tests and confirm expected failures.** Run `go test ./internal/store -run 'Test(ExportData|ImportData)' -count=1`; it should fail to compile or fail the new behavior assertions before implementation.
- [ ] **Step 3: Define the DTOs in `internal/model/transfer.go`.** Use explicit JSON tags, `format: "warden-data"`, `version: 1`, an RFC3339 timestamp, and slices (not nil arrays) for each record collection. Use purpose-specific transfer structs so secret-bearing and computed fields are explicit. Include group/connection notes, database lists, proxy settings, key-pair reference IDs, and full key-pair material.
- [ ] **Step 4: Implement `ExportData` with a consistent read transaction.** Query every managed table, including notes and all report rows. Decrypt SSH/DB/key-pair secret columns with existing AAD helpers. Keep plaintext only in the returned in-memory bundle; do not persist/log it. Resolve neither dangling soft references nor display-only names.
- [ ] **Step 5: Implement `ImportData` validation and transaction.** Validate format/version, non-zero exported_at, record IDs and uniqueness, names/fields using existing store validation rules, timestamp parsing, JSON syntax for jump-route IDs, SSH password/key-pair mutual exclusion, and hard report-to-project references. Permit dangling jump/tunnel/key-pair/group soft IDs where existing behavior allows them. Begin one write transaction; under that transaction require SSH/DB/group/key-pair/project/report/connection_notes tables all empty; insert dependency records while preserving IDs/timestamps; encrypt each secret using destination codec and existing AAD; commit only after every insert succeeds. Roll back on every error. Restore all connection-note rows from the top-level collection, rejecting duplicate `(connection_type, connection_id)` pairs. Enforce SSH password/key-pair mutual exclusion without modifying accepted records. Return a distinct conflict sentinel for a non-empty destination.
- [ ] **Step 6: Re-run focused tests and add rollback/empty-destination coverage.** Verify every imported secret can be read using the destination's different key, malformed input leaves every managed table unchanged, a mid-import SQL failure rolls back earlier inserts, and a destination with any managed row is rejected unchanged. Run `go test ./internal/store -run 'Test(ExportData|ImportData)' -count=1`.

### Task 2: HTTP export/import endpoints and server contract tests

**Files:**
- Create: `internal/server/profiles/transfer.go`
- Modify: `internal/server/profiles/handlers.go`
- Test: `internal/server/profiles/transfer_test.go` (or the existing `handlers_test.go` if keeping package conventions)
- Test helper: `internal/server/profiles/helpers_test.go` only if shared test setup needs a safe minimal addition

**Interfaces:**
- `GET /api/v1/data/export` returns one JSON bundle as an attachment.
- `POST /api/v1/data/import` accepts one strict JSON bundle and returns `204 No Content` on success.
- Errors use existing stable envelopes: `400 invalid_request`/`validation_error`, `409 conflict` for non-empty destination, `413 payload_too_large`, and sanitized `500 internal_error`.

- [ ] **Step 1: Add failing endpoint tests first.** Cover export content type, attachment filename, `Cache-Control: no-store`, complete secrets, import success, invalid format/body, duplicate/invalid records, a 50 MiB+1 body and a valid JSON object followed by whitespace exceeding the body limit (both cases must return 413), non-empty destination conflict, and proof that audit/error logging never includes payload secrets. Verify failed import leaves store unchanged.
- [ ] **Step 2: Run the endpoint tests and confirm expected failures.** Run `go test ./internal/server/profiles -run 'Test(DataExport|DataImport)' -count=1` before adding routes.
- [ ] **Step 3: Register the routes and write handlers.** Apply `http.MaxBytesReader` before JSON decoding; use `DisallowUnknownFields` and enforce exactly one JSON value. Return export with `Content-Disposition: attachment; filename="warden-data.json"` and `Cache-Control: no-store`; set `Cache-Control: no-store` on import responses too. Marshal errors safely and never emit request bodies in logs/audit metadata.
- [ ] **Step 4: Map storage errors to API errors and audit metadata.** Map invalid bundles to 400, payload overflow (including while decoding trailing data) to 413, non-empty stores to 409, and unexpected failures to generic 500. Record operation/result and safe counts only after processing; do not include secrets, entire bundle, or report contents. Ensure importing a failed bundle does not make a clean destination count as managed data.
- [ ] **Step 5: Run API tests and all Go package tests.** Run `go test ./internal/server/profiles -run 'Test(DataExport|DataImport)' -count=1` then `go test ./internal/server/... ./internal/store/...`.

### Task 3: Web controls, warnings, and user documentation

**Files:**
- Modify: `web/src/api/client.ts`
- Modify: `web/src/app.tsx`
- Modify: `web/src/app.test.tsx`
- Test: `web/src/api/client.test.ts`
- Modify: `README.md`
- Generated: `internal/web/dist/` via `cd web && npm run build` (inspect generated diff; do not hand-edit)

**Interfaces:**
- `api.exportData(): Promise<Blob>` downloads the raw JSON attachment without using the normal JSON response parser.
- `api.importData(file: File): Promise<void>` submits the JSON file to the import route.
- The app provides explicit Export and Import controls, an import file chooser and confirmation/warning step, result notifications, and refresh of SSH, DB, groups, projects, and key-pair resources after success.

- [ ] **Step 1: Add failing client and app tests first.** Mock fetch to verify export returns a blob, import transmits the file as JSON, API errors retain useful conflict/validation messages, confirmation is required before upload, failed imports do not refresh resources, and successful imports refresh all affected lists and show a result. Verify export/import warnings identify plaintext credentials.
- [ ] **Step 2: Run focused web tests and confirm failure.** Run `cd web && npx vitest run src/api/client.test.ts src/app.test.tsx` before implementation.
- [ ] **Step 3: Implement API transfer calls.** Export handles the attachment response as a `Blob`; import reads a selected file as text and posts strict JSON with `Content-Type: application/json`, allowing the request client to map error envelopes.
- [ ] **Step 4: Add app controls and safe interaction.** Put clearly labeled actions in the Warden Hub header. Warn that the file is unencrypted and contains credentials before initiating export and before import submission. Require a selected JSON file; expose the existing global notification mechanism for completion/errors. After successful import reload all five list resources; do not refresh after failure. Keep active components stable while lists update.
- [ ] **Step 5: Document migration and plaintext handling.** Add concise README instructions: export from source, transfer the plaintext file securely, import into an empty destination, and note that the target uses its own master key. State that export files contain plaintext secrets and should be protected/deleted after migration.
- [ ] **Step 6: Run focused web tests and production build.** Run `cd web && npm test` and `cd web && npm run build`; inspect `git diff -- internal/web/dist` and confirm embedded output is regenerated.

### Task 4: Integrated verification and final review

**Files:**
- No new source files; review all files from Tasks 1–3.

- [ ] **Step 1: Run the complete Go suite.** Run `go test ./...`.
- [ ] **Step 2: Run Go static checks.** Run `go vet ./...`.
- [ ] **Step 3: Run the complete web test and build commands.** Run `cd web && npm test && npm run build`.
- [ ] **Step 4: Inspect the complete diff for requirement coverage and plaintext leaks.** Confirm generated JS contains no accidental credentials; bundle and error logging paths never log bundle contents; all managed-table checks include `connection_notes`; soft references round-trip; destination data is untouched on invalid/non-empty import; no unrelated files changed.
- [ ] **Step 5: Report verification and skipped checks accurately.** Do not commit, push, or publish without separate approval.
