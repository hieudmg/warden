# Web data export/import design

## Goal

Add web-view data export and import for migrating Warden-managed data to another
hosting instance. Export is a portable, unencrypted JSON bundle. Import is
allowed only when the destination has no managed data and must fail without
changing it otherwise.

The bundle includes SSH connections, database connections, groups, SSH key
pairs, projects, reports, connection notes (including notes whose connection
reference is missing or uses an unrecognized type), and all associated secret
values (passwords, proxy passwords, private keys, and private-key passphrases).
Internal audit history and server configuration are not included.

## Transfer format

Use one versioned JSON document with a format identifier, schema version, export
timestamp, and typed arrays for each supported record kind, including a
`connection_notes` collection containing every stored note row. A note row
contains `connection_type`, `connection_id`, and `note`; keep it separate from
SSH/DB records so empty, orphaned, and unrecognized-type notes are preserved.
Include stable record IDs, timestamps, complete non-secret fields, and secret
values. Require
a non-zero `exported_at` timestamp. Preserve
IDs so SSH jump routes, DB-to-SSH tunnels, group assignments, and SSH key-pair
references remain unchanged after import. Preserve dangling soft references
exactly as stored: Warden intentionally allows jump, tunnel, and key-pair
references to become unresolved. Validate their syntax and enforce actual
database constraints (including report-to-project links), but do not require
soft references to resolve. Reject unsupported versions, malformed JSON,
unknown fields, and duplicate or invalid IDs before writing data.

The export contains plaintext secrets. The UI must warn users before download
and before import, and the API response must use `Cache-Control: no-store`.

## Server API and storage

Add server-side export and import endpoints. Export reads the complete managed
dataset from the store rather than composing redacted list APIs. The store
returns decrypted secret values for bundle serialization; they are never
written back to disk as plaintext.

Import parses and validates the entire bounded request body before mutation.
In a single database transaction it verifies all managed tables are empty
(including `connection_notes`), then inserts all records with their original
IDs and timestamps, encrypting secrets using the destination store's master key
and existing row-bound AAD conventions. Restore every connection note row
verbatim from its separate bundle collection, including rows without an
attached profile. Any validation, uniqueness, encryption, or SQL error rolls back
the complete import. A non-empty destination is rejected without changing managed data. Audit events
are operational metadata and do not block migration.

The importer must not use the existing per-record CRUD sequence: it cannot
provide all-or-nothing behavior, and normal write APIs do not accept imported
IDs/timestamps. Record import success/failure through the existing audit
mechanism without recording bundle contents or secret values.

## Web UI

Add Export and Import controls to the existing Warden Hub view. Export requests
the bundle and downloads a clearly named `.json` file. Import selects a JSON
file, asks for explicit confirmation that its credentials are plaintext, then
submits it. Display a clear success result or actionable errors for invalid
files and non-empty destinations. Refresh all affected list resources after a
successful import. Do not automatically reload or overwrite an active UI state
on failure.

## Error handling and safety

- Export failures return a generic server error; never log bundle contents.
- Invalid bundles return a client error with a useful validation message.
- Non-empty destination returns a conflict response.
- Enforce a 50 MiB maximum upload size before decoding. If the limit is crossed
  while checking for trailing JSON data, return the same payload-too-large error.
- Use strict decoding and validate relationships before opening the write
  transaction where possible; repeat emptiness validation under the transaction
  to avoid races.
- Import is atomic. A failed import leaves all managed records unchanged.
- The destination's master key is not required to match the source key; values
  are decrypted for export and re-encrypted by the destination on import.

## Testing

Add focused tests for bundle serialization and validation, secret round-trip
across stores with different master keys, preserved IDs/references/timestamps
(including dangling soft references), non-empty destination rejection, and
transaction rollback on invalid input or write failure. Add API tests for headers, status codes, size limits, redaction
boundaries, and audit metadata that excludes secrets. Add UI tests for warning,
file download/upload, errors, success, and resource refresh.

Run Go tests and the web test/type-check/build commands used by the repository.
