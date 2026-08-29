# Multi-database connection profiles

## Goal

Allow one database connection profile to expose multiple database names while sharing host, port, username, password, and optional SSH tunnel settings. Exactly one database is default.

CLI selection remains concise:

- `warden db <profile>` uses default database.
- `warden db <profile>/<database> ...` uses named database.

## Data model and persistence

Add a `DatabaseInfo` value with `Name` and `IsDefault` fields. `DBProfile` owns an ordered slice of these values. The existing SQLite `db_connections.database` column is reused as the storage location:

- Legacy scalar rows such as `"app"` are readable as one default database.
- Canonical writes store JSON objects, for example `[{"name":"app","is_default":true},{"name":"audit","is_default":false}]`.
- Migration 005 rewrites existing non-JSON scalar values into canonical one-entry arrays. The read fallback remains defensive for rows created before migration or externally modified.
- Store validation requires at least one database, non-empty unique names, exactly one default, and names compatible with `profile/database` CLI syntax (no `/` or control characters).

Migration does not add or remove columns, preserving existing encrypted password AAD and row identity.

## HTTP/API contract

New API fields:

```json
{
  "databases": [
    {"name":"app","is_default":true},
    {"name":"audit","is_default":false}
  ],
  "database": "app"
}
```

`database` remains a read compatibility alias containing the default name. Write requests accept either:

- legacy `database: "app"`, normalized to one default entry; or
- new `databases` list.

If both are supplied, they must agree with the default entry; otherwise the request is invalid. New responses always include canonical `databases` and the default-name alias.

The transport DB endpoint keeps current behavior when no selector is supplied and accepts an optional URL-encoded `database` query parameter. Resolver selects the default when empty, or the exact named database when supplied; unknown names return a stable validation/transport error and never return partial credentials.

## CLI behavior

Because profile names already disallow `/`, parse an operand at most once into profile name and optional database name. Resolve the profile by name, then request a DB transport bundle with the optional database selector. Existing profile-only invocations and error behavior remain unchanged.

## Frontend behavior

Replace the single database input with a dynamic ordered list. Each row has:

- database name input;
- radio/default control;
- remove control.

The form always starts with one default row, permits adding/removing rows, prevents removing the final row, and blocks submission unless names are non-empty/unique and exactly one row is default. Edit forms accept new `databases`; legacy `database` responses become one default row. List display shows all names and identifies the default without exposing secrets.

## Error handling and compatibility

Malformed stored JSON is treated as a storage/validation error rather than silently selecting an arbitrary database. Legacy scalar values remain readable. Invalid selectors are rejected before SSH resolution or secret disclosure. Password handling, redaction, audit logging, group assignment, and SSH graph behavior remain unchanged.

## Testing

Add coverage for:

- scalar-to-canonical migration and legacy read fallback;
- database-list validation, create/update persistence, and default selection;
- API request compatibility, response alias, and transport selector behavior;
- CLI profile-only and `profile/database` parsing/selection;
- frontend form conversion, dynamic add/remove/default behavior, legacy fallback, and list rendering;
- existing direct and tunneled DB query paths using selected database names.
