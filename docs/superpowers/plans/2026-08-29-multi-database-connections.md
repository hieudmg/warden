# Multi-database connections Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add shared-credential database lists with one mandatory default, compatible persistence/API reads, and `profile/database` CLI selection.

**Architecture:** Keep SQLite column `db_connections.database`, migrating legacy scalar values to canonical JSON arrays of `{name,is_default}` entries. Domain/API models expose `databases`, retain `database` as the default-name compatibility alias, and normalize legacy writes. Resolver selects default or an explicit query parameter; frontend edits ordered database rows with one radio-selected default.

**Tech Stack:** Go, SQLite migrations via `golang-migrate`, `net/http`, React 19, TypeScript, Vitest, Testing Library.

**Spec:** `docs/superpowers/specs/2026-08-29-multi-database-connections-design.md`

## Global Constraints

- Shared host, port, username, password, and SSH settings apply to every database name in one profile.
- Exactly one database entry is default.
- Existing SQLite `db_connections.database` column is reused; migration 005 canonicalizes legacy scalar rows.
- API responses include canonical `databases` and legacy `database` default-name alias.
- API writes accept either legacy `database` or new `databases`; conflicting values are invalid.
- Empty/duplicate/control-character/slash-containing database names are invalid.
- Omitted transport selector means default; explicit unknown selector fails before secret disclosure.
- Existing password encryption, redaction, audit logging, groups, and SSH graph behavior remain unchanged.
- Every production change follows a failing-test-first cycle and is committed separately with only intended paths staged.

---

### Task 1: Add database-list value types and canonical storage codec

**Files:**
- Modify: `internal/model/profile.go`
- Modify: `internal/model/api.go`
- Modify: `internal/store/profiles.go`
- Test: `internal/store/profiles_test.go`

**Interfaces:**
- Produces `model.DatabaseInfo{Name string; IsDefault bool}`.
- Produces `model.DBProfile.Databases []model.DatabaseInfo`.
- Produces API `DBConnection.Databases []model.DatabaseInfo`, `DBConnection.Database string`, and request fields `Databases []model.DatabaseInfo`, `Database string`.
- Produces store helpers that decode legacy scalar or canonical JSON and encode canonical JSON.

- [ ] **Step 1: Write failing store tests**

Add tests that call the intended codec/validation behavior through `CreateDB`/`GetDB` and direct row inspection:

```go
func TestCreateDBStoresCanonicalDatabaseList(t *testing.T) {
    _, s, _ := newTestAPI(t)
    p, err := s.CreateDB(context.Background(), model.DBProfile{
        Name: "multi", Host: "db.invalid", Port: 3306, Username: "app",
        Databases: []model.DatabaseInfo{
            {Name: "app", IsDefault: true}, {Name: "audit"},
        },
    })
    if err != nil { t.Fatal(err) }
    var raw string
    if err := s.db.QueryRow("SELECT database FROM db_connections WHERE id=?", p.ID).Scan(&raw); err != nil { t.Fatal(err) }
    if raw != `[{"name":"app","is_default":true},{"name":"audit","is_default":false}]` {
        t.Fatalf("stored database = %q", raw)
    }
}

func TestGetDBReadsLegacyScalarAsDefault(t *testing.T) {
    _, s, _ := newTestAPI(t)
    // Insert a row using the existing scalar column shape, then assert GetDB
    // returns one DatabaseInfo named "legacy" with IsDefault true.
}

func TestCreateDBRejectsInvalidDatabaseList(t *testing.T) {
    cases := []struct{ name string; databases []model.DatabaseInfo }{
        {"empty", nil},
        {"no default", []model.DatabaseInfo{{Name: "app"}}},
        {"two defaults", []model.DatabaseInfo{{Name: "app", IsDefault: true}, {Name: "audit", IsDefault: true}}},
        {"duplicate", []model.DatabaseInfo{{Name: "app", IsDefault: true}, {Name: "app"}}},
        {"slash", []model.DatabaseInfo{{Name: "app/db", IsDefault: true}}},
    }
    for _, tc := range cases {
        t.Run(tc.name, func(t *testing.T) {
            _, s, _ := newTestAPI(t)
            _, err := s.CreateDB(context.Background(), model.DBProfile{
                Name: tc.name, Host: "db.invalid", Port: 3306, Username: "app", Databases: tc.databases,
            })
            if !errors.Is(err, store.ErrValidation) { t.Fatalf("error = %v", err) }
        })
    }
}
```

Use the existing test setup; expose no new production-only testing hook. If direct SQL inspection is needed, use the existing raw SQLite helper or add a test-local query helper consistent with current tests.

- [ ] **Step 2: Run focused tests and verify expected RED**

Run:

```bash
go test ./internal/store -run 'Test(CreateDBStoresCanonicalDatabaseList|GetDBReadsLegacyScalarAsDefault|CreateDBRejectsInvalidDatabaseList)' -count=1
```

Expected: compile/test failure because `DatabaseInfo`, `Databases`, and canonical codec behavior do not exist.

- [ ] **Step 3: Implement minimal model and codec**

Add `DatabaseInfo` and replace the domain `Database string` with `Databases []DatabaseInfo`. Add API fields while retaining `database` as a compatibility alias. In `internal/store/profiles.go`, implement:

```go
func encodeDatabases(databases []model.DatabaseInfo) (string, error)
func decodeDatabases(raw string) ([]model.DatabaseInfo, error)
func validateDatabases(databases []model.DatabaseInfo) error
func defaultDatabase(databases []model.DatabaseInfo) (string, error)
```

`decodeDatabases` must first accept canonical JSON object arrays, then treat a non-empty non-JSON scalar as one default entry. Reject malformed JSON, JSON of the wrong shape, empty names, duplicate names, invalid names, and anything other than exactly one default. `encodeDatabases` must emit compact JSON and normalize `IsDefault:false` explicitly. Update DB create/get/update SQL paths to encode/decode the existing column and populate `DBProfile.Databases`.

- [ ] **Step 4: Run focused tests and verify GREEN**

Run the same command. Expected: all focused store tests pass.

- [ ] **Step 5: Commit**

```bash
git add internal/model/profile.go internal/model/api.go internal/store/profiles.go internal/store/profiles_test.go
git commit -m "feat: model multiple databases per connection"
```

### Task 2: Migrate existing SQLite rows

**Files:**
- Create: `migrations/005_multiple_databases.up.sql`
- Modify: `internal/store/store_test.go`

**Interfaces:**
- Consumes Task 1 canonical JSON shape.
- Produces migration 005 that keeps row IDs, encrypted password blobs, and column name unchanged.

- [ ] **Step 1: Write failing migration test**

Add `TestOpenMigratesLegacyDatabaseScalar` that creates schema through migration 004, inserts `database='legacy'`, marks schema version 4, opens with `store.Open`, and asserts the column equals `[{"name":"legacy","is_default":true}]` (using the exact compact JSON string) and `GetDB` returns one default entry.

- [ ] **Step 2: Run test to verify RED**

```bash
go test ./internal/store -run TestOpenMigratesLegacyDatabaseScalar -count=1
```

Expected: FAIL because migration 005 does not exist and the row remains scalar.

- [ ] **Step 3: Implement migration**

Create `migrations/005_multiple_databases.up.sql`:

```sql
UPDATE db_connections
SET database = '[{"name":' || json_quote(database) || ',"is_default":true}]'
WHERE json_valid(database) = 0;
```

This converts legacy plain text, including empty text, without changing row identity. Keep read validation so an empty legacy value is surfaced for correction rather than silently selecting it.

- [ ] **Step 4: Run migration test to verify GREEN**

```bash
go test ./internal/store -run TestOpenMigratesLegacyDatabaseScalar -count=1
```

- [ ] **Step 5: Commit**

```bash
git add migrations/005_multiple_databases.up.sql internal/store/store_test.go
git commit -m "feat: migrate legacy database fields"
```

### Task 3: Normalize DB API requests and responses

**Files:**
- Modify: `internal/server/profiles/handlers.go`
- Modify: `internal/server/profiles/handlers_test.go`
- Modify: `internal/server/profiles/helpers_test.go`
- Modify: `internal/client/api/client.go`
- Modify: `internal/client/api/client_test.go`

**Interfaces:**
- Consumes `model.DBProfile.Databases` and API fields from Task 1.
- Produces `redactDB(model.DBProfile) model.DBConnection` with `databases` plus default `database` alias.
- Produces request normalization accepting legacy or new payloads.

- [ ] **Step 1: Write failing handler/client tests**

Add tests covering:

```go
func TestCreateDBAcceptsDatabasesAndReturnsLegacyDefaultAlias(t *testing.T)
func TestCreateDBAcceptsLegacyDatabaseAndUpgradesStoredValue(t *testing.T)
func TestCreateDBRejectsConflictingDatabaseFields(t *testing.T)
func TestGetDBReturnsDatabasesAndDefaultAlias(t *testing.T)
```

POST the new shape `{"name":"app","host":"db.invalid","port":3306,"username":"u","databases":[{"name":"main","is_default":true},{"name":"audit"}]}` and assert response contains both `databases` and `database:"main"`. POST legacy `database:"main"` and assert returned `databases` has one default entry. POST both with different defaults and assert HTTP 400/422 using existing error conventions.

Update API client fixture JSON and assertions to verify both fields decode.

- [ ] **Step 2: Run focused tests to verify RED**

```bash
go test ./internal/server/profiles ./internal/client/api -run 'Test(CreateDB|GetDB|.*DB.*Decod)' -count=1
```

Expected: compile/test failures due to missing request fields/normalization and changed domain field.

- [ ] **Step 3: Implement normalization and redaction**

Add a handler helper:

```go
func dbProfileFromRequest(id int64, req model.DBConnectionRequest) (model.DBProfile, error)
```

If `len(req.Databases)==0`, require non-empty legacy `req.Database` and create one default entry. If both are supplied, require `req.Database` to equal the name of the sole default entry. Copy password, SSH, and group fields unchanged. `redactDB` returns a defensive copy of `Databases` and computes `Database` from the default entry. Keep strict JSON decoding by declaring both known keys in the request type.

Update client fixtures/types only as needed; client remains able to decode current and new response payloads.

- [ ] **Step 4: Run focused tests to verify GREEN**

Run the same focused command; expected all new and existing profile/API tests pass.

- [ ] **Step 5: Commit**

```bash
git add internal/server/profiles/handlers.go internal/server/profiles/handlers_test.go internal/server/profiles/helpers_test.go internal/client/api/client.go internal/client/api/client_test.go
git commit -m "feat: expose compatible database list API"
```

### Task 4: Select named databases in transport and CLI

**Files:**
- Modify: `internal/server/profiles/resolve.go`
- Modify: `internal/server/profiles/resolve_test.go`
- Modify: `internal/server/profiles/handlers.go`
- Modify: `internal/server/profiles/handlers_test.go`
- Modify: `internal/client/api/client.go`
- Modify: `cmd/warden/main.go`
- Modify: `cmd/warden/main_test.go`

**Interfaces:**
- Produces `ResolveDBBundle(ctx context.Context, id int64, databaseName ...string) (model.DBBundle, error)`; no selector means default.
- Produces API client `GetDBBundle(ctx context.Context, id int64, databaseName ...string) (model.DBBundle, error)`; omitted selector preserves current callers.
- Produces `parseDBReference(raw string) (profileName, databaseName string, err error)`.

- [ ] **Step 1: Write failing resolver/CLI tests**

Add resolver tests creating `Databases: [{Name:"main", IsDefault:true},{Name:"audit"}]` and asserting:

```go
bundle, err := r.ResolveDBBundle(ctx, dbp.ID, "audit")
if err != nil { t.Fatal(err) }
if bundle.Database != "audit" { t.Fatalf("database = %q", bundle.Database) }
_, err = r.ResolveDBBundle(ctx, dbp.ID, "missing")
if err == nil { t.Fatal("missing selector accepted") }
```

Add CLI unit tests for `parseDBReference("prod") == ("prod", "")`, `parseDBReference("prod/audit") == ("prod", "audit")`, and malformed `"prod/"` returning an error. Update transport handler/client tests to expect `?database=audit` and selected bundle database.

- [ ] **Step 2: Run tests to verify RED**

```bash
go test ./internal/server/profiles ./cmd/warden ./internal/client/api -run '(ResolveDBBundle|DBReference|TransportDB|GetDBBundle)' -count=1
```

Expected: FAIL because resolver ignores selectors and CLI has no reference parser.

- [ ] **Step 3: Implement selector flow**

Make `ResolveDBBundle` choose the default entry when selector is empty; otherwise find exact `Name`, returning a validation error for unknown names before calling `ResolveSSHBundle`. Set `DBBundle.Database` to the selected name.

In `transportDB`, read `r.URL.Query().Get("database")` and pass it to the resolver. In `GetDBBundle`, append a URL-encoded `database` query only when a selector is supplied.

In `runDB`, parse the first operand once, match the profile portion against `DBConnection.Name`, and call `GetDBBundle(ctx, id, selectedDatabase)`. Preserve existing usage/error output for malformed or missing references. Profile names cannot contain `/`, so split at the first slash.

- [ ] **Step 4: Run focused tests to verify GREEN**

Run the same focused command, then run:

```bash
go test ./internal/client/db ./internal/client/agent ./cmd/warden -run Test -count=1
```

- [ ] **Step 5: Commit**

```bash
git add internal/server/profiles/resolve.go internal/server/profiles/resolve_test.go internal/server/profiles/handlers.go internal/server/profiles/handlers_test.go internal/client/api/client.go cmd/warden/main.go cmd/warden/main_test.go
git commit -m "feat: select named databases from CLI"
```

### Task 5: Add dynamic database list form

**Files:**
- Modify: `web/src/api/types.ts`
- Modify: `web/src/features/db/db-form.tsx`
- Modify: `web/src/features/db/db-tab.tsx`
- Modify: `web/src/features/db/db-form.test.tsx`
- Modify: `web/src/features/db/db-tab.test.tsx`

**Interfaces:**
- Consumes API `databases` plus legacy `database` alias.
- Produces `DBFormState.databases: DatabaseFormEntry[]` and `toDBRequest` with canonical `databases` plus legacy default `database`.

- [ ] **Step 1: Write failing frontend tests**

Update fixtures and add tests that assert:

```tsx
expect(dbFormFromConnection(legacyDB).databases).toEqual([{ name: "legacy", isDefault: true }])
expect(toDBRequest({ ...emptyDBForm(), databases: [
  { name: "main", isDefault: true }, { name: "audit", isDefault: false },
]})).toMatchObject({
  database: "main",
  databases: [{ name: "main", is_default: true }, { name: "audit", is_default: false }],
})
```

Render `DBForm` and verify add creates a second row, selecting its default radio unsets the first, remove deletes a non-final row, and Save does not call `onSubmit` with blank/duplicate names or no default. Add a tab test asserting all database names and a visible default marker render in one table cell.

- [ ] **Step 2: Run Vitest to verify RED**

```bash
cd web && npx vitest run src/features/db/db-form.test.tsx src/features/db/db-tab.test.tsx
```

Expected: FAIL because current form has one `database` string and no list controls.

- [ ] **Step 3: Implement list state and UI**

Add TypeScript `DatabaseInfo` and request/response fields. Normalize connection data with `connection.databases` when present, otherwise `[ {name: connection.database, isDefault: true} ]`. Keep password behavior unchanged.

Replace the single input with an ordered row list. Use stable local row IDs for React keys, controlled name inputs, radio buttons sharing one group, Add button, and Remove buttons disabled when only one row remains. `toDBRequest` emits `databases` and the selected default alias. Validate trimmed non-empty unique names and exactly one default before invoking `onSubmit`; preserve entered name text in payload while using trimmed values only for validation. Display names joined with commas and mark the default in the table.

- [ ] **Step 4: Run focused frontend tests to verify GREEN**

```bash
cd web && npx vitest run src/features/db/db-form.test.tsx src/features/db/db-tab.test.tsx
```

- [ ] **Step 5: Commit**

```bash
git add web/src/api/types.ts web/src/features/db/db-form.tsx web/src/features/db/db-tab.tsx web/src/features/db/db-form.test.tsx web/src/features/db/db-tab.test.tsx
git commit -m "feat: edit multiple databases in web form"
```

### Task 6: Update all fixtures, documentation, and verify full repository

**Files:**
- Modify: `internal/store/profiles_test.go`
- Modify: `internal/server/profiles/handlers_test.go`
- Modify: `internal/client/api/client_test.go`
- Modify: `cmd/warden/main_test.go`
- Modify: `web/src/app.test.tsx`
- Modify: `README.md`

- [ ] **Step 1: Add/adjust remaining regression fixtures**

Replace domain literals using `Database: "x"` with one default `Databases` entry where they exercise new domain behavior. Keep at least one legacy JSON/scalar fixture for compatibility. Update README CLI examples to document `warden db <profile>/<database>` and default selection.

- [ ] **Step 2: Run Go formatting and focused static checks**

```bash
gofmt -w internal/model internal/store internal/server/profiles internal/client/api cmd/warden
go test ./internal/model ./internal/store ./internal/server/profiles ./internal/client/api ./internal/client/db ./internal/client/agent ./cmd/warden -count=1
```

Expected: exit 0 with no test failures.

- [ ] **Step 3: Run frontend checks**

```bash
cd web && npm test && npm run build
```

Expected: Vitest, distribution verification, TypeScript compilation, and Vite build all succeed.

- [ ] **Step 4: Run full repository verification**

```bash
cd .. && go test ./...
git diff --check
git status --short
```

Expected: all Go packages pass, diff has no whitespace errors, and only intended files are modified/untracked.

- [ ] **Step 5: Commit final fixture/docs changes**

```bash
git add internal/store/profiles_test.go internal/server/profiles/handlers_test.go internal/client/api/client_test.go cmd/warden/main_test.go web/src/app.test.tsx README.md
git commit -m "docs: describe multi-database selection"
```

- [ ] **Step 6: Prepare PR evidence**

Review:

```bash
git log --oneline origin/main..HEAD
git diff --stat origin/main...HEAD
git status --short --branch
```

Then follow repository git-feature-pr-flow: push with explicit refspec, create PR against `main`, and report branch, commits, verification commands, and PR URL.
