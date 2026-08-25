# Connection Groups Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add managed, named Groups shared by SSH and DB connections, rendered in web UI and xssh picker search/detail.

**Architecture:** SQLite stores Groups plus a non-null `group_id` sentinel on connection rows (`0` is ungrouped). Store transactions validate assignments and clear them before a group is deleted; redacted API responses include both id and joined name. React loads groups once at application level, passes them to forms/tables, and provides full Group CRUD in a dedicated tab.

**Tech Stack:** Go 1.x, SQLite, golang-migrate embedded SQL migrations, `net/http` `ServeMux`, React, TypeScript, Vite, Vitest, Testing Library.

**Spec:** `docs/superpowers/specs/2026-08-25-connection-groups-design.md`

## Global Constraints

- Group names: trim before persistence; must match `[A-Za-z0-9._-]{1,100}`; unique case-sensitive.
- Group assignment: stored `group_id = 0` is ungrouped; positive ids must name an existing Group; negative ids are invalid.
- Group deletion must never be blocked: transactionally clear matching SSH/DB `group_id`s to `0`, then delete Group.
- SSH/DB transport resolution, secret encryption/redaction, jump-chain resolution, `warden ssh`, `warden db`, and `warden config search` behavior remain unchanged.
- Group list responses include SSH and DB connection counts; never issue one dependents request per Group table row.
- Web displays `GroupName`, `(Ungrouped)` for `group_id = 0`, and `Missing group #<id>` only for externally-corrupted nonzero references.
- xssh list rows remain unchanged; its detail pane displays Group and its filter matches group name case-insensitively.
- Keep strict JSON decoding, bounded request bodies, audit recording, existing error envelopes, secret redaction, and accessibility patterns.

---

## File Structure

| Path | Responsibility |
|---|---|
| `migrations/003_groups.up.sql` | Creates Groups and adds indexed `group_id` columns with default `0`. |
| `internal/model/profile.go` | Group dependents and Group fields on SSH/DB profiles. |
| `internal/model/api.go` | Single Group domain/API representation, Group request, and redacted connection group fields. |
| `internal/store/groups.go` | Group CRUD, aggregate counts, dependent lookup, transactional delete cleanup. |
| `internal/store/groups_test.go` | Store-level group and cleanup tests. |
| `internal/store/profiles.go` | Validated Group assignment in SSH/DB create/update and joined Group reads. |
| `internal/store/profiles_test.go` | Group assignment round-trip and validation coverage. |
| `internal/server/profiles/handlers.go` | Group routes, profile request plumbing, resource-neutral duplicate error, redaction. |
| `internal/server/profiles/groups.go` | Group HTTP CRUD/dependents handlers. |
| `internal/server/profiles/groups_test.go` | HTTP group CRUD/audit/dependents tests. |
| `internal/server/profiles/handlers_test.go` | Profile `group_id` HTTP round-trip/error tests. |
| `internal/client/picker/picker.go` | Group-name filter condition. |
| `internal/client/picker/render.go` | Group detail field and missing-reference label. |
| `internal/client/picker/picker_test.go` | Group picker detail and search tests. |
| `web/src/api/types.ts` | Group and group-aware SSH/DB TypeScript types. |
| `web/src/api/client.ts` | Group API methods. |
| `web/src/features/groups/groups-tab.tsx` | Group list/search/create/rename/delete UI. |
| `web/src/features/groups/groups-tab.test.tsx` | Groups tab behavior tests. |
| `web/src/features/ssh/ssh-form.tsx` | Group combobox and request mapping for SSH. |
| `web/src/features/db/db-form.tsx` | Group combobox and request mapping for DB. |
| `web/src/features/ssh/ssh-tab.tsx` | Group table cell and Group-aware SSH form props. |
| `web/src/features/db/db-tab.tsx` | Group table cell and Group-aware DB form props. |
| `web/src/features/ssh/jump-route.ts` | Group suffix in shared jump-candidate labels. |
| `web/src/features/ssh/*.test.tsx` / `jump-route.test.ts` | Updated SSH/DB/jump UI expectations. |
| `web/src/app.tsx` | Loads Groups, passes group data, mounts Groups tab. |

## Task 1: Persist and Manage Groups in Store

**Files:**
- Create: `migrations/003_groups.up.sql`
- Create: `internal/store/groups.go`
- Create: `internal/store/groups_test.go`
- Modify: `internal/model/profile.go`
- Modify: `internal/model/api.go`
- Test: `internal/store/store_test.go`

**Interfaces:**
- Produces `model.Group`, `model.GroupDependents`.
- Produces `(*Store).CreateGroup(context.Context, model.Group) (model.Group, error)`, `GetGroup`, `ListGroups`, `UpdateGroup`, `DeleteGroup`, and `GroupDependents`.
- Produces schema columns consumed by profile persistence in Task 2.

- [ ] **Step 1: Write failing group-store tests**

Create `internal/store/groups_test.go`. Use `newTestStore(t)` and `context.Background()` like `profiles_test.go`. Cover trimmed persistence, duplicate/invalid/not-found errors, alphabetic list order, zero counts, aggregate counts, both dependency kinds, and deletion cleanup.

```go
func TestDeleteGroupClearsProfileAssignments(t *testing.T) {
    s := newTestStore(t)
    ctx := context.Background()
    group, err := s.CreateGroup(ctx, model.Group{Name: "prod"})
    if err != nil { t.Fatal(err) }

    ssh, err := s.CreateSSH(ctx, SSHProfileForTest("web", "[]"))
    if err != nil { t.Fatal(err) }
    db, err := s.CreateDB(ctx, DBProfileForTest("appdb", 0))
    if err != nil { t.Fatal(err) }
    if _, err := s.db.ExecContext(ctx,
        "UPDATE ssh_connections SET group_id=? WHERE id=?", group.ID, ssh.ID); err != nil { t.Fatal(err) }
    if _, err := s.db.ExecContext(ctx,
        "UPDATE db_connections SET group_id=? WHERE id=?", group.ID, db.ID); err != nil { t.Fatal(err) }

    if err := s.DeleteGroup(ctx, group.ID); err != nil { t.Fatal(err) }
    var sshGroupID, dbGroupID int64
    if err := s.db.QueryRowContext(ctx, "SELECT group_id FROM ssh_connections WHERE id=?", ssh.ID).Scan(&sshGroupID); err != nil { t.Fatal(err) }
    if err := s.db.QueryRowContext(ctx, "SELECT group_id FROM db_connections WHERE id=?", db.ID).Scan(&dbGroupID); err != nil { t.Fatal(err) }
    if sshGroupID != 0 || dbGroupID != 0 { t.Fatalf("group ids = %d, %d; want 0, 0", sshGroupID, dbGroupID) }
}
```

Add a `TestListGroupsIncludesConnectionCounts` that sets `group_id` directly on two SSH rows and one DB row and asserts `SSHConnectionCount == 2` and `DBConnectionCount == 1`. Add a `TestGroupDependentsRejectsMissingGroup` assertion for `errors.Is(err, ErrNotFound)`.

- [ ] **Step 2: Run store tests to verify migration/store API is absent**

Run: `go test ./internal/store -run 'Test(CreateGroup|ListGroups|DeleteGroup|GroupDependents)' -count=1`

Expected: FAIL because migration/table and Group store methods do not exist.

- [ ] **Step 3: Add migration and domain/API types**

Create `migrations/003_groups.up.sql`:

```sql
CREATE TABLE groups (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

ALTER TABLE ssh_connections ADD COLUMN group_id INTEGER NOT NULL DEFAULT 0;
CREATE INDEX idx_ssh_connections_group_id ON ssh_connections(group_id);

ALTER TABLE db_connections ADD COLUMN group_id INTEGER NOT NULL DEFAULT 0;
CREATE INDEX idx_db_connections_group_id ON db_connections(group_id);
```

Add `GroupDependents` to `internal/model/profile.go`:

```go
type GroupDependents struct {
    SSH []DependentRef
    DB  []DependentRef
}
```

Define `model.Group` once in `internal/model/api.go`; Groups need no separate
redacted API view:

```go
type Group struct {
    ID                 int64     `json:"id"`
    Name               string    `json:"name"`
    SSHConnectionCount int       `json:"ssh_connection_count"`
    DBConnectionCount  int       `json:"db_connection_count"`
    CreatedAt          time.Time `json:"created_at"`
    UpdatedAt          time.Time `json:"updated_at"`
}
```

Do not add a SQL foreign key. The Store enforces valid IDs and deletion cleanup explicitly.

- [ ] **Step 4: Implement Group store methods**

Create `internal/store/groups.go`. Reuse `nowUTC`, `parseTime`, `isUniqueViolation`, `ErrDuplicate`, `ErrNotFound`, `ErrValidation`, and `timeLayout` from package `store`.

```go
var groupNameRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,100}$`)

func normalizeGroupName(name string) (string, error) {
    name = strings.TrimSpace(name)
    if !groupNameRe.MatchString(name) {
        return "", fmt.Errorf("%w: invalid group name %q: must match [A-Za-z0-9._-]{1,100}", ErrValidation, name)
    }
    return name, nil
}
```

`ListGroups` must issue one query using correlated count subqueries (or two LEFT JOIN aggregate subqueries) and `ORDER BY g.name`; do not multiply SSH and DB counts through a three-way join:

```sql
SELECT g.id, g.name,
       (SELECT COUNT(*) FROM ssh_connections s WHERE s.group_id = g.id),
       (SELECT COUNT(*) FROM db_connections d WHERE d.group_id = g.id),
       g.created_at, g.updated_at
FROM groups g
ORDER BY g.name
```

`DeleteGroup` must use one transaction: update SSH rows, update DB rows, delete the Group, check `RowsAffected`, then commit. `GroupDependents` must call `GetGroup` first so missing IDs return `ErrNotFound`, then produce non-nil reference slices.

- [ ] **Step 5: Run focused store tests**

Run: `go test ./internal/store -run 'Test(CreateGroup|GetGroup|ListGroups|UpdateGroup|DeleteGroup|GroupDependents)' -count=1`

Expected: PASS.

- [ ] **Step 6: Run all store tests and commit**

Run: `go test ./internal/store -count=1`

Expected: PASS.

```bash
git add migrations/003_groups.up.sql internal/model/profile.go internal/model/api.go internal/store/groups.go internal/store/groups_test.go
git commit -m "feat: persist connection groups"
```

## Task 2: Add Validated Group Assignment to SSH and DB Profiles

**Files:**
- Modify: `internal/model/profile.go`
- Modify: `internal/store/profiles.go`
- Modify: `internal/store/profiles_test.go`

**Interfaces:**
- Consumes Task 1 `groups` schema and `model.Group`.
- Produces `SSHProfile.GroupID`, `SSHProfile.GroupName`, `DBProfile.GroupID`, `DBProfile.GroupName`.
- Produces valid profile creation/update where `GroupID == 0` clears and positive IDs are required to exist.

- [ ] **Step 1: Write failing profile assignment tests**

Add tests that create a Group, assign it on SSH and DB creation, retrieve both profiles, and assert id/name. Update each profile to `GroupID: 0` and assert id/name clear. Add table-driven invalid tests for `GroupID: -1` (`ErrValidation`) and a nonexistent positive ID (`ErrValidation`). Add one direct-SQL test that writes `group_id = 999999` and asserts `GetSSH` returns the original ID and empty `GroupName` without failing.

```go
func TestSSHGroupRoundTripAndClear(t *testing.T) {
    s := newTestStore(t); ctx := context.Background()
    group, _ := s.CreateGroup(ctx, model.Group{Name: "prod"})
    input := SSHProfileForTest("web", "[]")
    input.GroupID = group.ID
    created, err := s.CreateSSH(ctx, input)
    if err != nil { t.Fatal(err) }
    got, err := s.GetSSH(ctx, created.ID)
    if err != nil { t.Fatal(err) }
    if got.GroupID != group.ID || got.GroupName != "prod" { t.Fatalf("group = %d/%q", got.GroupID, got.GroupName) }
    got.GroupID = 0
    if err := s.UpdateSSH(ctx, got); err != nil { t.Fatal(err) }
    got, _ = s.GetSSH(ctx, created.ID)
    if got.GroupID != 0 || got.GroupName != "" { t.Fatalf("group = %d/%q", got.GroupID, got.GroupName) }
}
```

- [ ] **Step 2: Run focused profile tests to verify they fail**

Run: `go test ./internal/store -run 'Test(SSH|DB)Group' -count=1`

Expected: FAIL because profile models and queries do not carry Group fields.

- [ ] **Step 3: Add profile fields and assignment validator**

Add to both domain profile structs:

```go
GroupID   int64
GroupName string
```

Add a Store helper used inside the `CreateSSH`, `UpdateSSH`, `CreateDB`, and `UpdateDB` transactions:

```go
func validateGroupID(ctx context.Context, tx *sql.Tx, groupID int64) error {
    if groupID < 0 {
        return fmt.Errorf("%w: group_id must not be negative", ErrValidation)
    }
    if groupID == 0 { return nil }
    var found int
    err := tx.QueryRowContext(ctx, "SELECT 1 FROM groups WHERE id=?", groupID).Scan(&found)
    if errors.Is(err, sql.ErrNoRows) {
        return fmt.Errorf("%w: group_id %d does not exist", ErrValidation, groupID)
    }
    if err != nil { return fmt.Errorf("validate group id: %w", err) }
    return nil
}
```

Call it after `BeginTx` and before INSERT/UPDATE. Preserve each existing metadata validation and secret transaction behavior.

- [ ] **Step 4: Extend SQL writes and joined reads**

Add `group_id` to SSH and DB INSERT column/value lists and UPDATE SET clauses. In `GetSSH` and `GetDB`, qualify all existing selected columns with table aliases and add:

```sql
s.group_id, COALESCE(g.name, '')
FROM ssh_connections s
LEFT JOIN groups g ON g.id = s.group_id
WHERE s.id = ?
```

Use equivalent `d` alias for DB. Scan into `p.GroupID` and `p.GroupName`. Keep `ListSSH`/`ListDB` behavior unchanged; their per-ID reads now include Group fields.

- [ ] **Step 5: Run focused profile tests**

Run: `go test ./internal/store -run 'Test(SSH|DB)Group' -count=1`

Expected: PASS.

- [ ] **Step 6: Run full store suite and commit**

Run: `go test ./internal/store -count=1`

Expected: PASS.

```bash
git add internal/model/profile.go internal/store/profiles.go internal/store/profiles_test.go
git commit -m "feat: assign groups to connection profiles"
```

## Task 3: Expose Group APIs and Group Fields in Profile APIs

**Files:**
- Modify: `internal/model/api.go`
- Modify: `internal/server/profiles/handlers.go`
- Create: `internal/server/profiles/groups.go`
- Create: `internal/server/profiles/groups_test.go`
- Modify: `internal/server/profiles/handlers_test.go`

**Interfaces:**
- Consumes Task 1 Group Store API and Task 2 profile Group fields.
- Produces `/api/v1/groups` CRUD/dependents endpoints and group-aware SSH/DB JSON payloads.
- Produces resource-neutral duplicate name API error text.

- [ ] **Step 1: Write failing HTTP tests**

Create `groups_test.go` in package `profiles_test`, using `newTestAPI`, `doRequest`, and the request helpers already in `handlers_test.go`. Cover create/list/get/rename/delete, invalid name 400 with `validation_error`, duplicate 409 with `conflict`, missing get/dependents/delete 404, dependents payload including one SSH and DB row, audit event operation, and delete clearing assignments.

Add `handlers_test.go` tests sending these bodies and checking both response fields and Store state:

```json
{"name":"grouped","host":"h.invalid","port":22,"username":"u","jump_connection_ids":"[]","group_id":1}
```

and DB equivalent. Test `group_id: 0` clears a prior assignment and `group_id: 999999` returns 400 `validation_error`.

- [ ] **Step 2: Run server profile tests to verify they fail**

Run: `go test ./internal/server/profiles -run 'Test(Group|CreateSSH.*Group|CreateDB.*Group|UpdateSSH.*Group|UpdateDB.*Group)' -count=1`

Expected: FAIL because routes/types/handlers are absent.

- [ ] **Step 3: Add remaining HTTP model fields**

`model.Group` was defined once in Task 1. In `internal/model/api.go`, add:

```go
type GroupRequest struct { Name string `json:"name"` }
```

Add `GroupID int64 'json:"group_id"'` and `GroupName string 'json:"group_name,omitempty"'` to both redacted connection structs. Add `GroupID int64 'json:"group_id"'` to both write request structs.

- [ ] **Step 4: Add routes, Group handlers, and profile plumbing**

Register all routes before transport routes:

```go
mux.HandleFunc("GET /api/v1/groups", h.listGroups)
mux.HandleFunc("POST /api/v1/groups", h.createGroup)
mux.HandleFunc("GET /api/v1/groups/{id}", h.getGroup)
mux.HandleFunc("PUT /api/v1/groups/{id}", h.updateGroup)
mux.HandleFunc("DELETE /api/v1/groups/{id}", h.deleteGroup)
mux.HandleFunc("GET /api/v1/groups/{id}/dependents", h.groupDependents)
```

Implement handlers in `groups.go` following exact `createSSH`/`updateSSH` strict-decoding, `pathID`, Store-error, audit, and `server.WriteJSON` patterns. Return `model.Group` directly: it is already a non-secret API representation. `groupDependents` returns `model.DependentsResponse{SSH: nonNilRefs(deps.SSH), DB: nonNilRefs(deps.DB)}`.

In SSH/DB create/update handlers set `GroupID: req.GroupID`; in `redactSSH`/`redactDB` copy both Group fields. Change `writeStoreError` duplicate message to a resource-neutral `"a resource with that name already exists"` without changing status/code mapping.

- [ ] **Step 5: Run focused server tests**

Run: `go test ./internal/server/profiles -run 'Test(Group|CreateSSH.*Group|CreateDB.*Group|UpdateSSH.*Group|UpdateDB.*Group)' -count=1`

Expected: PASS.

- [ ] **Step 6: Run all server profile tests and commit**

Run: `go test ./internal/server/profiles -count=1`

Expected: PASS.

```bash
git add internal/model/api.go internal/server/profiles/handlers.go internal/server/profiles/groups.go internal/server/profiles/groups_test.go internal/server/profiles/handlers_test.go
git commit -m "feat: expose connection group APIs"
```

## Task 4: Add Group to xssh Picker Detail and Search

**Files:**
- Modify: `internal/client/picker/picker.go`
- Modify: `internal/client/picker/render.go`
- Modify: `internal/client/picker/picker_test.go`

**Interfaces:**
- Consumes `model.SSHConnection.GroupID` and `GroupName` from Task 3.
- Produces Group field in `FormatConnection` and group-name case-insensitive filtering.

- [ ] **Step 1: Write failing picker tests**

Rename `TestStateFiltersNameAndHostCaseInsensitively` to include Group and add a connection with `GroupName: "Production"`; type `p`, `r`, `o`, `d` and assert its ID is returned. Extend `TestFormatConnectionRedactsSecretsAndShowsAllFields` with `GroupID: 3, GroupName: "prod"` and assert `Group: prod`. Add a separate test for `GroupID: 9, GroupName: ""` asserting `Group: Missing group #9`, plus `GroupID: 0` asserting `(not set)`.

- [ ] **Step 2: Run picker tests to verify failure**

Run: `go test ./internal/client/picker -run 'Test(StateFilters|FormatConnection)' -count=1`

Expected: FAIL because Group is not rendered or searched.

- [ ] **Step 3: Implement group display and filter**

Add a private rendering helper:

```go
func groupValue(c model.SSHConnection) string {
    if c.GroupName != "" { return c.GroupName }
    if c.GroupID == 0 { return "(not set)" }
    return "Missing group #" + strconv.FormatInt(c.GroupID, 10)
}
```

Add `{Label: "Group", Value: groupValue(c)}` immediately after Name in `FormatConnection`.

In `State.rebuild`, preserve name/host logic and add only real group names to matcher:

```go
strings.Contains(strings.ToLower(c.GroupName), needle)
```

An empty GroupName naturally never matches a nonempty query; do not add synthetic missing-label text to search.

- [ ] **Step 4: Run picker tests**

Run: `go test ./internal/client/picker -count=1`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/client/picker/picker.go internal/client/picker/render.go internal/client/picker/picker_test.go
git commit -m "feat: show groups in xssh picker"
```

## Task 5: Add Group Types, Client Methods, and Form Selectors

**Files:**
- Modify: `web/src/api/types.ts`
- Modify: `web/src/api/client.ts`
- Modify: `web/src/features/ssh/ssh-form.tsx`
- Modify: `web/src/features/db/db-form.tsx`
- Modify: `web/src/features/ssh/ssh-form.test.tsx`
- Modify: `web/src/features/db/db-form.test.tsx`

**Interfaces:**
- Consumes `/api/v1/groups` and connection payload fields from Task 3.
- Produces `Group`, `GroupRequest`, Group client methods, and form props accepting `readonly Group[]`.
- Produces `groupOptions(groups, currentID)` with `None` and missing-reference option behavior.

- [ ] **Step 1: Write failing form tests**

Add a Group fixture to both form test files. Test create defaults to `None`, edit selects existing group, selecting a group makes `toSSHRequest`/`toDBRequest` emit its numeric `group_id`, selecting None emits `0`, and an edited connection whose `group_id` is missing from supplied groups displays `Missing group #<id>`.

```ts
expect(toSSHRequest({ ...emptySSHForm(), groupID: "5" }).group_id).toBe(5)
expect(toDBRequest({ ...emptyDBForm(), groupID: "0" }).group_id).toBe(0)
```

Use Testing Library combobox interactions matching current DB SSH-combobox tests.

- [ ] **Step 2: Run form tests to verify failure**

Run: `cd web && npm test -- --run src/features/ssh/ssh-form.test.tsx src/features/db/db-form.test.tsx`

Expected: FAIL because Group types, state, and controls do not exist.

- [ ] **Step 3: Add TypeScript API contract and client methods**

In `web/src/api/types.ts`, add:

```ts
export interface Group {
  id: number
  name: string
  ssh_connection_count: number
  db_connection_count: number
  created_at: string
  updated_at: string
}
export interface GroupRequest { name: string }
```

Add required `group_id: number` and optional `group_name?: string` to SSH/DB read types, then required `group_id: number` to SSH/DB request types.

In `web/src/api/client.ts`, import Group types and add `listGroups`, `getGroup`, `createGroup`, `updateGroup`, `deleteGroup`, and `groupDependents`, using the same typed `request` expressions as SSH/DB methods. `listGroups` alone accepts optional `AbortSignal`.

- [ ] **Step 4: Implement Group form state and selectors**

Add `groupID: string` to both form-state interfaces; empty forms set it to `"0"`, mapping from a connection uses `String(connection.group_id)`, and request serializers use `group_id: Number(form.groupID)`.

Export a Group option helper from one shared form-local implementation or duplicate the compact helper in each form:

```ts
function groupOptions(groups: readonly Group[], currentID: number): SSHProfileOption[] {
  const options = [{ value: "0", label: "None" }]
  if (currentID !== 0 && !groups.some(group => group.id === currentID)) {
    options.push({ value: String(currentID), label: `Missing group #${currentID}` })
  }
  options.push(...groups.map(group => ({ value: String(group.id), label: group.name })))
  return options
}
```

Use existing `SSHProfileCombobox` for both forms with distinct `id`, accessible label, group-specific placeholders, and `onValueChange={value => set("groupID", value)}`. Place it immediately after Name. Extend each form prop with `groups: readonly Group[]`.

- [ ] **Step 5: Run form tests and TypeScript build**

Run: `cd web && npm test -- --run src/features/ssh/ssh-form.test.tsx src/features/db/db-form.test.tsx && npm run build`

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add web/src/api/types.ts web/src/api/client.ts web/src/features/ssh/ssh-form.tsx web/src/features/ssh/ssh-form.test.tsx web/src/features/db/db-form.tsx web/src/features/db/db-form.test.tsx
git commit -m "feat: select groups on connection forms"
```

## Task 6: Render Groups in SSH/DB Tables and Jump Host Picker

**Files:**
- Modify: `web/src/features/ssh/ssh-tab.tsx`
- Modify: `web/src/features/db/db-tab.tsx`
- Modify: `web/src/features/ssh/jump-route.ts`
- Modify: `web/src/features/ssh/ssh-tab.test.tsx`
- Modify: `web/src/features/db/db-tab.test.tsx`
- Modify: `web/src/features/ssh/jump-route.test.ts`

**Interfaces:**
- Consumes group-aware connection data and `groups` form prop from Task 5.
- Produces `groupCell` display and Group suffix in `jumpCandidates` labels.

- [ ] **Step 1: Write failing table and jump-label tests**

Update SSH and DB fixture builders to supply `group_id: 0`. Add table tests asserting one named Group and one `(Ungrouped)` muted label. Add an externally-corrupted fixture (`group_id: 7`, absent `group_name`) expecting `Missing group #7`.

Update jump route tests so a candidate with `group_name: "prod"` has option label `jump-a — 10.0.0.2:22 (prod)` while an ungrouped candidate preserves current label exactly.

- [ ] **Step 2: Run UI tests to verify failure**

Run: `cd web && npm test -- --run src/features/ssh/ssh-tab.test.tsx src/features/db/db-tab.test.tsx src/features/ssh/jump-route.test.ts`

Expected: FAIL because table cells and labels do not use Group fields.

- [ ] **Step 3: Implement display helpers and pass groups to forms**

In each tab add:

```ts
function groupCell(connection: SSHConnection | DBConnection): string {
  if (connection.group_name) return connection.group_name
  if (connection.group_id === 0) return "(Ungrouped)"
  return `Missing group #${connection.group_id}`
}
```

Render `(Ungrouped)` with `<span className="text-sm text-muted-foreground">`; named/missing values can use plain text. Add a Group header between Name and Host and a matching cell in every body row.

Extend `SSHTabProps`/`DBTabProps` with `groups: readonly Group[]` and pass it to `SSHForm`/`DBForm` in dialog render branches.

In `jumpLabel` or the candidate label generator, append ` (${profile.group_name})` only when the name is nonempty. Keep missing jump-ID labels and route order behavior unchanged.

- [ ] **Step 4: Run focused UI tests**

Run: `cd web && npm test -- --run src/features/ssh/ssh-tab.test.tsx src/features/db/db-tab.test.tsx src/features/ssh/jump-route.test.ts`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add web/src/features/ssh/ssh-tab.tsx web/src/features/ssh/ssh-tab.test.tsx web/src/features/db/db-tab.tsx web/src/features/db/db-tab.test.tsx web/src/features/ssh/jump-route.ts web/src/features/ssh/jump-route.test.ts
git commit -m "feat: display groups with connection pickers"
```

## Task 7: Build Groups Tab, Apply DB-Form Group Suffix, and Wire Application Data Flow

**Files:**
- Create: `web/src/features/groups/groups-tab.tsx`
- Create: `web/src/features/groups/groups-tab.test.tsx`
- Modify: `web/src/features/db/db-form.tsx`
- Modify: `web/src/features/db/db-form.test.tsx`
- Modify: `web/src/app.tsx`
- Modify: `web/src/app.test.tsx`

**Interfaces:**
- Consumes `api.listGroups/createGroup/updateGroup/deleteGroup/groupDependents`, `Group`, `GroupRequest`, and `ListResource<Group>`.
- Produces a Groups tab with searchable CRUD and dependents warning. Supplies `groups.data` to SSH/DB tabs.
- Produces a group suffix on every SSH option label rendered by `db-form.tsx`'s `sshOptions` helper, reusing `jumpOptionLabel` from `jump-route.ts` (controller ruling: spec line 225–228 requires the suffix on all SSH picker surfaces, not only the jump-route Add combobox).

- [ ] **Step 1: Write failing Groups tab + DB form SSH selector tests**

Create test coverage for:

- Group rows with `SSH 2 · DB 1` used-by text and case-insensitive search.
- Create dialog posting `{ name: "prod" }`, reload, close, success toast callback.
- Rename dialog prefilled with current name and PUT request.
- Delete click fetching dependents; warning lists SSH/DB names; confirm remains enabled; DELETE then reload/close/success toast.
- API error leaves dialog open and exposes `role="alert"`.
- DB form `sshOptions` renders group suffix (`(prod)`) on SSH connection options when `group_name` is non-empty, and unchanged plain label when absent. Mock `fetch` like existing SSH/DB tab tests and render a real `useListResource` result or a shaped `ListResource<Group>` fixture according to current test helpers.

- [ ] **Step 2: Run test to verify failure**

Run: `cd web && npm test -- --run src/features/groups/groups-tab.test.tsx src/features/db/db-form.test.tsx`

Expected: FAIL because GroupsTab does not exist and DB form SSH options lack group suffix.

- [ ] **Step 3: Implement GroupsTab and DB form group suffix**

Mirror state/error/focus restoration patterns from `SSHTab`; do not introduce a new modal primitive. Define:

```ts
type FormDialogState = { mode: "create" } | { mode: "edit"; group: Group }
interface DeleteDialogState {
  target: Group
  dependents: DependentsResponse | null
  loading: boolean
  error: string | null
}
```

Use a controlled name `<Input>` with `required`, table filter from `name.toLowerCase().includes(query.trim().toLowerCase())`, and `Used by` formatted exactly `SSH ${group.ssh_connection_count} · DB ${group.db_connection_count}`. On delete, first call `api.groupDependents`; render warning lists when either array has entries; still enable deletion. Reuse `ResourceError`, `Dialog`, table, `notify`, error text, reload sequencing, and focus restore semantics from `SSHTab`.

For the DB form SSH selector, modify `sshOptions` in `web/src/features/db/db-form.tsx` to use `jumpOptionLabel(profile)` instead of the inline `${profile.name} — ${profile.host}:${profile.port}` template. The current `jumpOptionLabel` already implements `name — host:port (group)` when `group_name` is non-empty and the unchanged label otherwise; reusing it satisfies `web/src/components/ssh-profile-combobox.tsx` spec bullet without duplication.

- [ ] **Step 4: Switch `groups` prop to required and wire `App`**

Change `SSHTabProps.groups` and `DBTabProps.groups` from `groups?: readonly Group[]` (with default `[]`) to required `groups: readonly Group[]`; remove the default. This is a load-bearing follow-up to the Task 6 deviation: required now that every consumer (Task 7's `app.tsx`) supplies real data.

In `app.tsx` add:

```ts
const groups = useListResource(api.listGroups)
```

Add a `Groups` trigger after Databases, its content rendering `<GroupsTab resource={groups} notify={notify} />`, and pass `groups={groups.data}` to both `<SSHTab>` and `<DBTab>` (now required). Update `app.test.tsx` mocks/expectations for the extra `GET /api/v1/groups` request and tab.

- [ ] **Step 5: Run groups/app/DB-form tests and production build**

Run: `cd web && npm test -- --run src/features/groups/groups-tab.test.tsx src/features/db/db-form.test.tsx src/app.test.tsx && npm run build`

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add web/src/features/groups/groups-tab.tsx web/src/features/groups/groups-tab.test.tsx web/src/features/db/db-form.tsx web/src/features/db/db-form.test.tsx web/src/app.tsx web/src/app.test.tsx web/src/features/ssh/ssh-tab.tsx web/src/features/db/db-tab.tsx
git commit -m "feat: manage connection groups in web UI"
```

## Task 8: Full Regression, Migration Upgrade Check, and Review

**Files:**
- Modify: `internal/store/store_test.go` (migration upgrade test)
- Modify only if another verification command reveals a concrete defect.

**Interfaces:**
- Verifies all outputs from Tasks 1–7 together.

- [ ] **Step 1: Run all Go checks**

Run:

```bash
gofmt -w internal/model/profile.go internal/model/api.go internal/store/groups.go internal/store/groups_test.go internal/store/profiles.go internal/store/profiles_test.go internal/server/profiles/handlers.go internal/server/profiles/groups.go internal/server/profiles/groups_test.go internal/server/profiles/handlers_test.go internal/client/picker/picker.go internal/client/picker/render.go internal/client/picker/picker_test.go
go test ./...
go build ./...
```

Expected: all tests and build PASS.

- [ ] **Step 2: Run all web checks**

Run:

```bash
cd web && npm test && npm run build
```

Expected: Vitest, distribution verification, TypeScript, Vite build, and embedded-dist verification PASS.

- [ ] **Step 3: Add and run migration upgrade test**

In `internal/store/store_test.go`, import `time` and `warden/migrations`. Add a test that seeds the exact embedded 001+002 schema and marks `schema_migrations` at version 2 before calling `Open`:

```go
func TestOpenMigratesExistingConnectionsToUngrouped(t *testing.T) {
    var key [32]byte
    if _, err := rand.Read(key[:]); err != nil { t.Fatal(err) }
    path := filepath.Join(t.TempDir(), "warden.db")
    db, err := sql.Open("sqlite", sqliteDSN(path))
    if err != nil { t.Fatal(err) }
    initial, err := migrations.FS.ReadFile("001_initial.up.sql")
    if err != nil { t.Fatal(err) }
    defaultDir, err := migrations.FS.ReadFile("002_default_dir.up.sql")
    if err != nil { t.Fatal(err) }
    for _, statement := range []string{string(initial), string(defaultDir),
        "CREATE TABLE schema_migrations (version uint64, dirty bool)",
        "INSERT INTO schema_migrations (version, dirty) VALUES (2, false)"} {
        if _, err := db.Exec(statement); err != nil { t.Fatal(err) }
    }
    ts := time.Now().UTC().Format(time.RFC3339Nano)
    if _, err := db.Exec(`INSERT INTO ssh_connections (name, host, port, username, jump_connection_ids, default_dir, created_at, updated_at) VALUES ('ssh', 'h', 22, 'u', '[]', '', ?, ?)`, ts, ts); err != nil { t.Fatal(err) }
    if _, err := db.Exec(`INSERT INTO db_connections (name, host, port, username, database, created_at, updated_at) VALUES ('db', 'h', 3306, 'u', 'd', ?, ?)`, ts, ts); err != nil { t.Fatal(err) }
    if err := db.Close(); err != nil { t.Fatal(err) }

    s, err := Open(context.Background(), path, key)
    if err != nil { t.Fatal(err) }
    defer s.Close()
    var sshGroupID, dbGroupID, groupCount int
    if err := s.db.QueryRow("SELECT group_id FROM ssh_connections WHERE name='ssh'").Scan(&sshGroupID); err != nil { t.Fatal(err) }
    if err := s.db.QueryRow("SELECT group_id FROM db_connections WHERE name='db'").Scan(&dbGroupID); err != nil { t.Fatal(err) }
    if err := s.db.QueryRow("SELECT COUNT(*) FROM groups").Scan(&groupCount); err != nil { t.Fatal(err) }
    if sshGroupID != 0 || dbGroupID != 0 || groupCount != 0 {
        t.Fatalf("migration result = ssh:%d db:%d groups:%d; want 0, 0, 0", sshGroupID, dbGroupID, groupCount)
    }
}
```

Run: `go test ./internal/store -run TestOpenMigratesExistingConnectionsToUngrouped -count=1`

Expected: PASS. This proves migration 003 upgrades persisted preexisting rows without a backfill.

- [ ] **Step 4: Inspect final changes before integration**

Run:

```bash
git diff --check
git status --short
git log --oneline main..HEAD
```

Expected: no whitespace errors, only intended files changed, and commits correspond to Tasks 1–7.

- [ ] **Step 5: Commit only concrete verification fixes**

```bash
git add internal/store/store_test.go <other-intended-files>
git commit -m "test: verify connection group migration"
```

Do not create an empty commit when no verification fix was needed.

## Plan Self-Review

- **Spec coverage:** Task 1 handles schema, naming, counts, dependents, and cleanup deletion. Task 2 enforces assignment validity and joined reads. Task 3 provides routes/audit/redaction/error behavior. Task 4 handles xssh detail/filter. Tasks 5–7 cover web types/client, form selectors, SSH/DB display, jump picker label, Groups tab, and app wiring. Task 8 covers full build and migration upgrade.
- **Placeholder scan:** No TBD/TODO/future-work steps. Commands, files, interfaces, expected test states, UI copy, and SQL semantics are explicit.
- **Type consistency:** Group counts are `SSHConnectionCount`/`DBConnectionCount` in Go and `ssh_connection_count`/`db_connection_count` in JSON/TypeScript. Connection assignment uses `GroupID`/`group_id`; display name uses `GroupName`/`group_name` throughout.
