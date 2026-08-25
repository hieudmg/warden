# Connection Groups — Design Spec

**Date:** 2026-08-25
**Status:** Approved
**Path:** web (UI), Go server, SQLite schema, xssh terminal picker
**CLI surface:** unchanged (no CLI flag/argument additions)

## Purpose

Users manage many SSH and DB connections. Finding the right one in a list or
picker is faster when they are organized into named groups. Groups are a
**user-facing label**, not a security or routing primitive — they never affect
transport resolution, secret handling, or jump-chain logic.

## Scope

- A new `groups` table holding named, unique labels.
- An optional `group_id` reference on every `ssh_connections` and
  `db_connections` row. NULL (0 in code) means **ungrouped**.
- Web UI: dedicated **Groups** tab, group column on SSH/DB lists, group
  combobox on SSH/DB forms, group suffix on the jump-route combobox.
- xssh native picker: Group field in the detail pane; group-name substring
  added to the search filter.
- HTTP API: full CRUD on groups + dependents warning endpoint, plus
  `group_id` field on SSH/DB connection read/write payloads.
- Out of scope: `warden ssh`, `warden db`, `warden config search` CLI
  output — these do not display groups; the user-facing surfaces are the
  web UI and the xssh picker.

## Design Decisions

| Decision | Choice | Rationale |
|---|---|---|
| Group storage | Managed entity in own table (id, unique name) | Renaming is a single-row update; uniqueness enforced by DB; pattern matches SSH/DB/projects. |
| Group → connection link | Nullable integer column, no FK constraint | Deletion is never blocked (matches `ssh_connection_id` pattern); orphaned refs resolved at read time via LEFT JOIN. |
| Group name format | `[A-Za-z0-9._-]{1,100}`, trimmed, unique case-sensitive | Reuses existing connection-name regex for consistency; no shell-tokenization concerns since groups never appear in CLI args. |
| Group delete behaviour | Hard delete; `GET /dependents` warns but never blocks | Matches SSH delete pattern. |
| Group management UI | Dedicated **Groups** tab | Users need to rename and delete groups; mirror existing per-resource tab pattern. |
| Form group selector | Read-only combobox | Single source of truth = Groups tab; users create groups there first. Avoids implicit creation from forms. |
| xssh picker display | Detail pane only | List rows stay clean; detail pane is where secondary metadata belongs. |
| xssh picker search | Match name + host + group (case-insensitive substring) | GroupName is searched only when non-empty. |
| `(Ungrouped)` rendering | Web UI label only; picker uses existing `(not set)` | Two surfaces, two conventions; picker change stays minimal. |

## Data Model

### New table

```sql
CREATE TABLE groups (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
```

### Schema additions (migration `003_groups.up.sql`)

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

Existing rows migrate to `group_id = 0` (ungrouped). No data backfill.

### Model

```go
// internal/model/profile.go
type Group struct {
    ID        int64
    Name      string
    CreatedAt time.Time
    UpdatedAt time.Time
}

type GroupDependents struct {
    SSH []DependentRef
    DB  []DependentRef
}
```

### API types

```go
// internal/model/api.go
type Group struct {
    ID        int64     `json:"id"`
    Name      string    `json:"name"`
    CreatedAt time.Time `json:"created_at"`
    UpdatedAt time.Time `json:"updated_at"`
}

type GroupRequest struct {
    Name string `json:"name"`
}

// SSHConnection gains:
//   GroupID   int64  `json:"group_id"`           // 0 = ungrouped
//   GroupName string `json:"group_name,omitempty"` // empty when ungrouped
// DBConnection gains the same two fields.
// SSHConnectionRequest gains: GroupID int64 `json:"group_id"` (0 = clear)
// DBConnectionRequest gains:   GroupID int64 `json:"group_id"` (0 = clear)
```

## Store Layer

### `internal/store/groups.go` (new)

Functions: `CreateGroup`, `GetGroup`, `ListGroups`, `UpdateGroup`,
`DeleteGroup`, `GroupDependents`.

Validation:

- Trim before validation.
- `groupNameRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,100}$`)`
- Trimmed value stored (no leading/trailing whitespace ever persisted).
- Duplicate name → `ErrDuplicate`.
- Missing id on update → `errors.New("update group requires id")`.
- `GroupDependents`: two SELECTs against `ssh_connections` and
  `db_connections` filtered by `group_id = ?`.

### `internal/store/profiles.go` changes

- `SSHProfile` and `DBProfile` gain `GroupID int64` and `GroupName string`.
- `CreateSSH`/`UpdateSSH` write `group_id`. `CreateDB`/`UpdateDB` write
  `group_id`.
- `GetSSH`/`GetDB` use a `LEFT JOIN groups g ON g.id = s.group_id`,
  selecting `group_id` and `COALESCE(g.name, '') AS group_name`. Missing
  group (orphaned FK) yields `GroupID = <original>`, `GroupName = ""`. The
  picker renders `(not set)`; the web UI renders `(Ungrouped)`.
- `ListSSH`/`ListDB` already loop through per-id reads; no extra change.

## HTTP API

New routes, mounted by existing `Handler.Register`:

```
GET    /api/v1/groups                    list
POST   /api/v1/groups                    create
GET    /api/v1/groups/{id}               get
PUT    /api/v1/groups/{id}               rename
DELETE /api/v1/groups/{id}               hard delete
GET    /api/v1/groups/{id}/dependents    warning payload (SSH + DB refs)
```

Audit operations: `group.list`, `group.get`, `group.create`, `group.update`,
`group.delete`, `group.dependents`.

Error mapping via existing `writeStoreError`:

- `ErrDuplicate` → 409 Conflict
- `ErrValidation` → 400 Bad Request
- `ErrNotFound` → 404 Not Found

`redactSSH` and `redactDB` populate `GroupID` and `GroupName` from the
profile struct. Response always carries `group_id` (0 when ungrouped);
`group_name` is omitted via `omitempty` when empty.

## xssh Native Picker

`internal/client/picker/render.go`:

- `FormatConnection` adds `{Label: "Group", Value: orNotSet(c.GroupName)}`
  after the `Name` field.

`internal/client/picker/picker.go`:

- `rebuild()` adds `c.GroupName` to the case-insensitive substring
  matcher, guarded by `c.GroupName != ""`.
- List rows: unchanged.

CLI `warden xssh` is unchanged in behavior — only the rendered detail and
filter logic gain the group.

## Web UI

### `web/src/features/groups/groups-tab.tsx` (new)

Mirrors `ssh-tab.tsx`:

- Search box filters by name (case-insensitive substring).
- Columns: `Name`, `Used by` (dependent count), `Created`, `Updated`.
- Create dialog (name input only).
- Edit dialog (rename).
- Delete dialog: fetches `/dependents`, shows warning rows, confirm
  button always enabled (matches SSH delete pattern).
- `notify` prop for success/error toasts.

### `SSHTab` and `DBTab` table changes

- New **Group** column between `Name` and `Host`.
- Renders `GroupName` when non-empty; otherwise `(Ungrouped)` in
  `text-muted-foreground`.

### `SSHForm` and `DBForm`

- New `<Select>` placed immediately after the `Name` field (before `Host`).
- Populated from `api.listGroups()` (passed in from `app.tsx`).
- Options: `None` (value `0`) at top, then one entry per group.
- Submit includes `group_id` in the request payload (0 when "None" is
  selected).

### `ssh-profile-combobox.tsx`

- Option label: `name — host (group)` when `group_name` is non-empty;
  otherwise unchanged.

### `app.tsx`

- `groups = useListResource(api.listGroups)`.
- New `TabsTrigger value="groups"` + `TabsContent`.
- `groups` passed to `SSHTab`, `DBTab`, `GroupsTab`.

### API client

`web/src/api/client.ts`:

```ts
listGroups(): Promise<Group[]>
getGroup(id: number): Promise<Group>
createGroup(req: GroupRequest): Promise<Group>
updateGroup(id: number, req: GroupRequest): Promise<Group>
deleteGroup(id: number): Promise<void>
getGroupDependents(id: number): Promise<DependentsResponse>
```

### Type updates

`web/src/api/types.ts`:

```ts
interface Group {
  id: number
  name: string
  created_at: string
  updated_at: string
}

interface GroupRequest { name: string }

// SSHConnection + DBConnection gain:
//   group_id: number      // 0 = ungrouped
//   group_name?: string   // present when non-empty
// SSHConnectionRequest + DBConnectionRequest gain: group_id: number
```

## Testing & Verification

### Go (TDD — write tests first)

- `internal/store/groups_test.go`: Create/Get/List/Update/Delete,
  validation (empty/long/special chars), duplicate, not-found,
  GroupDependents coverage.
- `internal/store/profiles_test.go`: CreateSSH/UpdateSSH/CreateDB/UpdateDB
  with `GroupID`; roundtrip preserves; clear via `GroupID = 0`;
  LEFT JOIN tolerates orphaned FK.
- `internal/server/profiles/groups_test.go` (new): HTTP handler tests
  for full CRUD + dependents + audit.
- `internal/server/profiles/handlers_test.go`: SSH/DB request with
  `group_id` roundtrip.
- `internal/client/picker/picker_test.go`: Group field in
  `FormatConnection`; `rebuild()` matches by group substring.

### Web (Vitest)

- `web/src/features/groups/groups-tab.test.tsx` (new): list, search,
  create, edit, delete-with-dependents.
- `web/src/features/ssh/ssh-tab.test.tsx`: group column.
- `web/src/features/db/db-tab.test.tsx`: group column.
- `web/src/features/ssh/ssh-form.test.tsx`: group combobox selection
  sends `group_id`.
- `web/src/features/db/db-form.test.tsx`: same.
- `web/src/components/ssh-profile-combobox.test.tsx` (or add): group
  suffix in option label.

### Migration verification

- Apply migration to existing DB; verify `group_id = 0` on every row;
  verify `groups` table is empty; create a group, assign, rename,
  delete, observe `(Ungrouped)` reappearing.

### Build verification

- `go build ./...`
- `go test ./...`
- `npm run build`
- `npm test`

## Files Touched

Go:
- `migrations/003_groups.up.sql` (new)
- `internal/model/profile.go` (Group, GroupDependents)
- `internal/model/api.go` (Group, GroupRequest, group_id/group_name)
- `internal/store/groups.go` (new)
- `internal/store/profiles.go` (GroupID/GroupName plumbing)
- `internal/server/profiles/handlers.go` (route registration)
- `internal/server/profiles/groups.go` (new — handlers)
- `internal/client/picker/render.go` (FormatConnection Group field)
- `internal/client/picker/picker.go` (rebuild GroupName match)
- `internal/client/api/client.go` (group methods on Client)

Web:
- `web/src/api/types.ts` (Group, group_id/group_name)
- `web/src/api/client.ts` (list/get/create/update/delete/dependents)
- `web/src/app.tsx` (tabs + useListResource)
- `web/src/features/groups/groups-tab.tsx` (new)
- `web/src/features/groups/groups-tab.test.tsx` (new)
- `web/src/features/ssh/ssh-tab.tsx` (group column)
- `web/src/features/ssh/ssh-form.tsx` (group combobox)
- `web/src/features/db/db-tab.tsx` (group column)
- `web/src/features/db/db-form.tsx` (group combobox)
- `web/src/components/ssh-profile-combobox.tsx` (group suffix)
