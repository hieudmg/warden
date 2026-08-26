# Key-Pair Vault Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a vault for reusable SSH key pairs and refactor SSH key authentication to select a stored pair instead of storing private-key material per connection.

**Architecture:** Migration 004 creates encrypted key-pair rows and rebuilds SSH rows to remove legacy private-key ciphertext while preserving every other connection field. Store resolves and validates key-pair references; resolver injects the selected shared pair into unchanged transport nodes. The HTTP/UI layers expose a metadata-only list plus authenticated-later vault GET for individual key material.

**Tech Stack:** Go 1.25, SQLite via modernc.org/sqlite, golang-migrate embedded SQL, AES-256-GCM store codec, net/http ServeMux, React 19, TypeScript, Vite, Vitest, Testing Library.

**Spec:** `docs/superpowers/specs/2026-08-26-key-pair-vault-design.md`

## Global Constraints

- Encrypt public key, private key, and private-key passphrase with AAD `warden/key-pair/<id>/<field>`; never persist plaintext.
- Key-pair name is required/unique; public key, private key, and passphrase are independently optional.
- Existing per-SSH private-key and passphrase data is intentionally discarded by migration; preserve all other SSH data, including inline passwords.
- SSH password and nonzero `key_pair_id` are mutually exclusive. A positive pair ID must exist and contain a private key.
- Do not add foreign key from SSH to key pairs. Deletion warns then leaves references dangling.
- Key-pair list payloads contain metadata/presence flags only. Individual vault GET intentionally returns raw public/private/passphrase values; Hub currently has no authentication and user accepted this risk.
- Do not add generic credentials, reusable passwords, or an authentication layer.
- Preserve existing client transport JSON shape (`model.SSHNode.PrivateKey` and `PrivateKeyPassphrase`) and `Cache-Control: no-store` behavior.

---

## File map

| File | Responsibility |
| --- | --- |
| `migrations/004_key_pairs.up.sql` | Create encrypted key-pair table; rebuild `ssh_connections` with `key_pair_id`; discard legacy SSH key ciphertext. |
| `internal/model/profile.go` | Add key-pair domain/list-summary values; replace SSH raw key fields with reference fields. |
| `internal/model/api.go` | Define key-pair list/vault/write API types and SSH key-pair fields. |
| `internal/store/key_pairs.go` | Encrypt/decrypt key pairs, CRUD, validation, and SSH dependents. |
| `internal/store/profiles.go` | Persist/select `key_pair_id`; validate/exclude password vs selected pair; remove per-SSH key encryption. |
| `internal/store/*_test.go` | Migration, key-pair storage, SSH-switching, and schema regression coverage. |
| `internal/server/profiles/key_pairs.go` | Key-pair HTTP handlers and audit events. |
| `internal/server/profiles/handlers.go` | Register routes; map SSH requests/responses to `key_pair_id`. |
| `internal/server/profiles/resolve.go` | Resolve selected pair into unchanged `SSHNode` transport secrets. |
| `internal/server/profiles/*_test.go` | Handler, vault disclosure, resolution, and dangling-reference behavior. |
| `internal/client/picker/render.go` | Replace obsolete private-key status output with redacted key-pair reference display. |
| `web/src/api/types.ts`, `web/src/api/client.ts` | Mirror key-pair and SSH API changes. |
| `web/src/features/key-pairs/key-pairs-tab.tsx` | Vault list/create/view/edit/delete UI. |
| `web/src/features/key-pairs/key-pairs-tab.test.tsx` | Key-pair tab behavior tests. |
| `web/src/features/ssh/ssh-form.tsx`, `ssh-tab.tsx` | Stored-key-pair selector and SSH auth display. |
| `web/src/features/ssh/*.test.tsx` | SSH form/tab serialization and UI regression tests. |
| `web/src/app.tsx`, `web/src/app.test.tsx` | Load/render Key Pairs tab and pass summaries to SSH tab/form. |

### Task 1: Migration and domain/API contracts

**Files:**
- Create: `migrations/004_key_pairs.up.sql`
- Modify: `internal/model/profile.go`
- Modify: `internal/model/api.go`
- Modify: `internal/store/store_test.go`
- Modify: `internal/store/profiles_test.go`

**Interfaces:**
- Produces domain types used by every later task:

```go
type KeyPair struct {
    ID int64; Name string
    PublicKey, PrivateKey, PrivateKeyPassphrase []byte
    CreatedAt, UpdatedAt time.Time
}
type KeyPairSummary struct {
    ID int64 `json:"id"`; Name string `json:"name"`
    HasPublicKey bool `json:"has_public_key"`
    HasPrivateKey bool `json:"has_private_key"`
    HasPrivateKeyPassphrase bool `json:"has_private_key_passphrase"`
    CreatedAt time.Time `json:"created_at"`; UpdatedAt time.Time `json:"updated_at"`
}
```

- `model.SSHProfile` gains `KeyPairID int64`, `KeyPairName string`, and removes `PrivateKey`/`PrivateKeyPassphrase`.
- `model.SSHConnection` gains `KeyPairID`/`KeyPairName` and removes private-key presence fields.
- `model.KeyPairVault` uses string values for a single vault GET; `model.KeyPairRequest` uses `*string` fields so omission can retain a stored secret on update.
- `model.SSHConnectionRequest` replaces `private_key` and `private_key_passphrase` with `key_pair_id int64`.

- [ ] **Step 1: Write migration regression tests before migration**

Add `TestOpenMigratesSSHKeysToKeyPairReferences` in `internal/store/store_test.go`. Build a temporary database by applying embedded migrations 001, 002, and 003, stamp `schema_migrations` version 3, and insert an SSH row with a password, private-key blob, passphrase blob, proxy fields, default dir, group ID, and timestamps. Open with `store.Open`.

Assert all of the following after migration:

```go
var password []byte
var keyPairID, groupID int64
err := s.db.QueryRow(`SELECT password, key_pair_id, group_id FROM ssh_connections WHERE name='ssh'`).
    Scan(&password, &keyPairID, &groupID)
if err != nil { t.Fatal(err) }
if !bytes.Equal(password, oldPassword) || keyPairID != 0 || groupID != oldGroupID {
    t.Fatalf("migrated ssh = password:%x keyPair:%d group:%d", password, keyPairID, groupID)
}
```

Use `PRAGMA table_info(ssh_connections)` to assert `private_key` and `private_key_passphrase` are absent and `key_pair_id` is present. Assert `key_pairs` exists, `idx_ssh_connections_group_id` and `idx_ssh_connections_key_pair_id` exist, and the legacy private ciphertext cannot be selected.

Update `TestSecretColumnsAreBLOB` to expect `key_pairs.public_key`, `key_pairs.private_key`, and `key_pairs.private_key_passphrase`, and to stop expecting removed SSH columns. Update test fixtures and assertions in `profiles_test.go` to stop constructing/reading the removed fields.

- [ ] **Step 2: Run migration/domain tests to verify failure**

Run:

```bash
go test ./internal/store -run 'Test(OpenMigratesSSHKeysToKeyPairReferences|SecretColumnsAreBLOB|SSHCreateGetRoundTrip)$' -count=1
```

Expected: compilation failure for missing model fields and/or migration test failure because version 004 does not exist.

- [ ] **Step 3: Add model/API contracts and migration 004**

Add the types described above. Implement `migrations/004_key_pairs.up.sql` exactly as an up-only destructive-key migration:

```sql
CREATE TABLE key_pairs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    public_key BLOB,
    private_key BLOB,
    private_key_passphrase BLOB,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE ssh_connections_new (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    host TEXT NOT NULL,
    port INTEGER NOT NULL,
    username TEXT NOT NULL,
    password BLOB,
    proxy_host TEXT,
    proxy_port INTEGER,
    proxy_username TEXT,
    proxy_password BLOB,
    jump_connection_ids TEXT NOT NULL DEFAULT '[]',
    default_dir TEXT NOT NULL DEFAULT '',
    group_id INTEGER NOT NULL DEFAULT 0,
    key_pair_id INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
INSERT INTO ssh_connections_new (
    id, name, host, port, username, password, proxy_host, proxy_port,
    proxy_username, proxy_password, jump_connection_ids, default_dir,
    group_id, key_pair_id, created_at, updated_at
) SELECT id, name, host, port, username, password, proxy_host, proxy_port,
    proxy_username, proxy_password, jump_connection_ids, default_dir,
    group_id, 0, created_at, updated_at
FROM ssh_connections;
DROP TABLE ssh_connections;
ALTER TABLE ssh_connections_new RENAME TO ssh_connections;
CREATE INDEX idx_ssh_connections_group_id ON ssh_connections(group_id);
CREATE INDEX idx_ssh_connections_key_pair_id ON ssh_connections(key_pair_id);
```

Keep the new vault response separate from byte-backed domain `KeyPair` so Go never base64-encodes secret bytes accidentally:

```go
type KeyPairVault struct {
    ID int64 `json:"id"`; Name string `json:"name"`
    PublicKey string `json:"public_key"`
    PrivateKey string `json:"private_key"`
    PrivateKeyPassphrase string `json:"private_key_passphrase"`
    CreatedAt time.Time `json:"created_at"`; UpdatedAt time.Time `json:"updated_at"`
}
type KeyPairRequest struct {
    Name string `json:"name"`
    PublicKey *string `json:"public_key"`
    PrivateKey *string `json:"private_key"`
    PrivateKeyPassphrase *string `json:"private_key_passphrase"`
}
```

- [ ] **Step 4: Run migration/domain tests to verify pass**

Run:

```bash
gofmt -w internal/model/profile.go internal/model/api.go internal/store/store_test.go internal/store/profiles_test.go
go test ./internal/store -run 'Test(OpenMigratesSSHKeysToKeyPairReferences|SecretColumnsAreBLOB|SSHCreateGetRoundTrip)$' -count=1
```

Expected: PASS. The database upgrades from version 3 while retaining password/metadata and dropping the legacy key columns/data.

- [ ] **Step 5: Commit migration and contracts**

```bash
git add migrations/004_key_pairs.up.sql internal/model/profile.go internal/model/api.go internal/store/store_test.go internal/store/profiles_test.go
git commit -m "feat: add key-pair persistence schema"
```

### Task 2: Key-pair encrypted store and dependency queries

**Files:**
- Create: `internal/store/key_pairs.go`
- Create: `internal/store/key_pairs_test.go`
- Modify: `internal/store/profiles.go`

**Interfaces:**
- Consumes `model.KeyPair`, `model.KeyPairSummary`, `model.DependentRef`, `store.ErrValidation`, and Task 1 schema.
- Produces:

```go
func (s *Store) CreateKeyPair(ctx context.Context, p model.KeyPair) (model.KeyPair, error)
func (s *Store) GetKeyPair(ctx context.Context, id int64) (model.KeyPair, error)
func (s *Store) ListKeyPairs(ctx context.Context) ([]model.KeyPairSummary, error)
func (s *Store) UpdateKeyPair(ctx context.Context, p model.KeyPair) error
func (s *Store) DeleteKeyPair(ctx context.Context, id int64) error
func (s *Store) KeyPairDependents(ctx context.Context, id int64) ([]model.DependentRef, error)
func validateKeyPairID(ctx context.Context, tx *sql.Tx, id int64) error
```

- `validateKeyPairID` accepts zero, rejects negative, and for positive ID verifies a row with `private_key IS NOT NULL` exists.

- [ ] **Step 1: Write failing key-pair store tests**

Create `internal/store/key_pairs_test.go` with a helper returning named plaintext test material. Add tests for:

```go
func TestKeyPairCreateGetRoundTrip(t *testing.T)       // all three values decrypt exactly
func TestKeyPairKeysAreEncryptedAtRest(t *testing.T)  // SELECT blobs do not contain plaintext
func TestKeyPairListReturnsOnlyPresenceMetadata(t *testing.T)
func TestKeyPairUpdateRetainsNilAndClearsEmptySecret(t *testing.T)
func TestKeyPairDeleteLeavesSSHReferenceAndDependents(t *testing.T)
func TestKeyPairRejectsInvalidOrDuplicateName(t *testing.T)
```

For retain/clear, create `{PublicKey: []byte("pub"), PrivateKey: []byte("priv"), PrivateKeyPassphrase: []byte("phrase")}`, update with `PrivateKey: nil` and `PrivateKeyPassphrase: []byte{}`, then assert private remains `priv` and passphrase is nil. For dependency behavior, create password SSH profile, update its `KeyPairID` to pair ID after Task 3 contract is available; until then create an SQL reference directly and assert `KeyPairDependents` returns it, `DeleteKeyPair` succeeds, and row's ID remains unchanged.

- [ ] **Step 2: Run key-pair store tests to verify failure**

Run:

```bash
go test ./internal/store -run '^TestKeyPair' -count=1
```

Expected: compile failure because key-pair store methods do not exist.

- [ ] **Step 3: Implement encrypted key-pair store**

Use `normalizeGroupName` for canonical name validation. Add a `keyPairAAD` helper:

```go
func keyPairAAD(id int64, field string) []byte {
    return []byte(fmt.Sprintf("warden/key-pair/%d/%s", id, field))
}
```

Create allocates metadata row in a transaction, encrypts each field through `encryptSecret`, and updates blob columns before commit. Get scans BLOBs and decrypts each using key-pair AAD. List must not decrypt: select `public_key IS NOT NULL`, `private_key IS NOT NULL`, and `private_key_passphrase IS NOT NULL` into `KeyPairSummary` flags. Update must execute metadata update first, return `ErrNotFound` when no row changes, and update only non-nil secret fields; empty non-nil secret writes SQL `NULL` through `encryptSecret`.

Implement `KeyPairDependents` by first calling `GetKeyPair`, then querying `SELECT id, name FROM ssh_connections WHERE key_pair_id=? ORDER BY name`. `DeleteKeyPair` executes only `DELETE FROM key_pairs WHERE id=?`; it must not alter SSH rows.

Implement `validateKeyPairID` with this classification:

```go
if id < 0 { return fmt.Errorf("%w: key_pair_id must not be negative", ErrValidation) }
if id == 0 { return nil }
var found int
err := tx.QueryRowContext(ctx,
    "SELECT 1 FROM key_pairs WHERE id=? AND private_key IS NOT NULL", id).Scan(&found)
if errors.Is(err, sql.ErrNoRows) {
    return fmt.Errorf("%w: key_pair_id %d must reference a key pair with a private key", ErrValidation, id)
}
```

- [ ] **Step 4: Run key-pair store tests to verify pass**

Run:

```bash
gofmt -w internal/store/key_pairs.go internal/store/key_pairs_test.go
go test ./internal/store -run '^TestKeyPair' -count=1
```

Expected: PASS; no returned summary contains raw material and database blobs are encrypted.

- [ ] **Step 5: Commit key-pair store**

```bash
git add internal/store/key_pairs.go internal/store/key_pairs_test.go internal/store/profiles.go
git commit -m "feat: store encrypted key pairs"
```

### Task 3: Refactor SSH persistence and resolver to use selected key pairs

**Files:**
- Modify: `internal/store/profiles.go`
- Modify: `internal/store/profiles_test.go`
- Modify: `internal/server/profiles/resolve.go`
- Modify: `internal/server/profiles/resolve_test.go`
- Modify: `internal/server/profiles/handlers_test.go`

**Interfaces:**
- Consumes Task 2 `GetKeyPair` and `validateKeyPairID`.
- Produces transport-compatible `model.SSHBundle` values whose nodes contain pair-derived `PrivateKey` and `PrivateKeyPassphrase`; no caller changes in `internal/client/ssh/graph.go`.

- [ ] **Step 1: Write failing SSH store/resolver tests**

Replace old raw-key tests with these named cases:

```go
func TestSSHCreateRejectsPasswordAndKeyPair(t *testing.T)
func TestSSHUpdateKeyPairClearsPassword(t *testing.T)
func TestSSHUpdatePasswordClearsKeyPair(t *testing.T)
func TestSSHRejectsMissingOrPublicOnlyKeyPair(t *testing.T)
func TestResolveSSHBundleLoadsSelectedKeyPair(t *testing.T)
func TestResolveSSHBundleRejectsDeletedKeyPair(t *testing.T)
func TestResolveSSHBundleRejectsPairWhosePrivateKeyWasCleared(t *testing.T)
```

Create a pair with a parseable test private key for resolver test. Create SSH profile with `KeyPairID`, resolve, and assert transport node contains exact pair key/passphrase. For deleted/cleared references, create valid connection, delete pair or update pair private key to empty, then assert `errors.As(err, &GraphError)` and assert message names connection and pair ID. Include a jump-host key-pair test so `resolveJumps` also uses dynamic pair injection.

- [ ] **Step 2: Run SSH store/resolver tests to verify failure**

Run:

```bash
go test ./internal/store ./internal/server/profiles -run 'TestSSH(CreateRejectsPasswordAndKeyPair|UpdateKeyPairClearsPassword|UpdatePasswordClearsKeyPair|RejectsMissingOrPublicOnlyKeyPair)|TestResolveSSHBundle(LoadsSelectedKeyPair|RejectsDeletedKeyPair|RejectsPairWhosePrivateKeyWasCleared)' -count=1
```

Expected: FAIL because SSH still persists raw private-key columns or resolver copies raw profile key fields.

- [ ] **Step 3: Refactor SSH persistence and resolver**

In `CreateSSH`, insert `key_pair_id`; remove encryption/update of `private_key` and `private_key_passphrase`. In `GetSSH`, `ListSSH`, and `UpdateSSH`, select/write `key_pair_id` and left join `key_pairs` for `KeyPairName`; do not select legacy fields. Validate group and key-pair IDs within the existing transaction.

Replace `normalizeSSHAuthentication` with key-pair logic:

```go
func normalizeSSHAuthentication(p *model.SSHProfile) error {
    if len(p.Password) > 0 && p.KeyPairID != 0 {
        return errors.New("password and key_pair_id are mutually exclusive")
    }
    if len(p.Password) > 0 { p.KeyPairID = 0 }
    return nil
}
```

When update has non-empty password, SQL-clear `key_pair_id`; when `KeyPairID > 0`, SQL-clear `password`. Preserve nil-password semantics when neither auth selection changes.

Change resolver node construction to be context/error-aware:

```go
func (r *Resolver) sshNode(ctx context.Context, p model.SSHProfile) (model.SSHNode, error)
```

Build normal node fields first. If `p.KeyPairID == 0`, return it. Otherwise call `r.store.GetKeyPair`; map `store.ErrNotFound` to `graphErrorf("connection %d references deleted key pair %d", p.ID, p.KeyPairID)`, map empty private key to `graphErrorf("connection %d references key pair %d without a private key", p.ID, p.KeyPairID)`, and copy pair private key/passphrase to node. Propagate decryption failures unchanged. Update target and jump resolution to call this method and return no partial bundle on failure.

- [ ] **Step 4: Run SSH store/resolver tests to verify pass**

Run:

```bash
gofmt -w internal/store/profiles.go internal/store/profiles_test.go internal/server/profiles/resolve.go internal/server/profiles/resolve_test.go internal/server/profiles/handlers_test.go
go test ./internal/store ./internal/server/profiles -count=1
```

Expected: PASS. Password and selected-pair transitions clear stale auth, while transport still exposes pair key material only through no-store transport bundles.

- [ ] **Step 5: Commit SSH key-pair reference refactor**

```bash
git add internal/store/profiles.go internal/store/profiles_test.go internal/server/profiles/resolve.go internal/server/profiles/resolve_test.go internal/server/profiles/handlers_test.go
git commit -m "refactor: resolve SSH keys from key pairs"
```

### Task 4: Key-pair and refactored SSH HTTP API

**Files:**
- Create: `internal/server/profiles/key_pairs.go`
- Modify: `internal/server/profiles/handlers.go`
- Modify: `internal/server/profiles/handlers_test.go`
- Modify: `internal/client/picker/render.go`
- Modify: `internal/client/picker/picker_test.go`

**Interfaces:**
- Consumes Task 2 store methods and Task 3 SSH key-pair fields.
- Produces JSON endpoints and these mappings:

```go
func keyPairSummaryResponse(model.KeyPairSummary) model.KeyPairSummary
func keyPairVaultResponse(model.KeyPair) model.KeyPairVault
func redactSSH(model.SSHProfile) model.SSHConnection
```

- [ ] **Step 1: Write failing HTTP and picker tests**

Add handler tests using `newTestAPI`:

```go
func TestKeyPairListRedactsVaultMaterial(t *testing.T)
func TestGetKeyPairReturnsVaultMaterial(t *testing.T)
func TestKeyPairCreateUpdateAndClear(t *testing.T)
func TestKeyPairDeleteWarnsButLeavesSSHReference(t *testing.T)
func TestSSHHandlersAcceptKeyPairAndRejectPasswordConflict(t *testing.T)
```

Assert list JSON never contains `PRIVATE-KEY-MATERIAL`/passphrase but GET JSON returns exact strings. Assert unknown JSON field returns 400 `invalid_request`, duplicate name returns 409 `conflict`, public-only selection returns 400 `validation_error`, and key-pair dependents emits `{"ssh":[...],"db":[]}`. Ensure audit assertions only inspect resource identifiers, never raw request values.

Update picker tests to expect `Key pair` rather than obsolete `Private key` and `Private-key passphrase` fields. Test a missing key-pair reference renders `Missing key pair #<id>` and does not render any secret text.

- [ ] **Step 2: Run HTTP/picker tests to verify failure**

Run:

```bash
go test ./internal/server/profiles ./internal/client/picker -run 'Test(KeyPair|GetKeyPair|SSHHandlersAcceptKeyPair|FormatConnection)' -count=1
```

Expected: compile failure due to absent routes/mappings and obsolete picker fields.

- [ ] **Step 3: Implement routes, handlers, and redacted picker output**

Register exact routes in `Handler.Register`:

```go
mux.HandleFunc("GET /api/v1/key-pairs", h.listKeyPairs)
mux.HandleFunc("POST /api/v1/key-pairs", h.createKeyPair)
mux.HandleFunc("GET /api/v1/key-pairs/{id}", h.getKeyPair)
mux.HandleFunc("PUT /api/v1/key-pairs/{id}", h.updateKeyPair)
mux.HandleFunc("DELETE /api/v1/key-pairs/{id}", h.deleteKeyPair)
mux.HandleFunc("GET /api/v1/key-pairs/{id}/dependents", h.keyPairDependents)
```

Use audit operations `key_pair.list`, `key_pair.create`, `key_pair.get`, `key_pair.update`, `key_pair.delete`, and `key_pair.dependents` with resource type `key_pair`. Convert request pointers to `[]byte` only when non-nil. Convert stored bytes to strings only in `getKeyPair`; never log them. Reuse `writeStoreError`, `decodeStrict`, `pathID`, and `nonNilRefs`.

Refactor `createSSH`/`updateSSH` to accept `KeyPairID` and remove private-key request conversion. Refactor `redactSSH` to expose pair ID/name and only password/proxy presence.

In picker `FormatConnection`, replace two obsolete status fields with `Key pair`. Render name when nonempty, `Missing key pair #<id>` when ID is nonzero without name, and `[not configured]` when zero.

- [ ] **Step 4: Run HTTP/picker tests to verify pass**

Run:

```bash
gofmt -w internal/server/profiles/key_pairs.go internal/server/profiles/handlers.go internal/server/profiles/handlers_test.go internal/client/picker/render.go internal/client/picker/picker_test.go
go test ./internal/server/profiles ./internal/client/picker -count=1
```

Expected: PASS. Only individual vault GET discloses key material; list and picker remain secret-free.

- [ ] **Step 5: Commit HTTP API and picker changes**

```bash
git add internal/server/profiles/key_pairs.go internal/server/profiles/handlers.go internal/server/profiles/handlers_test.go internal/client/picker/render.go internal/client/picker/picker_test.go
git commit -m "feat: expose key-pair vault API"
```

### Task 5: Web API contracts and Key Pairs vault tab

**Files:**
- Modify: `web/src/api/types.ts`
- Modify: `web/src/api/client.ts`
- Modify: `web/src/api/client.test.ts`
- Create: `web/src/features/key-pairs/key-pairs-tab.tsx`
- Create: `web/src/features/key-pairs/key-pairs-tab.test.tsx`
- Modify: `web/src/app.tsx`
- Modify: `web/src/app.test.tsx`

**Interfaces:**
- Consumes API JSON from Task 4.
- Produces `KeyPairsTab` with `resource: ListResource<KeyPairSummary>` and `notify` props; App loads `const keyPairs = useListResource(api.listKeyPairs)` and supplies key-pair summaries to later SSH UI work.

- [ ] **Step 1: Write failing client/tab/App tests**

Define TypeScript contracts:

```ts
interface KeyPairSummary {
  id: number; name: string
  has_public_key: boolean; has_private_key: boolean
  has_private_key_passphrase: boolean
  created_at: string; updated_at: string
}
interface KeyPairVault extends KeyPairSummary {
  public_key: string; private_key: string; private_key_passphrase: string
}
interface KeyPairRequest {
  name: string
  public_key: string | null; private_key: string | null
  private_key_passphrase: string | null
}
```

Add API client tests for list/get/create/update/delete/dependents paths and `ApiError` behavior. Add Key Pairs tab tests for loading, retry, empty state, searchable list, create, vault GET before edit fields appear, editing private/passphrase, explicit clear, delete warning with SSH names, delete despite failed dependents lookup, and focus restoration. Add App test asserting Key Pairs trigger/content and `api.listKeyPairs` load.

- [ ] **Step 2: Run web tests to verify failure**

Run:

```bash
cd web && npx vitest run src/api/client.test.ts src/features/key-pairs/key-pairs-tab.test.tsx src/app.test.tsx
```

Expected: module/type failures because key-pair types, API methods, tab, and App resource are absent.

- [ ] **Step 3: Implement TypeScript client and vault tab**

Add `getKeyPair`, CRUD, and `keyPairDependents` to the grouped API client. Implement tab using existing `GroupsTab` dialog/delete state pattern, but use a `loadVault(id)` call before edit opens fields. Keep raw values only in edit dialog state, never table state.

Use this edit serialization rule so unchanged empty fields are retained but user edits can clear:

```ts
function changedSecret(current: string, original: string): string | null {
  return current === original ? null : current
}
```

For new pairs use `value === "" ? null : value`. Render public/private/passphrase textareas or plain text inputs with `autoComplete="off"`; do not use password-masking because vault requirement is visible/selectable values. Add buttons labelled `Clear public key`, `Clear private key`, and `Clear private key passphrase` that set the corresponding controlled value to `""`.

Add `Key Pairs` TabsTrigger and content in `App`; supply its `useListResource` result. Preserve existing notification behavior and dialog focus restoration.

- [ ] **Step 4: Run web tests to verify pass**

Run:

```bash
cd web && npx vitest run src/api/client.test.ts src/features/key-pairs/key-pairs-tab.test.tsx src/app.test.tsx
```

Expected: PASS. List data does not include raw values; opening edit calls GET and displays raw vault values.

- [ ] **Step 5: Commit web vault tab**

```bash
git add web/src/api/types.ts web/src/api/client.ts web/src/api/client.test.ts web/src/features/key-pairs/key-pairs-tab.tsx web/src/features/key-pairs/key-pairs-tab.test.tsx web/src/app.tsx web/src/app.test.tsx
git commit -m "feat: add key-pair vault tab"
```

### Task 6: Replace SSH plaintext-key UI with stored key-pair selection

**Files:**
- Modify: `web/src/features/ssh/ssh-form.tsx`
- Modify: `web/src/features/ssh/ssh-form.test.tsx`
- Modify: `web/src/features/ssh/ssh-tab.tsx`
- Modify: `web/src/features/ssh/ssh-tab.test.tsx`
- Modify: `web/src/app.tsx`
- Modify: `web/src/app.test.tsx`

**Interfaces:**
- Consumes `KeyPairSummary` from Task 5 and refactored `SSHConnection`/`SSHConnectionRequest` from Task 4.
- `SSHFormProps` gains `keyPairs: readonly KeyPairSummary[]`; `SSHTabProps` gains same and passes it to form.
- Produces request payload with exactly one active authentication source:

```ts
password: form.authMode === "password" ? nullableSecret(form.password) : null,
key_pair_id: form.authMode === "keyPair" ? Number(form.keyPairID) : 0,
```

- [ ] **Step 1: Write failing SSH form/tab/App tests**

Replace private-key textarea/passphrase tests with:

```ts
test("serializes password mode with key_pair_id zero")
test("serializes stored-key mode with password null and selected ID")
test("stored-key mode only offers pairs with private keys")
test("preserves missing selected key-pair ID as a visible option")
test("requires a stored key-pair selection in stored-key mode")
test("SSH row displays selected key-pair name")
```

In `ssh-tab.test.tsx`, assert a form submission from stored-key mode calls `api.createSSH` with `key_pair_id: 7`, `password: null`, and no `private_key`/`private_key_passphrase` properties. In App tests, assert `keyPairs.data` reaches SSH tab after resources resolve.

- [ ] **Step 2: Run SSH web tests to verify failure**

Run:

```bash
cd web && npx vitest run src/features/ssh/ssh-form.test.tsx src/features/ssh/ssh-tab.test.tsx src/app.test.tsx
```

Expected: FAIL because the form still exposes raw private-key fields and types lack key-pair fields.

- [ ] **Step 3: Implement stored-pair SSH auth UI**

Change form state to:

```ts
authMode: "password" | "keyPair"
password: string
keyPairID: string
```

Remove `privateKey` and `privateKeyPassphrase` state/controls. `sshFormFromConnection` selects `keyPair` when `connection.key_pair_id !== 0`; otherwise it uses password. Build selector options from `keyPairs.filter(pair => pair.has_private_key)`, then prepend current missing nonzero ID as `Missing key pair #<id>` when it is absent. Use `SSHProfileCombobox` with labels `Stored key pair`, `Search key pairs`, and `No key pairs with private keys found.`

On auth mode switch, clear inactive form state. In submit, prevent submit and render `Select a stored key pair.` when key-pair mode has `keyPairID === "0"`; do not send an ambiguous no-credential key-auth request. Password mode keeps existing blank-password behavior for local-agent fallback.

Thread `keyPairs` from App to `SSHTab`, then to `SSHForm`. Replace connection-table private-key badges with a `Key pair: <name>` badge/label; display `Missing key pair #<id>` for dangling references.

- [ ] **Step 4: Run SSH web tests to verify pass**

Run:

```bash
cd web && npx vitest run src/features/ssh/ssh-form.test.tsx src/features/ssh/ssh-tab.test.tsx src/app.test.tsx
```

Expected: PASS. UI cannot choose public-only pairs, never serializes raw key material, and makes dangling selected IDs visible.

- [ ] **Step 5: Commit SSH UI refactor**

```bash
git add web/src/features/ssh/ssh-form.tsx web/src/features/ssh/ssh-form.test.tsx web/src/features/ssh/ssh-tab.tsx web/src/features/ssh/ssh-tab.test.tsx web/src/app.tsx web/src/app.test.tsx
git commit -m "refactor: select stored key pairs for SSH"
```

### Task 7: Full verification, review, report, and PR update

**Files:**
- Modify only files required by failures discovered during verification.

**Interfaces:**
- Consumes all previous tasks.
- Produces validated branch update with no staged/unintended files.

- [ ] **Step 1: Run complete Go verification**

```bash
gofmt -w internal/model/profile.go internal/model/api.go internal/store/key_pairs.go internal/store/key_pairs_test.go internal/store/profiles.go internal/store/profiles_test.go internal/store/store_test.go internal/server/profiles/key_pairs.go internal/server/profiles/handlers.go internal/server/profiles/handlers_test.go internal/server/profiles/resolve.go internal/server/profiles/resolve_test.go internal/client/picker/render.go internal/client/picker/picker_test.go
go test ./...
```

Expected: exit 0. If a test fails, first follow `superpowers:systematic-debugging`; change only the proven failing boundary and rerun the focused test before rerunning all Go tests.

- [ ] **Step 2: Run complete web verification**

```bash
cd web && npm test && npm run build
```

Expected: exit 0; Vitest suite, distribution verification, TypeScript build, Vite build, and `verify-dist` complete.

- [ ] **Step 3: Inspect final scope**

```bash
git diff --check
git status --short
git diff origin/main...HEAD --stat
git diff origin/main...HEAD --check
```

Expected: no whitespace errors; every changed file belongs to this feature or test/documentation support.

- [ ] **Step 4: Request independent code review**

Dispatch a read-only reviewer with the spec path, plan path, and `git diff origin/main...HEAD`. Require findings ordered by severity, with special attention to vault secret exposure being limited to individual GET, AAD correctness, migration data preservation/destruction boundary, dangling delete behavior, and transport error classification.

- [ ] **Step 5: Address verified review findings and rerun affected/full tests**

For every finding, verify it against code/spec before changing it. Run its focused test after each accepted fix, then rerun both `go test ./...` and `cd web && npm test && npm run build` if any production code changed.

- [ ] **Step 6: Commit, report, and push final verification changes**

Stage only intended paths using a NUL-delimited pathspec file, inspect `git diff --cached`, then commit any final fixes with an action-first message. Create required report:

```bash
warden report create warden --title "Add key-pair vault management" --summary "Add encrypted shared key-pair vault, migrate SSH key auth to selected pairs, expose vault UI, and verify Go/web suites." --agent-model "$PI_MODEL"
git push --progress --porcelain origin refs/heads/hieudmg/fix-ssh-auth-exclusivity:refs/heads/hieudmg/fix-ssh-auth-exclusivity
```

Expected: report command returns report ID and branch push updates existing PR without merging.
