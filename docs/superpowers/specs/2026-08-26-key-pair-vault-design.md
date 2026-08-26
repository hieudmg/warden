# Key-Pair Vault Design

## Goal

Add named SSH key-pair vault management. A pair stores optional public key, private key, and private-key passphrase. SSH connections retain inline password authentication or reference one stored key pair; they no longer store private-key material themselves.

Hub clients may view vault secrets. This is an explicit accepted risk until authentication and authorization are added.

## Scope and decisions

- Key-pair name is required and unique; public key, private key, and passphrase are independently optional.
- Key pairs are shared references. Editing a pair changes credentials used by every SSH connection referring to it.
- SSH password remains inline and mutually exclusive with a nonzero `key_pair_id`.
- An SSH connection may select only an existing pair with a private key.
- Deleting a referenced pair is permitted after a warning. References remain dangling. Resolving such an SSH connection fails explicitly.
- Existing SSH private-key and private-key-passphrase data is deliberately lost in migration. Existing SSH metadata, passwords, proxy settings, jump routes, default directories, and groups survive.
- Reusable password credentials and an authentication layer are out of scope.

## Persistence and migration

Migration 004 creates:

```sql
key_pairs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  public_key BLOB,
  private_key BLOB,
  private_key_passphrase BLOB,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
)
```

All key-pair material, including public key, is encrypted at rest. AAD is bound to `warden/key-pair/<id>/<field>`.

The migration rebuilds `ssh_connections` rather than adding another unused secret column. It copies all supported connection fields while omitting legacy `private_key` and `private_key_passphrase`, adds `key_pair_id INTEGER NOT NULL DEFAULT 0`, then recreates existing indexes and adds an index for `key_pair_id`. It intentionally has no foreign key: deletion must leave dangling references after warning.

`model.SSHProfile` replaces raw private-key fields with `KeyPairID int64`. `model.KeyPair` holds plaintext in memory only. The store owns encryption/decryption.

## Store rules

Key-pair store methods mirror groups: create, get, list, update, delete, and SSH dependents. Name validation uses the existing connection-name rules. Secret write semantics are:

- Create: absent or empty key fields store SQL `NULL`.
- Update: omitted fields retain stored values; a non-nil empty field explicitly clears.
- Get: decrypt every key-pair field.

SSH creation and update validate `key_pair_id` inside their write transaction:

- Negative IDs are invalid.
- `0` means no selected stored key.
- A positive ID must exist and have a non-empty private key.
- Non-empty password and a positive key-pair ID are invalid.
- Saving password clears `key_pair_id`; saving a key-pair selection clears stored password.

There is no database foreign key. `DeleteKeyPair` deletes only key-pair row; it does not change SSH rows. `KeyPairDependents` lists SSH connections with matching IDs for deletion warnings.

## API and transport

Routes follow existing profile conventions:

- `GET, POST /api/v1/key-pairs`
- `GET, PUT, DELETE /api/v1/key-pairs/{id}`
- `GET /api/v1/key-pairs/{id}/dependents`

All routes use strict decode, standard store error mapping, and sanitized audit events. List responses return key-pair metadata and presence flags only. A single-pair GET returns raw public key, private key, and passphrase for vault view/edit. This is deliberately different from existing redacted connection API policy.

Key-pair write payloads use nullable secret pointers: absent retains on update; empty clears. UI provides explicit clear actions so an untouched blank field does not erase stored material.

SSH API drops `private_key`, `private_key_passphrase`, and their presence flags. It adds `key_pair_id` and display-only `key_pair_name`. SSH requests contain `key_pair_id`; `0` clears the selection.

SSH resolution dynamically gets selected pair, decrypts its private key/passphrase, and injects them into the existing transport bundle. Client SSH auth code remains unchanged. Missing pair, or a referenced pair whose private key was later cleared, produces explicit transport-resolution failure instead of silently falling through to agent authentication.

## Web UI

`App` loads key-pair summaries and adds a **Key Pairs** tab.

The tab provides searchable list, create, edit/view, and delete flows matching Groups UI patterns:

- List displays name, public/private/passphrase presence badges, timestamps, and actions. It does not place raw material in list payloads.
- Create dialog accepts name plus public key, private key, and passphrase. Keys are optional.
- Edit/view opens with a single-pair vault GET and displays all stored fields as plain, selectable text. Users may edit values. Explicit clear controls send empty values; untouched fields remain unchanged.
- Delete first requests dependents, shows warning and affected SSH names, then still permits deletion.

SSH form has two authentication modes: **Password** and **Stored key pair**. Password remains an inline field. Stored-key mode replaces private-key and passphrase inputs with a selector restricted to summaries having private keys. Missing current selections remain visibly labelled rather than silently cleared. SSH list auth display shows Password or selected key-pair name.

## Testing and verification

Tests cover:

- Migration from schema version 3: private-key columns/data removed, other SSH data preserved, indexes and new table present.
- Key-pair encryption, CRUD, name validation, clear/retain semantics, and dependents.
- SSH create/update validation and clearing across password/key-pair modes.
- Resolver successful key-pair injection, missing-pair error, and key-pair-without-private-key error.
- Handler routes, vault GET disclosure, list metadata-only behavior, strict JSON/error mapping, audit-safe failures, and deletion warning dependents.
- Web API types/client, Key Pairs tab CRUD/vault behavior, delete warning, and SSH selector serialization/missing-selection handling.

Final verification runs Go tests, web tests, formatting, and a focused review of staged changes.
