# Old-release export → fresh initialization → version 1 import

This is the **only supported legacy transfer** on the security-hardening branch.
It is a manual, operator-approved cutover, **not an in-place encrypted-DB upgrade**.
Do not point the new server at the old database, copy old encrypted tables into a
new vault, delete an identity marker, generate a replacement `master.key`, or
remove files to make startup succeed. Legacy/unknown/corrupt/partial storage is
refused before original SQLite migrations, WAL pragmas or permission changes.
There is no old-key fallback or automatic data deletion.

T5's automated evidence uses only disposable SQLite and synthetic secrets. It
proves the data-transfer contract, not genuine authenticator PRF/browser support,
native Windows, a live-account migration, or release/security acceptance. See
[initialization](initialization.md) for setup/auth/recovery and the
[T5 evidence report](superpowers/reports/2026-11-14-t5-transfer-preservation.md).

## 1. Prepare rollback and protect the plaintext export

1. Identify and retain the **exact old executable/version**, its config/service
   configuration, database and old master key. Record paths privately; check that
   backup media are private and recoverable. Retain the old executable rather
   than relying on a later download. Do not run the upgrader/installer as a data
   migration tool; they do not perform this workflow.
2. Quiesce managed-data writes on the old instance before taking the final export.
   Use that **old release's web Export control** to download `warden-data.json`.
   Its identity must be `"format":"warden-data"`, `"version":1` with a nonzero
   `exported_at` and **all seven arrays**, including empty ones. Export from full
   storage, not redacted list/CLI/transport responses. Older releases without this
   documented exporter need a separately approved path; do not invent a converter.
3. Keep the export on deliberately private local/offline storage. It contains
   **plaintext passwords, proxy passwords, public/private key material and
   passphrases**, as well as notes/reports. Avoid sync/shared folders, shell
   arguments/environment, terminal output, logs, tickets and screenshots. Hash it
   privately if needed for transfer integrity; a checksum does not encrypt it.
4. Stop the old server cleanly after export, while preserving the frozen dataset.
   Make a **coherent backup set** of its config, DB, master key and any WAL/SHM
   sidecars present at that stopped boundary. Never copy only a running WAL-mode
   main DB: recent committed data may exist only in `-wal`; copying a changing
   main/WAL/SHM set piecemeal is not a consistent backup. A clean close can already
   have checkpointed/removed sidecars; record what actually exists. Preserve any
   uncertain prior backup separately for inspection; do not force checkpoint,
   edit, rename away or delete legacy artifacts to suppress refusal. Keep the
   old set and its access permissions separate from the destination.

An export must fit the existing **50 MiB JSON request-body limit**, including
whitespace. Do not truncate collections or silently split into several imports:
the first nonempty import makes subsequent imports conflicts. If the old data
cannot produce a valid bounded v1 file, stop for a separately approved transfer
strategy. T6 owns full-size supported-link deadline/slow-client acceptance.

## 2. Create an independent fresh destination

Use a separate new storage directory/config, trusted HTTPS origin/RP ID and TLS
certificate (or explicitly configured same-host loopback reverse proxy):

```sh
/path/to/new/warden-server init --config /path/to/fresh/server.json
# Prompts: select a NEW database path, not the old DB or its backup.
# Complete passkey registration + PRF, save/hide/re-enter recovery; init exits.
/path/to/new/warden-server serve --config /path/to/fresh/server.json
```

These are manual instructions, **not commands executed on your installation by
T5 tests**. New initialization must verify working PRF and saved recovery before
publishing identity. An existing config is not an initialized identity. Normal
serve starts **locked**, even after restart. Authenticate with the destination
passkey, then perform a separate fresh PRF unlock. No plaintext source DEK,
source master-key upload, or server-disk key is needed by import: the old export
already contains the plaintext transfer values.

Auth metadata, browser sessions, approved client verifiers and audit events may
already exist in the destination. All **managed tables** must be empty:
`groups`, `key_pairs`, `ssh_connections`, `db_connections`, `projects`, `reports`,
`connection_notes`. Even one orphan/empty note counts as managed data. Do not
delete current data to make import work; choose another fresh destination if
this is not empty. Import never replaces owner, passkeys, recovery wrappers,
sessions, client verifiers, installation ID or authorization generation.

## 3. Import exactly the documented version 1 file

In the destination web UI, select **Import**, read/confirm the plaintext-secret
warning, and complete the fresh passkey assertion for that exact upload. The
management endpoint is `POST /api/v1/data/import`: JSON (not multipart), exact
configured Origin + CSRF + a single-use fresh grant bound to method/path/body
SHA-256/session/credential/vault generation. A CLI bearer credential cannot
import. Do not hand-edit/reformat a body after authorizing it or reuse a consumed
grant. Never place session cookies, grants or file contents in a shell command.

The existing wire format is unchanged:

- Top level: `format`, `version`, `exported_at`, `groups`, `key_pairs`,
  `ssh_connections`, `db_connections`, `projects`, `reports`, `connection_notes`.
- Secrets are **JSON strings**, not the base64 byte fields from other APIs.
  `jump_connection_ids` is the **raw JSON-array text inside a string**, including
  its stored whitespace/order/duplicates. DB `databases` is an array of
  `{ "name": "...", "is_default": true|false }`, not a scalar database name.
- Preserve all IDs and managed timestamps; project and note records have no
  invented timestamps. Missing `archived` means active; explicit true survives.
- Notes travel only in `connection_notes`, including empty notes, unknown/empty
  types and orphan references. Group/key/jump/tunnel references may dangle and are
  preserved; this does not make an invalid transport graph usable. Reports must
  reference a project included in the bundle (a **hard** constraint).
- No auth/config/audit/client collections are accepted or exported. Unknown
  fields/format/version, invalid IDs, duplicate keys and invalid hard report
  links fail rather than being dropped. Existing CRUD validation is unchanged.

Success returns **204**. Validation/decoding failures return 400, a nonempty
managed destination returns **409**, and storage/encryption/commit failures return
500. Auth/locked/fresh-action failures require the corresponding login/unlock/
new assertion, not a data reset. Error/success responses are `no-store`.

Every import transaction checks emptiness and inserts the entire dataset with
original IDs/timestamps, encrypting secrets with the **destination DEK** and exact
resource/row/field AAD. Failure before commit rolls back all managed writes and
preserves identity; remove the external cause and retry with a **new grant**.
Concurrent attempts yield at most one complete winner, not a merge: a contender
can receive a transient SQLite/storage failure or a nonempty conflict. Recheck
state before retrying. A lost HTTP response after successful commit is ambiguous:
first verify/export destination state; do not assume a disconnected client means
rollback. A repeated import into a committed dataset returns 409, never overwrite.
Audit metadata can grow (and an already-canceled audit write can fail); audit
history is not transferred and is not part of the managed-data rollback promise.

## 4. Verify before cutover

Keep the old rollback set intact. Compare the original export with a **freshly
authorized destination export** locally on private storage, disregarding only
`exported_at`. Do not paste either file into a remote diff/online JSON tool.
Verify:

- every collection's count and all IDs/names/timestamps;
- SSH proxy/default directory/settings, raw jumps and group/key references;
- DB ports/users, every database and its selected default, tunnel/group refs;
- key material, passwords/passphrases, notes (including empty/orphan/unknown
  types), archive flags, project/report linkage and report text/model/time;
- destination key-vault/profile values decrypt correctly; destination identity,
  saved recovery, session binding and existing approved clients remain usable;
- restart starts locked, separate login/unlock succeeds and data is still readable.

Dangling references and archived connections should continue to fail connection
resolution as designed, not be silently repaired/activated. Any optional test
connection to a real SSH/DB system requires separate operator approval; none is
performed by T5. Only after verification should the operator switch service
configuration/client endpoints. New installation authentication is independent;
reapprove clients for that installation as needed. Do not run both writable
instances against the same files or automatically restart a service as part of
transfer. Existing external DB and HTTP CONNECT proxy transport is unchanged;
Warden HTTPS does not protect an onward plaintext external leg.

## 5. Rollback and retention

If import/verification fails, leave the failed destination isolated for inspection.
Stop the new service before switching back. Restore/use the retained **old binary
with its matching old config, coherent DB/WAL/SHM and master key**; never start the
old binary on the new DB or use the new executable to rewrite the old one. Review
any post-cutover writes before rollback: this importer has no automatic reverse
merge/reconciliation, and rollback to the frozen old set loses later changes
unless separately handled. Keep both sets; do not overwrite either casually.

No script or import operation automatically deletes plaintext exports, old keys,
old binaries or backups. The owner chooses protected retention/disposal after
acceptance. Exports are plaintext regardless of DB encryption, and old snapshots
retaining old wrappers/keys remain decryptable after current passkey/recovery
revocation. Recovery-key rotation cannot revoke historical backups. Loss of all
usable destination passkeys **and** its saved recovery key has no administrative
bypass; retain and test the approved recovery path separately.

## Disposable reproducible proof (no live installation)

```sh
bash scripts/test-transfer-fixture.sh
# Compiles c104353's exporter offline in mktemp, compares the synthetic fixture.
go test ./internal/store ./internal/server/profiles ./internal/server/runtime \
  -run 'TestVersion1|TestImport|TestConcurrentInitializedImports|TestLegacyDBRefusal|TestHTTPSVersion1' \
  -count=1 -v
go test -race ./internal/store ./internal/server/profiles ./internal/server/runtime ./internal/crypto -count=1
```

The retained [fixture provenance](../internal/store/testdata/README.md) identifies
its complete synthetic SQL constructor, serializer source and checksums. These
commands never exercise a live account, upgrade or real old-release server.
`scripts/test.sh` still contains the historical unauthenticated HTTP/master-key
lifecycle; **do not use it for this migration**. T17 owns its full replacement,
not T5's narrowly scoped offline fixture flow.
