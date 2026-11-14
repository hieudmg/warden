# Synthetic c104353 transfer provenance

No real credentials, account data, valid SSH keys or old-release server process.
`export-c104353_test.go.txt` is a constructor compiled as a test ONLY against
historical `c104353` source in a temporary module. It seeds actual release
001–007 SQLite tables with explicit SQL IDs/timestamps/references and encrypts
synthetic secret strings with the historical codec and explicit source AAD.
It calls the actual old `Store.ExportData` then `encoding/json.MarshalIndent`.
Only nondeterministic `exported_at` is frozen; no managed field is rewritten.
The old HTTP handler uses `server.WriteJSON` on this same returned bundle.

```sh
bash scripts/test-transfer-fixture.sh
# To deliberately regenerate ONLY synthetic artifacts (review checksums/tests):
bash scripts/test-transfer-fixture.sh --write-synthetic-fixture
```

The script reads committed historical go.mod/go.sum, store/model/crypto and
migrations with `git show`, skips old tests, and runs ONLY this constructor with
`GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local`. Dependencies must already be installed.
No checkout, worktree, old executable, HTTP listener or network download.
Temporary synthetic databases/source are cleaned on exit, never live paths.
Default mode compares the generated plaintext fixture byte-for-byte. Source
ciphertexts use fresh random nonces; only explicit regeneration replaces their
artifact (and its checksum); ordinary verification does not overwrite anything.

- `warden-data-v1-c104353.json`: SHA-256
  `732de3caaac4993b39baffcec6ea7c3328b3c620d91837e763ab9eefc8933337`.
- `ciphertexts-c104353.json`: SHA-256
  `1d0376d350660cee5b8dfdd14164dad65e682a875ceea1b2d8aa719d2b2d7cf9`.
  Actual old-source encrypted blobs for all seven populated encrypted fields;
  source synthetic key `[32]byte{0xa1, 2}`. Destination synthetic key differs.

Fixture counts: groups2, key_pairs2, SSH3, DB2, projects2, reports2, notes7.
Covers nullable/empty key fields, plaintext string secrets, proxy settings,
active/archived rows, duplicate/whitespace-preserving raw jumps, dangling
key/group/jump/tunnel refs, multiple DB settings with a nonfirst default,
empty/orphan/unknown/empty-type notes, Unicode, hard report/project references
and nanosecond timestamps. It never imports auth/config/audit metadata.

Current model/transfer.go and store/transfer.go match the historical source at
the T5 baseline; **that fact alone is not fixture provenance**. Running the old
producer above establishes it. Tests independently verify full managed output,
actual getters/counts, old-ciphertext decryption/destination encryption and
wrong-key/row/field/resource/tamper rejection. Passing-current characterizations
and temporary guard sensitivity checks are explicitly distinguished from
TDD production work in the T5 report.
