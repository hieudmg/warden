-- Key-pair vault: named, encrypted SSH key pairs shared by SSH connections.
--
-- This is an up-only destructive-key migration by design. ssh_connections is
-- rebuilt to drop the legacy per-connection private_key and
-- private_key_passphrase columns; that key material is intentionally lost.
-- All other SSH data (password, host, proxy, jump ids, default dir, group)
-- is preserved, and key_pair_id defaults to 0 (no stored pair selected).
-- There is deliberately no foreign key: deleting a referenced key pair is
-- permitted after a warning, leaving references dangling for explicit
-- resolution failure.

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
