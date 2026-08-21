-- Warden Hub initial schema.
-- Secret-bearing columns are BLOB and hold AES-256-GCM encrypted values
-- ([version:1B][nonce:12B][ciphertext+tag]); they are never plaintext.
-- ssh_connections.jump_connection_ids is application data (JSON integer
-- array), intentionally NOT a SQL foreign-key edge table: syntax is
-- validated on write, logical references are resolved at transport time.
-- db_connections.ssh_connection_id is deliberately NOT a foreign key so SSH
-- deletion is never blocked by DB profiles referencing it.

CREATE TABLE ssh_connections (
    id                     INTEGER PRIMARY KEY AUTOINCREMENT,
    name                   TEXT NOT NULL UNIQUE,
    host                   TEXT NOT NULL,
    port                   INTEGER NOT NULL,
    username               TEXT NOT NULL,
    password               BLOB,
    private_key            BLOB,
    private_key_passphrase BLOB,
    proxy_host             TEXT,
    proxy_port             INTEGER,
    proxy_username         TEXT,
    proxy_password         BLOB,
    jump_connection_ids    TEXT NOT NULL DEFAULT '[]',
    created_at             TEXT NOT NULL,
    updated_at             TEXT NOT NULL
);

CREATE TABLE db_connections (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    name               TEXT NOT NULL UNIQUE,
    host               TEXT NOT NULL,
    port               INTEGER NOT NULL,
    username           TEXT NOT NULL,
    password           BLOB,
    database           TEXT NOT NULL,
    ssh_connection_id  INTEGER NOT NULL DEFAULT 0,
    created_at         TEXT NOT NULL,
    updated_at         TEXT NOT NULL
);

CREATE INDEX idx_db_connections_ssh_connection_id ON db_connections(ssh_connection_id);

CREATE TABLE projects (
    id   INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE
);

CREATE TABLE reports (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id  INTEGER NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
    title       TEXT NOT NULL,
    summary     TEXT NOT NULL,
    agent_model TEXT NOT NULL,
    created_at  TEXT NOT NULL
);

CREATE INDEX idx_reports_project_created ON reports(project_id, created_at);

CREATE TABLE audit_events (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    operation     TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id   TEXT NOT NULL,
    source        TEXT NOT NULL,
    result        TEXT NOT NULL,
    error         TEXT NOT NULL,
    metadata      TEXT NOT NULL,
    created_at    TEXT NOT NULL
);

CREATE INDEX idx_audit_events_created_at ON audit_events(created_at);
