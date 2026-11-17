CREATE TABLE http_connections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    origin TEXT NOT NULL,
    auth_type TEXT NOT NULL,
    credential BLOB,
    username BLOB,
    password BLOB,
    group_id INTEGER NOT NULL DEFAULT 0,
    archived INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX idx_http_connections_group_id ON http_connections(group_id);
