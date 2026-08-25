-- Connection groups: flat, named labels shared by SSH and DB profiles.
-- group_id is a non-null integer sentinel (0 = ungrouped), deliberately NOT
-- a foreign key: deletion is never blocked, and the store transactionally
-- clears references before deleting a group.

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
