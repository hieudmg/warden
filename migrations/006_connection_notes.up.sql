-- Optional display notes for SSH and DB connections. The polymorphic
-- reference is intentionally not a foreign key so deleting a connection
-- never depends on note-table referential integrity.
CREATE TABLE connection_notes (
    connection_type TEXT NOT NULL,
    connection_id   INTEGER NOT NULL,
    note            TEXT NOT NULL,
    UNIQUE (connection_type, connection_id)
);
