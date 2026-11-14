CREATE TABLE client_credentials (
 id TEXT PRIMARY KEY,
 verifier TEXT NOT NULL UNIQUE,
 label TEXT NOT NULL,
 generation INTEGER NOT NULL,
 created INTEGER NOT NULL,
 revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN (0,1))
);
