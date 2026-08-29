-- Upgrade legacy scalar database names to the canonical database-list JSON
-- representation while retaining the existing column and row identity.
UPDATE db_connections
SET database = '[{"name":' || json_quote(database) || ',"is_default":true}]'
WHERE json_valid(database) = 0;
