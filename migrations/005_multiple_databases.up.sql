-- Upgrade legacy scalar database names to the canonical database-list JSON
-- representation while retaining the existing column and row identity.
-- json_type is evaluated only for valid JSON: malformed values beginning with
-- a container delimiter remain untouched for the decoder to reject.
UPDATE db_connections
SET database = '[{"name":' || json_quote(database) || ',"is_default":true}]'
WHERE CASE WHEN json_valid(database) THEN json_type(database) ELSE '' END <> 'array'
  AND substr(ltrim(database), 1, 1) NOT IN ('[', '{');
