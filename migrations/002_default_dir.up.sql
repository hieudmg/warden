-- Add optional default working directory to SSH profiles. The xssh command
-- uses it as a one-shot `cd <dir> && exec ${SHELL:-sh} -l` prefix so the
-- remote login shell lands in the project directory. Empty (the default)
-- preserves prior behavior. Validation lives in the store/handler layer;
-- the column is plain TEXT for forward compatibility.

ALTER TABLE ssh_connections ADD COLUMN default_dir TEXT NOT NULL DEFAULT '';