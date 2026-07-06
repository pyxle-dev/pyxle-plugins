-- pyxle-auth flexible identity (0.4.0) — MySQL.
--
-- Add a nullable, UNIQUE `username` and relax `email` to nullable so an account
-- may be identified by either (see AuthSettings.identifier). In-place ALTERs —
-- no table rebuild, every session preserved. MySQL has no ADD COLUMN IF NOT
-- EXISTS, but the migrator applies each migration exactly once (checksum-
-- tracked), so this runs cleanly on the 0001 schema. MODIFY keeps the column's
-- existing UNIQUE index on `email`; it only drops the NOT NULL.

ALTER TABLE users ADD COLUMN username VARCHAR(64) NULL UNIQUE;

ALTER TABLE users MODIFY email VARCHAR(255) NULL;
