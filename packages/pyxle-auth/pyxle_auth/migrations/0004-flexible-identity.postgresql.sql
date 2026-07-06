-- pyxle-auth flexible identity (0.4.0) — PostgreSQL.
--
-- Add a nullable, UNIQUE `username` and relax `email` to nullable so an account
-- may be identified by either (see AuthSettings.identifier). All in-place
-- ALTERs — no table rebuild, every session preserved. Idempotent: re-running is
-- a no-op (the migrator applies each migration once, but IF NOT EXISTS / DROP
-- NOT NULL keep it safe regardless).

ALTER TABLE users ADD COLUMN IF NOT EXISTS username VARCHAR(64);

ALTER TABLE users ALTER COLUMN email DROP NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS users_username_key ON users (username);
