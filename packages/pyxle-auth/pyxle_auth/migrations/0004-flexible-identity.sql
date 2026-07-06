-- pyxle-auth flexible identity (0.4.0) — SQLite.
--
-- Adds a nullable, UNIQUE `username` and relaxes `email` to nullable, so an
-- account may be identified by either (see AuthSettings.identifier). SQLite
-- cannot drop a NOT NULL via ALTER, and the migrator runs this inside a
-- transaction with foreign_keys ON (so the pragma can't be toggled) — so we
-- rebuild `users`. `sessions` is a leaf (nothing references it), so we stash
-- its rows, drop it, rebuild `users` cleanly, then recreate `sessions` with
-- its original FK + indexes and restore every row. No login is lost.

CREATE TABLE sessions_backup_0004 AS SELECT * FROM sessions;

DROP TABLE sessions;

CREATE TABLE users_v2 (
    id                VARCHAR(64) PRIMARY KEY,
    email             VARCHAR(255) UNIQUE,
    username          VARCHAR(64) UNIQUE,
    password_hash     TEXT NOT NULL,
    email_verified_at TIMESTAMP,
    created_at        TIMESTAMP NOT NULL,
    plan              TEXT NOT NULL
);

INSERT INTO users_v2 (id, email, password_hash, email_verified_at, created_at, plan)
    SELECT id, email, password_hash, email_verified_at, created_at, plan FROM users;

DROP TABLE users;

ALTER TABLE users_v2 RENAME TO users;

CREATE TABLE sessions (
    token_sha256 VARCHAR(64) PRIMARY KEY,
    user_id      VARCHAR(64) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at   TIMESTAMP NOT NULL,
    expires_at   TIMESTAMP NOT NULL,
    user_agent   TEXT,
    ip           TEXT
);

INSERT INTO sessions (token_sha256, user_id, created_at, expires_at, user_agent, ip)
    SELECT token_sha256, user_id, created_at, expires_at, user_agent, ip
    FROM sessions_backup_0004;

DROP TABLE sessions_backup_0004;

CREATE INDEX IF NOT EXISTS sessions_user ON sessions (user_id);

CREATE INDEX IF NOT EXISTS sessions_expires ON sessions (expires_at);
