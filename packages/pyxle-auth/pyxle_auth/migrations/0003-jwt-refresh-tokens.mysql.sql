-- pyxle-auth JWT refresh tokens — MySQL override.
--
-- Identical to 0003-jwt-refresh-tokens.sql but DATETIME(6) instead of
-- TIMESTAMP (MySQL TIMESTAMP is 2038-capped and second-rounded), and bare
-- CREATE INDEX (MySQL has no IF NOT EXISTS for indexes; the migration runs
-- once per database, checksum-tracked). The Migrator picks this file on MySQL;
-- both share the migration id.

CREATE TABLE IF NOT EXISTS jwt_refresh_tokens (
    token_sha256 VARCHAR(64) PRIMARY KEY,
    family_id    VARCHAR(64) NOT NULL,
    user_id      VARCHAR(64) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    issued_at    DATETIME(6) NOT NULL,
    expires_at   DATETIME(6) NOT NULL,
    used_at      DATETIME(6),
    revoked_at   DATETIME(6)
);

CREATE INDEX jwt_refresh_family ON jwt_refresh_tokens (family_id);

CREATE INDEX jwt_refresh_user ON jwt_refresh_tokens (user_id);
