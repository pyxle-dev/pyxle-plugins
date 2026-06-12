-- pyxle-auth core schema — MySQL override.
--
-- Identical to the base 0001-pyxle-auth-core.sql except every datetime
-- column is DATETIME(6) instead of TIMESTAMP: MySQL's TIMESTAMP type is
-- capped at 2038 (configurable session/token expiries can exceed it),
-- rounds to whole seconds without a precision, and is converted through
-- the session time zone. DATETIME(6) stores the UTC wall time pyxle-db
-- binds, byte for byte. The Migrator picks this file over the base one
-- when the dialect is mysql; both share the migration id.
--
-- Index statements are bare CREATE INDEX: MySQL has no IF NOT EXISTS for
-- indexes. That is fine for the migration path (it runs exactly once per
-- database, checksum-tracked); the services' ensure_schema() uses an
-- information_schema probe for its idempotent index creation instead.

CREATE TABLE IF NOT EXISTS users (
    id                VARCHAR(64) PRIMARY KEY,
    email             VARCHAR(255) NOT NULL UNIQUE,
    password_hash     TEXT NOT NULL,
    email_verified_at DATETIME(6),
    created_at        DATETIME(6) NOT NULL,
    plan              TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    token_sha256 VARCHAR(64) PRIMARY KEY,
    user_id      VARCHAR(64) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at   DATETIME(6) NOT NULL,
    expires_at   DATETIME(6) NOT NULL,
    user_agent   TEXT,
    ip           TEXT
);

CREATE INDEX sessions_user ON sessions (user_id);

CREATE INDEX sessions_expires ON sessions (expires_at);

CREATE TABLE IF NOT EXISTS ratelimit_buckets (
    bucket_key VARCHAR(320) PRIMARY KEY,
    count      INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);

CREATE INDEX ratelimit_buckets_expires ON ratelimit_buckets (expires_at);

CREATE TABLE IF NOT EXISTS auth_tokens (
    token_sha256 VARCHAR(64) PRIMARY KEY,
    purpose      VARCHAR(64) NOT NULL,
    user_id      VARCHAR(64) NOT NULL,
    created_at   DATETIME(6) NOT NULL,
    expires_at   DATETIME(6) NOT NULL,
    used_at      DATETIME(6) NULL
);

CREATE INDEX idx_auth_tokens_user ON auth_tokens (user_id, purpose);

CREATE TABLE IF NOT EXISTS api_tokens (
    id            VARCHAR(64) PRIMARY KEY,
    token_sha256  VARCHAR(64) NOT NULL UNIQUE,
    user_id       VARCHAR(64) NOT NULL,
    name          TEXT NOT NULL,
    scopes        TEXT NOT NULL,
    created_at    DATETIME(6) NOT NULL,
    expires_at    DATETIME(6),
    last_used_at  DATETIME(6),
    revoked_at    DATETIME(6)
);

CREATE INDEX idx_api_tokens_user ON api_tokens (user_id);

CREATE TABLE IF NOT EXISTS roles (
    name        VARCHAR(64) PRIMARY KEY,
    permissions TEXT NOT NULL,
    created_at  DATETIME(6) NOT NULL
);

CREATE TABLE IF NOT EXISTS user_roles (
    user_id    VARCHAR(64) NOT NULL,
    role_name  VARCHAR(64) NOT NULL,
    granted_at DATETIME(6) NOT NULL,
    PRIMARY KEY (user_id, role_name)
);
