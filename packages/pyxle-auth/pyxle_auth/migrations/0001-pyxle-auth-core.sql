-- pyxle-auth core schema.
--
-- The full set of tables the pyxle-auth services use: AuthService
-- (users, sessions), RateLimiter (ratelimit_buckets), TokenService
-- (auth_tokens), ApiTokenService (api_tokens), and the RBAC role store
-- (roles, user_roles).
--
-- Host apps that own a migrations directory copy this file into it and
-- the plugin applies this file automatically at startup (checksum-tracked).
-- the migration id from colliding with the app's own migrations. Every
-- statement is guarded with IF NOT EXISTS so a database bootstrapped by
-- the services' ensure_schema() methods adopts this migration cleanly.
--
-- Written in pyxle-db's portable dialect: VARCHAR(n) for every key or
-- indexed column (MySQL cannot index bare TEXT), TEXT for payloads,
-- TIMESTAMP columns, and explicit inserted values instead of column
-- DEFAULTs. The .mysql.sql override mirrors this schema with DATETIME(6)
-- (MySQL TIMESTAMP is 2038-capped and second-rounded).

CREATE TABLE IF NOT EXISTS users (
    id                VARCHAR(64) PRIMARY KEY,
    email             VARCHAR(255) NOT NULL UNIQUE,
    password_hash     TEXT NOT NULL,
    email_verified_at TIMESTAMP,
    created_at        TIMESTAMP NOT NULL,
    plan              TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    token_sha256 VARCHAR(64) PRIMARY KEY,
    user_id      VARCHAR(64) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at   TIMESTAMP NOT NULL,
    expires_at   TIMESTAMP NOT NULL,
    user_agent   TEXT,
    ip           TEXT
);

CREATE INDEX IF NOT EXISTS sessions_user ON sessions (user_id);

CREATE INDEX IF NOT EXISTS sessions_expires ON sessions (expires_at);

CREATE TABLE IF NOT EXISTS ratelimit_buckets (
    bucket_key VARCHAR(320) PRIMARY KEY,
    count      INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS ratelimit_buckets_expires ON ratelimit_buckets (expires_at);

CREATE TABLE IF NOT EXISTS auth_tokens (
    token_sha256 VARCHAR(64) PRIMARY KEY,
    purpose      VARCHAR(64) NOT NULL,
    user_id      VARCHAR(64) NOT NULL,
    created_at   TIMESTAMP NOT NULL,
    expires_at   TIMESTAMP NOT NULL,
    used_at      TIMESTAMP NULL
);

CREATE INDEX IF NOT EXISTS idx_auth_tokens_user ON auth_tokens (user_id, purpose);

CREATE TABLE IF NOT EXISTS api_tokens (
    id            VARCHAR(64) PRIMARY KEY,
    token_sha256  VARCHAR(64) NOT NULL UNIQUE,
    user_id       VARCHAR(64) NOT NULL,
    name          TEXT NOT NULL,
    scopes        TEXT NOT NULL,
    created_at    TIMESTAMP NOT NULL,
    expires_at    TIMESTAMP,
    last_used_at  TIMESTAMP,
    revoked_at    TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_api_tokens_user ON api_tokens (user_id);

CREATE TABLE IF NOT EXISTS roles (
    name        VARCHAR(64) PRIMARY KEY,
    permissions TEXT NOT NULL,
    created_at  TIMESTAMP NOT NULL
);

CREATE TABLE IF NOT EXISTS user_roles (
    user_id    VARCHAR(64) NOT NULL,
    role_name  VARCHAR(64) NOT NULL,
    granted_at TIMESTAMP NOT NULL,
    PRIMARY KEY (user_id, role_name)
);
