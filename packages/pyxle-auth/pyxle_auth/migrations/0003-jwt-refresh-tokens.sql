-- pyxle-auth JWT refresh tokens.
--
-- One row per opaque refresh token, stored as its SHA-256 hash. Tokens from a
-- single sign-in share a family_id; rotation marks a token used and issues a
-- successor in the same family, and presenting a used token revokes the whole
-- family (theft detection). Created by JWTService and its idempotent
-- ensure_schema(); apps that never enable JWT keep an empty table.
--
-- Portable dialect: VARCHAR(n) for indexed/key columns, TIMESTAMP datetimes;
-- the .mysql.sql override swaps TIMESTAMP for DATETIME(6).

CREATE TABLE IF NOT EXISTS jwt_refresh_tokens (
    token_sha256 VARCHAR(64) PRIMARY KEY,
    family_id    VARCHAR(64) NOT NULL,
    user_id      VARCHAR(64) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    issued_at    TIMESTAMP NOT NULL,
    expires_at   TIMESTAMP NOT NULL,
    used_at      TIMESTAMP,
    revoked_at   TIMESTAMP
);

CREATE INDEX IF NOT EXISTS jwt_refresh_family ON jwt_refresh_tokens (family_id);

CREATE INDEX IF NOT EXISTS jwt_refresh_user ON jwt_refresh_tokens (user_id);
