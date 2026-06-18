-- pyxle-auth OAuth identities.
--
-- One row per linked social account: (provider, subject) is the provider's
-- stable account id, mapped to a local user. Created by OAuthService and also
-- by the service's idempotent ensure_schema() — guarded with IF NOT EXISTS so
-- either path adopts it cleanly. Apps that never enable OAuth simply keep an
-- empty table.
--
-- Portable dialect: VARCHAR(n) for indexed/key columns, TIMESTAMP datetimes;
-- the .mysql.sql override swaps TIMESTAMP for DATETIME(6).

CREATE TABLE IF NOT EXISTS oauth_identities (
    provider   VARCHAR(64)  NOT NULL,
    subject    VARCHAR(255) NOT NULL,
    user_id    VARCHAR(64)  NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    email      TEXT,
    created_at TIMESTAMP NOT NULL,
    PRIMARY KEY (provider, subject)
);

CREATE INDEX IF NOT EXISTS oauth_identities_user ON oauth_identities (user_id);
