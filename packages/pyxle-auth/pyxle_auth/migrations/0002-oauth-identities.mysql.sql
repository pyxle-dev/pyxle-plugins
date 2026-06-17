-- pyxle-auth OAuth identities — MySQL override.
--
-- Identical to 0002-oauth-identities.sql but DATETIME(6) instead of TIMESTAMP
-- (MySQL TIMESTAMP is 2038-capped and second-rounded), and a bare CREATE INDEX
-- (MySQL has no IF NOT EXISTS for indexes; the migration runs once per
-- database, checksum-tracked). The Migrator picks this file on MySQL; both
-- share the migration id.

CREATE TABLE IF NOT EXISTS oauth_identities (
    provider   VARCHAR(64)  NOT NULL,
    subject    VARCHAR(255) NOT NULL,
    user_id    VARCHAR(64)  NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    email      TEXT,
    created_at DATETIME(6) NOT NULL,
    PRIMARY KEY (provider, subject)
);

CREATE INDEX oauth_identities_user ON oauth_identities (user_id);
