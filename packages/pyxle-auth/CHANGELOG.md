# Changelog

All notable changes to `pyxle-auth` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-06-11

### Changed (BREAKING)

- Requires `pyxle-db>=0.2.0`. Its transaction methods became
  coroutines (`await tx.execute(...)`), and all pyxle-auth SQL is now
  written in portable qmark style — the plugin works unchanged on
  SQLite, PostgreSQL, and MySQL (DML fully portable; shipped DDL targets
  SQLite/PostgreSQL — MySQL schema needs a dialect override, see README).
  Upgraders from 0.1: the `ratelimit_buckets.key` column is now
  `bucket_key` (KEY is reserved in MySQL); drop the old table — bucket
  data is ephemeral hourly counters and recreates itself.
- The plugin now hard-requires the `pyxle-db` plugin to have run
  first. List `"pyxle-db"` before `"pyxle-auth"` in
  `pyxle.config.json::plugins`; startup aborts with an actionable
  error otherwise.
- The `ensureSchema` plugin setting is removed. The plugin always
  applies its bundled migrations and then runs each service's
  idempotent `ensure_schema()` — both are no-ops on an up-to-date
  database, so there is nothing left to opt out of.

### Added

- Password reset and email verification flows, powered by
  `TokenService`: single-use, purpose-scoped, expiring tokens with
  only the SHA-256 stored at rest. The library never sends email —
  your app delivers the token through its own mailer.
- `RoleService` (RBAC): roles, permissions, and per-user grants,
  registered as `auth.rbac`.
- `ApiTokenService`: long-lived `pyxle_pat_` personal access tokens
  with scopes, per-user caps enforced atomically, and revocation.
  Registered as `auth.api_tokens`.
- Request guards: `current_user`, `require_user_page`,
  `require_user_action`, `require_permission_page`,
  `require_permission_action`, and `bearer_token`, re-exported from
  the package root.
- New settings: `password_reset_ttl_seconds` (default 1800),
  `email_verify_ttl_seconds` (default 86400), and
  `rate_limit_password_reset_per_hour` (default 3), each with a
  `PYXLE_AUTH_*` environment variable and a camelCase plugin key.
- Settings precedence: plugin `settings` in `pyxle.config.json`
  override `PYXLE_AUTH_*` environment variables, which override the
  built-in defaults. `AuthSettings.from_env` grew an `overrides`
  parameter to express this.
- Bundled migrations (`pyxle_auth/migrations`) applied through
  `pyxle_db.Migrator` at startup, with `ensure_schema()` as
  belt-and-braces after.
- New exports: `SessionInfo`, `InvalidToken`, `TokenClaim`,
  `TokenService`, `ApiToken`, `ApiTokenService`, `TokenLimitReached`,
  `TOKEN_PREFIX`, and `RoleService`.
- Live-backend test suite (`tests/test_live_backends.py`) running the
  real plugin schema path and a full account lifecycle against
  PostgreSQL and MySQL (gated on `PYXLE_DB_TEST_POSTGRES_URL` /
  `PYXLE_DB_TEST_MYSQL_URL`, shared with pyxle-db's suites).
- `PYXLE_AUTH_STRICT` environment variable: `strict` now resolves
  config > env > secure-default(True), so a committed config can stay
  production-safe (strict + Secure cookies) while local HTTP dev
  relaxes via the environment.
- **Bring your own database.** Services and the plugin now bind to the
  `pyxle_db.DatabaseLike` protocol instead of the concrete `Database`
  class, and the plugin's requirement is the `db.database` service
  *name* — any plugin registering a protocol-satisfying object can back
  pyxle-auth (pyxle-db remains the reference provider and a hard
  dependency for the error types and migrator). The contract (surface,
  `IntegrityError` translation, dialect, datetimes) is documented in the
  README and enforced by `tests/test_database_contract.py`, which runs
  the full lifecycle against a deliberately foreign database object.

### Fixed

- **Schema is now genuinely portable** (found by the live-server
  suites). Key and indexed columns are `VARCHAR(n)` instead of `TEXT`
  (MySQL cannot index bare `TEXT`), a `0001-pyxle-auth-core.mysql.sql`
  override uses `DATETIME(6)` (MySQL `TIMESTAMP` is 2038-capped,
  second-rounded, and session-time-zone converted), and
  `ensure_schema()` creates indexes through an `information_schema`
  probe on MySQL, which has no `CREATE INDEX IF NOT EXISTS`.
- Dependency floor corrected to `pyxle-framework>=0.4.0` — the
  `pyxle.plugins` API first shipped in 0.4.0.

## [0.1.0] - 2026-04-23

### Added

- Initial release: email+password `AuthService` (argon2id hashing,
  sliding sessions with an absolute cap, SHA-256 token storage,
  enumeration-resistant errors, fixed-window rate limits), the
  `pyxle-auth` plugin registering `auth.service`/`auth.settings`, and
  `AuthSettings` loadable from the environment.
