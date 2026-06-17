# Changelog

All notable changes to `pyxle-auth` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2026-06-17

### Added

- **`AuthSessionMiddleware`** — contributed automatically through the
  plugin's middleware seam. It populates `request.user` (a `User` or
  `None`) on every request and serves two endpoints the client `useAuth`
  hook talks to:
  - `GET {authPathPrefix}/me` — the current user as JSON (safe method;
    CSRF-exempt).
  - `POST {authPathPrefix}/logout` — revoke the session and clear the
    cookie (state-changing; covered by core CSRF, which runs first).

  A request without the session cookie does zero database work; one that
  carries it performs a single indexed lookup, and the guards reuse that
  resolved value (cached on the request) so a guarded loader never
  resolves the session twice.
- **Credentials API** — `POST {prefix}/login` and `POST {prefix}/signup`
  (email + password), gated by `enableCredentialsApi` (default on). They
  reuse the hardened `AuthService.sign_in` / `sign_up` (per-IP and
  per-email rate limiting, enumeration-safe errors) and map failures to
  conventional status codes: `401` invalid credentials, `409` account
  exists, `422` weak password, `403` unverified email, `429` rate limited
  (with `Retry-After`). The framework `useAuth()` hook calls them; apps
  rolling custom flows turn them off and keep `/me` + `/logout`.
- **SSR seed** — the middleware publishes the signed-in user plus the
  endpoint map on `request.scope["pyxle.auth"]`, which Pyxle core seeds
  into `window.__PYXLE_AUTH__`. The client `useAuth()` hook reads it to
  render the user on the first frame with no round-trip.
- `AuthSettings.auth_path_prefix` (config key `authPathPrefix`, env
  `PYXLE_AUTH_PATH_PREFIX`; default `/auth`) — move the middleware's
  endpoints if your app already owns `/auth`.
- `AuthSettings.enable_credentials_api` (config key `enableCredentialsApi`,
  env `PYXLE_AUTH_ENABLE_CREDENTIALS_API`; default `True`).
- **OAuth 2.0 / OIDC sign-in** (`pyxle_auth.oauth`, `[oauth]` extra) —
  built-in Google, GitHub, and Discord providers, served at
  `GET {prefix}/oauth/{provider}/{start,callback}`. Security model:
  - **PKCE `S256` mandatory** — the verifier never leaves the server.
  - A **signed, single-use, HttpOnly `state` cookie** binds the flow to the
    browser (provider + PKCE verifier + `next` + nonce, HMAC-verified with
    `hmac.compare_digest`); the echoed `state` must match the cookie nonce.
    This is the login-CSRF defense for the `GET` callback.
  - **Account linking only on a provider-verified email** — the
    takeover guard; a returning identity signs in directly.
  - The post-login `next` is **same-origin path only** (open-redirect
    guard), re-checked on use.
  - Client **secrets come from the environment only**
    (`PYXLE_AUTH_OAUTH_<PROVIDER>_CLIENT_ID` / `…_CLIENT_SECRET`) and are
    redacted in `repr`; the state cookie is signed with `PYXLE_AUTH_SECRET`
    (or `PYXLE_SECRET_KEY`), required in strict mode.

  Configure with the `oauth` plugin setting:
  `{ "oauth": { "providers": ["google", "github"] } }`. New `oauth_identities`
  table (migration `0002`). `AuthService` gained `start_session()` and
  `create_external_user()` for passwordless, externally-authenticated sign-in.
- **JWT for API / mobile clients** (`pyxle_auth.jwt_tokens.JWTService`,
  `[jwt]` extra). Short-lived signed **access tokens** (HS256) plus long-lived
  **opaque refresh tokens** stored hashed-at-rest. Refresh does
  **rotation with reuse detection**: every refresh issues a new token and
  marks the old one used; replaying a rotated token **revokes the whole token
  family** (theft detection). Served at `POST {prefix}/token` (email+password
  → pair) and `POST {prefix}/token/refresh` (rotate) when the `jwt` setting is
  configured. New guards: `bearer_user()` (JWT → PAT) and `authenticate()`
  (session → JWT → PAT). New `jwt_refresh_tokens` table (migration `0003`).
  `AuthService.verify_credentials()` extracted from `sign_in` so token
  issuance reuses the same rate-limited, enumeration-safe check without
  minting a session. Add `{prefix}/token*` to `csrf.exempt_paths` for
  non-browser clients (the endpoints authenticate from the body, not cookies).
- Roadmap-named guard aliases: `login_required` / `login_required_action`
  and `permission_required` / `permission_required_action` — thin,
  explicit re-exports of the existing `require_user_*` / `require_permission_*`
  guards (a wrapping decorator would violate the framework's
  "decorators add metadata, not behaviour" rule).

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
