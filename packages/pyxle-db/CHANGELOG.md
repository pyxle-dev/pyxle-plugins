# Changelog

All notable changes to `pyxle-db` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- `__version__` and the plugin's `version` are read from installed distribution
  metadata instead of restated in source, so they cannot drift from
  `pyproject.toml`.

## [0.3.0] - 2026-06-17

Enterprise database support. All additive — no breaking changes.

### Added

- **Request-scoped database injection.** With the plugin installed, every loader
  and action gets a lazy database handle on `request.state.db` — no import, no
  service lookup. A request that never queries opens no connection. The injecting
  middleware is **pure-ASGI** (not `BaseHTTPMiddleware`), so it never buffers the
  response — it works with streaming-SSR (`<Suspense>`) pages and never raises
  `No response returned` on a mid-stream client disconnect.
- **Automatic transactions.** An unsafe-method request (POST/PUT/PATCH/DELETE)
  runs its writes in one transaction that commits when the action succeeds and
  rolls back when it fails. Because Pyxle's dispatcher catches an action's
  exception and returns a non-2xx response (the exception never escapes),
  commit/rollback is keyed on the response status, not on an escaping exception —
  so a failed action never commits a partial write. Opt out per action with the
  `@no_auto_transaction` decorator, or app-wide with `"autoTransactions": false`.
- **SQLAlchemy ORM path** (optional `[sqlalchemy]` extra). `pyxle_db.orm` adds an
  async `Engine` + `async_sessionmaker`, a `Base` declarative base, request-scoped
  `request.state.session` (same auto-transaction rules), connection pooling
  (`orm.pool`, `pool_pre_ping` on by default), and `get_session()` for work
  outside a request. SQLAlchemy errors are translated to the same `pyxle_db`
  error types as the explicit-SQL path. The base install stays SQLAlchemy-free.
- **`pyxle-db` CLI.** `pyxle-db migrate` / `migrate --dry-run` / `status` drive
  the checksum migrator; `alembic-init` / `revision --autogenerate` / `upgrade` /
  `downgrade` / `current` / `history` drive Alembic for the ORM path. The CLI
  reads the app's own `pyxle.config.json` + `.env`. Also `python -m pyxle_db.cli`.
- `Migrator.status()` returning a `MigrationStatus` (applied vs pending).
- `DatabaseConfig.sqlalchemy_url()` building the async SQLAlchemy URL.

## [0.2.0] - 2026-06-11

### Changed (BREAKING)

- `Database.transaction()` now yields a transaction whose methods are
  coroutines: `await tx.execute(...)`, `await tx.fetchone(...)`, etc.
  In 0.1 these calls were synchronous inside the async context manager.
- `Database.close()` and `Database.sync_transaction()` are SQLite-only
  and raise `UnsupportedOperationError` on server backends. Use
  `await db.aclose()` and `async with db.transaction()` — both work on
  every backend.
- Mapping (named) parameters are SQLite-only; portable SQL uses
  positional `?` parameters.

### Added

- PostgreSQL backend via `asyncpg` (`pip install 'pyxle-db[postgres]'`)
  and MySQL backend via `asyncmy` (`pip install 'pyxle-db[mysql]'`).
  The base install remains SQLite-only with zero extra dependencies.
- Database URLs: `Database(...)`/`connect(...)` accept
  `sqlite:///...`, `postgresql://...`, and `mysql://...` connection
  strings alongside the 0.1 bare SQLite path. `DatabaseConfig` and
  `parse_database_url` are exported for programmatic use.
- Portable placeholders: qmark (`?`) SQL is translated per backend
  (`$1` for PostgreSQL, `%s` for MySQL) with a literal-aware rewriter;
  `??` escapes a literal question mark for PostgreSQL JSON operators.
- Backend-neutral `Row` result type (index + name access) and `Dialect`
  metadata, both exported from `pyxle_db`.
- New error types: `OperationalError` (retryable connection/timeout
  family), `ConfigurationError`, and `UnsupportedOperationError`.
  Driver exceptions are translated on every backend — application code
  never handles `sqlite3`/`asyncpg`/`asyncmy` exceptions.
- Datetimes come back timezone-aware UTC on every backend; naive values
  stored in the database are assumed UTC and tagged.
- Plugin: new `url` setting that takes precedence over `path`, with
  `env:VAR_NAME` indirection so credentials stay out of the committed
  `pyxle.config.json` (startup raises `ConfigurationError` when the
  variable is unset). The plugin now also registers `db.url`, a
  password-redacted connection string for logging.
- Migrations: backend-specific override files
  (`0003-fulltext-index.postgresql.sql` next to
  `0003-fulltext-index.sql`) for migrations that need per-dialect DDL.

- `DatabaseLike` / `TransactionLike` protocols (`pyxle_db.contract`,
  exported at top level): the structural contract third-party database
  layers implement to back plugins like pyxle-auth. `Database` is the
  reference implementation; both protocols are `runtime_checkable` and
  the conformance is regression-tested.

### Fixed

- Plugin shutdown awaits `Database.aclose()`, releasing async pools
  cleanly instead of relying on the SQLite-only synchronous close.
- **Aware datetimes now bind on every backend** (found by the live-server
  suites). PostgreSQL and MySQL pass parameters through
  `utc_naive_params()`: an aware datetime is converted to UTC and bound
  naive, matching the SQLite adapter and the read-side "naive equals
  UTC" rule. Previously asyncpg rejected aware datetimes for `TIMESTAMP`
  columns and asyncmy silently serialised the foreign wall clock.
- The MySQL pool pins each session to UTC (`SET time_zone = '+00:00'`),
  so `TIMESTAMP` columns and `NOW()` are no longer shifted through the
  server's system time zone on read.
- The `mysql` extra now includes `cryptography`: MySQL 8's default
  `caching_sha2_password` auth fails at connect without it.
- Dependency floor corrected to `pyxle-framework>=0.4.0` — the
  `pyxle.plugins` API first shipped in 0.4.0, so older resolutions
  could not import.

## [0.1.0] - 2026-04-23

### Added

- Initial release: SQLite `Database` wrapper (thread-local connections,
  WAL journaling, foreign-key and performance PRAGMAs), filesystem
  `Migrator` with SHA-256 checksum tracking, `connect()` one-call setup,
  and the `pyxle-db` plugin registering `db.database`/`db.path`.
