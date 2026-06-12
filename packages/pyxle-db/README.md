# pyxle-db

The official database plugin for [Pyxle](https://pyxle.dev). One explicit-SQL
API over **SQLite**, **PostgreSQL**, and **MySQL** — no ORM, no query builder,
Django-grade ergonomics for people who like writing SQL.

- Write SQL once, in portable qmark style (`?` placeholders); pyxle-db
  translates per backend with a literal-aware rewriter.
- Every backend returns the same `Row` type, raises the same
  `pyxle_db` error types, and hands back timezone-aware UTC datetimes —
  application code never imports `sqlite3`, `asyncpg`, or `asyncmy`.
- Filesystem migrations with SHA-256 checksum tracking, applied atomically.
- First-class Pyxle plugin: one entry in `pyxle.config.json` and your app
  has an open database at startup.

## Install

```bash
pip install pyxle-db               # SQLite — zero extra dependencies
pip install 'pyxle-db[postgres]'   # + asyncpg
pip install 'pyxle-db[mysql]'      # + asyncmy
```

## Quickstart

Same code on every backend — only the connection string changes.

```python
from pyxle_db import connect

# SQLite (a bare path, exactly like 0.1)
db = await connect("./data/app.db", migrations_dir="migrations")

# PostgreSQL
db = await connect("postgresql://app:s3cret@localhost/app")

# MySQL
db = await connect("mysql://app:s3cret@localhost/app")

await db.execute(
    "INSERT INTO users (id, email) VALUES (?, ?)", (user_id, email)
)

row = await db.fetchone("SELECT email, created_at FROM users WHERE id = ?", (user_id,))
row["email"]        # name access
row[0]              # index access
row["created_at"]   # timezone-aware UTC datetime, on every backend

user = await db.get("SELECT * FROM users WHERE id = ?", (user_id,))  # raises NotFoundError if absent

await db.aclose()
```

Constraint violations raise `pyxle_db.IntegrityError`; unreachable/timed-out
databases raise `pyxle_db.OperationalError` (the retryable family); everything
else is a `pyxle_db.DatabaseError` subclass. Driver exceptions never leak.

## Database URLs

`Database(...)`, `connect(...)`, and the plugin's `url` setting all accept:

| Form | Opens |
|------|-------|
| `./data/app.db` (no scheme) | SQLite at that path — 0.1-compatible |
| `sqlite:///relative/path.db` | SQLite, path relative to the working directory |
| `sqlite:////absolute/path.db` | SQLite, absolute path |
| `sqlite:///:memory:` | SQLite, in-memory |
| `postgresql://user:pass@host:5432/dbname?sslmode=require` | PostgreSQL (`postgres://` also accepted) |
| `mysql://user:pass@host:3306/dbname` | MySQL (`mariadb://` also accepted) |

Ports default to 5432/3306. Query-string options (e.g. `sslmode`) pass
through to the driver. Credentials are percent-decoded, so encode special
characters (`p@ss` → `p%40ss`).

## Placeholders

Always write `?`. pyxle-db rewrites it to the backend's native style —
`?` for SQLite, `$1`/`$2` for PostgreSQL, `%s` for MySQL.

When you need a *literal* question mark — PostgreSQL's JSON operators —
escape it as `??`:

```python
await db.fetchall(
    "SELECT id FROM events WHERE payload ?? 'user_id' AND kind = ?",
    ("signup",),
)
# asyncpg receives: SELECT id FROM events WHERE payload ? 'user_id' AND kind = $1
```

The rewriter is literal-aware: `?` inside string literals, quoted
identifiers, comments, and dollar-quoted bodies is never touched, so user
data can't become SQL structure during translation.

## Writing portable schemas

Rules proven against real PostgreSQL and MySQL servers (the live suites
in `tests/` enforce them):

- **`VARCHAR(n)` for every key or indexed column.** MySQL cannot index
  bare `TEXT` (error 1170). SQLite and PostgreSQL treat `VARCHAR` as
  `TEXT`, so nothing is lost. Keep `TEXT` for payloads.
- **Datetimes: bind anything, read aware UTC.** Columns store UTC wall
  time. You may bind naive datetimes (assumed UTC) or aware ones (the
  backend converts to UTC before binding); every read comes back as an
  aware-UTC `datetime` on all three engines.
- **`TIMESTAMP` columns are fine on SQLite and PostgreSQL.** On MySQL
  prefer `DATETIME(6)` via a per-dialect migration override
  (`0002-x.mysql.sql`): MySQL's `TIMESTAMP` is capped at 2038 and rounds
  to whole seconds. (The backend pins each session to UTC, so even
  `TIMESTAMP` columns read back correct instants.)
- **MySQL has no `CREATE INDEX IF NOT EXISTS`.** Create indexes in
  migrations (they run exactly once, checksum-tracked) or probe
  `information_schema.statistics` before creating.
- **Spell out inserted values instead of relying on column `DEFAULT`s**,
  which drift subtly between engines.

## Transactions

```python
async with db.transaction() as tx:
    await tx.execute("UPDATE accounts SET balance = balance - ? WHERE id = ?", (amount, src))
    await tx.execute("UPDATE accounts SET balance = balance + ? WHERE id = ?", (amount, dst))
```

Commits on exit, rolls back on exception. Concurrent transactions never
interleave statements on the same connection.

**SQLite only:** synchronous scripts and tests can use
`with db.sync_transaction() as tx: ...` and `db.close()`. Server backends
hold async pools, so both raise `UnsupportedOperationError` there — use
`async with db.transaction()` and `await db.aclose()`.

## Migrations

Each migration is a `.sql` file named `<NNNN>-<slug>.sql` in your
migrations directory:

```
migrations/
  0001-initial-schema.sql
  0002-add-sessions.sql
  0003-fulltext-index.sql
  0003-fulltext-index.postgresql.sql   # backend-specific override
```

- The numeric prefix is the canonical order; two files may not share one.
- A dialect-suffixed file (`.sqlite.sql`, `.postgresql.sql`, `.mysql.sql`)
  replaces the base file on that backend — for the rare migration that
  genuinely needs backend-specific DDL.
- Each migration runs in its own transaction and is applied exactly once
  per database, recorded in `schema_migrations` with the file's SHA-256.
- **Checksum policy:** every startup re-hashes applied migrations. An
  edited file raises `MigrationChecksumMismatch`; a deleted one raises
  `MigrationError`. Once applied anywhere, a migration is immutable —
  write a follow-up migration instead.

Apply on startup via `connect(..., migrations_dir="migrations")`, the
plugin's `migrationsDir` setting, or explicitly:

```python
from pathlib import Path
from pyxle_db import Migrator

await Migrator(db, Path("migrations")).apply_all()
```

## Using it as a Pyxle plugin

```json
{
  "plugins": [
    {
      "name": "pyxle-db",
      "settings": {
        "url": "env:DATABASE_URL",
        "migrationsDir": "migrations"
      }
    }
  ]
}
```

Settings (all optional):

| Key | Meaning | Default |
|-----|---------|---------|
| `url` | Database URL; wins over `path`. The `env:VAR` form resolves the named environment variable at startup — keep secrets out of the committed config. Startup fails with `ConfigurationError` if the variable is unset. | — |
| `path` | SQLite path, resolved against the project root | `./data/app.db` |
| `migrationsDir` | Migrations directory, applied at startup if it exists | `migrations` |
| `waitForFileMs` | Poll this long for a SQLite file being created by another process | `0` |

Registered services: `db.database` (the open `Database`), `db.url`
(password-redacted connection string for logging), and — SQLite only —
`db.path` (the resolved file path, kept for 0.1 consumers).

In loaders and actions, skip the service registry boilerplate:

```python
from pyxle_db import get_database

@server
async def load(request):
    db = get_database()
    return {"posts": await db.fetchall("SELECT * FROM posts ORDER BY id DESC")}
```

## Upgrading from 0.1

> **Breaking changes in 0.2**
>
> - Transaction methods are now coroutines. `async with db.transaction()
>   as tx:` then `await tx.execute(...)` / `await tx.fetchone(...)` —
>   0.1's sync calls inside the async block no longer work.
> - `db.close()` and `db.sync_transaction()` are now SQLite-only and raise
>   `UnsupportedOperationError` on PostgreSQL/MySQL. Prefer
>   `await db.aclose()` everywhere — it works on every backend.
> - Mapping (named) parameters are SQLite-only; portable SQL uses
>   positional `?` parameters.
>
> Everything else is additive: bare SQLite paths, the migration format,
> and the plugin settings from 0.1 keep working unchanged.

## Roadmap

Short list, subject to change: pool-size tuning options for server
backends, streaming fetches for large result sets, and `pyxle db` CLI
commands for migration status/creation. Issues and PRs welcome.

## License

MIT.
