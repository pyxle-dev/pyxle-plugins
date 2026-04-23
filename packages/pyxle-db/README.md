# pyxle-db

SQLite-first database plugin for Pyxle apps.

## What you get

- `Database` — async-friendly wrapper around stdlib `sqlite3` with a
  per-thread connection pool, transaction context manager, and
  parameter-safe query helpers. WAL journaling, foreign keys, and
  sensible performance PRAGMAs are applied at connection time.
- `Migrator` — filesystem-driven migrations with checksum tracking.
  Applied migrations are recorded in `schema_migrations`; editing a
  committed migration raises `MigrationChecksumMismatch` on the next
  startup.
- `connect(path, migrations_dir=...)` — open a database and apply
  every pending migration in one call.

## Install

```bash
pip install pyxle-db
```

## Quick start

```python
from pyxle_db import connect

db = await connect("app.db", migrations_dir="migrations")

async with db.transaction() as tx:
    tx.execute(
        "INSERT INTO users (id, email) VALUES (?, ?)",
        (user_id, email),
    )

row = await db.fetchone(
    "SELECT email FROM users WHERE id = ?",
    (user_id,),
)
```

## Migration files

Each migration is `<NNN>-<slug>.sql` in your migrations directory:

```
migrations/
  0001-initial-schema.sql
  0002-add-sessions.sql
```

Multi-statement files are fine — the plugin splits on semicolons
outside of strings and comments. A migration runs in its own
transaction; failures roll back that migration only.

## Design notes

- Zero third-party runtime dependencies.
- Parameterised queries only — never interpolate user data into SQL.
- Connection-per-thread, safe under an asyncio event loop via
  `asyncio.to_thread` wrappers exposed on `Database`.
- Integrity violations raise `pyxle_db.IntegrityError` (not the
  stdlib `sqlite3.IntegrityError`) so callers don't need to import
  `sqlite3` to handle constraint failures.

## License

MIT.
