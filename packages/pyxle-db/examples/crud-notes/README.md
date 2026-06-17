# crud-notes — a pyxle-db example

A minimal CRUD app showing **request-scoped DB injection** and **automatic
transactions** with the explicit-SQL path. The same UI works on the ORM path —
see the "ORM path" section of the [pyxle-db README](../../README.md).

## Run it

```bash
pip install pyxle-framework pyxle-db
cd examples/crud-notes
pyxle-db migrate        # apply migrations/0001-notes.sql -> ./data/notes.db
pyxle dev               # http://localhost:8000
```

## What it shows

- `request.state.db` available in the loader and actions — no imports, no wiring.
- `@action add_note` / `delete_note` run inside an automatic transaction: a
  failed action (a raised `ActionError`) rolls back with no partial write; a
  successful one commits. No `commit()`/`rollback()` in app code.
- The loader runs read-only (a `GET`), so it never holds a write transaction.
