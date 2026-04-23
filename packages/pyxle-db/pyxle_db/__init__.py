"""pyxle-db — SQLite-first database plugin for Pyxle.

The plugin exposes three layers:

* :class:`Database` — async-friendly connection wrapper around the stdlib
  :mod:`sqlite3` driver. Connection pooling, PRAGMA hardening, parameter-safe
  query helpers, transaction context manager.
* :class:`Migrator` — discovery + atomic application of ordered SQL
  migrations from a filesystem directory. Keeps a ``schema_migrations``
  table with applied-hash tracking so edits to committed migrations are
  detected and rejected.
* :func:`connect` — convenience entry point that opens a :class:`Database`
  and applies a migrations directory in one call.

Design constraints:

* Zero third-party runtime dependencies. ``sqlite3`` only.
* Parameterised queries only — no string interpolation in SQL.
* Every write goes through a transaction (implicit or explicit).
* Connection-per-thread, safe under Pyxle's async event loop via
  ``asyncio.to_thread`` wrappers exposed on :class:`Database`.
* Fail loudly: unknown migrations, checksum drift, unsupported PRAGMA
  combinations all raise :class:`DatabaseError` subclasses.
"""

from __future__ import annotations

from pyxle_db.database import Database, Transaction, connect
from pyxle_db.errors import (
    DatabaseError,
    IntegrityError,
    MigrationError,
    MigrationChecksumMismatch,
    NotFoundError,
)
from pyxle_db.migrator import Migration, Migrator


def get_database() -> Database:
    """Return the :class:`Database` the active ``pyxle-db`` plugin opened.

    Short form for app code that wants the database without reaching
    through ``request.app.state.pyxle_plugins``::

        from pyxle_db import get_database

        @server
        async def load(request):
            db = get_database()
            row = await db.fetchone("SELECT ... FROM ...")

    Requires ``pyxle-db`` to be listed in ``pyxle.config.json::plugins``
    — otherwise raises :class:`pyxle.plugins.PluginServiceError`.
    """
    from pyxle.plugins import plugin as _plugin  # local import to
    # avoid pyxle-db depending on pyxle at module-load time; the plugin
    # system is only needed at *call* time.

    return _plugin("db.database")


__all__ = [
    "Database",
    "Transaction",
    "connect",
    "Migration",
    "Migrator",
    "DatabaseError",
    "IntegrityError",
    "NotFoundError",
    "MigrationError",
    "MigrationChecksumMismatch",
    "get_database",
]

__version__ = "0.1.0"
