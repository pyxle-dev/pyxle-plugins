"""pyxle-db — the official database plugin for Pyxle.

One explicit-SQL API over SQLite, PostgreSQL, and MySQL:

* :class:`Database` — async facade over a driver backend. Accepts a bare
  SQLite path (0.1-compatible) or any supported database URL. Queries are
  written once in canonical qmark style (``?`` placeholders) and translated
  per backend with a literal-aware rewriter.
* :class:`Migrator` — discovery + atomic application of ordered SQL
  migrations from a filesystem directory. Keeps a ``schema_migrations``
  table with applied-hash tracking so edits to committed migrations are
  detected and rejected.
* :func:`connect` — convenience entry point that opens a :class:`Database`
  and applies a migrations directory in one call.

Design constraints:

* Zero third-party dependencies for SQLite; PostgreSQL and MySQL drivers
  install via extras (``pyxle-db[postgres]``, ``pyxle-db[mysql]``).
* Parameterised queries only — no string interpolation in SQL.
* Every write goes through a transaction (implicit or explicit).
* Driver exceptions never leak: every failure crosses the boundary as a
  :class:`DatabaseError` subclass, so application code never imports
  ``sqlite3``/``asyncpg``/``asyncmy`` just to handle an error.
* Fail loudly: bad URLs, missing drivers, unknown migrations, and checksum
  drift all raise specific, actionable error types.
"""

from __future__ import annotations

from pyxle_db.autotx import no_auto_transaction
from pyxle_db.backends import Dialect
from pyxle_db.contract import DatabaseLike, TransactionLike
from pyxle_db.database import Database, Transaction, connect
from pyxle_db.errors import (
    ConfigurationError,
    DatabaseError,
    IntegrityError,
    MigrationChecksumMismatch,
    MigrationError,
    NotFoundError,
    OperationalError,
    UnsupportedOperationError,
)
from pyxle_db.migrator import Migration, Migrator
from pyxle_db.rows import Row
from pyxle_db.url import DatabaseConfig, parse_database_url


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
    "DatabaseLike",
    "Transaction",
    "TransactionLike",
    "Row",
    "connect",
    "Migration",
    "Migrator",
    "Dialect",
    "DatabaseConfig",
    "parse_database_url",
    "DatabaseError",
    "IntegrityError",
    "OperationalError",
    "ConfigurationError",
    "UnsupportedOperationError",
    "NotFoundError",
    "MigrationError",
    "MigrationChecksumMismatch",
    "get_database",
    "no_auto_transaction",
]

__version__ = "0.3.0"
