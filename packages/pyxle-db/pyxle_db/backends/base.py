"""Backend protocol — the contract every database driver adapter implements.

A backend owns connections/pools for exactly one database and speaks that
database's native parameter style. Everything above the backend (the
:class:`pyxle_db.Database` facade, the migrator, application code) speaks
canonical qmark SQL; the facade translates via :mod:`pyxle_db.sql` before
calling the backend, so every backend receives SQL already in its native
parameter style (for SQLite that native style happens to be qmark).

Implementations:

* :mod:`pyxle_db.backends.sqlite` — stdlib ``sqlite3``, thread-local
  connections bridged with ``asyncio.to_thread``. Zero dependencies.
* :mod:`pyxle_db.backends.postgresql` — ``asyncpg`` pool
  (install extra: ``pyxle-db[postgres]``).
* :mod:`pyxle_db.backends.mysql` — ``asyncmy`` pool
  (install extra: ``pyxle-db[mysql]``).

Contract rules (enforced by the shared conformance tests):

1. Every error raised crosses the boundary as a :mod:`pyxle_db.errors`
   type — driver exceptions never leak.
2. Constraint violations (unique, FK, NOT NULL, CHECK) raise
   :class:`pyxle_db.errors.IntegrityError`.
3. Fetch methods return :class:`pyxle_db.rows.Row`.
4. Timestamp/datetime columns come back timezone-aware UTC; naive values
   read from the database are assumed UTC and tagged as such. The
   guarantee covers top-level column values (not datetimes nested inside
   driver-specific composite/array types).
5. ``connect()`` is idempotent; ``aclose()`` is idempotent and the backend
   must be reusable after a subsequent ``connect()``. Backends MAY also
   reopen lazily after close (SQLite does, preserving 0.1 semantics).
6. A transaction is exclusive to its caller; concurrent ``transaction()``
   calls must not interleave statements on the same underlying connection.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, AsyncContextManager, Iterable, Sequence

from pyxle_db.rows import Row

Params = Sequence[Any]


def utc_naive_params(params: Params) -> tuple[Any, ...]:
    """Normalise top-level datetime parameters to naive UTC for binding.

    The package-wide datetime contract is symmetric: columns store UTC wall
    time, reads come back as aware-UTC datetimes, and callers may bind either
    naive (assumed UTC) or aware (converted to UTC) datetimes. The SQLite
    backend gets this from its registered adapter; PostgreSQL and MySQL
    drivers do not — asyncpg rejects aware datetimes for ``TIMESTAMP``
    columns outright, and asyncmy would silently serialise an aware
    datetime's *foreign wall clock*, corrupting the stored instant. Both
    backends therefore run every parameter sequence through this before
    handing it to the driver. Only top-level values are touched, matching
    the read-side rule (containers are passed through untouched).
    """
    return tuple(
        value.astimezone(timezone.utc).replace(tzinfo=None)
        if isinstance(value, datetime) and value.tzinfo is not None
        else value
        for value in params
    )


@dataclass(frozen=True)
class Dialect:
    """What the SQL layer needs to know about a backend's flavour."""

    name: str
    """``"sqlite"`` | ``"postgresql"`` | ``"mysql"``."""

    paramstyle: str
    """``"qmark"`` | ``"numeric_dollar"`` | ``"format"`` (see pyxle_db.sql)."""

    migrations_table_ddl: str
    """``CREATE TABLE IF NOT EXISTS schema_migrations`` for this dialect."""

    supports_sync: bool = False
    """True only for SQLite — powers ``Database.sync_transaction()``."""


SQLITE_DIALECT = Dialect(
    name="sqlite",
    paramstyle="qmark",
    migrations_table_ddl=(
        "CREATE TABLE IF NOT EXISTS schema_migrations (\n"
        "    id TEXT PRIMARY KEY,\n"
        "    checksum TEXT NOT NULL,\n"
        "    applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP\n"
        ")"
    ),
    supports_sync=True,
)

POSTGRESQL_DIALECT = Dialect(
    name="postgresql",
    paramstyle="numeric_dollar",
    migrations_table_ddl=(
        "CREATE TABLE IF NOT EXISTS schema_migrations (\n"
        "    id TEXT PRIMARY KEY,\n"
        "    checksum TEXT NOT NULL,\n"
        "    applied_at TIMESTAMPTZ NOT NULL DEFAULT now()\n"
        ")"
    ),
)

MYSQL_DIALECT = Dialect(
    name="mysql",
    paramstyle="format",
    migrations_table_ddl=(
        "CREATE TABLE IF NOT EXISTS schema_migrations (\n"
        "    id VARCHAR(255) PRIMARY KEY,\n"
        "    checksum VARCHAR(64) NOT NULL,\n"
        "    applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP\n"
        ")"
    ),
)


class BackendTransaction(ABC):
    """One open transaction. All methods receive backend-native SQL."""

    @abstractmethod
    async def execute(self, sql: str, params: Params = ()) -> int:
        """Run one statement; return affected rowcount (-1 if unknown)."""

    @abstractmethod
    async def executemany(self, sql: str, seq_params: Iterable[Params]) -> None: ...

    @abstractmethod
    async def fetchone(self, sql: str, params: Params = ()) -> Row | None: ...

    @abstractmethod
    async def fetchall(self, sql: str, params: Params = ()) -> list[Row]: ...


class Backend(ABC):
    """Connection owner for one configured database."""

    dialect: Dialect

    @abstractmethod
    async def connect(self) -> None:
        """Create pools / verify connectivity. Idempotent."""

    @abstractmethod
    async def aclose(self) -> None:
        """Release every connection. Idempotent."""

    @abstractmethod
    async def execute(self, sql: str, params: Params = ()) -> int:
        """One-shot autocommitted statement; returns affected rowcount."""

    @abstractmethod
    async def executemany(self, sql: str, seq_params: Iterable[Params]) -> None:
        """One-shot bulk statement, atomically (single transaction)."""

    @abstractmethod
    async def fetchone(self, sql: str, params: Params = ()) -> Row | None: ...

    @abstractmethod
    async def fetchall(self, sql: str, params: Params = ()) -> list[Row]: ...

    @abstractmethod
    def transaction(self) -> AsyncContextManager[BackendTransaction]:
        """Open a transaction scope; commit on exit, roll back on exception."""
