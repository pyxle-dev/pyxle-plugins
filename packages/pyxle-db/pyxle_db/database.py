"""The public database API — one facade over every supported backend.

.. code-block:: python

    from pyxle_db import Database

    db = Database("./data/app.db")                       # SQLite (0.1-compatible)
    db = Database.from_url("postgresql://app:s3c@db/app")  # PostgreSQL
    db = Database.from_url("mysql://app:s3c@db/app")       # MySQL

    await db.connect()
    row = await db.fetchone("SELECT * FROM users WHERE id = ?", (uid,))
    async with db.transaction() as tx:
        await tx.execute("UPDATE accounts SET balance = balance - ? WHERE id = ?", (amt, a))
        await tx.execute("UPDATE accounts SET balance = balance + ? WHERE id = ?", (amt, b))
    await db.aclose()

Write SQL once, in canonical qmark style (``?`` placeholders); the facade
translates per backend (``$1`` for PostgreSQL, ``%s`` for MySQL) with a
literal-aware rewriter, so user data can never become SQL structure during
translation. ``??`` escapes a literal question mark (PostgreSQL JSON
operators).

Changed in 0.2 (breaking): transaction methods are now coroutines —
``await tx.execute(...)`` — because PostgreSQL/MySQL drivers are natively
async. SQLite scripts can keep using :meth:`Database.sync_transaction`.
"""

from __future__ import annotations

import asyncio
import time
from pathlib import Path
from typing import Any, ContextManager, Iterable, Mapping, Sequence

from pyxle_db.backends import Backend, BackendTransaction, Dialect, create_backend
from pyxle_db.errors import ConfigurationError, NotFoundError, UnsupportedOperationError
from pyxle_db.rows import Row
from pyxle_db.sql import translate
from pyxle_db.url import DatabaseConfig, parse_database_url

Params = Sequence[Any] | Mapping[str, Any]

__all__ = ["Database", "Transaction", "connect", "Row"]


def _normalise_params(params: Params | None, dialect: Dialect) -> Sequence[Any]:
    if params is None:
        return ()
    if isinstance(params, Mapping):
        # Named parameters only work where the driver supports them natively
        # and our translator doesn't renumber placeholders.
        if dialect.name != "sqlite":
            raise ConfigurationError(
                "Mapping (named) parameters are SQLite-only; use positional "
                "qmark parameters for portable SQL"
            )
        return params  # type: ignore[return-value]  # sqlite3 accepts mappings
    return params


class Transaction:
    """One open transaction. Methods take canonical qmark SQL."""

    __slots__ = ("_tx", "_dialect")

    def __init__(self, tx: BackendTransaction, dialect: Dialect) -> None:
        self._tx = tx
        self._dialect = dialect

    async def execute(self, sql: str, params: Params | None = None) -> int:
        return await self._tx.execute(
            translate(sql, self._dialect.paramstyle),
            _normalise_params(params, self._dialect),
        )

    async def executemany(self, sql: str, seq_params: Iterable[Params]) -> None:
        native = translate(sql, self._dialect.paramstyle)
        await self._tx.executemany(
            native, [_normalise_params(p, self._dialect) for p in seq_params]
        )

    async def fetchone(self, sql: str, params: Params | None = None) -> Row | None:
        return await self._tx.fetchone(
            translate(sql, self._dialect.paramstyle),
            _normalise_params(params, self._dialect),
        )

    async def fetchall(self, sql: str, params: Params | None = None) -> list[Row]:
        return await self._tx.fetchall(
            translate(sql, self._dialect.paramstyle),
            _normalise_params(params, self._dialect),
        )

    async def get(self, sql: str, params: Params | None = None) -> Row:
        """Fetch one row; raise :class:`NotFoundError` if there isn't one."""
        row = await self.fetchone(sql, params)
        if row is None:
            raise NotFoundError(f"No row for query: {sql}")
        return row


class Database:
    """Backend-agnostic database handle. Open once, share app-wide."""

    def __init__(self, path_or_url: str | Path) -> None:
        self._config: DatabaseConfig = parse_database_url(str(path_or_url))
        self._backend: Backend = create_backend(self._config)
        self._connected = False
        self._connect_lock = asyncio.Lock()
        self._query_count = 0

    # -- construction --------------------------------------------------------

    @classmethod
    def from_url(cls, url: str) -> "Database":
        """Explicit-name twin of the constructor; reads better at call sites."""
        return cls(url)

    # -- lifecycle ------------------------------------------------------------

    async def connect(self) -> None:
        """Open pools / verify connectivity. Idempotent and lazy-safe:
        every query path calls this, so explicit use is optional."""
        if self._connected:
            return
        async with self._connect_lock:
            if not self._connected:
                await self._backend.connect()
                self._connected = True

    async def aclose(self) -> None:
        """Release every connection. Works on every backend."""
        await self._backend.aclose()
        self._connected = False

    def close(self) -> None:
        """Synchronous close — SQLite only (0.1 compatibility).

        Server backends hold async pools; call ``await db.aclose()``.
        """
        sync_close = getattr(self._backend, "close_sync", None)
        if sync_close is None:
            raise UnsupportedOperationError(
                f"close() is SQLite-only; the {self.dialect.name} backend "
                "needs `await db.aclose()`"
            )
        sync_close()
        self._connected = False

    # -- queries ---------------------------------------------------------------

    async def execute(self, sql: str, params: Params | None = None) -> int:
        """Run a single write and commit. Returns the affected rowcount
        (-1 when the backend can't tell)."""
        await self.connect()
        affected = await self._backend.execute(
            translate(sql, self.dialect.paramstyle),
            _normalise_params(params, self.dialect),
        )
        self._query_count += 1
        return affected

    async def executemany(self, sql: str, seq_params: Iterable[Params]) -> None:
        """Bulk write; the whole batch is one transaction."""
        await self.connect()
        native = translate(sql, self.dialect.paramstyle)
        await self._backend.executemany(
            native, [_normalise_params(p, self.dialect) for p in seq_params]
        )
        self._query_count += 1

    async def fetchone(self, sql: str, params: Params | None = None) -> Row | None:
        await self.connect()
        self._query_count += 1
        return await self._backend.fetchone(
            translate(sql, self.dialect.paramstyle),
            _normalise_params(params, self.dialect),
        )

    async def fetchall(self, sql: str, params: Params | None = None) -> list[Row]:
        await self.connect()
        self._query_count += 1
        return await self._backend.fetchall(
            translate(sql, self.dialect.paramstyle),
            _normalise_params(params, self.dialect),
        )

    async def get(self, sql: str, params: Params | None = None) -> Row:
        """Fetch one row; raise :class:`NotFoundError` if none."""
        row = await self.fetchone(sql, params)
        if row is None:
            raise NotFoundError(f"No row for query: {sql}")
        return row

    # -- transactions ------------------------------------------------------------

    def transaction(self) -> "_TxCtx":
        """Async transaction scope::

            async with db.transaction() as tx:
                await tx.execute("INSERT ...", (value,))
        """
        return _TxCtx(self)

    def sync_transaction(self) -> ContextManager["Any"]:
        """Synchronous transaction — SQLite only, for scripts and tests.

        Inside async request handlers always use :meth:`transaction`.

        Translation contract: the backend's sync transaction object applies
        the qmark translation itself (the facade hands it straight through),
        so the ``??`` escape behaves identically on both paths.
        """
        sync_tx = getattr(self._backend, "sync_transaction", None)
        if sync_tx is None:
            raise UnsupportedOperationError(
                f"sync_transaction() is SQLite-only; the {self.dialect.name} "
                "backend needs `async with db.transaction()`"
            )
        self._query_count += 1
        return sync_tx()

    # -- maintenance / introspection ----------------------------------------------

    async def vacuum(self) -> None:
        """``VACUUM`` (SQLite). Server backends manage their own maintenance."""
        if self.dialect.name != "sqlite":
            raise UnsupportedOperationError(
                f"vacuum() is SQLite-only (got {self.dialect.name})"
            )
        await self.connect()
        await self._backend.execute("VACUUM", ())

    @property
    def dialect(self) -> Dialect:
        return self._backend.dialect

    @property
    def config(self) -> DatabaseConfig:
        return self._config

    @property
    def query_count(self) -> int:
        """Facade-level operations served since open. Exposed for metrics."""
        return self._query_count

    @property
    def path(self) -> str:
        """SQLite file path, or a password-redacted URL for server backends."""
        if self._config.backend == "sqlite":
            return self._config.path
        return self._config.redacted()


class _TxCtx:
    __slots__ = ("_db", "_inner")

    def __init__(self, db: Database) -> None:
        self._db = db
        self._inner: Any = None

    async def __aenter__(self) -> Transaction:
        await self._db.connect()
        self._inner = self._db._backend.transaction()
        backend_tx = await self._inner.__aenter__()
        return Transaction(backend_tx, self._db.dialect)

    async def __aexit__(self, exc_type, exc, tb) -> bool | None:
        self._db._query_count += 1
        return await self._inner.__aexit__(exc_type, exc, tb)


async def connect(
    path_or_url: str | Path,
    *,
    migrations_dir: str | Path | None = None,
    wait_for_file_ms: int = 0,
) -> Database:
    """Open a :class:`Database`, optionally applying migrations.

    Accepts everything :class:`Database` accepts (bare SQLite path or any
    database URL). ``wait_for_file_ms`` tolerates a transient "SQLite file
    doesn't exist yet" race when another process is creating it.
    """
    from pyxle_db.migrator import Migrator  # lazy: keep import surface lean

    db = Database(path_or_url)

    if wait_for_file_ms and db.config.backend == "sqlite" and db.config.path != ":memory:":
        deadline = time.monotonic() + wait_for_file_ms / 1000.0
        while not Path(db.config.path).exists() and time.monotonic() < deadline:
            await asyncio.sleep(0.05)

    await db.connect()
    if migrations_dir is not None:
        migrator = Migrator(db, Path(migrations_dir))
        await migrator.apply_all()
    return db
