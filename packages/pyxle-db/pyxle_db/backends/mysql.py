"""MySQL/MariaDB backend on an :mod:`asyncmy` connection pool.

Install with ``pip install 'pyxle-db[mysql]'``. The pool is created lazily on
first :meth:`MysqlBackend.connect` with ``charset=utf8mb4`` (always) and
``autocommit=False`` — every one-shot helper therefore commits explicitly,
including the fetch helpers: with autocommit off even a ``SELECT`` opens an
InnoDB read view, and the connection must not return to the pool holding one.

Pool sizing is configurable through URL options::

    mysql://app:secret@db.internal:3306/appdb?pool_min=2&pool_max=20

SQL arrives already translated to ``%s`` style by the facade
(:func:`pyxle_db.sql.translate`), which also doubles literal percent signs
outside string literals. asyncmy only collapses those ``%%`` back to ``%``
when ``args`` is not ``None``, so every cursor call here passes a parameter
tuple — an empty one when the statement takes no parameters.

Contract compliance (see :mod:`pyxle_db.backends.base`):

* asyncmy exceptions are translated via :func:`_translate` and never leak.
* Fetches return :class:`pyxle_db.rows.Row` with datetimes normalised to
  timezone-aware UTC (asyncmy returns naive values; they are assumed UTC).
* ``connect()`` / ``aclose()`` are idempotent; the backend is reusable after
  ``aclose()`` followed by another ``connect()``.
* Each transaction holds its own pooled connection for its whole scope, so
  concurrent transactions can never interleave statements.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, AsyncIterator, Awaitable, Callable, Iterable, Mapping, Sequence, TypeVar

import asyncmy
import asyncmy.errors

from pyxle_db.backends.base import (
    MYSQL_DIALECT,
    Backend,
    BackendTransaction,
    Params,
    utc_naive_params,
)
from pyxle_db.errors import (
    ConfigurationError,
    DatabaseError,
    IntegrityError,
    OperationalError,
)
from pyxle_db.rows import Row
from pyxle_db.url import DatabaseConfig

__all__ = ["MysqlBackend"]

T = TypeVar("T")

_DEFAULT_POOL_MIN = 1
_DEFAULT_POOL_MAX = 10


def _translate(exc: Exception) -> DatabaseError:
    """Map an asyncmy exception onto the :mod:`pyxle_db.errors` hierarchy.

    * ``asyncmy.errors.IntegrityError`` → :class:`IntegrityError`
      (duplicate key, FK violation, NOT NULL, …).
    * ``asyncmy.errors.OperationalError`` / ``InterfaceError`` →
      :class:`OperationalError` — the retryable family, covering the
      connection errnos (2002/2003 can't connect, 2006 server has gone away,
      2013 lost connection) and 1205 lock-wait timeout.
    * Any other ``asyncmy.errors.MySQLError`` → :class:`DatabaseError`.

    Callers chain the original with ``raise _translate(exc) from exc``.
    """
    if isinstance(exc, asyncmy.errors.IntegrityError):
        return IntegrityError(str(exc))
    if isinstance(exc, (asyncmy.errors.OperationalError, asyncmy.errors.InterfaceError)):
        return OperationalError(str(exc))
    return DatabaseError(str(exc))


def _as_utc(value: Any) -> Any:
    """Tag naive datetimes as UTC; convert aware ones to UTC (contract rule 4)."""
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)
    return value


def _build_row(description: Sequence[Sequence[Any]], values: Sequence[Any]) -> Row:
    """Build a :class:`Row` from a DB-API cursor description and one tuple."""
    return Row([column[0] for column in description], [_as_utc(v) for v in values])


def _pool_bounds(options: Mapping[str, str]) -> tuple[int, int]:
    """Read ``pool_min`` / ``pool_max`` URL options into asyncmy pool sizes."""
    minsize = _int_option(options, "pool_min", _DEFAULT_POOL_MIN)
    maxsize = _int_option(options, "pool_max", _DEFAULT_POOL_MAX)
    if minsize < 0:
        raise ConfigurationError(f"pool_min must be >= 0, got {minsize}")
    if maxsize < 1:
        raise ConfigurationError(f"pool_max must be >= 1, got {maxsize}")
    if maxsize < minsize:
        raise ConfigurationError(
            f"pool_max ({maxsize}) must be >= pool_min ({minsize})"
        )
    return minsize, maxsize


def _int_option(options: Mapping[str, str], key: str, default: int) -> int:
    raw = options.get(key)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        raise ConfigurationError(
            f"Database URL option {key!r} must be an integer, got {raw!r}"
        ) from None


async def _rollback_quietly(conn: asyncmy.Connection) -> None:
    """Best-effort rollback while another exception is already in flight.

    If the rollback itself fails (typically because the connection died) the
    original error is the one worth reporting, so driver errors are dropped.
    """
    try:
        await conn.rollback()
    except asyncmy.errors.MySQLError:
        pass


class _MysqlTransaction(BackendTransaction):
    """Statements on one pooled connection; commit/rollback is the scope's job."""

    __slots__ = ("_conn",)

    def __init__(self, conn: asyncmy.Connection) -> None:
        self._conn = conn

    async def execute(self, sql: str, params: Params = ()) -> int:
        try:
            async with self._conn.cursor() as cursor:
                await cursor.execute(sql, utc_naive_params(params))
                return int(cursor.rowcount)
        except asyncmy.errors.MySQLError as exc:
            raise _translate(exc) from exc

    async def executemany(self, sql: str, seq_params: Iterable[Params]) -> None:
        rows = [utc_naive_params(p) for p in seq_params]
        if not rows:
            return
        try:
            async with self._conn.cursor() as cursor:
                await cursor.executemany(sql, rows)
        except asyncmy.errors.MySQLError as exc:
            raise _translate(exc) from exc

    async def fetchone(self, sql: str, params: Params = ()) -> Row | None:
        try:
            async with self._conn.cursor() as cursor:
                await cursor.execute(sql, utc_naive_params(params))
                values = await cursor.fetchone()
                if values is None:
                    return None
                return _build_row(cursor.description, values)
        except asyncmy.errors.MySQLError as exc:
            raise _translate(exc) from exc

    async def fetchall(self, sql: str, params: Params = ()) -> list[Row]:
        try:
            async with self._conn.cursor() as cursor:
                await cursor.execute(sql, utc_naive_params(params))
                values = await cursor.fetchall()
                return [_build_row(cursor.description, row) for row in values]
        except asyncmy.errors.MySQLError as exc:
            raise _translate(exc) from exc


class MysqlBackend(Backend):
    """MySQL adapter. SQL must already be in ``%s`` (format) parameter style."""

    dialect = MYSQL_DIALECT

    def __init__(self, config: DatabaseConfig) -> None:
        self._config = config
        self._pool_min, self._pool_max = _pool_bounds(config.options)
        self._pool: asyncmy.Pool | None = None
        self._connect_lock = asyncio.Lock()

    # -- lifecycle ------------------------------------------------------------

    async def connect(self) -> None:
        await self._ensure_pool()

    async def aclose(self) -> None:
        pool, self._pool = self._pool, None
        if pool is None:
            return
        pool.close()
        await pool.wait_closed()

    async def _ensure_pool(self) -> asyncmy.Pool:
        pool = self._pool
        if pool is not None:
            return pool
        async with self._connect_lock:
            if self._pool is None:
                try:
                    self._pool = await asyncmy.create_pool(
                        host=self._config.host,
                        port=self._config.port,
                        user=self._config.user,
                        password=self._config.password,
                        database=self._config.database,
                        charset="utf8mb4",
                        autocommit=False,
                        minsize=self._pool_min,
                        maxsize=self._pool_max,
                        # Pin the session to UTC. MySQL converts TIMESTAMP
                        # columns to the session time_zone on read (default:
                        # the server's SYSTEM zone), which would shift values
                        # that the row layer then mis-tags as UTC. With the
                        # session pinned, TIMESTAMP and NOW() speak UTC and
                        # the naive-equals-UTC contract holds everywhere.
                        init_command="SET time_zone = '+00:00'",
                    )
                except asyncmy.errors.MySQLError as exc:
                    raise _translate(exc) from exc
            return self._pool

    # -- one-shot helpers -------------------------------------------------------

    async def _autocommit(self, op: Callable[[_MysqlTransaction], Awaitable[T]]) -> T:
        """Run ``op`` on a pooled connection, commit, and always release.

        Rolls back on any failure so the connection re-enters the pool clean.
        ``op`` raises already-translated errors; the outer handler translates
        what the commit itself may raise.
        """
        pool = await self._ensure_pool()
        conn = await pool.acquire()
        try:
            try:
                result = await op(_MysqlTransaction(conn))
                await conn.commit()
                return result
            except BaseException:
                await _rollback_quietly(conn)
                raise
        except asyncmy.errors.MySQLError as exc:
            raise _translate(exc) from exc
        finally:
            pool.release(conn)

    async def execute(self, sql: str, params: Params = ()) -> int:
        return await self._autocommit(lambda tx: tx.execute(sql, params))

    async def executemany(self, sql: str, seq_params: Iterable[Params]) -> None:
        rows = [utc_naive_params(p) for p in seq_params]
        if not rows:
            return
        await self._autocommit(lambda tx: tx.executemany(sql, rows))

    async def fetchone(self, sql: str, params: Params = ()) -> Row | None:
        return await self._autocommit(lambda tx: tx.fetchone(sql, params))

    async def fetchall(self, sql: str, params: Params = ()) -> list[Row]:
        return await self._autocommit(lambda tx: tx.fetchall(sql, params))

    # -- transactions ------------------------------------------------------------

    @asynccontextmanager
    async def transaction(self) -> AsyncIterator[BackendTransaction]:
        """One ``BEGIN``-scoped connection: commit on exit, roll back on error.

        The connection is acquired for the whole scope and released in all
        cases, so concurrent transactions never share a connection
        (contract rule 6).
        """
        pool = await self._ensure_pool()
        conn = await pool.acquire()
        try:
            try:
                await conn.begin()
                yield _MysqlTransaction(conn)
            except BaseException:
                await _rollback_quietly(conn)
                raise
            else:
                await conn.commit()
        except asyncmy.errors.MySQLError as exc:
            raise _translate(exc) from exc
        finally:
            pool.release(conn)
