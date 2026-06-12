"""PostgreSQL backend — an :mod:`asyncpg` connection-pool adapter.

Requires the ``postgres`` extra (``pip install 'pyxle-db[postgres]'``);
:func:`pyxle_db.backends.create_backend` turns a missing driver into a
clear :class:`~pyxle_db.errors.ConfigurationError`.

SQL arrives already translated to asyncpg's dollar-numbered parameter
style (``$1``, ``$2``, …) by the :class:`~pyxle_db.Database` facade —
this module never sees a ``?`` placeholder and never re-translates.

Configuration (``DatabaseConfig.options``, i.e. URL query parameters):

* ``pool_min`` / ``pool_max`` — connection pool size bounds. Integers in
  ``1..100``; defaults ``1`` and ``10``. ``pool_min`` may not exceed
  ``pool_max``.
* ``sslmode`` — libpq-style SSL mode, mapped to asyncpg's ``ssl``
  argument. asyncpg natively understands the libpq mode names, so apart
  from ``disable`` (asyncpg's explicit "no SSL" spelling is ``False``)
  the mapping is a validated pass-through:

  =================  ====================================================
  ``disable``        ``False`` — plaintext only
  ``allow``          ``"allow"`` — plaintext first, SSL if required
  ``prefer``         ``"prefer"`` — SSL first, plaintext fallback
  ``require``        ``"require"`` — SSL, certificate not verified
  ``verify-ca``      ``"verify-ca"`` — certificate chain verified
  ``verify-full``    ``"verify-full"`` — chain and hostname verified
  =================  ====================================================

  Omitted means ``None`` — asyncpg's default (``prefer`` for TCP).
  Unknown modes raise :class:`~pyxle_db.errors.ConfigurationError`.
* Every other option is forwarded as a PostgreSQL server setting
  (asyncpg's ``server_settings``), so ``?application_name=myapp``
  behaves the way libpq users expect.

Datetime handling: asyncpg returns ``timestamptz`` columns as aware
datetimes but plain ``timestamp`` columns as naive ones. To honour
contract rule 4 (:mod:`pyxle_db.backends.base`), naive datetimes among
*top-level column values* are assumed UTC and tagged as such, and aware
datetimes are converted to UTC. Datetimes nested inside arrays, ranges,
or JSON values are returned exactly as asyncpg decoded them.

Error translation (contract rule 1 — chained with ``raise … from exc``,
message preserved):

* ``IntegrityConstraintViolationError`` — and any server error whose
  SQLSTATE is in class 23 — → :class:`~pyxle_db.errors.IntegrityError`.
* Connection-family failures → :class:`~pyxle_db.errors.OperationalError`:
  SQLSTATE class 08 (``PostgresConnectionError``), operator intervention
  (``OperatorInterventionError`` — server shutdown,
  ``CannotConnectNowError``), asyncpg's client-side ``InterfaceError``
  (connection closed/released/in use), and ``OSError``/``TimeoutError``
  from the socket layer (connection refused, pool acquire timeout).
* Any other server error (``PostgresError``) or driver-internal error
  (``InternalClientError``) → :class:`~pyxle_db.errors.DatabaseError`.
"""

from __future__ import annotations

import asyncio
import re
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, AsyncContextManager, AsyncIterator, Iterable, NoReturn

import asyncpg
from asyncpg import exceptions as apg_exc

from pyxle_db.backends.base import (
    POSTGRESQL_DIALECT,
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

__all__ = ["PostgresBackend"]

_POOL_MIN_DEFAULT = 1
_POOL_MAX_DEFAULT = 10
_POOL_SIZE_FLOOR = 1
_POOL_SIZE_CEILING = 100

_SSLMODE_TO_SSL: dict[str, Any] = {
    "disable": False,
    "allow": "allow",
    "prefer": "prefer",
    "require": "require",
    "verify-ca": "verify-ca",
    "verify-full": "verify-full",
}

_COMMAND_TAG_ROWCOUNT = re.compile(r"\s(\d+)$")


def _parse_pool_size(raw: str | None, option: str, default: int) -> int:
    """Parse a pool-size option, enforcing the 1..100 bounds."""
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError:
        raise ConfigurationError(
            f"Pool option {option!r} must be an integer, got {raw!r}"
        ) from None
    if not _POOL_SIZE_FLOOR <= value <= _POOL_SIZE_CEILING:
        raise ConfigurationError(
            f"Pool option {option!r} must be between {_POOL_SIZE_FLOOR} and "
            f"{_POOL_SIZE_CEILING}, got {value}"
        )
    return value


def _ssl_from_sslmode(sslmode: str | None) -> Any:
    """Map a libpq ``sslmode`` to asyncpg's ``ssl`` argument (see module doc)."""
    if sslmode is None:
        return None
    try:
        return _SSLMODE_TO_SSL[sslmode]
    except KeyError:
        valid = ", ".join(sorted(_SSLMODE_TO_SSL))
        raise ConfigurationError(
            f"Unknown sslmode {sslmode!r}; valid modes: {valid}"
        ) from None


def _rowcount_from_tag(tag: str) -> int:
    """Extract the affected-row count from a command tag.

    PostgreSQL command tags end in the row count for DML (``UPDATE 3``,
    ``DELETE 0``, ``INSERT 0 5`` — for INSERT the count is the last of two
    numbers). Tags without a trailing count (``CREATE TABLE``) give ``-1``.
    """
    match = _COMMAND_TAG_ROWCOUNT.search(tag)
    return int(match.group(1)) if match else -1


def _normalise_datetime(value: Any) -> Any:
    """Return ``value`` as an aware-UTC datetime when it is a datetime.

    Naive datetimes (asyncpg's decoding of ``timestamp without time
    zone``) are assumed UTC and tagged; aware datetimes are converted to
    UTC. Applied to top-level column values only — containers are not
    recursed into.
    """
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)
    return value


def _record_to_row(record: asyncpg.Record) -> Row:
    """Convert an :class:`asyncpg.Record` to a portable :class:`Row`."""
    return Row(
        tuple(record.keys()),
        tuple(_normalise_datetime(value) for value in record.values()),
    )


def _translate_exception(exc: BaseException) -> DatabaseError | None:
    """Map a driver exception to its :mod:`pyxle_db.errors` equivalent.

    Returns ``None`` when the exception is not a driver error — already a
    :class:`DatabaseError`, or an application exception raised inside a
    transaction body — so the caller re-raises it untouched.
    """
    if isinstance(exc, DatabaseError):
        return None
    message = str(exc) or type(exc).__name__
    if isinstance(exc, apg_exc.PostgresError):
        sqlstate = getattr(exc, "sqlstate", None) or ""
        if isinstance(
            exc, apg_exc.IntegrityConstraintViolationError
        ) or sqlstate.startswith("23"):
            return IntegrityError(message)
        if isinstance(
            exc,
            (apg_exc.PostgresConnectionError, apg_exc.OperatorInterventionError),
        ):
            return OperationalError(message)
        return DatabaseError(message)
    if isinstance(exc, apg_exc.ClientConfigurationError):
        # Subclasses InterfaceError, but a client-side misconfiguration is
        # never retryable — keep it out of the OperationalError family.
        return ConfigurationError(message)
    if isinstance(exc, apg_exc.InterfaceError):
        return OperationalError(message)
    if isinstance(exc, (OSError, TimeoutError, asyncio.TimeoutError)):
        return OperationalError(message)
    if isinstance(exc, apg_exc.InternalClientError):
        return DatabaseError(message)
    return None


def _raise_translated(exc: Exception) -> NoReturn:
    """Raise the pyxle-db equivalent of ``exc``, chained; re-raise otherwise."""
    translated = _translate_exception(exc)
    if translated is None:
        raise exc
    raise translated from exc


class _PostgresTransaction(BackendTransaction):
    """Statements on the one pooled connection a transaction has acquired.

    The connection is exclusive to this transaction for its whole scope
    (contract rule 6) — :meth:`PostgresBackend.transaction` acquires it
    from the pool and releases it only after commit or rollback.
    """

    __slots__ = ("_conn",)

    def __init__(self, conn: asyncpg.Connection) -> None:
        self._conn = conn

    async def execute(self, sql: str, params: Params = ()) -> int:
        try:
            tag = await self._conn.execute(sql, *utc_naive_params(params))
        except Exception as exc:
            _raise_translated(exc)
        return _rowcount_from_tag(tag)

    async def executemany(self, sql: str, seq_params: Iterable[Params]) -> None:
        batch = [utc_naive_params(params) for params in seq_params]
        try:
            await self._conn.executemany(sql, batch)
        except Exception as exc:
            _raise_translated(exc)

    async def fetchone(self, sql: str, params: Params = ()) -> Row | None:
        try:
            record = await self._conn.fetchrow(sql, *utc_naive_params(params))
        except Exception as exc:
            _raise_translated(exc)
        return None if record is None else _record_to_row(record)

    async def fetchall(self, sql: str, params: Params = ()) -> list[Row]:
        try:
            records = await self._conn.fetch(sql, *utc_naive_params(params))
        except Exception as exc:
            _raise_translated(exc)
        return [_record_to_row(record) for record in records]


class PostgresBackend(Backend):
    """asyncpg-backed :class:`Backend` for one PostgreSQL database.

    The pool is created lazily on the first :meth:`connect` (which every
    query path goes through), sized by the ``pool_min``/``pool_max``
    options. ``connect()`` and ``aclose()`` are idempotent; after
    ``aclose()`` the backend is reusable via another ``connect()``.
    """

    dialect = POSTGRESQL_DIALECT

    def __init__(self, config: DatabaseConfig) -> None:
        options = dict(config.options)
        self._pool_min = _parse_pool_size(
            options.pop("pool_min", None), "pool_min", _POOL_MIN_DEFAULT
        )
        self._pool_max = _parse_pool_size(
            options.pop("pool_max", None), "pool_max", _POOL_MAX_DEFAULT
        )
        if self._pool_min > self._pool_max:
            raise ConfigurationError(
                f"pool_min ({self._pool_min}) may not exceed "
                f"pool_max ({self._pool_max})"
            )
        self._ssl = _ssl_from_sslmode(options.pop("sslmode", None))
        self._server_settings = options or None
        self._config = config
        self._pool: asyncpg.Pool | None = None
        self._connect_lock = asyncio.Lock()

    # -- lifecycle -------------------------------------------------------------

    async def connect(self) -> None:
        if self._pool is not None:
            return
        async with self._connect_lock:
            if self._pool is not None:
                return
            try:
                self._pool = await asyncpg.create_pool(
                    host=self._config.host,
                    port=self._config.port,
                    user=self._config.user or None,
                    password=self._config.password or None,
                    database=self._config.database,
                    min_size=self._pool_min,
                    max_size=self._pool_max,
                    ssl=self._ssl,
                    server_settings=self._server_settings,
                )
            except Exception as exc:
                _raise_translated(exc)

    async def aclose(self) -> None:
        async with self._connect_lock:
            pool, self._pool = self._pool, None
            if pool is None:
                return
            try:
                await pool.close()
            except Exception as exc:
                _raise_translated(exc)

    async def _ensure_pool(self) -> asyncpg.Pool:
        await self.connect()
        pool = self._pool
        if pool is None:
            raise OperationalError(
                "The PostgreSQL pool was closed while the operation was starting"
            )
        return pool

    # -- one-shot statements -----------------------------------------------------

    async def execute(self, sql: str, params: Params = ()) -> int:
        pool = await self._ensure_pool()
        try:
            async with pool.acquire() as conn:
                tag = await conn.execute(sql, *utc_naive_params(params))
        except Exception as exc:
            _raise_translated(exc)
        return _rowcount_from_tag(tag)

    async def executemany(self, sql: str, seq_params: Iterable[Params]) -> None:
        batch = [utc_naive_params(params) for params in seq_params]
        pool = await self._ensure_pool()
        try:
            async with pool.acquire() as conn:
                # asyncpg's executemany is already atomic; the explicit
                # transaction states the Backend contract rather than
                # relying on a driver detail.
                async with conn.transaction():
                    await conn.executemany(sql, batch)
        except Exception as exc:
            _raise_translated(exc)

    async def fetchone(self, sql: str, params: Params = ()) -> Row | None:
        pool = await self._ensure_pool()
        try:
            async with pool.acquire() as conn:
                record = await conn.fetchrow(sql, *utc_naive_params(params))
        except Exception as exc:
            _raise_translated(exc)
        return None if record is None else _record_to_row(record)

    async def fetchall(self, sql: str, params: Params = ()) -> list[Row]:
        pool = await self._ensure_pool()
        try:
            async with pool.acquire() as conn:
                records = await conn.fetch(sql, *utc_naive_params(params))
        except Exception as exc:
            _raise_translated(exc)
        return [_record_to_row(record) for record in records]

    # -- transactions --------------------------------------------------------------

    def transaction(self) -> AsyncContextManager[BackendTransaction]:
        return self._transaction_scope()

    @asynccontextmanager
    async def _transaction_scope(self) -> AsyncIterator[BackendTransaction]:
        pool = await self._ensure_pool()
        try:
            conn = await pool.acquire()
        except Exception as exc:
            _raise_translated(exc)
        try:
            tx = conn.transaction()
            try:
                await tx.start()
            except Exception as exc:
                _raise_translated(exc)
            try:
                yield _PostgresTransaction(conn)
            except BaseException:
                try:
                    await tx.rollback()
                except Exception:
                    # The body's exception is the meaningful one. A failed
                    # rollback means the connection died — the open
                    # transaction is gone with it, and release() below
                    # discards the broken connection.
                    pass
                raise
            try:
                await tx.commit()
            except Exception as exc:
                _raise_translated(exc)
        finally:
            await pool.release(conn)
