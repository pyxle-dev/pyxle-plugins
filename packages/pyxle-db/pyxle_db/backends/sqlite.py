"""SQLite backend — stdlib :mod:`sqlite3` bridged onto asyncio.

Design (carried over from pyxle-db 0.1, where it shipped as the whole
``Database`` class):

* Uses the stdlib ``sqlite3`` driver because it's fast, zero-dep, and
  bundled with every supported Python. ``aiosqlite`` was considered and
  rejected: it layers a thread per connection on top of stdlib and adds
  latency without buying us anything ``asyncio.to_thread`` can't.
* Connection-per-thread for one-shot statements. SQLite connections are
  not safe to share across threads by default; we open a fresh connection
  on first use in a given thread and cache it in ``threading.local``.
  Every connection is also recorded in a backend-level list so
  :meth:`SqliteBackend.close_sync` can release connections opened by
  threads that have since exited.
* Each :meth:`SqliteBackend.transaction` opens a *dedicated* connection.
  Transaction statements are coroutines in 0.2, so consecutive statements
  may run on different worker threads — a thread-local connection would
  leak statements from concurrent callers into the open transaction
  (contract rule 6 in :mod:`pyxle_db.backends.base`). A dedicated
  connection, opened at ``BEGIN IMMEDIATE`` and closed at COMMIT/ROLLBACK,
  makes the transaction exclusive by construction.
* ``:memory:`` is special: every connection gets its own private empty
  database, so thread-local connections would each see different data.
  The backend therefore keeps a SINGLE shared in-memory connection guarded
  by a :class:`threading.RLock`. The lock is reentrant (not a plain
  ``Lock``) so a thread that already owns it — e.g. a misuse like nesting
  ``sync_transaction()`` scopes — re-acquires cleanly and fails with
  SQLite's own "cannot start a transaction within a transaction" error
  instead of deadlocking. Because an ``RLock`` can only be released by its
  owning thread, async transactions on ``:memory:`` pin all their work to
  one private worker thread that holds the lock from BEGIN to
  COMMIT/ROLLBACK; lock acquisition times out after
  ``_MEMORY_LOCK_TIMEOUT`` seconds, mirroring the ``busy_timeout`` PRAGMA.
* PRAGMAs applied at connection time (in order): ``journal_mode=WAL``,
  ``synchronous=NORMAL``, ``foreign_keys=ON``, ``busy_timeout=5000``,
  ``temp_store=MEMORY``, ``cache_size=-65536`` (64 MB per connection).
  These are the "fast and safe for a web app" defaults; WAL keeps readers
  and writers from blocking each other.
* Python 3.12 deprecated the stdlib's default datetime adapters for
  sqlite3 — they produced timezone-naive strings which silently broke apps
  that store UTC timestamps. This module registers explicit adapters that
  serialise to a format compatible with SQLite's ``CURRENT_TIMESTAMP``
  (space separator, no timezone suffix, UTC-normalised). Lexicographic
  comparison of mixed formats silently produces wrong results —
  ``"2026-01-01 12:00:00"`` sorts before ``"2026-01-01T12:00:00+00:00"``
  because space (0x20) < ``T`` (0x54) — so every stored datetime is
  normalised on the way in and tagged with ``timezone.utc`` on the way
  out. Registration is process-global, exactly as it was in 0.1.

Per the backend contract the async methods receive SQL the facade has
already translated. The one exception is :class:`SqliteSyncTransaction`,
which the facade hands straight to callers and which therefore runs the
qmark translation itself.
"""

from __future__ import annotations

import asyncio
import sqlite3
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import date, datetime, timezone
from functools import partial
from typing import Any, Awaitable, Callable, Iterable, Iterator, Mapping, Sequence, TypeVar

from pyxle_db.backends.base import SQLITE_DIALECT, Backend, BackendTransaction
from pyxle_db.errors import DatabaseError, IntegrityError, NotFoundError, OperationalError
from pyxle_db.rows import Row
from pyxle_db.sql import translate
from pyxle_db.url import DatabaseConfig

SqliteParams = Sequence[Any] | Mapping[str, Any]
"""sqlite3 natively binds both positional sequences and named mappings."""

_T = TypeVar("_T")

_MEMORY_LOCK_TIMEOUT: float = 5.0
"""Seconds to wait for the shared ``:memory:`` lock — mirrors busy_timeout."""


# ---------------------------------------------------------------------------
# datetime adapters / converters (process-global, see module docstring)

_SQLITE_DATETIME_FORMAT = "%Y-%m-%d %H:%M:%S.%f"


def _adapt_datetime(value: datetime) -> str:
    # Normalise to UTC before serialising so comparisons stay stable.
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    else:
        value = value.astimezone(timezone.utc)
    return value.strftime(_SQLITE_DATETIME_FORMAT)


def _adapt_date(value: date) -> str:
    return value.isoformat()


def _convert_timestamp(raw: bytes) -> datetime:
    """Parse a TIMESTAMP column. Tolerant of:

    * ``YYYY-MM-DD HH:MM:SS.ffffff`` (our adapter's output)
    * ``YYYY-MM-DD HH:MM:SS`` (SQLite's CURRENT_TIMESTAMP)
    * ``YYYY-MM-DDTHH:MM:SS[.ffffff][+HH:MM]`` (ISO with/without tz)

    Never returns a naive datetime — UTC is assumed for naive values
    (contract rule 4).
    """
    text = raw.decode("utf-8")
    parsed: datetime
    try:
        parsed = datetime.strptime(text, _SQLITE_DATETIME_FORMAT)
    except ValueError:
        try:
            parsed = datetime.strptime(text, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            # ISO-style fallback (e.g. data migrated in from another source).
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _convert_date(raw: bytes) -> date:
    return date.fromisoformat(raw.decode("utf-8"))


sqlite3.register_adapter(datetime, _adapt_datetime)
sqlite3.register_adapter(date, _adapt_date)
sqlite3.register_converter("TIMESTAMP", _convert_timestamp)
sqlite3.register_converter("DATE", _convert_date)


# ---------------------------------------------------------------------------
# PRAGMAs applied to every connection on open.
#
# The tuple-of-pairs shape (not a dict) is intentional — order matters:
# ``journal_mode`` must be set before ``synchronous`` takes its final
# effect, and ``foreign_keys`` must be set on every connection because
# SQLite otherwise resets it to OFF.

_PRAGMAS: tuple[tuple[str, str], ...] = (
    ("journal_mode", "WAL"),
    ("synchronous", "NORMAL"),
    ("foreign_keys", "ON"),
    ("busy_timeout", "5000"),
    ("temp_store", "MEMORY"),
    ("cache_size", "-65536"),
)

_PRAGMA_RETRY_TIMEOUT: float = 5.0
"""Seconds to keep retrying a locked PRAGMA at open — mirrors busy_timeout."""

_PRAGMA_RETRY_INTERVAL: float = 0.01


def _apply_pragmas(conn: sqlite3.Connection) -> None:
    """Apply ``_PRAGMAS`` in order, absorbing the journal-mode open race.

    ``PRAGMA journal_mode = WAL`` takes a brief exclusive lock, and it is
    the one statement where SQLite reports SQLITE_BUSY *without consulting
    the busy handler* — so when several processes open a fresh database at
    the same time (every worker of a multi-worker server does at startup),
    losers would fail instantly with ``database is locked`` despite the
    5-second connect ``timeout``. Retrying is safe: every pragma here is
    idempotent. The deadline mirrors the busy handler's own patience.
    """
    deadline = time.monotonic() + _PRAGMA_RETRY_TIMEOUT
    index = 0
    while index < len(_PRAGMAS):
        name, value = _PRAGMAS[index]
        try:
            conn.execute(f"PRAGMA {name} = {value}")
        except sqlite3.OperationalError as exc:
            if (
                "database is locked" not in str(exc)
                or time.monotonic() >= deadline
            ):
                raise
            time.sleep(_PRAGMA_RETRY_INTERVAL)
            continue
        index += 1


# ---------------------------------------------------------------------------
# Error translation (contract rules 1 and 2)

_RETRYABLE_FRAGMENTS = ("database is locked", "unable to open")


def _translate_error(exc: sqlite3.Error) -> DatabaseError:
    """Map a driver exception onto the :mod:`pyxle_db.errors` hierarchy."""
    if isinstance(exc, sqlite3.IntegrityError):
        return IntegrityError(str(exc))
    if isinstance(exc, sqlite3.OperationalError):
        message = str(exc)
        if any(fragment in message for fragment in _RETRYABLE_FRAGMENTS):
            return OperationalError(message)
    return DatabaseError(str(exc))


@contextmanager
def _translated_errors() -> Iterator[None]:
    """Re-raise any ``sqlite3.Error`` as its pyxle-db equivalent."""
    try:
        yield
    except sqlite3.Error as exc:
        raise _translate_error(exc) from exc


def _rollback_quietly(conn: sqlite3.Connection) -> None:
    """Best-effort ROLLBACK so the original error keeps propagating."""
    try:
        conn.execute("ROLLBACK")
    except sqlite3.Error:
        pass


# ---------------------------------------------------------------------------
# Statement helpers — synchronous, operate on an explicit connection.
# Shared by the one-shot paths, the async transaction, and the sync
# transaction so every entry point translates errors and builds Rows
# identically.


def _column_names(cursor: sqlite3.Cursor) -> tuple[str, ...]:
    description = cursor.description
    if description is None:
        return ()
    return tuple(column[0] for column in description)


def _execute_on(conn: sqlite3.Connection, sql: str, params: SqliteParams) -> int:
    with _translated_errors():
        cursor = conn.execute(sql, params)
        affected = cursor.rowcount
        cursor.close()
        return affected


def _executemany_on(
    conn: sqlite3.Connection, sql: str, seq_params: list[SqliteParams]
) -> None:
    with _translated_errors():
        cursor = conn.executemany(sql, seq_params)
        cursor.close()


def _fetchone_on(
    conn: sqlite3.Connection, sql: str, params: SqliteParams
) -> Row | None:
    with _translated_errors():
        cursor = conn.execute(sql, params)
        try:
            raw = cursor.fetchone()
            if raw is None:
                return None
            return Row(_column_names(cursor), raw)
        finally:
            cursor.close()


def _fetchall_on(
    conn: sqlite3.Connection, sql: str, params: SqliteParams
) -> list[Row]:
    with _translated_errors():
        cursor = conn.execute(sql, params)
        try:
            names = _column_names(cursor)
            return [Row(names, raw) for raw in cursor.fetchall()]
        finally:
            cursor.close()


# ---------------------------------------------------------------------------
# Transactions


class SqliteSyncTransaction:
    """Synchronous transaction scope — for scripts and migrations.

    Yielded by ``Database.sync_transaction()`` on SQLite. Unlike the async
    transaction methods — which receive SQL the facade has already
    translated — this object is handed straight to callers, so it runs the
    qmark translation itself: the portable ``??`` escape behaves
    identically in both paths.
    """

    __slots__ = ("_conn",)

    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    def execute(self, sql: str, params: SqliteParams | None = None) -> int:
        return _execute_on(self._conn, translate(sql, "qmark"), params or ())

    def executemany(
        self, sql: str, seq_params: Iterable[SqliteParams]
    ) -> None:
        _executemany_on(self._conn, translate(sql, "qmark"), list(seq_params))

    def fetchone(self, sql: str, params: SqliteParams | None = None) -> Row | None:
        return _fetchone_on(self._conn, translate(sql, "qmark"), params or ())

    def fetchall(self, sql: str, params: SqliteParams | None = None) -> list[Row]:
        return _fetchall_on(self._conn, translate(sql, "qmark"), params or ())

    def get(self, sql: str, params: SqliteParams | None = None) -> Row:
        """Fetch one row; raise :class:`NotFoundError` if there isn't one."""
        row = self.fetchone(sql, params)
        if row is None:
            raise NotFoundError(f"No row for query: {sql}")
        return row


class _SqliteTransaction(BackendTransaction):
    """Statements inside one open async transaction.

    Every call is dispatched through ``run`` — ``asyncio.to_thread`` for
    file databases (any worker thread may touch the dedicated connection),
    or the transaction's pinned single-thread executor for ``:memory:``
    (only the lock-owning thread may touch the shared connection).
    """

    __slots__ = ("_conn", "_run")

    def __init__(
        self,
        conn: sqlite3.Connection,
        run: Callable[..., Awaitable[Any]],
    ) -> None:
        self._conn = conn
        self._run = run

    async def execute(self, sql: str, params: SqliteParams = ()) -> int:
        return await self._run(_execute_on, self._conn, sql, params)

    async def executemany(
        self, sql: str, seq_params: Iterable[SqliteParams]
    ) -> None:
        await self._run(_executemany_on, self._conn, sql, list(seq_params))

    async def fetchone(self, sql: str, params: SqliteParams = ()) -> Row | None:
        return await self._run(_fetchone_on, self._conn, sql, params)

    async def fetchall(self, sql: str, params: SqliteParams = ()) -> list[Row]:
        return await self._run(_fetchall_on, self._conn, sql, params)


class _SqliteTransactionContext:
    """``async with backend.transaction()`` scope.

    Commits on success, rolls back on exception. See the module docstring
    for why file databases get a dedicated connection while ``:memory:``
    pins its work to one lock-owning worker thread.
    """

    __slots__ = ("_backend", "_conn", "_executor")

    def __init__(self, backend: "SqliteBackend") -> None:
        self._backend = backend
        self._conn: sqlite3.Connection | None = None
        self._executor: ThreadPoolExecutor | None = None

    async def _run(self, fn: Callable[..., _T], /, *args: Any) -> _T:
        if self._executor is None:
            return await asyncio.to_thread(fn, *args)
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(self._executor, partial(fn, *args))

    async def __aenter__(self) -> _SqliteTransaction:
        backend = self._backend
        if backend._is_memory:
            self._executor = ThreadPoolExecutor(
                max_workers=1, thread_name_prefix="pyxle-db-memory-tx"
            )
            try:
                self._conn = await self._run(backend._begin_memory_transaction)
            except BaseException:
                self._executor.shutdown(wait=False)
                self._executor = None
                raise
        else:
            self._conn = await self._run(backend._begin_file_transaction)
        return _SqliteTransaction(self._conn, self._run)

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: object,
    ) -> bool:
        try:
            await self._run(self._finish, exc is None)
        finally:
            if self._executor is not None:
                self._executor.shutdown(wait=True)
                self._executor = None
        return False

    def _finish(self, commit: bool) -> None:
        """COMMIT/ROLLBACK, then release the connection — on its thread."""
        conn = self._conn
        if conn is None:
            return
        self._conn = None
        backend = self._backend
        try:
            with _translated_errors():
                if commit:
                    try:
                        conn.execute("COMMIT")
                    except sqlite3.Error:
                        _rollback_quietly(conn)
                        raise
                else:
                    conn.execute("ROLLBACK")
        finally:
            if backend._is_memory:
                backend._memory_lock.release()
            else:
                backend._discard_connection(conn)


# ---------------------------------------------------------------------------
# Backend


class SqliteBackend(Backend):
    """SQLite driver adapter. See the module docstring for the design."""

    dialect = SQLITE_DIALECT

    def __init__(self, config: DatabaseConfig) -> None:
        self._path = config.path
        self._is_memory = config.path == ":memory:"
        self._local = threading.local()
        self._tracking_lock = threading.Lock()
        # Every connection ever opened, so close_sync() can release
        # connections created by threads that have since exited.
        self._connections: list[sqlite3.Connection] = []
        # Bumped on close so threads with a stale cached connection
        # transparently reopen instead of using a closed handle.
        self._generation = 0
        self._memory_conn: sqlite3.Connection | None = None
        self._memory_lock = threading.RLock()

    # -- lifecycle -------------------------------------------------------------

    async def connect(self) -> None:
        await asyncio.to_thread(self._connect_sync)

    def _connect_sync(self) -> None:
        with self._lease():
            # Opening (and caching) a connection is the connectivity
            # check: a bad path raises OperationalError here, not on the
            # first query.
            pass

    async def aclose(self) -> None:
        await asyncio.to_thread(self.close_sync)

    def close_sync(self) -> None:
        """Close every tracked connection. Idempotent.

        Powers the facade's synchronous ``Database.close()``. The backend
        reopens lazily afterwards, so 0.1's close-then-reuse pattern keeps
        working.
        """
        with self._tracking_lock:
            connections = self._connections
            self._connections = []
            self._generation += 1
        self._memory_conn = None
        for conn in connections:
            try:
                conn.close()
            except sqlite3.Error:
                # Best-effort; nothing useful we can do on close failure.
                pass

    # -- connection management ---------------------------------------------------

    def _open_connection(self) -> sqlite3.Connection:
        with _translated_errors():
            conn = sqlite3.connect(
                self._path,
                isolation_level=None,  # autocommit; transactions are explicit
                detect_types=sqlite3.PARSE_DECLTYPES,
                check_same_thread=False,
                timeout=5.0,
            )
            _apply_pragmas(conn)
        with self._tracking_lock:
            self._connections.append(conn)
        return conn

    def _discard_connection(self, conn: sqlite3.Connection) -> None:
        with self._tracking_lock:
            if conn in self._connections:
                self._connections.remove(conn)
        try:
            conn.close()
        except sqlite3.Error:
            pass

    def _thread_connection(self) -> sqlite3.Connection:
        cached: tuple[sqlite3.Connection, int] | None = getattr(
            self._local, "entry", None
        )
        if cached is not None and cached[1] == self._generation:
            return cached[0]
        conn = self._open_connection()
        self._local.entry = (conn, self._generation)
        return conn

    def _memory_connection(self) -> sqlite3.Connection:
        """The shared ``:memory:`` connection. Call holding the lock."""
        if self._memory_conn is None:
            self._memory_conn = self._open_connection()
        return self._memory_conn

    def _acquire_memory_lock(self) -> None:
        if not self._memory_lock.acquire(timeout=_MEMORY_LOCK_TIMEOUT):
            raise OperationalError(
                "database is locked: timed out waiting for the shared "
                ":memory: connection (is a transaction still open?)"
            )

    @contextmanager
    def _lease(self) -> Iterator[sqlite3.Connection]:
        """Yield a connection for one self-contained batch of statements."""
        if self._is_memory:
            self._acquire_memory_lock()
            try:
                yield self._memory_connection()
            finally:
                self._memory_lock.release()
        else:
            yield self._thread_connection()

    # -- one-shot statements -------------------------------------------------------

    async def execute(self, sql: str, params: SqliteParams = ()) -> int:
        return await asyncio.to_thread(self._execute_sync, sql, params)

    def _execute_sync(self, sql: str, params: SqliteParams) -> int:
        # isolation_level=None puts the connection in autocommit, so a
        # single statement is atomic by itself — and statements that must
        # run outside a transaction (VACUUM) work too.
        with self._lease() as conn:
            return _execute_on(conn, sql, params)

    async def executemany(
        self, sql: str, seq_params: Iterable[SqliteParams]
    ) -> None:
        await asyncio.to_thread(self._executemany_sync, sql, list(seq_params))

    def _executemany_sync(self, sql: str, seq_params: list[SqliteParams]) -> None:
        with self._lease() as conn:
            with _translated_errors():
                conn.execute("BEGIN IMMEDIATE")
            try:
                _executemany_on(conn, sql, seq_params)
            except BaseException:
                _rollback_quietly(conn)
                raise
            with _translated_errors():
                conn.execute("COMMIT")

    async def fetchone(self, sql: str, params: SqliteParams = ()) -> Row | None:
        return await asyncio.to_thread(self._fetchone_sync, sql, params)

    def _fetchone_sync(self, sql: str, params: SqliteParams) -> Row | None:
        with self._lease() as conn:
            return _fetchone_on(conn, sql, params)

    async def fetchall(self, sql: str, params: SqliteParams = ()) -> list[Row]:
        return await asyncio.to_thread(self._fetchall_sync, sql, params)

    def _fetchall_sync(self, sql: str, params: SqliteParams) -> list[Row]:
        with self._lease() as conn:
            return _fetchall_on(conn, sql, params)

    # -- transactions -----------------------------------------------------------

    def transaction(self) -> _SqliteTransactionContext:
        return _SqliteTransactionContext(self)

    def _begin_file_transaction(self) -> sqlite3.Connection:
        """Open a dedicated connection and take the write lock."""
        conn = self._open_connection()
        try:
            with _translated_errors():
                conn.execute("BEGIN IMMEDIATE")
        except BaseException:
            self._discard_connection(conn)
            raise
        return conn

    def _begin_memory_transaction(self) -> sqlite3.Connection:
        """Take the shared-connection lock, then the write lock.

        Runs on the transaction's pinned worker thread, which thereby
        becomes the RLock owner until ``_finish`` releases it there.
        """
        self._acquire_memory_lock()
        try:
            conn = self._memory_connection()
            with _translated_errors():
                conn.execute("BEGIN IMMEDIATE")
        except BaseException:
            self._memory_lock.release()
            raise
        return conn

    @contextmanager
    def sync_transaction(self) -> Iterator[SqliteSyncTransaction]:
        """Synchronous ``BEGIN IMMEDIATE`` scope — scripts and migrations.

        Powers the facade's ``Database.sync_transaction()``. The caller's
        thread blocks for the whole scope, so its cached connection cannot
        be touched by anything else; ``:memory:`` holds the shared
        connection's lock instead.
        """
        if self._is_memory:
            self._acquire_memory_lock()
            try:
                yield from self._sync_scope(self._memory_connection())
            finally:
                self._memory_lock.release()
        else:
            yield from self._sync_scope(self._thread_connection())

    def _sync_scope(
        self, conn: sqlite3.Connection
    ) -> Iterator[SqliteSyncTransaction]:
        with _translated_errors():
            conn.execute("BEGIN IMMEDIATE")
        try:
            yield SqliteSyncTransaction(conn)
        except BaseException:
            _rollback_quietly(conn)
            raise
        try:
            with _translated_errors():
                conn.execute("COMMIT")
        except BaseException:
            _rollback_quietly(conn)
            raise
