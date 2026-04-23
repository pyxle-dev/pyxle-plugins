"""Async-friendly SQLite wrapper for Pyxle apps.

Design:

* Uses the stdlib ``sqlite3`` driver because it's fast, zero-dep, and
  bundled with every supported Python. ``aiosqlite`` was considered and
  rejected: it layers a thread per connection on top of stdlib and adds
  latency without buying us anything the wrapper can't do with
  ``asyncio.to_thread``.
* Connection-per-thread pool. SQLite connections are not safe to share
  across threads by default; we open a fresh connection on first use in
  a given thread and cache it in ``threading.local``.
* Every write operation uses a transaction. A connection acquired via
  :meth:`Database.transaction` commits on successful exit and rolls back
  on exception.
* PRAGMAs applied at connection time: ``foreign_keys=ON``,
  ``journal_mode=WAL``, ``synchronous=NORMAL``, ``busy_timeout=5000``,
  ``temp_store=MEMORY``, ``cache_size=-65536`` (64 MB per connection).
  These are the "fast and safe for a web app" defaults; the WAL keeps
  readers and writers from blocking each other.
"""

from __future__ import annotations

import asyncio
import sqlite3
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator, Mapping, Sequence

from pyxle_db.errors import DatabaseError, IntegrityError, NotFoundError


# ---------------------------------------------------------------------------
# datetime adapters
#
# Python 3.12 deprecated the stdlib's default datetime/date adapters for
# sqlite3 — they produced timezone-naive strings which silently broke
# apps that store UTC timestamps. We register explicit adapters that
# serialise to a format compatible with SQLite's ``CURRENT_TIMESTAMP``
# (space separator, no timezone suffix, UTC normalised). This is
# important because lexicographic comparison of mixed formats silently
# produces wrong results — "2026-01-01 12:00:00" compares less than
# "2026-01-01T12:00:00+00:00" because space (0x20) < T (0x54).
#
# Every stored datetime is assumed UTC; the converter re-attaches
# :class:`datetime.timezone.utc` on the way out.


_SQLITE_DATETIME_FORMAT = "%Y-%m-%d %H:%M:%S.%f"


def _adapt_datetime(value: datetime) -> str:
    # Normalise to UTC before serialising so comparisons stay stable.
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    else:
        value = value.astimezone(timezone.utc)
    # strftime with %f gives microseconds — matches SQLite's own default
    # to ~second precision while still being sortable.
    return value.strftime(_SQLITE_DATETIME_FORMAT)


def _adapt_date(value: date) -> str:
    return value.isoformat()


def _convert_timestamp(raw: bytes) -> datetime:
    """Parse a TIMESTAMP column. Tolerant of:

    * ``YYYY-MM-DD HH:MM:SS.ffffff`` (our adapter's output)
    * ``YYYY-MM-DD HH:MM:SS`` (SQLite's CURRENT_TIMESTAMP)
    * ``YYYY-MM-DDTHH:MM:SS[.ffffff][+HH:MM]`` (ISO with/without tz)

    Never returns a naive datetime — UTC is assumed for naive values.
    """
    s = raw.decode("utf-8")
    parsed: datetime
    try:
        parsed = datetime.strptime(s, _SQLITE_DATETIME_FORMAT)
    except ValueError:
        try:
            parsed = datetime.strptime(s, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            # ISO-style fallback (e.g. data migrated in from another source).
            parsed = datetime.fromisoformat(s.replace("Z", "+00:00"))
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
# PRAGMAs applied to every connection on first open.
#
# The tuple-of-pairs shape (not a dict) is intentional — order matters.
# ``journal_mode`` must be set before ``synchronous`` takes its final effect,
# and ``foreign_keys`` must be set on every connection because SQLite
# otherwise resets it to OFF.

_PRAGMAS: tuple[tuple[str, str], ...] = (
    ("journal_mode", "WAL"),
    ("synchronous", "NORMAL"),
    ("foreign_keys", "ON"),
    ("busy_timeout", "5000"),
    ("temp_store", "MEMORY"),
    ("cache_size", "-65536"),
)


# ---------------------------------------------------------------------------
# Row typing


Row = sqlite3.Row
Params = Sequence[Any] | Mapping[str, Any]


def _row_factory(cursor: sqlite3.Cursor, row: tuple[Any, ...]) -> sqlite3.Row:
    """Return ``sqlite3.Row`` so results work as both tuple and mapping."""
    return sqlite3.Row(cursor, row)


# ---------------------------------------------------------------------------
# Transaction context


@dataclass
class Transaction:
    """Active transaction scope. Yielded from :meth:`Database.transaction`.

    The wrapper delegates to the underlying connection for query execution
    and commits / rolls back automatically when the context exits.

    Attributes:
        conn: The underlying ``sqlite3.Connection``. Expose only the
            methods we need so downstream code doesn't start pulling on
            connection-specific features that would break when we swap
            drivers.
    """

    conn: sqlite3.Connection

    def execute(self, sql: str, params: Params | None = None) -> sqlite3.Cursor:
        try:
            return self.conn.execute(sql, _params(params))
        except sqlite3.IntegrityError as exc:
            raise IntegrityError(str(exc)) from exc
        except sqlite3.Error as exc:
            raise DatabaseError(str(exc)) from exc

    def executemany(self, sql: str, seq_params: Iterable[Params]) -> sqlite3.Cursor:
        try:
            return self.conn.executemany(sql, [_params(p) for p in seq_params])
        except sqlite3.IntegrityError as exc:
            raise IntegrityError(str(exc)) from exc
        except sqlite3.Error as exc:
            raise DatabaseError(str(exc)) from exc

    def fetchone(self, sql: str, params: Params | None = None) -> Row | None:
        return self.execute(sql, params).fetchone()

    def fetchall(self, sql: str, params: Params | None = None) -> list[Row]:
        return self.execute(sql, params).fetchall()

    def get(self, sql: str, params: Params | None = None) -> Row:
        """Fetch one row; raise :class:`NotFoundError` if there isn't one."""
        row = self.fetchone(sql, params)
        if row is None:
            raise NotFoundError(f"No row for query: {sql}")
        return row


def _params(p: Params | None) -> Params:
    """Normalise the ``None`` case so callers don't need a guard."""
    return () if p is None else p


# ---------------------------------------------------------------------------
# Database


class Database:
    """Connection-pooled SQLite wrapper.

    Open once at app startup, close at shutdown:

    .. code-block:: python

        db = Database(":memory:")
        try:
            async with db.transaction() as tx:
                tx.execute("CREATE TABLE ...")
        finally:
            db.close()

    Or, using the :func:`connect` convenience:

    .. code-block:: python

        db = await connect("app.db", migrations_dir="migrations")
    """

    def __init__(self, path: str | Path) -> None:
        self._path = str(path)
        self._local = threading.local()
        self._lock = threading.Lock()
        # Track every connection we hand out so :meth:`close` can close them
        # even if they were created on a thread that has since ended.
        self._connections: list[sqlite3.Connection] = []
        # Monotonic counter of queries served. Exposed for metrics.
        self._query_count = 0

    # ---- connection management -------------------------------------------------

    def _thread_conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            return conn
        conn = sqlite3.connect(
            self._path,
            isolation_level=None,  # manage transactions explicitly
            detect_types=sqlite3.PARSE_DECLTYPES,
            check_same_thread=False,
            timeout=5.0,
        )
        conn.row_factory = _row_factory
        for name, value in _PRAGMAS:
            conn.execute(f"PRAGMA {name} = {value}")
        self._local.conn = conn
        with self._lock:
            self._connections.append(conn)
        return conn

    def close(self) -> None:
        """Close every connection we've opened. Idempotent."""
        with self._lock:
            conns, self._connections = self._connections, []
        for conn in conns:
            try:
                conn.close()
            except sqlite3.Error:
                # Best-effort; nothing useful we can do on close failure.
                pass

    # ---- query helpers ---------------------------------------------------------

    @contextmanager
    def _sync_transaction(self) -> Iterator[Transaction]:
        conn = self._thread_conn()
        conn.execute("BEGIN IMMEDIATE")
        tx = Transaction(conn)
        try:
            yield tx
        except BaseException:
            conn.execute("ROLLBACK")
            raise
        else:
            conn.execute("COMMIT")
        finally:
            self._query_count += 1

    class _AsyncTxCtx:
        """Async-friendly transaction context manager.

        Acquires the connection in a worker thread (so we don't block the
        event loop on the ``BEGIN IMMEDIATE`` when the write-lock is
        contended) and delivers a :class:`Transaction` back to the caller.
        """

        def __init__(self, db: "Database") -> None:
            self._db = db
            self._conn: sqlite3.Connection | None = None

        async def __aenter__(self) -> Transaction:
            self._conn = await asyncio.to_thread(self._begin)
            return Transaction(self._conn)

        def _begin(self) -> sqlite3.Connection:
            conn = self._db._thread_conn()
            conn.execute("BEGIN IMMEDIATE")
            return conn

        async def __aexit__(
            self,
            exc_type: type[BaseException] | None,
            exc: BaseException | None,
            tb: object,
        ) -> bool:
            conn = self._conn
            assert conn is not None
            if exc is None:
                await asyncio.to_thread(conn.execute, "COMMIT")
            else:
                await asyncio.to_thread(conn.execute, "ROLLBACK")
            self._db._query_count += 1
            return False

    def transaction(self) -> "Database._AsyncTxCtx":
        """Open an async transaction scope.

        .. code-block:: python

            async with db.transaction() as tx:
                tx.execute("INSERT ...", (value,))
        """
        return Database._AsyncTxCtx(self)

    def sync_transaction(self) -> "contextmanager[Transaction]":  # pragma: no cover - typing helper
        """Synchronous variant, for scripts and migrations.

        Use :meth:`transaction` inside async request handlers.
        """
        return self._sync_transaction()

    # ---- one-shot query helpers ------------------------------------------------

    async def execute(self, sql: str, params: Params | None = None) -> None:
        """Run a single write and commit."""

        def _run() -> None:
            with self._sync_transaction() as tx:
                tx.execute(sql, params)

        await asyncio.to_thread(_run)

    async def executemany(self, sql: str, seq_params: Iterable[Params]) -> None:
        """Bulk-insert flavoured write. Runs in one transaction."""
        materialised = [p for p in seq_params]

        def _run() -> None:
            with self._sync_transaction() as tx:
                tx.executemany(sql, materialised)

        await asyncio.to_thread(_run)

    async def fetchone(self, sql: str, params: Params | None = None) -> Row | None:
        def _run() -> Row | None:
            conn = self._thread_conn()
            cur = conn.execute(sql, _params(params))
            try:
                return cur.fetchone()
            finally:
                cur.close()

        self._query_count += 1
        return await asyncio.to_thread(_run)

    async def fetchall(self, sql: str, params: Params | None = None) -> list[Row]:
        def _run() -> list[Row]:
            conn = self._thread_conn()
            cur = conn.execute(sql, _params(params))
            try:
                return cur.fetchall()
            finally:
                cur.close()

        self._query_count += 1
        return await asyncio.to_thread(_run)

    async def get(self, sql: str, params: Params | None = None) -> Row:
        """Fetch one row; raise :class:`NotFoundError` if none."""
        row = await self.fetchone(sql, params)
        if row is None:
            raise NotFoundError(f"No row for query: {sql}")
        return row

    # ---- maintenance -----------------------------------------------------------

    async def vacuum(self) -> None:
        """Run ``VACUUM``. Rarely needed with WAL, but useful for tests."""
        await asyncio.to_thread(self._thread_conn().execute, "VACUUM")

    # ---- metrics ---------------------------------------------------------------

    @property
    def query_count(self) -> int:
        """Total transactions committed or rolled back since open."""
        return self._query_count

    # ---- path / introspection --------------------------------------------------

    @property
    def path(self) -> str:
        return self._path


# ---------------------------------------------------------------------------
# Convenience factory


async def connect(
    path: str | Path,
    *,
    migrations_dir: str | Path | None = None,
    wait_for_file_ms: int = 0,
) -> Database:
    """Open a :class:`Database` and optionally apply migrations.

    ``wait_for_file_ms`` is useful when opening a path that another
    process is just finishing creating (e.g. a test harness starting
    the server under test). Defaults to 0 — no wait.
    """
    # Lazy import to keep Database importable without migrator deps.
    from pyxle_db.migrator import Migrator

    path_str = str(path)

    if wait_for_file_ms and path_str != ":memory:":
        deadline = time.monotonic() + wait_for_file_ms / 1000.0
        while not Path(path_str).exists() and time.monotonic() < deadline:
            await asyncio.sleep(0.05)

    db = Database(path_str)
    if migrations_dir is not None:
        migrator = Migrator(db, Path(migrations_dir))
        await migrator.apply_all()
    return db
