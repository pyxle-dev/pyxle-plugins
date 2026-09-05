"""SQLite-backend specifics: shared ``:memory:`` handling, thread-local
connection pooling, transaction exclusivity, sync transactions, and the
driver-to-pyxle error mapping. Facade-level behaviour lives in
``test_database.py``."""

from __future__ import annotations

import asyncio
import sqlite3
import threading
from pathlib import Path
from typing import AsyncIterator

import pytest

import pyxle_db.backends.sqlite as sqlite_backend_module
from pyxle_db.backends.base import SQLITE_DIALECT
from pyxle_db.backends.sqlite import SqliteBackend
from pyxle_db.errors import (
    DatabaseError,
    IntegrityError,
    NotFoundError,
    OperationalError,
)
from pyxle_db.rows import Row
from pyxle_db.url import parse_database_url


def _file_backend(tmp_path: Path) -> SqliteBackend:
    return SqliteBackend(parse_database_url(str(tmp_path / "backend.db")))


def _memory_backend() -> SqliteBackend:
    return SqliteBackend(parse_database_url(":memory:"))


@pytest.fixture(params=["memory", "file"])
async def backend(
    request: pytest.FixtureRequest, tmp_path: Path
) -> AsyncIterator[SqliteBackend]:
    instance = (
        _memory_backend() if request.param == "memory" else _file_backend(tmp_path)
    )
    await instance.connect()
    try:
        yield instance
    finally:
        await instance.aclose()


# ---------------------------------------------------------------------------
# Dialect


def test_dialect_is_sqlite() -> None:
    backend = _memory_backend()
    assert backend.dialect is SQLITE_DIALECT
    assert backend.dialect.supports_sync is True


# ---------------------------------------------------------------------------
# :memory: — one shared connection, visible from every worker thread


async def test_memory_database_is_shared_across_threads() -> None:
    """One-shots run on ``asyncio.to_thread`` workers while transactions
    run on their own pinned thread — with per-thread private ``:memory:``
    databases the transaction would see an empty schema."""
    backend = _memory_backend()
    try:
        await backend.execute("CREATE TABLE t (v INTEGER)")
        await backend.execute("INSERT INTO t (v) VALUES (1)")
        async with backend.transaction() as tx:
            await tx.execute("INSERT INTO t (v) VALUES (2)")
            rows = await tx.fetchall("SELECT v FROM t ORDER BY v")
            assert [r["v"] for r in rows] == [1, 2]
        rows = await backend.fetchall("SELECT v FROM t ORDER BY v")
        assert [r["v"] for r in rows] == [1, 2]
    finally:
        await backend.aclose()


async def test_memory_lock_timeout_maps_to_operational_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A one-shot statement issued while a ``:memory:`` transaction is
    open must wait for the shared connection — and surface a retryable
    OperationalError when the wait times out, mirroring busy_timeout."""
    monkeypatch.setattr(sqlite_backend_module, "_MEMORY_LOCK_TIMEOUT", 0.05)
    backend = _memory_backend()
    try:
        await backend.execute("CREATE TABLE t (v INTEGER)")
        async with backend.transaction() as tx:
            await tx.execute("INSERT INTO t (v) VALUES (1)")
            with pytest.raises(OperationalError):
                await backend.execute("INSERT INTO t (v) VALUES (2)")
    finally:
        await backend.aclose()


# ---------------------------------------------------------------------------
# Transactions are exclusive to their caller (contract rule 6)


async def test_concurrent_transactions_serialize(backend: SqliteBackend) -> None:
    await backend.execute("CREATE TABLE c (n INTEGER)")
    await backend.execute("INSERT INTO c (n) VALUES (0)")

    async def bump() -> None:
        async with backend.transaction() as tx:
            row = await tx.fetchone("SELECT n FROM c")
            assert row is not None
            await asyncio.sleep(0.05)  # widen the lost-update window
            await tx.execute("UPDATE c SET n = ?", (row["n"] + 1,))

    await asyncio.gather(bump(), bump())
    row = await backend.fetchone("SELECT n FROM c")
    assert row is not None
    assert row["n"] == 2  # a lost update would leave 1


async def test_failed_transaction_releases_the_connection(
    backend: SqliteBackend,
) -> None:
    await backend.execute("CREATE TABLE t (v INTEGER UNIQUE)")
    await backend.execute("INSERT INTO t (v) VALUES (1)")

    with pytest.raises(IntegrityError):
        async with backend.transaction() as tx:
            await tx.execute("INSERT INTO t (v) VALUES (1)")

    # The write lock (and for :memory: the shared-connection lock) must be
    # free again for both one-shots and fresh transactions.
    await backend.execute("INSERT INTO t (v) VALUES (2)")
    async with backend.transaction() as tx:
        await tx.execute("INSERT INTO t (v) VALUES (3)")
    rows = await backend.fetchall("SELECT v FROM t ORDER BY v")
    assert [r["v"] for r in rows] == [1, 2, 3]


async def test_transaction_sees_own_writes_and_rollback_discards(
    backend: SqliteBackend,
) -> None:
    await backend.execute("CREATE TABLE t (v INTEGER)")

    class Boom(Exception):
        pass

    with pytest.raises(Boom):
        async with backend.transaction() as tx:
            await tx.execute("INSERT INTO t (v) VALUES (1)")
            row = await tx.fetchone("SELECT COUNT(*) AS n FROM t")
            assert row is not None
            assert row["n"] == 1  # uncommitted write visible inside the tx
            raise Boom()

    rows = await backend.fetchall("SELECT v FROM t")
    assert rows == []


# ---------------------------------------------------------------------------
# Thread-local connections (file databases)


def test_thread_local_connections_are_reused_and_closed(tmp_path: Path) -> None:
    """White-box: one connection per thread, and close_sync() releases
    connections opened by threads that have since exited."""
    backend = _file_backend(tmp_path)

    first = backend._thread_connection()
    assert backend._thread_connection() is first  # same thread → same conn

    from_worker: list[sqlite3.Connection] = []
    worker = threading.Thread(
        target=lambda: from_worker.append(backend._thread_connection())
    )
    worker.start()
    worker.join()
    assert from_worker[0] is not first  # different thread → different conn

    backend.close_sync()  # the worker thread is gone; its conn must still close
    with pytest.raises(sqlite3.ProgrammingError):
        from_worker[0].execute("SELECT 1")
    with pytest.raises(sqlite3.ProgrammingError):
        first.execute("SELECT 1")

    # After close the backend transparently reopens on next use.
    assert backend._thread_connection() is not first
    backend.close_sync()


async def test_connect_and_aclose_are_idempotent(tmp_path: Path) -> None:
    backend = _file_backend(tmp_path)
    await backend.connect()
    await backend.connect()
    await backend.execute("CREATE TABLE t (v INTEGER)")
    await backend.aclose()
    await backend.aclose()
    # Reusable after another connect().
    await backend.connect()
    assert await backend.fetchall("SELECT v FROM t") == []
    await backend.aclose()


# ---------------------------------------------------------------------------
# One-shot statements


async def test_execute_returns_affected_rowcount(backend: SqliteBackend) -> None:
    await backend.execute("CREATE TABLE t (v INTEGER)")
    assert await backend.execute("INSERT INTO t (v) VALUES (1)") == 1
    assert await backend.execute("INSERT INTO t (v) VALUES (2)") == 1
    assert await backend.execute("UPDATE t SET v = v + 1") == 2


async def test_executemany_is_atomic(backend: SqliteBackend) -> None:
    await backend.execute("CREATE TABLE t (v INTEGER UNIQUE)")
    with pytest.raises(IntegrityError):
        await backend.executemany(
            "INSERT INTO t (v) VALUES (?)", [(1,), (2,), (1,)]
        )
    assert await backend.fetchall("SELECT v FROM t") == []


async def test_fetches_return_rows(backend: SqliteBackend) -> None:
    await backend.execute("CREATE TABLE t (a INTEGER, b TEXT)")
    await backend.execute("INSERT INTO t (a, b) VALUES (1, 'x')")

    one = await backend.fetchone("SELECT a, b FROM t")
    assert isinstance(one, Row)
    assert (one["a"], one[1]) == (1, "x")

    everything = await backend.fetchall("SELECT a, b FROM t")
    assert all(isinstance(row, Row) for row in everything)
    assert await backend.fetchone("SELECT a FROM t WHERE a = 99") is None


# ---------------------------------------------------------------------------
# sync_transaction — the script/migration path


def test_sync_transaction_commits_and_returns_rows(tmp_path: Path) -> None:
    backend = _file_backend(tmp_path)
    try:
        with backend.sync_transaction() as tx:
            tx.execute("CREATE TABLE t (v TEXT)")
            tx.executemany("INSERT INTO t (v) VALUES (?)", [("a",), ("b",)])
            rows = tx.fetchall("SELECT v FROM t ORDER BY v")
            assert all(isinstance(row, Row) for row in rows)
            assert [r["v"] for r in rows] == ["a", "b"]
        with backend.sync_transaction() as tx:
            assert tx.get("SELECT COUNT(*) AS n FROM t")["n"] == 2
    finally:
        backend.close_sync()


def test_sync_transaction_rolls_back_on_exception(tmp_path: Path) -> None:
    backend = _file_backend(tmp_path)

    class Boom(Exception):
        pass

    try:
        with backend.sync_transaction() as tx:
            tx.execute("CREATE TABLE t (v TEXT)")
        with pytest.raises(Boom):
            with backend.sync_transaction() as tx:
                tx.execute("INSERT INTO t (v) VALUES ('a')")
                raise Boom()
        with backend.sync_transaction() as tx:
            assert tx.fetchall("SELECT v FROM t") == []
    finally:
        backend.close_sync()


def test_sync_transaction_get_raises_not_found(tmp_path: Path) -> None:
    backend = _file_backend(tmp_path)
    try:
        with backend.sync_transaction() as tx:
            tx.execute("CREATE TABLE t (v TEXT)")
            with pytest.raises(NotFoundError):
                tx.get("SELECT v FROM t WHERE v = ?", ("missing",))
    finally:
        backend.close_sync()


def test_sync_transaction_translates_the_qmark_escape(tmp_path: Path) -> None:
    """The sync path is the translation entry point for scripts, so the
    portable ``??`` escape must collapse exactly like the async path."""
    backend = _file_backend(tmp_path)
    try:
        with backend.sync_transaction() as tx:
            assert tx.get("SELECT ?? AS v", ("ok",))["v"] == "ok"
            assert tx.get("SELECT '??' AS v")["v"] == "??"
    finally:
        backend.close_sync()


def test_sync_transaction_works_on_memory() -> None:
    backend = _memory_backend()
    try:
        with backend.sync_transaction() as tx:
            tx.execute("CREATE TABLE t (v INTEGER)")
            tx.execute("INSERT INTO t (v) VALUES (1)")
        with backend.sync_transaction() as tx:
            assert tx.get("SELECT v FROM t")["v"] == 1
    finally:
        backend.close_sync()


# ---------------------------------------------------------------------------
# Error mapping (contract rules 1 and 2)


async def test_unable_to_open_maps_to_operational_error(tmp_path: Path) -> None:
    backend = SqliteBackend(
        parse_database_url(str(tmp_path / "missing-dir" / "app.db"))
    )
    with pytest.raises(OperationalError):
        await backend.connect()


async def test_syntax_error_maps_to_database_error(backend: SqliteBackend) -> None:
    # sqlite3 reports syntax errors as sqlite3.OperationalError, but they
    # are programming errors, not the retryable family.
    with pytest.raises(DatabaseError) as excinfo:
        await backend.execute("THIS IS NOT SQL")
    assert not isinstance(excinfo.value, OperationalError)


async def test_integrity_error_maps_at_backend_level(backend: SqliteBackend) -> None:
    await backend.execute("CREATE TABLE t (v INTEGER NOT NULL)")
    with pytest.raises(IntegrityError):
        await backend.execute("INSERT INTO t (v) VALUES (NULL)")


# ---------------------------------------------------------------------------
# Connection-open pragma race


class _FlakyPragmaConn:
    """Minimal connection stand-in for the pragma-retry logic."""

    def __init__(self, locked_failures: int) -> None:
        self.locked_failures = locked_failures
        self.executed: list[str] = []

    def execute(self, sql: str) -> None:
        if "journal_mode" in sql and self.locked_failures > 0:
            self.locked_failures -= 1
            raise sqlite3.OperationalError("database is locked")
        self.executed.append(sql)


def test_apply_pragmas_retries_a_locked_journal_mode() -> None:
    """``PRAGMA journal_mode = WAL`` can report SQLITE_BUSY without
    consulting the busy handler when several processes open a fresh
    database together (every worker of a multi-worker server at startup);
    the open path must wait it out, not fail the worker."""
    conn = _FlakyPragmaConn(locked_failures=3)
    sqlite_backend_module._apply_pragmas(conn)
    assert [s.split(" = ")[0] for s in conn.executed] == [
        f"PRAGMA {name}" for name, _ in sqlite_backend_module._PRAGMAS
    ]


def test_apply_pragmas_still_fails_after_the_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sqlite_backend_module, "_PRAGMA_RETRY_TIMEOUT", 0.05)
    monkeypatch.setattr(sqlite_backend_module, "_PRAGMA_RETRY_INTERVAL", 0.005)
    conn = _FlakyPragmaConn(locked_failures=10_000)
    with pytest.raises(sqlite3.OperationalError, match="database is locked"):
        sqlite_backend_module._apply_pragmas(conn)


def test_apply_pragmas_propagates_non_lock_errors() -> None:
    class _Broken:
        def execute(self, sql: str) -> None:
            raise sqlite3.OperationalError("disk I/O error")

    with pytest.raises(sqlite3.OperationalError, match="disk I/O"):
        sqlite_backend_module._apply_pragmas(_Broken())
