from __future__ import annotations

from pathlib import Path

import pytest

from pyxle_db import Database, IntegrityError, NotFoundError


# ---------------------------------------------------------------------------
# PRAGMAs


def test_wal_and_foreign_keys_enabled(sync_db: Database) -> None:
    """The connection-time PRAGMAs must stick.

    Regression guard: turning off FK enforcement lets bad data slip into
    cloud tables that expect cascade deletes; a broken WAL setting causes
    reader/writer contention.
    """
    with sync_db.sync_transaction() as tx:
        assert tx.fetchone("PRAGMA journal_mode")[0].lower() == "wal"
        assert tx.fetchone("PRAGMA foreign_keys")[0] == 1
        assert tx.fetchone("PRAGMA synchronous")[0] == 1  # NORMAL


# ---------------------------------------------------------------------------
# Transactions + error mapping


async def test_async_transaction_commits_on_success(async_db: Database) -> None:
    async with async_db.transaction() as tx:
        tx.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)")
        tx.execute("INSERT INTO t (v) VALUES (?)", ("hello",))
    rows = await async_db.fetchall("SELECT v FROM t")
    assert [r["v"] for r in rows] == ["hello"]


async def test_async_transaction_rolls_back_on_exception(async_db: Database) -> None:
    async with async_db.transaction() as tx:
        tx.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)")

    class Boom(Exception):
        pass

    with pytest.raises(Boom):
        async with async_db.transaction() as tx:
            tx.execute("INSERT INTO t (v) VALUES (?)", ("a",))
            raise Boom()

    rows = await async_db.fetchall("SELECT v FROM t")
    assert rows == []


async def test_integrity_error_is_mapped(async_db: Database) -> None:
    async with async_db.transaction() as tx:
        tx.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT UNIQUE)")
        tx.execute("INSERT INTO t (v) VALUES ('x')")

    with pytest.raises(IntegrityError):
        async with async_db.transaction() as tx:
            tx.execute("INSERT INTO t (v) VALUES ('x')")


async def test_get_raises_not_found_when_empty(async_db: Database) -> None:
    async with async_db.transaction() as tx:
        tx.execute("CREATE TABLE t (id INTEGER PRIMARY KEY)")
    with pytest.raises(NotFoundError):
        await async_db.get("SELECT * FROM t WHERE id = 1")


# ---------------------------------------------------------------------------
# executemany


async def test_executemany_runs_in_one_transaction(async_db: Database) -> None:
    async with async_db.transaction() as tx:
        tx.execute("CREATE TABLE t (v INTEGER)")

    await async_db.executemany(
        "INSERT INTO t (v) VALUES (?)",
        [(1,), (2,), (3,)],
    )
    rows = await async_db.fetchall("SELECT v FROM t ORDER BY v")
    assert [r["v"] for r in rows] == [1, 2, 3]


# ---------------------------------------------------------------------------
# close() is idempotent and survives a follow-up thread open


def test_close_is_idempotent(sync_db: Database) -> None:
    sync_db.close()
    sync_db.close()


# ---------------------------------------------------------------------------
# query_count metric


async def test_query_count_increments(async_db: Database) -> None:
    before = async_db.query_count
    async with async_db.transaction() as tx:
        tx.execute("CREATE TABLE t (id INTEGER)")
    async with async_db.transaction() as tx:
        tx.execute("INSERT INTO t (id) VALUES (1)")
    await async_db.fetchone("SELECT * FROM t")
    # 2 write txs + 1 read = 3
    assert async_db.query_count - before == 3
