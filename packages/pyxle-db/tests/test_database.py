from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from pyxle_db import Database, IntegrityError, NotFoundError
from pyxle_db.rows import Row


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
# Lifecycle: lazy connect, close(), aclose()


async def test_facade_connects_lazily(db_path: Path) -> None:
    """Every query path connects on demand — no explicit connect() needed."""
    db = Database(db_path)
    try:
        await db.execute("CREATE TABLE t (v TEXT)")
        await db.execute("INSERT INTO t (v) VALUES (?)", ("lazy",))
        row = await db.fetchone("SELECT v FROM t")
        assert row is not None
        assert row["v"] == "lazy"
    finally:
        await db.aclose()


def test_close_is_idempotent(sync_db: Database) -> None:
    sync_db.close()
    sync_db.close()


async def test_close_then_reuse_reopens(async_db: Database) -> None:
    await async_db.execute("CREATE TABLE t (v TEXT)")
    await async_db.execute("INSERT INTO t (v) VALUES (?)", ("kept",))
    async_db.close()
    row = await async_db.get("SELECT v FROM t")
    assert row["v"] == "kept"


async def test_aclose_is_idempotent_and_reusable(async_db: Database) -> None:
    await async_db.execute("CREATE TABLE t (v TEXT)")
    await async_db.aclose()
    await async_db.aclose()
    rows = await async_db.fetchall("SELECT v FROM t")
    assert rows == []


# ---------------------------------------------------------------------------
# Transactions + error mapping


async def test_async_transaction_commits_on_success(async_db: Database) -> None:
    async with async_db.transaction() as tx:
        await tx.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)")
        await tx.execute("INSERT INTO t (v) VALUES (?)", ("hello",))
    rows = await async_db.fetchall("SELECT v FROM t")
    assert [r["v"] for r in rows] == ["hello"]


async def test_async_transaction_rolls_back_on_exception(async_db: Database) -> None:
    async with async_db.transaction() as tx:
        await tx.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)")

    class Boom(Exception):
        pass

    with pytest.raises(Boom):
        async with async_db.transaction() as tx:
            await tx.execute("INSERT INTO t (v) VALUES (?)", ("a",))
            raise Boom()

    rows = await async_db.fetchall("SELECT v FROM t")
    assert rows == []


async def test_integrity_error_is_mapped(async_db: Database) -> None:
    async with async_db.transaction() as tx:
        await tx.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT UNIQUE)")
        await tx.execute("INSERT INTO t (v) VALUES ('x')")

    with pytest.raises(IntegrityError):
        async with async_db.transaction() as tx:
            await tx.execute("INSERT INTO t (v) VALUES ('x')")


async def test_get_raises_not_found_when_empty(async_db: Database) -> None:
    async with async_db.transaction() as tx:
        await tx.execute("CREATE TABLE t (id INTEGER PRIMARY KEY)")
    with pytest.raises(NotFoundError):
        await async_db.get("SELECT * FROM t WHERE id = 1")


# ---------------------------------------------------------------------------
# executemany


async def test_executemany_runs_in_one_transaction(async_db: Database) -> None:
    async with async_db.transaction() as tx:
        await tx.execute("CREATE TABLE t (v INTEGER)")

    await async_db.executemany(
        "INSERT INTO t (v) VALUES (?)",
        [(1,), (2,), (3,)],
    )
    rows = await async_db.fetchall("SELECT v FROM t ORDER BY v")
    assert [r["v"] for r in rows] == [1, 2, 3]


# ---------------------------------------------------------------------------
# Rows


async def test_row_supports_name_and_index_access(async_db: Database) -> None:
    row = await async_db.get("SELECT 1 AS a, 'x' AS b")
    assert isinstance(row, Row)
    assert row["a"] == 1
    assert row[0] == 1
    assert row["b"] == "x"
    assert row[1] == "x"
    assert row.keys() == ("a", "b")
    assert row == (1, "x")


# ---------------------------------------------------------------------------
# qmark translation: the ?? escape


async def test_double_question_mark_escape_end_to_end(async_db: Database) -> None:
    """``??`` is the portable escape for a literal question mark.

    On SQLite the translated single ``?`` is itself a parameter marker, so
    ``SELECT ?? AS v`` must bind exactly ONE parameter — untranslated it
    would be a syntax error.
    """
    row = await async_db.get("SELECT ?? AS v", ("ok",))
    assert row["v"] == "ok"


async def test_question_marks_inside_literals_pass_through(async_db: Database) -> None:
    row = await async_db.get("SELECT '??' AS v")
    assert row["v"] == "??"


# ---------------------------------------------------------------------------
# Mapping (named) parameters — SQLite keeps supporting them


async def test_mapping_params_work_on_sqlite(async_db: Database) -> None:
    await async_db.execute("CREATE TABLE t (v TEXT)")
    await async_db.execute("INSERT INTO t (v) VALUES (:v)", {"v": "named"})
    row = await async_db.get("SELECT v FROM t WHERE v = :v", {"v": "named"})
    assert row["v"] == "named"


# ---------------------------------------------------------------------------
# Datetimes round-trip timezone-aware UTC


async def test_datetime_round_trip_is_aware_utc(async_db: Database) -> None:
    await async_db.execute(
        "CREATE TABLE evts (id INTEGER PRIMARY KEY, at TIMESTAMP NOT NULL)"
    )
    ist = timezone(timedelta(hours=5, minutes=30))
    moment = datetime(2026, 6, 11, 9, 30, 15, 123456, tzinfo=ist)
    await async_db.execute("INSERT INTO evts (at) VALUES (?)", (moment,))

    row = await async_db.get("SELECT at FROM evts")
    assert row["at"].tzinfo is timezone.utc
    assert row["at"] == moment  # same instant, normalised to UTC


async def test_database_satisfies_the_published_contract(async_db: Database) -> None:
    """`Database` is the reference implementation of `DatabaseLike` — the
    structural contract third-party layers implement to back plugins like
    pyxle-auth. If this fails, either the protocol or the class drifted."""
    from pyxle_db import DatabaseLike, TransactionLike

    assert isinstance(async_db, DatabaseLike)
    async with async_db.transaction() as tx:
        assert isinstance(tx, TransactionLike)


def test_utc_naive_params_normalises_aware_datetimes() -> None:
    """The write side of the datetime contract: aware values bind as naive
    UTC (what TIMESTAMP/DATETIME columns store), everything else passes
    through untouched. PG/MySQL backends run all params through this —
    asyncpg rejects aware datetimes for TIMESTAMP columns and asyncmy would
    silently store a foreign wall clock."""
    from pyxle_db.backends.base import utc_naive_params

    ist = timezone(timedelta(hours=5, minutes=30))
    aware = datetime(2026, 6, 11, 9, 30, 15, 123456, tzinfo=ist)
    naive = datetime(2026, 6, 11, 4, 0, 15, 123456)
    out = utc_naive_params((aware, naive, "text", 7, None, [aware]))

    assert out[0] == datetime(2026, 6, 11, 4, 0, 15, 123456)  # IST-5:30 → UTC
    assert out[0].tzinfo is None
    assert out[1] is naive  # naive passes through (assumed UTC already)
    assert out[2:5] == ("text", 7, None)
    assert out[5] == [aware]  # containers untouched, matching the read rule


async def test_current_timestamp_reads_back_aware_utc(async_db: Database) -> None:
    await async_db.execute(
        "CREATE TABLE evts ("
        "  id INTEGER PRIMARY KEY,"
        "  at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP"
        ")"
    )
    await async_db.execute("INSERT INTO evts DEFAULT VALUES")
    row = await async_db.get("SELECT at FROM evts")
    assert row["at"].tzinfo is timezone.utc


# ---------------------------------------------------------------------------
# query_count metric


async def test_query_count_increments(async_db: Database) -> None:
    before = async_db.query_count
    async with async_db.transaction() as tx:
        await tx.execute("CREATE TABLE t (id INTEGER)")
    async with async_db.transaction() as tx:
        await tx.execute("INSERT INTO t (id) VALUES (1)")
    await async_db.fetchone("SELECT * FROM t")
    # 2 write txs + 1 read = 3
    assert async_db.query_count - before == 3
