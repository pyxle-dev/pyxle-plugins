"""Concurrent migration application against real backends.

``test_migrator.py`` proves the migrator's per-dialect lock protocol
hermetically against a stub; this module proves the actual concurrency
story:

* SQLite — real ``BEGIN IMMEDIATE`` contention, both in-process
  (``asyncio.gather``) and across spawned processes: the shape of
  ``pyxle serve --workers N``, where every worker applies migrations at
  startup and racing one pending migration used to crash the losers with
  ``UNIQUE constraint failed: schema_migrations.id``.
* PostgreSQL / MySQL — the same invariants against live servers,
  auto-skipped unless ``PYXLE_DB_TEST_POSTGRES_URL`` /
  ``PYXLE_DB_TEST_MYSQL_URL`` is set (matching the backend suites).

Interleavings are made deterministic with a barrier or explicit
sequencing, never with sleeps — the asserted invariant (exactly one
process applies, everyone else skips cleanly, side effects happen once)
must hold for *every* interleaving.
"""

from __future__ import annotations

import asyncio
import multiprocessing
import os
import uuid
from pathlib import Path

import pytest

from pyxle_db import Database, Migrator

# Deliberately NOT "IF NOT EXISTS": a loser that wrongly re-runs the SQL
# fails loudly instead of hiding behind idempotent DDL.
_GUESTBOOK_SQL = (
    "CREATE TABLE guestbook (id INTEGER PRIMARY KEY, note TEXT NOT NULL);\n"
    "INSERT INTO guestbook (note) VALUES ('hello');\n"
)


@pytest.fixture
def mdir(tmp_path: Path) -> Path:
    directory = tmp_path / "migrations"
    directory.mkdir()
    (directory / "0001-guestbook.sql").write_text(
        _GUESTBOOK_SQL, encoding="utf-8"
    )
    return directory


# ---------------------------------------------------------------------------
# SQLite — real contention on one database file


def _apply_in_worker(
    db_path: str,
    migrations_dir: str,
    barrier,  # multiprocessing.Barrier — untyped: the proxy type is private
    results,  # multiprocessing.Queue
) -> None:
    """One 'server worker': wait at the barrier, then apply migrations."""

    async def apply() -> list[str]:
        db = Database(db_path)
        try:
            applied = await Migrator(db, Path(migrations_dir)).apply_all()
            return [migration.id for migration in applied]
        finally:
            await db.aclose()

    try:
        barrier.wait(timeout=30)
        results.put(("ok", asyncio.run(apply())))
    except BaseException as exc:  # report everything; the parent asserts
        results.put(("error", f"{type(exc).__name__}: {exc}"))


async def test_four_processes_racing_apply_exactly_once(
    mdir: Path, tmp_path: Path
) -> None:
    """The production shape: N workers start together with one pending
    migration. Every worker must come up clean, exactly one may apply it,
    and its side effects must happen once."""
    db_path = tmp_path / "race.db"
    ctx = multiprocessing.get_context("spawn")
    barrier = ctx.Barrier(4)
    results = ctx.Queue()
    workers = [
        ctx.Process(
            target=_apply_in_worker,
            args=(str(db_path), str(mdir), barrier, results),
        )
        for _ in range(4)
    ]
    for worker in workers:
        worker.start()
    try:
        outcomes = [results.get(timeout=60) for _ in workers]
    finally:
        for worker in workers:
            worker.join(timeout=30)
            if worker.is_alive():
                worker.terminate()

    errors = [detail for status, detail in outcomes if status != "ok"]
    assert errors == []
    applied_counts = sorted(len(ids) for _, ids in outcomes)
    assert applied_counts == [0, 0, 0, 1]

    db = Database(db_path)
    try:
        tracking = await db.fetchall("SELECT id FROM schema_migrations")
        assert [row["id"] for row in tracking] == ["0001-guestbook"]
        notes = await db.fetchall("SELECT note FROM guestbook")
        assert [row["note"] for row in notes] == ["hello"]
    finally:
        await db.aclose()


async def test_two_handles_gathered_in_one_process(
    mdir: Path, tmp_path: Path
) -> None:
    """Two connections racing inside one process — real ``BEGIN IMMEDIATE``
    contention through the backend's thread bridge."""
    db_path = tmp_path / "race.db"
    first = Database(db_path)
    second = Database(db_path)
    try:
        results = await asyncio.gather(
            Migrator(first, mdir).apply_all(),
            Migrator(second, mdir).apply_all(),
        )
        assert sorted(len(applied) for applied in results) == [0, 1]
        notes = await first.fetchall("SELECT note FROM guestbook")
        assert [row["note"] for row in notes] == ["hello"]
    finally:
        await first.aclose()
        await second.aclose()


async def test_stale_pending_scan_skips_on_the_real_backend(
    mdir: Path, tmp_path: Path
) -> None:
    """The exact losing interleaving, sequenced deterministically: scan
    while pending, lose the apply race, proceed on the stale scan."""
    db_path = tmp_path / "race.db"
    winner_db = Database(db_path)
    loser_db = Database(db_path)
    try:
        loser = Migrator(loser_db, mdir)
        stale = loser.discover()[0]  # scanned before the winner landed
        winner_ids = [m.id for m in await Migrator(winner_db, mdir).apply_all()]
        assert winner_ids == ["0001-guestbook"]

        # Private seam on purpose: this is the precise moment a losing
        # worker re-enters with an outdated pending list.
        assert await loser._apply_one(stale) is False
        assert await loser.apply_all() == []

        notes = await loser_db.fetchall("SELECT note FROM guestbook")
        assert [row["note"] for row in notes] == ["hello"]
    finally:
        await winner_db.aclose()
        await loser_db.aclose()


# ---------------------------------------------------------------------------
# Live server backends — skipped unless the engine URLs are set

POSTGRES_URL = os.environ.get("PYXLE_DB_TEST_POSTGRES_URL", "")
MYSQL_URL = os.environ.get("PYXLE_DB_TEST_MYSQL_URL", "")


class _LiveConcurrencyContract:
    """The concurrency invariants, run against a live engine.

    Subclasses pin the URL and driver. Table names are unique per run so
    parallel CI jobs and leftover state cannot collide; each run drops its
    own tables afterwards.
    """

    url = ""
    driver = ""

    @pytest.fixture
    def names(self) -> tuple[str, str]:
        token = uuid.uuid4().hex[:12]
        return f"pyxle_mig_track_{token}", f"pyxle_mig_target_{token}"

    @pytest.fixture
    def live_mdir(self, tmp_path: Path, names: tuple[str, str]) -> Path:
        _, target = names
        directory = tmp_path / "migrations"
        directory.mkdir()
        (directory / "0001-target.sql").write_text(
            f"CREATE TABLE {target} "
            "(id INTEGER PRIMARY KEY, note VARCHAR(64) NOT NULL);\n"
            f"INSERT INTO {target} (id, note) VALUES (1, 'hello');\n",
            encoding="utf-8",
        )
        return directory

    @pytest.fixture
    async def handles(self, names: tuple[str, str]):
        pytest.importorskip(self.driver)
        first = Database(self.url)
        second = Database(self.url)
        await first.connect()
        await second.connect()
        try:
            yield first, second
        finally:
            tracking, target = names
            for table in (target, tracking):
                await first.execute(f"DROP TABLE IF EXISTS {table}")
            await first.aclose()
            await second.aclose()

    async def test_gathered_appliers_apply_exactly_once(
        self, handles, live_mdir: Path, names: tuple[str, str]
    ) -> None:
        tracking, target = names
        first, second = handles
        results = await asyncio.gather(
            Migrator(first, live_mdir, tracking_table=tracking).apply_all(),
            Migrator(second, live_mdir, tracking_table=tracking).apply_all(),
        )
        assert sorted(len(applied) for applied in results) == [0, 1]
        rows = await first.fetchall(f"SELECT note FROM {target}")
        assert [row["note"] for row in rows] == ["hello"]
        recorded = await first.fetchall(f"SELECT id FROM {tracking}")
        assert [row["id"] for row in recorded] == ["0001-target"]

    async def test_stale_pending_scan_skips(
        self, handles, live_mdir: Path, names: tuple[str, str]
    ) -> None:
        tracking, _ = names
        first, second = handles
        loser = Migrator(second, live_mdir, tracking_table=tracking)
        stale = loser.discover()[0]
        await Migrator(first, live_mdir, tracking_table=tracking).apply_all()
        assert await loser._apply_one(stale) is False
        assert await loser.apply_all() == []


@pytest.mark.skipif(
    not POSTGRES_URL, reason="PYXLE_DB_TEST_POSTGRES_URL is not set"
)
class TestLivePostgresConcurrency(_LiveConcurrencyContract):
    url = POSTGRES_URL
    driver = "asyncpg"


@pytest.mark.skipif(not MYSQL_URL, reason="PYXLE_DB_TEST_MYSQL_URL is not set")
class TestLiveMysqlConcurrency(_LiveConcurrencyContract):
    url = MYSQL_URL
    driver = "asyncmy"
