"""Migrator tests.

The migrator reaches the database exclusively through the
:class:`pyxle_db.Database` facade, so this suite runs it against a
minimal contract-shaped backend (SQLite storage behind any dialect
label) injected through the backend factory. That keeps the tests
hermetic — PostgreSQL/MySQL override selection is exercised without
those servers — and proves the migrator uses only the public facade API.
"""

from __future__ import annotations

import hashlib
import logging
import re
import sqlite3
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, AsyncIterator, Iterable, Iterator, Sequence

import pytest

import pyxle_db.database
from pyxle_db import (
    Database,
    MigrationChecksumMismatch,
    MigrationError,
    Migrator,
    connect,
)
from pyxle_db.backends.base import (
    MYSQL_DIALECT,
    POSTGRESQL_DIALECT,
    SQLITE_DIALECT,
    Backend,
    BackendTransaction,
    Dialect,
)
from pyxle_db.errors import DatabaseError, IntegrityError, OperationalError
from pyxle_db.migrator import (
    _mysql_lock_name,
    _postgres_lock_keys,
    select_migration_files,
)
from pyxle_db.rows import Row
from pyxle_db.url import DatabaseConfig

PG_URL = "postgresql://app:secret@localhost/app"
MYSQL_URL = "mysql://app:secret@localhost/app"


# ---------------------------------------------------------------------------
# Stub backend — SQLite storage behind any dialect label

_EVENTS: list[tuple[Any, ...]] = []
"""Chronological trace of stub activity, cleared per test by ``_clear_events``.

Entries are ``("sql", <native statement>)`` for every statement reaching the
stub, plus ``("pg_advisory_xact_lock", high, low)`` / ``("get_lock", name,
timeout)`` / ``("release_lock", name)`` when the registered stand-ins for the
server lock functions execute — letting tests assert the migrator's
per-dialect lock protocol (which lock, keyed how, ordered where) without a
live server.
"""


def _register_lock_stand_ins(conn: sqlite3.Connection) -> None:
    """SQLite stand-ins for the server-side lock functions.

    Single-process stub tests never contend, so each stand-in records the
    call and reports success; the blocking semantics belong to the live
    suites in ``test_migrator_concurrency.py``.
    """

    def pg_advisory_xact_lock(high: int, low: int) -> None:
        _EVENTS.append(("pg_advisory_xact_lock", high, low))

    def get_lock(name: str, timeout: int) -> int:
        _EVENTS.append(("get_lock", name, timeout))
        return 1

    def release_lock(name: str) -> int:
        _EVENTS.append(("release_lock", name))
        return 1

    conn.create_function("pg_advisory_xact_lock", 2, pg_advisory_xact_lock)
    conn.create_function("get_lock", 2, get_lock)
    conn.create_function("release_lock", 1, release_lock)


def _to_sqlite(sql: str) -> str:
    """Rewrite dialect-native SQL just enough for sqlite3 to run it.

    Placeholders: the facade hands backends native SQL — ``$1`` on
    PostgreSQL, ``%s`` on MySQL — while the stub binds positionally with
    ``?``. DDL: PostgreSQL's tracking-table default ``now()`` is not a
    constant to SQLite; ``CURRENT_TIMESTAMP`` is its equivalent.
    """
    sql = re.sub(r"\$\d+", "?", sql).replace("%s", "?")
    return sql.replace("DEFAULT now()", "DEFAULT CURRENT_TIMESTAMP")


def _run(conn: sqlite3.Connection, sql: str, params: Sequence[Any]) -> sqlite3.Cursor:
    _EVENTS.append(("sql", sql))
    if sql.startswith("SET TRANSACTION"):
        # Server-side session statement with no SQLite equivalent; the
        # trace entry above is its observable effect.
        return conn.execute("SELECT 0 WHERE 0")
    try:
        return conn.execute(_to_sqlite(sql), tuple(params))
    except sqlite3.IntegrityError as exc:
        raise IntegrityError(str(exc)) from exc
    except sqlite3.Error as exc:
        raise DatabaseError(str(exc)) from exc


def _to_row(cursor: sqlite3.Cursor, values: Sequence[Any]) -> Row:
    return Row([column[0] for column in cursor.description], values)


class _StubTransaction(BackendTransaction):
    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    async def execute(self, sql: str, params: Sequence[Any] = ()) -> int:
        return _run(self._conn, sql, params).rowcount

    async def executemany(
        self, sql: str, seq_params: Iterable[Sequence[Any]]
    ) -> None:
        for params in seq_params:
            _run(self._conn, sql, params)

    async def fetchone(self, sql: str, params: Sequence[Any] = ()) -> Row | None:
        cursor = _run(self._conn, sql, params)
        values = cursor.fetchone()
        return None if values is None else _to_row(cursor, values)

    async def fetchall(self, sql: str, params: Sequence[Any] = ()) -> list[Row]:
        cursor = _run(self._conn, sql, params)
        return [_to_row(cursor, values) for values in cursor.fetchall()]


class _StubBackend(Backend):
    """Test double for migrator tests: implements the Backend contract
    over stdlib sqlite3, with whichever dialect label the config implies.

    Deliberately minimal — only what the migrator exercises. Real driver
    adapters live in ``pyxle_db.backends`` and have their own suites.
    """

    def __init__(self, config: DatabaseConfig, dialect: Dialect) -> None:
        self.dialect = dialect
        self._path = config.path or ":memory:"
        self._conn: sqlite3.Connection | None = None
        self._tx_depth = 0

    async def connect(self) -> None:
        if self._conn is None:
            self._conn = sqlite3.connect(self._path, isolation_level=None)
            _register_lock_stand_ins(self._conn)

    async def aclose(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    async def execute(self, sql: str, params: Sequence[Any] = ()) -> int:
        return _run(self._connection(), sql, params).rowcount

    async def executemany(
        self, sql: str, seq_params: Iterable[Sequence[Any]]
    ) -> None:
        conn = self._connection()
        conn.execute("BEGIN")
        try:
            for params in seq_params:
                _run(conn, sql, params)
        except BaseException:
            conn.execute("ROLLBACK")
            raise
        conn.execute("COMMIT")

    async def fetchone(self, sql: str, params: Sequence[Any] = ()) -> Row | None:
        cursor = _run(self._connection(), sql, params)
        values = cursor.fetchone()
        return None if values is None else _to_row(cursor, values)

    async def fetchall(self, sql: str, params: Sequence[Any] = ()) -> list[Row]:
        cursor = _run(self._connection(), sql, params)
        return [_to_row(cursor, values) for values in cursor.fetchall()]

    @asynccontextmanager
    async def transaction(self) -> AsyncIterator[BackendTransaction]:
        # Reentrant: the migrator's MySQL path opens an inner transaction
        # while its session-lock guard transaction is still open. The real
        # backend uses two pooled connections for that; the stub has one,
        # so only the outermost scope owns BEGIN/COMMIT/ROLLBACK.
        conn = self._connection()
        outermost = self._tx_depth == 0
        if outermost:
            conn.execute("BEGIN")
        self._tx_depth += 1
        try:
            yield _StubTransaction(conn)
        except BaseException:
            self._tx_depth -= 1
            if outermost:
                conn.execute("ROLLBACK")
            raise
        self._tx_depth -= 1
        if outermost:
            conn.execute("COMMIT")

    def _connection(self) -> sqlite3.Connection:
        assert self._conn is not None, "backend used before connect()"
        return self._conn


@pytest.fixture(autouse=True)
def _clear_events() -> Iterator[None]:
    _EVENTS.clear()
    yield


@pytest.fixture(autouse=True)
def _stub_backends(monkeypatch: pytest.MonkeyPatch) -> None:
    dialects = {
        dialect.name: dialect
        for dialect in (SQLITE_DIALECT, POSTGRESQL_DIALECT, MYSQL_DIALECT)
    }

    def fake_create_backend(config: DatabaseConfig) -> _StubBackend:
        return _StubBackend(config, dialects[config.backend])

    monkeypatch.setattr(pyxle_db.database, "create_backend", fake_create_backend)


# ---------------------------------------------------------------------------
# Helpers


def _write(dir_: Path, name: str, body: str) -> Path:
    path = dir_ / name
    path.write_text(body, encoding="utf-8")
    return path


def _paths(*names: str) -> list[Path]:
    return [Path("migrations") / name for name in names]


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


@pytest.fixture
def mdir(tmp_path: Path) -> Path:
    directory = tmp_path / "migrations"
    directory.mkdir()
    return directory


@pytest.fixture
def sqlite_db(tmp_path: Path) -> Database:
    return Database(tmp_path / "test.db")


# ---------------------------------------------------------------------------
# select_migration_files — pure override resolution, no I/O


def test_select_base_files_sorted_by_prefix() -> None:
    selected = select_migration_files(_paths("0002-b.sql", "0001-a.sql"), "sqlite")
    assert [p.name for p in selected] == ["0001-a.sql", "0002-b.sql"]


def test_select_orders_numerically_not_lexically() -> None:
    selected = select_migration_files(
        _paths("0010-ten.sql", "002-two.sql"), "sqlite"
    )
    assert [p.name for p in selected] == ["002-two.sql", "0010-ten.sql"]


def test_select_override_wins_only_for_its_dialect() -> None:
    files = _paths("0001-init.sql", "0001-init.postgresql.sql")
    assert [p.name for p in select_migration_files(files, "postgresql")] == [
        "0001-init.postgresql.sql"
    ]
    assert [p.name for p in select_migration_files(files, "sqlite")] == [
        "0001-init.sql"
    ]
    assert [p.name for p in select_migration_files(files, "mysql")] == [
        "0001-init.sql"
    ]


def test_select_backend_only_migration_skipped_elsewhere() -> None:
    files = _paths("0001-init.sql", "0002-pg-extras.postgresql.sql")
    assert [p.name for p in select_migration_files(files, "postgresql")] == [
        "0001-init.sql",
        "0002-pg-extras.postgresql.sql",
    ]
    assert [p.name for p in select_migration_files(files, "sqlite")] == [
        "0001-init.sql"
    ]


def test_select_rejects_duplicate_prefix_across_ids() -> None:
    with pytest.raises(MigrationError, match="share prefix"):
        select_migration_files(_paths("0001-a.sql", "0001-b.sql"), "sqlite")


def test_select_rejects_duplicate_prefix_even_when_one_is_an_override() -> None:
    files = _paths("0001-base.sql", "0001-pg.postgresql.sql")
    with pytest.raises(MigrationError, match="share prefix"):
        select_migration_files(files, "sqlite")


def test_select_rejects_two_base_files_with_same_id() -> None:
    with pytest.raises(MigrationError, match="same migration id"):
        select_migration_files(_paths("0001-init.sql", "0001_init.sql"), "sqlite")


def test_select_rejects_two_overrides_for_same_dialect() -> None:
    files = _paths("0001-init.postgresql.sql", "0001_init.postgresql.sql")
    with pytest.raises(MigrationError, match="same migration id"):
        select_migration_files(files, "postgresql")


def test_select_rejects_malformed_filename() -> None:
    with pytest.raises(MigrationError, match="does not match"):
        select_migration_files(_paths("no-prefix.sql"), "sqlite")


def test_select_rejects_unknown_dialect_suffix() -> None:
    with pytest.raises(MigrationError, match="does not match"):
        select_migration_files(_paths("0001-init.oracle.sql"), "sqlite")


def test_select_rejects_unknown_dialect_name() -> None:
    with pytest.raises(MigrationError, match="Unknown dialect"):
        select_migration_files(_paths("0001-init.sql"), "oracle")


# ---------------------------------------------------------------------------
# Discovery


def test_rejects_malformed_filenames(sqlite_db: Database, mdir: Path) -> None:
    _write(mdir, "no-prefix.sql", "SELECT 1;")
    with pytest.raises(MigrationError, match="does not match"):
        Migrator(sqlite_db, mdir).discover()


def test_rejects_duplicate_prefixes(sqlite_db: Database, mdir: Path) -> None:
    _write(mdir, "0001-a.sql", "CREATE TABLE a (id INT);")
    _write(mdir, "0001-b.sql", "CREATE TABLE b (id INT);")
    with pytest.raises(MigrationError, match="share prefix"):
        Migrator(sqlite_db, mdir).discover()


def test_rejects_same_id_collision(sqlite_db: Database, mdir: Path) -> None:
    _write(mdir, "0001-init.sql", "CREATE TABLE a (id INT);")
    _write(mdir, "0001_init.sql", "CREATE TABLE b (id INT);")
    with pytest.raises(MigrationError, match="same migration id"):
        Migrator(sqlite_db, mdir).discover()


def test_ignores_non_sql_files(sqlite_db: Database, mdir: Path) -> None:
    _write(mdir, "0001-init.sql", "CREATE TABLE t (id INT);")
    _write(mdir, "README.md", "notes")
    assert [m.id for m in Migrator(sqlite_db, mdir).discover()] == ["0001-init"]


def test_missing_directory_raises(sqlite_db: Database, tmp_path: Path) -> None:
    with pytest.raises(MigrationError, match="does not exist"):
        Migrator(sqlite_db, tmp_path / "nope")


def test_discover_resolves_override_per_dialect(mdir: Path, tmp_path: Path) -> None:
    base_sql = "CREATE TABLE t (id INTEGER);"
    override_sql = "CREATE TABLE t (id BIGSERIAL PRIMARY KEY);"
    base = _write(mdir, "0001-init.sql", base_sql)
    override = _write(mdir, "0001-init.postgresql.sql", override_sql)

    sqlite_found = Migrator(Database(tmp_path / "s.db"), mdir).discover()
    pg_found = Migrator(Database(PG_URL), mdir).discover()
    mysql_found = Migrator(Database(MYSQL_URL), mdir).discover()

    # Same dialect-independent id everywhere.
    assert [m.id for m in sqlite_found] == ["0001-init"]
    assert [m.id for m in pg_found] == ["0001-init"]

    # PostgreSQL gets the override; everyone else gets the base file.
    assert pg_found[0].source_path == override
    assert pg_found[0].sql == override_sql
    assert sqlite_found[0].source_path == base
    assert mysql_found[0].source_path == base

    # Checksums follow the effective file, so they differ per dialect.
    assert pg_found[0].checksum == _sha256(override_sql)
    assert sqlite_found[0].checksum == _sha256(base_sql)
    assert sqlite_found[0].checksum != pg_found[0].checksum


def test_discover_includes_backend_only_migration_for_its_dialect_only(
    mdir: Path, tmp_path: Path
) -> None:
    _write(mdir, "0001-init.sql", "CREATE TABLE t (id INTEGER);")
    _write(
        mdir,
        "0002-pg-extras.postgresql.sql",
        "CREATE EXTENSION IF NOT EXISTS pgcrypto;",
    )
    pg_ids = [m.id for m in Migrator(Database(PG_URL), mdir).discover()]
    sqlite_ids = [m.id for m in Migrator(Database(tmp_path / "s.db"), mdir).discover()]
    assert pg_ids == ["0001-init", "0002-pg-extras"]
    assert sqlite_ids == ["0001-init"]


# ---------------------------------------------------------------------------
# Application


async def test_apply_all_runs_in_order(mdir: Path, tmp_path: Path) -> None:
    _write(mdir, "0001-first.sql", "CREATE TABLE t (id INTEGER PRIMARY KEY);")
    _write(mdir, "0002-second.sql", "INSERT INTO t (id) VALUES (1);")
    db = await connect(tmp_path / "m.db", migrations_dir=mdir)
    try:
        rows = await db.fetchall("SELECT id FROM t")
        assert [r["id"] for r in rows] == [1]
        applied = await db.fetchall("SELECT id FROM schema_migrations ORDER BY id")
        assert [r["id"] for r in applied] == ["0001-first", "0002-second"]
    finally:
        await db.aclose()


async def test_apply_all_is_idempotent(mdir: Path, tmp_path: Path) -> None:
    _write(mdir, "0001-init.sql", "CREATE TABLE t (id INTEGER);")
    db_path = tmp_path / "m.db"

    db1 = await connect(db_path, migrations_dir=mdir)
    await db1.aclose()

    db2 = await connect(db_path, migrations_dir=mdir)
    try:
        rows = await db2.fetchall("SELECT id FROM schema_migrations")
        assert len(rows) == 1
    finally:
        await db2.aclose()


async def test_apply_all_returns_newly_applied_only(
    mdir: Path, tmp_path: Path
) -> None:
    _write(mdir, "0001-init.sql", "CREATE TABLE t (id INTEGER);")
    db = await connect(tmp_path / "m.db")
    try:
        migrator = Migrator(db, mdir)
        assert [m.id for m in await migrator.apply_all()] == ["0001-init"]

        _write(mdir, "0002-more.sql", "CREATE TABLE u (id INTEGER);")
        assert [m.id for m in await migrator.apply_all()] == ["0002-more"]
        assert await migrator.apply_all() == []
    finally:
        await db.aclose()


async def test_checksum_mismatch_raises(mdir: Path, tmp_path: Path) -> None:
    f = _write(mdir, "0001-init.sql", "CREATE TABLE t (id INTEGER);")
    db_path = tmp_path / "m.db"
    db1 = await connect(db_path, migrations_dir=mdir)
    await db1.aclose()

    # Tamper with the applied migration on disk.
    f.write_text("CREATE TABLE t (id INTEGER, v TEXT);", encoding="utf-8")

    with pytest.raises(MigrationChecksumMismatch):
        await connect(db_path, migrations_dir=mdir)


async def test_adding_override_after_apply_raises_checksum_mismatch(
    mdir: Path, tmp_path: Path
) -> None:
    # An override changes the effective file for this dialect, which is
    # an edit of an already-applied migration — it must be rejected.
    _write(mdir, "0001-init.sql", "CREATE TABLE t (id INTEGER);")
    db_path = tmp_path / "m.db"
    db = await connect(db_path, migrations_dir=mdir)
    await db.aclose()

    _write(mdir, "0001-init.sqlite.sql", "CREATE TABLE t (id INTEGER, v TEXT);")

    with pytest.raises(MigrationChecksumMismatch):
        await connect(db_path, migrations_dir=mdir)


async def test_applied_migration_deleted_raises(mdir: Path, tmp_path: Path) -> None:
    f = _write(mdir, "0001-init.sql", "CREATE TABLE t (id INTEGER);")
    db_path = tmp_path / "m.db"
    db1 = await connect(db_path, migrations_dir=mdir)
    await db1.aclose()

    f.unlink()

    with pytest.raises(MigrationError, match="no longer present"):
        await connect(db_path, migrations_dir=mdir)


async def test_multi_statement_migration(mdir: Path, tmp_path: Path) -> None:
    _write(
        mdir,
        "0001-multi.sql",
        """
        -- two tables in one file
        CREATE TABLE a (id INTEGER);
        CREATE TABLE b (id INTEGER, a_id INTEGER REFERENCES a(id));
        INSERT INTO a (id) VALUES (1);
        """,
    )
    db = await connect(tmp_path / "m.db", migrations_dir=mdir)
    try:
        row = await db.fetchone("SELECT id FROM a")
        assert row is not None
        assert row["id"] == 1
    finally:
        await db.aclose()


async def test_failed_migration_does_not_record(mdir: Path, tmp_path: Path) -> None:
    _write(mdir, "0001-init.sql", "CREATE TABLE t (id INTEGER);")
    _write(mdir, "0002-bad.sql", "CREATE TABLE t (id INTEGER);")  # dup name
    db_path = tmp_path / "m.db"
    with pytest.raises(MigrationError, match="failed"):
        await connect(db_path, migrations_dir=mdir)

    db = Database(db_path)
    try:
        rows = await db.fetchall("SELECT id FROM schema_migrations")
        assert [r["id"] for r in rows] == ["0001-init"]
    finally:
        await db.aclose()


async def test_failed_migration_rolls_back_all_its_statements(
    mdir: Path, tmp_path: Path
) -> None:
    _write(
        mdir,
        "0001-bad.sql",
        "CREATE TABLE good (id INTEGER); CREATE TABLE good (id INTEGER);",
    )
    db_path = tmp_path / "m.db"
    with pytest.raises(MigrationError, match="failed"):
        await connect(db_path, migrations_dir=mdir)

    db = Database(db_path)
    try:
        rows = await db.fetchall(
            "SELECT name FROM sqlite_master WHERE name = 'good'"
        )
        assert rows == []
    finally:
        await db.aclose()


async def test_apply_uses_override_for_active_dialect(
    mdir: Path, tmp_path: Path
) -> None:
    override_sql = "CREATE TABLE override_table (id INTEGER);"
    _write(mdir, "0001-init.sql", "CREATE TABLE base_table (id INTEGER);")
    _write(mdir, "0001-init.sqlite.sql", override_sql)
    db = await connect(tmp_path / "m.db", migrations_dir=mdir)
    try:
        tables = await db.fetchall(
            "SELECT name FROM sqlite_master "
            "WHERE type = 'table' AND name LIKE '%_table'"
        )
        assert [r["name"] for r in tables] == ["override_table"]

        # The recorded checksum is the effective (override) file's hash.
        recorded = await db.fetchone(
            "SELECT checksum FROM schema_migrations WHERE id = ?", ("0001-init",)
        )
        assert recorded is not None
        assert recorded["checksum"] == _sha256(override_sql)
    finally:
        await db.aclose()


async def test_apply_skips_backend_only_migrations_of_other_dialects(
    mdir: Path, tmp_path: Path
) -> None:
    _write(mdir, "0001-init.sql", "CREATE TABLE t (id INTEGER);")
    _write(mdir, "0002-pg.postgresql.sql", "CREATE EXTENSION pgcrypto;")
    db = await connect(tmp_path / "m.db", migrations_dir=mdir)
    try:
        applied = await db.fetchall("SELECT id FROM schema_migrations")
        assert [r["id"] for r in applied] == ["0001-init"]
    finally:
        await db.aclose()


# ── multi-source coexistence (one DB, two migration directories) ─────────────


async def test_two_sources_share_a_db_without_drift(tmp_path):
    """Two Migrators with separate directories + tracking tables must not see
    each other's migrations as drift — the host-app + pyxle-auth scenario."""
    from pyxle_db import Database
    from pyxle_db.migrator import Migrator

    db = Database(str(tmp_path / "multi.db"))
    await db.connect()

    app_dir = tmp_path / "app"
    app_dir.mkdir()
    (app_dir / "0001-app.sql").write_text(
        "CREATE TABLE app_t (id TEXT PRIMARY KEY);", encoding="utf-8"
    )
    plugin_dir = tmp_path / "plugin"
    plugin_dir.mkdir()
    (plugin_dir / "0001-plugin.sql").write_text(
        "CREATE TABLE plugin_t (id TEXT PRIMARY KEY);", encoding="utf-8"
    )

    # Default tracking table for the app; a namespaced one for the plugin.
    assert len(await Migrator(db, app_dir).apply_all()) == 1
    assert len(
        await Migrator(db, plugin_dir, tracking_table="schema_migrations_plugin").apply_all()
    ) == 1

    # Re-running EITHER migrator is a clean no-op — neither flags the other's
    # 0001 as a deleted migration.
    assert await Migrator(db, app_dir).apply_all() == []
    assert (
        await Migrator(db, plugin_dir, tracking_table="schema_migrations_plugin").apply_all()
        == []
    )
    await db.aclose()


async def test_invalid_tracking_table_rejected(tmp_path):
    from pyxle_db import Database
    from pyxle_db.errors import MigrationError
    from pyxle_db.migrator import Migrator

    d = tmp_path / "m"
    d.mkdir()
    db = Database(":memory:")
    with pytest.raises(MigrationError, match="tracking_table"):
        Migrator(db, d, tracking_table="bad-name; DROP TABLE x")


# ---------------------------------------------------------------------------
# Concurrent appliers — lost races and the per-dialect lock protocol.
#
# Multi-worker servers apply migrations from every worker's startup, so two
# processes can race one pending migration. These tests drive the exact
# interleaving deterministically through the stub (one scans "pending", the
# other applies, the first proceeds on its stale scan); the real-contention
# and multi-process variants live in test_migrator_concurrency.py.


async def test_lost_race_is_a_clean_skip(
    mdir: Path, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """A process whose pending scan went stale must skip, not crash."""
    _write(mdir, "0001-init.sql", "CREATE TABLE t (id INTEGER);")
    db_path = tmp_path / "race.db"
    winner_db = Database(db_path)
    loser_db = Database(db_path)
    try:
        loser = Migrator(loser_db, mdir)
        stale = loser.discover()[0]  # scanned before anything was applied
        winner_ids = [m.id for m in await Migrator(winner_db, mdir).apply_all()]
        assert winner_ids == ["0001-init"]

        with caplog.at_level(logging.INFO, logger="pyxle_db.migrator"):
            assert await loser._apply_one(stale) is False
        assert "already applied by another process" in caplog.text

        rows = await loser_db.fetchall("SELECT id FROM schema_migrations")
        assert [row["id"] for row in rows] == ["0001-init"]
        # The loser's own apply_all stays an honest no-op afterwards.
        assert await loser.apply_all() == []
    finally:
        await winner_db.aclose()
        await loser_db.aclose()


async def test_lost_race_with_different_content_still_fails(
    mdir: Path, tmp_path: Path
) -> None:
    """Losing the race is only safe when the winner applied the SAME file."""
    _write(mdir, "0001-init.sql", "CREATE TABLE t (id INTEGER);")
    db_path = tmp_path / "race.db"
    loser_db = Database(db_path)
    other_db = Database(db_path)
    try:
        loser = Migrator(loser_db, mdir)
        stale = loser.discover()[0]
        # Another process recorded 0001-init from different content.
        await other_db.execute(SQLITE_DIALECT.migrations_table_ddl)
        await other_db.execute(
            "INSERT INTO schema_migrations (id, checksum) VALUES (?, ?)",
            ("0001-init", "f" * 64),
        )
        with pytest.raises(MigrationChecksumMismatch) as excinfo:
            await loser._apply_one(stale)
        assert excinfo.value.recorded_hash == "f" * 64
        assert excinfo.value.actual_hash == stale.checksum
    finally:
        await loser_db.aclose()
        await other_db.aclose()


async def test_migration_whose_sql_violates_a_constraint_still_fails(
    mdir: Path, tmp_path: Path
) -> None:
    """An IntegrityError from the migration's own SQL is a real failure —
    the lost-race resolver must not mistake it for a race."""
    _write(
        mdir,
        "0001-init.sql",
        "CREATE TABLE t (id INTEGER PRIMARY KEY); INSERT INTO t (id) VALUES (1);",
    )
    _write(mdir, "0002-dup.sql", "INSERT INTO t (id) VALUES (1);")
    db_path = tmp_path / "m.db"
    with pytest.raises(MigrationError, match="'0002-dup' failed"):
        await connect(db_path, migrations_dir=mdir)

    db = Database(db_path)
    try:
        rows = await db.fetchall("SELECT id FROM schema_migrations")
        assert [row["id"] for row in rows] == ["0001-init"]
    finally:
        await db.aclose()


async def test_resolve_tracking_conflict_matching_row_skips(
    mdir: Path, tmp_path: Path
) -> None:
    _write(mdir, "0001-init.sql", "CREATE TABLE t (id INTEGER);")
    db = Database(tmp_path / "m.db")
    try:
        migrator = Migrator(db, mdir)
        migration = migrator.discover()[0]
        await db.execute(SQLITE_DIALECT.migrations_table_ddl)
        await db.execute(
            "INSERT INTO schema_migrations (id, checksum) VALUES (?, ?)",
            (migration.id, migration.checksum),
        )
        original = IntegrityError("UNIQUE constraint failed: schema_migrations.id")
        assert await migrator._resolve_tracking_conflict(migration, original) is False
    finally:
        await db.aclose()


async def test_resolve_tracking_conflict_mismatched_row_raises(
    mdir: Path, tmp_path: Path
) -> None:
    _write(mdir, "0001-init.sql", "CREATE TABLE t (id INTEGER);")
    db = Database(tmp_path / "m.db")
    try:
        migrator = Migrator(db, mdir)
        migration = migrator.discover()[0]
        await db.execute(SQLITE_DIALECT.migrations_table_ddl)
        await db.execute(
            "INSERT INTO schema_migrations (id, checksum) VALUES (?, ?)",
            (migration.id, "f" * 64),
        )
        original = IntegrityError("UNIQUE constraint failed: schema_migrations.id")
        with pytest.raises(MigrationChecksumMismatch):
            await migrator._resolve_tracking_conflict(migration, original)
    finally:
        await db.aclose()


async def test_resolve_tracking_conflict_without_row_wraps_original(
    mdir: Path, tmp_path: Path
) -> None:
    """No tracking row means the IntegrityError came from the migration's
    own SQL — it must fail exactly like any failing migration."""
    _write(mdir, "0001-init.sql", "CREATE TABLE t (id INTEGER);")
    db = Database(tmp_path / "m.db")
    try:
        migrator = Migrator(db, mdir)
        migration = migrator.discover()[0]
        await db.execute(SQLITE_DIALECT.migrations_table_ddl)
        original = IntegrityError("NOT NULL constraint failed: t.v")
        with pytest.raises(MigrationError, match="'0001-init' failed") as excinfo:
            await migrator._resolve_tracking_conflict(migration, original)
        assert excinfo.value.__cause__ is original
        assert not isinstance(excinfo.value, MigrationChecksumMismatch)
    finally:
        await db.aclose()


async def test_sqlite_locked_transaction_is_retried(
    mdir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """'database is locked' (another process held BEGIN IMMEDIATE past
    busy_timeout) means wait and re-enter — never a startup failure."""
    _write(mdir, "0001-init.sql", "CREATE TABLE t (id INTEGER);")
    db = Database(tmp_path / "m.db")
    try:
        migrator = Migrator(db, mdir)
        migration = migrator.discover()[0]
        await db.execute(SQLITE_DIALECT.migrations_table_ddl)
        real_transaction = db.transaction
        attempts = 0

        def locked_once():
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                raise OperationalError("database is locked")
            return real_transaction()

        monkeypatch.setattr(db, "transaction", locked_once)
        assert await migrator._apply_one(migration) is True
        assert attempts == 2
    finally:
        await db.aclose()


async def test_operational_error_on_server_backends_is_not_retried(
    mdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The locked-retry loop is SQLite-specific; a server backend's
    OperationalError stays a hard failure, exactly as before."""
    _write(mdir, "0001-init.sql", "CREATE TABLE t (id INTEGER);")
    db = Database(PG_URL)
    try:
        migrator = Migrator(db, mdir)
        migration = migrator.discover()[0]

        def refused():
            raise OperationalError("connection refused")

        monkeypatch.setattr(db, "transaction", refused)
        with pytest.raises(MigrationError, match="connection refused"):
            await migrator._apply_one(migration)
    finally:
        await db.aclose()


async def test_tracking_table_ddl_race_is_tolerated(
    mdir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """PostgreSQL can surface a raced CREATE TABLE IF NOT EXISTS as a
    duplicate-key error on its catalogs; when the table exists, the
    applier must shrug it off."""
    _write(mdir, "0001-init.sql", "CREATE TABLE t (id INTEGER);")
    db_path = tmp_path / "m.db"
    first = await connect(db_path, migrations_dir=mdir)  # table exists now
    await first.aclose()

    _write(mdir, "0002-more.sql", "CREATE TABLE u (id INTEGER);")
    db = Database(db_path)
    try:
        real_execute = db.execute

        async def racy_execute(sql, params=None):
            if sql.startswith("CREATE TABLE IF NOT EXISTS schema_migrations"):
                raise IntegrityError(
                    "duplicate key value violates unique constraint "
                    '"pg_type_typname_nsp_index"'
                )
            return await real_execute(sql, params)

        monkeypatch.setattr(db, "execute", racy_execute)
        applied = [m.id for m in await Migrator(db, mdir).apply_all()]
        assert applied == ["0002-more"]
    finally:
        await db.aclose()


def test_lock_identities_are_stable_and_namespaced() -> None:
    """Pinned on purpose: old and new plugin versions must contend on the
    SAME lock during a rolling deploy, so these values may never change."""
    assert _postgres_lock_keys("schema_migrations") == (1929704322, -1835172326)
    assert (
        _mysql_lock_name("schema_migrations")
        == "pyxle_db_migrations_7304f382929d7e1a7818b4330b666537"
    )
    # Distinct histories on one database never serialize against each other.
    assert _postgres_lock_keys("schema_migrations_pyxle_auth") != (
        _postgres_lock_keys("schema_migrations")
    )
    assert _mysql_lock_name("schema_migrations_pyxle_auth") != (
        _mysql_lock_name("schema_migrations")
    )
    for key in _postgres_lock_keys("schema_migrations"):
        assert -(2**31) <= key < 2**31
    name = _mysql_lock_name("schema_migrations")
    assert len(name) <= 64
    assert re.fullmatch(r"[a-z0-9_]+", name)


async def test_postgresql_applier_locks_inside_the_transaction(
    mdir: Path,
) -> None:
    """On PostgreSQL the applier must take the advisory lock inside the
    migration's transaction, re-check under it, and only then apply."""
    _write(mdir, "0001-init.sql", "CREATE TABLE t (id INTEGER);")
    db = Database(PG_URL)
    try:
        applied = [m.id for m in await Migrator(db, mdir).apply_all()]
        assert applied == ["0001-init"]

        high, low = _postgres_lock_keys("schema_migrations")
        assert ("pg_advisory_xact_lock", high, low) in _EVENTS

        sqls = [entry[1] for entry in _EVENTS if entry[0] == "sql"]
        isolation = next(
            i for i, s in enumerate(sqls) if s.startswith("SET TRANSACTION")
        )
        lock = next(
            i for i, s in enumerate(sqls) if "pg_advisory_xact_lock" in s
        )
        recheck = next(
            i for i, s in enumerate(sqls) if s.startswith("SELECT checksum")
        )
        insert = next(
            i
            for i, s in enumerate(sqls)
            if s.startswith("INSERT INTO schema_migrations")
        )
        assert isolation < lock < recheck < insert
    finally:
        await db.aclose()


async def test_postgresql_lost_race_is_a_clean_skip(mdir: Path) -> None:
    _write(mdir, "0001-init.sql", "CREATE TABLE t (id INTEGER);")
    db = Database(PG_URL)
    try:
        loser = Migrator(db, mdir)
        stale = loser.discover()[0]
        await Migrator(db, mdir).apply_all()
        assert await loser._apply_one(stale) is False
        assert await loser.apply_all() == []
    finally:
        await db.aclose()


async def test_mysql_applier_holds_the_session_lock_across_the_migration(
    mdir: Path,
) -> None:
    """On MySQL the applier must take GET_LOCK before touching anything and
    release only after the migration and its tracking insert."""
    _write(mdir, "0001-init.sql", "CREATE TABLE t (id INTEGER);")
    db = Database(MYSQL_URL)
    try:
        applied = [m.id for m in await Migrator(db, mdir).apply_all()]
        assert applied == ["0001-init"]

        name = _mysql_lock_name("schema_migrations")
        assert any(e[0] == "get_lock" and e[1] == name for e in _EVENTS)
        assert ("release_lock", name) in _EVENTS

        sqls = [entry[1] for entry in _EVENTS if entry[0] == "sql"]
        lock = next(i for i, s in enumerate(sqls) if "GET_LOCK" in s)
        recheck = next(
            i for i, s in enumerate(sqls) if s.startswith("SELECT checksum")
        )
        insert = next(
            i
            for i, s in enumerate(sqls)
            if s.startswith("INSERT INTO schema_migrations")
        )
        release = next(i for i, s in enumerate(sqls) if "RELEASE_LOCK" in s)
        assert lock < recheck < insert < release
    finally:
        await db.aclose()


async def test_mysql_lock_released_when_the_migration_fails(mdir: Path) -> None:
    _write(
        mdir,
        "0001-bad.sql",
        "CREATE TABLE t (id INTEGER); CREATE TABLE t (id INTEGER);",
    )
    db = Database(MYSQL_URL)
    try:
        with pytest.raises(MigrationError, match="'0001-bad' failed"):
            await Migrator(db, mdir).apply_all()
        name = _mysql_lock_name("schema_migrations")
        assert ("release_lock", name) in _EVENTS
    finally:
        await db.aclose()


async def test_mysql_lost_race_is_a_clean_skip(mdir: Path) -> None:
    _write(mdir, "0001-init.sql", "CREATE TABLE t (id INTEGER);")
    db = Database(MYSQL_URL)
    try:
        loser = Migrator(db, mdir)
        stale = loser.discover()[0]
        await Migrator(db, mdir).apply_all()
        assert await loser._apply_one(stale) is False
        assert await loser.apply_all() == []
    finally:
        await db.aclose()
