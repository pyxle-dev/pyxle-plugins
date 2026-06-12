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
import sqlite3
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, AsyncIterator, Iterable, Sequence

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
from pyxle_db.errors import DatabaseError, IntegrityError
from pyxle_db.migrator import select_migration_files
from pyxle_db.rows import Row
from pyxle_db.url import DatabaseConfig

PG_URL = "postgresql://app:secret@localhost/app"
MYSQL_URL = "mysql://app:secret@localhost/app"


# ---------------------------------------------------------------------------
# Stub backend — SQLite storage behind any dialect label


def _run(conn: sqlite3.Connection, sql: str, params: Sequence[Any]) -> sqlite3.Cursor:
    try:
        return conn.execute(sql, tuple(params))
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

    async def connect(self) -> None:
        if self._conn is None:
            self._conn = sqlite3.connect(self._path, isolation_level=None)

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
        conn = self._connection()
        conn.execute("BEGIN")
        try:
            yield _StubTransaction(conn)
        except BaseException:
            conn.execute("ROLLBACK")
            raise
        conn.execute("COMMIT")

    def _connection(self) -> sqlite3.Connection:
        assert self._conn is not None, "backend used before connect()"
        return self._conn


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
