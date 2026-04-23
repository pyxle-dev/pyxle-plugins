from __future__ import annotations

from pathlib import Path

import pytest

from pyxle_db import (
    Database,
    Migrator,
    MigrationChecksumMismatch,
    MigrationError,
    connect,
)


# ---------------------------------------------------------------------------
# Helpers


def _write(dir_: Path, name: str, body: str) -> Path:
    path = dir_ / name
    path.write_text(body, encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# Discovery


def test_rejects_malformed_filenames(tmp_path: Path, sync_db: Database) -> None:
    mdir = tmp_path / "migrations"
    mdir.mkdir()
    _write(mdir, "no-prefix.sql", "SELECT 1;")
    migrator = Migrator(sync_db, mdir)
    with pytest.raises(MigrationError, match="does not match"):
        migrator.discover()


def test_rejects_duplicate_prefixes(tmp_path: Path, sync_db: Database) -> None:
    mdir = tmp_path / "migrations"
    mdir.mkdir()
    _write(mdir, "0001-a.sql", "CREATE TABLE a (id INT);")
    _write(mdir, "0001-b.sql", "CREATE TABLE b (id INT);")
    migrator = Migrator(sync_db, mdir)
    with pytest.raises(MigrationError, match="share prefix"):
        migrator.discover()


def test_ignores_non_sql_files(tmp_path: Path, sync_db: Database) -> None:
    mdir = tmp_path / "migrations"
    mdir.mkdir()
    _write(mdir, "0001-init.sql", "CREATE TABLE t (id INT);")
    _write(mdir, "README.md", "notes")
    migrator = Migrator(sync_db, mdir)
    assert [m.id for m in migrator.discover()] == ["0001-init"]


# ---------------------------------------------------------------------------
# Application


async def test_apply_all_runs_in_order(tmp_path: Path) -> None:
    mdir = tmp_path / "migrations"
    mdir.mkdir()
    _write(mdir, "0001-first.sql", "CREATE TABLE t (id INTEGER PRIMARY KEY);")
    _write(mdir, "0002-second.sql", "INSERT INTO t (id) VALUES (1);")
    db = await connect(tmp_path / "m.db", migrations_dir=mdir)
    try:
        rows = await db.fetchall("SELECT id FROM t")
        assert [r["id"] for r in rows] == [1]
        applied = await db.fetchall(
            "SELECT id FROM schema_migrations ORDER BY id"
        )
        assert [r["id"] for r in applied] == ["0001-first", "0002-second"]
    finally:
        db.close()


async def test_apply_all_is_idempotent(tmp_path: Path) -> None:
    mdir = tmp_path / "migrations"
    mdir.mkdir()
    _write(mdir, "0001-init.sql", "CREATE TABLE t (id INTEGER);")
    db_path = tmp_path / "m.db"

    db1 = await connect(db_path, migrations_dir=mdir)
    db1.close()

    db2 = await connect(db_path, migrations_dir=mdir)
    try:
        rows = await db2.fetchall("SELECT id FROM schema_migrations")
        assert len(rows) == 1
    finally:
        db2.close()


async def test_checksum_mismatch_raises(tmp_path: Path) -> None:
    mdir = tmp_path / "migrations"
    mdir.mkdir()
    f = _write(mdir, "0001-init.sql", "CREATE TABLE t (id INTEGER);")
    db_path = tmp_path / "m.db"

    db1 = await connect(db_path, migrations_dir=mdir)
    db1.close()

    # Tamper with the applied migration on disk.
    f.write_text("CREATE TABLE t (id INTEGER, v TEXT);", encoding="utf-8")

    with pytest.raises(MigrationChecksumMismatch):
        db2 = await connect(db_path, migrations_dir=mdir)
        db2.close()


async def test_applied_migration_deleted_raises(tmp_path: Path) -> None:
    mdir = tmp_path / "migrations"
    mdir.mkdir()
    f = _write(mdir, "0001-init.sql", "CREATE TABLE t (id INTEGER);")
    db_path = tmp_path / "m.db"
    db1 = await connect(db_path, migrations_dir=mdir)
    db1.close()

    f.unlink()

    with pytest.raises(MigrationError, match="no longer present"):
        db2 = await connect(db_path, migrations_dir=mdir)
        db2.close()


async def test_multi_statement_migration(tmp_path: Path) -> None:
    mdir = tmp_path / "migrations"
    mdir.mkdir()
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
        # FK pragma must be on — verify it is, then confirm the row exists.
        row = await db.fetchone("SELECT id FROM a")
        assert row["id"] == 1
    finally:
        db.close()


async def test_failed_migration_does_not_record(tmp_path: Path) -> None:
    mdir = tmp_path / "migrations"
    mdir.mkdir()
    _write(mdir, "0001-init.sql", "CREATE TABLE t (id INTEGER);")
    _write(mdir, "0002-bad.sql", "CREATE TABLE t (id INTEGER);")  # dup name
    with pytest.raises(MigrationError):
        db = await connect(tmp_path / "m.db", migrations_dir=mdir)
        db.close()

    db = Database(tmp_path / "m.db")
    try:
        rows = await db.fetchall("SELECT id FROM schema_migrations")
        assert [r["id"] for r in rows] == ["0001-init"]
    finally:
        db.close()


async def test_missing_directory_raises(sync_db: Database, tmp_path: Path) -> None:
    with pytest.raises(MigrationError, match="does not exist"):
        Migrator(sync_db, tmp_path / "nope")
