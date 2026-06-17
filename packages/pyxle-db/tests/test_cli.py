"""Tests for the ``pyxle-db`` migration CLI.

These are synchronous tests: ``main()`` runs its own event loop via
``asyncio.run``, so the test must not already be inside one. The resulting
SQLite database is inspected with the stdlib ``sqlite3`` driver.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from pyxle_db.cli import build_parser, main
from pyxle_db.cli._context import resolve_context
from pyxle_db.errors import ConfigurationError

_MIGRATION = "CREATE TABLE widgets (id INTEGER PRIMARY KEY, name TEXT);\n"


def _make_project(
    tmp_path: Path, *, with_plugin: bool = True, with_migration: bool = True
) -> Path:
    proj = tmp_path / "proj"
    proj.mkdir()
    plugins = (
        [{"name": "pyxle-db", "settings": {"path": "./data/app.db", "migrationsDir": "migrations"}}]
        if with_plugin
        else []
    )
    (proj / "pyxle.config.json").write_text(json.dumps({"plugins": plugins}), encoding="utf-8")
    if with_migration:
        mig = proj / "migrations"
        mig.mkdir()
        (mig / "0001-init.sql").write_text(_MIGRATION, encoding="utf-8")
    return proj


def _table_exists(db_file: Path, table: str) -> bool:
    con = sqlite3.connect(db_file)
    try:
        cur = con.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table,)
        )
        return cur.fetchone() is not None
    finally:
        con.close()


def test_migrate_applies_pending(tmp_path: Path) -> None:
    proj = _make_project(tmp_path)
    assert main(["migrate", "--project", str(proj)]) == 0
    assert _table_exists(proj / "data" / "app.db", "widgets")


def test_migrate_is_idempotent(tmp_path: Path) -> None:
    proj = _make_project(tmp_path)
    assert main(["migrate", "--project", str(proj)]) == 0
    # A second run is a clean no-op.
    assert main(["migrate", "--project", str(proj)]) == 0
    assert _table_exists(proj / "data" / "app.db", "widgets")


def test_migrate_dry_run_changes_nothing(tmp_path: Path) -> None:
    proj = _make_project(tmp_path)
    assert main(["migrate", "--project", str(proj), "--dry-run"]) == 0
    db_file = proj / "data" / "app.db"
    # connect() may create the file, but the migration must NOT have run.
    if db_file.exists():
        assert not _table_exists(db_file, "widgets")


def test_status_runs(tmp_path: Path) -> None:
    proj = _make_project(tmp_path)
    assert main(["status", "--project", str(proj)]) == 0
    main(["migrate", "--project", str(proj)])
    assert main(["status", "--project", str(proj)]) == 0


def test_missing_plugin_returns_error(tmp_path: Path) -> None:
    proj = _make_project(tmp_path, with_plugin=False)
    assert main(["migrate", "--project", str(proj)]) == 1


def test_missing_migrations_dir_returns_error(tmp_path: Path) -> None:
    proj = _make_project(tmp_path, with_migration=False)
    assert main(["migrate", "--project", str(proj)]) == 1


def test_resolve_context_finds_settings(tmp_path: Path) -> None:
    proj = _make_project(tmp_path)
    ctx = resolve_context(proj)
    assert ctx.migrations_dir == (proj / "migrations").resolve()
    assert ctx.settings["migrationsDir"] == "migrations"


def test_resolve_context_without_plugin_raises(tmp_path: Path) -> None:
    proj = _make_project(tmp_path, with_plugin=False)
    with pytest.raises(ConfigurationError):
        resolve_context(proj)


def test_parser_requires_a_command() -> None:
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args([])
