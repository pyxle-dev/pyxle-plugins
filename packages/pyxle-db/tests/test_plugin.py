"""Smoke tests for the ``pyxle-db`` plugin entry point.

Covers the standalone lifecycle — opening the database, registering
the ``db.database`` service, and closing on shutdown — without the
pyxle-auth layer in front, so a plugin-author who wants pyxle-db on
its own (e.g. for a CLI or a custom auth stack) has confidence the
minimal wiring works.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from pyxle.plugins import (
    PluginContext,
    PluginSpec,
    load_plugins,
    run_shutdown,
    run_startup,
)

from pyxle_db import Database


@pytest.fixture
def anyio_backend() -> str:  # pragma: no cover - fixture wiring
    return "asyncio"


class _FakeSettings:
    def __init__(self, project_root: Path) -> None:
        self.project_root = project_root


@pytest.mark.anyio
async def test_default_config_opens_db_at_data_app_db(tmp_path: Path) -> None:
    spec = PluginSpec.from_config_entry("pyxle-db")
    [plugin] = load_plugins([spec])
    ctx = PluginContext(settings=_FakeSettings(project_root=tmp_path))
    await run_startup([plugin], ctx)
    try:
        db = ctx.require("db.database")
        assert isinstance(db, Database)
        db_path = ctx.require("db.path")
        assert db_path == (tmp_path / "data" / "app.db").resolve()
        assert db_path.parent.is_dir()
    finally:
        await run_shutdown([plugin], ctx)


@pytest.mark.anyio
async def test_absolute_path_preserved(tmp_path: Path) -> None:
    target = tmp_path / "custom.db"
    spec = PluginSpec.from_config_entry(
        {"name": "pyxle-db", "settings": {"path": str(target)}}
    )
    [plugin] = load_plugins([spec])
    ctx = PluginContext(settings=_FakeSettings(project_root=tmp_path))
    await run_startup([plugin], ctx)
    try:
        assert ctx.require("db.path") == target
    finally:
        await run_shutdown([plugin], ctx)


@pytest.mark.anyio
async def test_runs_migrations_from_configured_dir(tmp_path: Path) -> None:
    migrations = tmp_path / "migrations"
    migrations.mkdir()
    (migrations / "0001-init.sql").write_text(
        "CREATE TABLE greetings (id INTEGER PRIMARY KEY, text TEXT);",
        encoding="utf-8",
    )

    spec = PluginSpec.from_config_entry(
        {
            "name": "pyxle-db",
            "settings": {"path": "test.db", "migrationsDir": "migrations"},
        }
    )
    [plugin] = load_plugins([spec])
    ctx = PluginContext(settings=_FakeSettings(project_root=tmp_path))
    await run_startup([plugin], ctx)
    try:
        db: Database = ctx.require("db.database")
        rows = await db.fetchall("SELECT id FROM schema_migrations")
        assert [r["id"] for r in rows] == ["0001-init"]
    finally:
        await run_shutdown([plugin], ctx)


@pytest.mark.anyio
async def test_missing_migrations_dir_is_silent(tmp_path: Path) -> None:
    """When ``migrationsDir`` points nowhere, the plugin skips migrations
    instead of failing — lets host apps ship a ``migrations/`` folder
    lazily without tripping on an empty one."""
    spec = PluginSpec.from_config_entry(
        {
            "name": "pyxle-db",
            "settings": {"path": "test.db", "migrationsDir": "absent/"},
        }
    )
    [plugin] = load_plugins([spec])
    ctx = PluginContext(settings=_FakeSettings(project_root=tmp_path))
    await run_startup([plugin], ctx)
    try:
        db: Database = ctx.require("db.database")
        # The DB was still opened.
        assert isinstance(db, Database)
    finally:
        await run_shutdown([plugin], ctx)


@pytest.mark.anyio
async def test_get_database_shortcut_resolves_via_active_context(
    tmp_path: Path,
) -> None:
    """``from pyxle_db import get_database`` is the Django-style short
    form — it should return the same instance as
    ``ctx.require('db.database')`` once the devserver's lifespan has
    set the active context."""
    from pyxle.plugins import set_active_context
    from pyxle_db import get_database

    spec = PluginSpec.from_config_entry("pyxle-db")
    [plugin] = load_plugins([spec])
    ctx = PluginContext(settings=_FakeSettings(project_root=tmp_path))
    await run_startup([plugin], ctx)
    set_active_context(ctx)
    try:
        direct = ctx.require("db.database")
        shortcut = get_database()
        assert shortcut is direct
    finally:
        set_active_context(None)
        await run_shutdown([plugin], ctx)
