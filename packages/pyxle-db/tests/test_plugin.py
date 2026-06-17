"""Smoke tests for the ``pyxle-db`` plugin entry point.

Covers the standalone lifecycle — opening the database from the ``path``
and ``url`` settings (including the ``env:`` secret indirection),
registering the ``db.database`` / ``db.url`` / ``db.path`` services, and
closing via ``aclose()`` on shutdown — without the pyxle-auth layer in
front, so a plugin author who wants pyxle-db on its own (e.g. for a CLI
or a custom auth stack) has confidence the minimal wiring works.
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

from pyxle_db import ConfigurationError, Database
from pyxle_db.plugin import _database_target


class _FakeSettings:
    def __init__(self, project_root: Path) -> None:
        self.project_root = project_root


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
        assert ctx.require("db.url") == f"sqlite:///{db_path}"
    finally:
        await run_shutdown([plugin], ctx)


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


async def test_url_setting_takes_precedence_over_path(tmp_path: Path) -> None:
    spec = PluginSpec.from_config_entry(
        {
            "name": "pyxle-db",
            "settings": {
                "path": "ignored.db",
                "url": "sqlite:///custom/app.db",
            },
        }
    )
    [plugin] = load_plugins([spec])
    ctx = PluginContext(settings=_FakeSettings(project_root=tmp_path))
    await run_startup([plugin], ctx)
    try:
        expected = (tmp_path / "custom" / "app.db").resolve()
        assert ctx.require("db.path") == expected
        assert expected.parent.is_dir()
        # The losing ``path`` setting was never touched.
        assert not (tmp_path / "ignored.db").exists()
    finally:
        await run_shutdown([plugin], ctx)


async def test_url_env_indirection_resolves_at_startup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "from_env.db"
    monkeypatch.setenv("PYXLE_DB_TEST_URL", f"sqlite:///{target}")
    spec = PluginSpec.from_config_entry(
        {"name": "pyxle-db", "settings": {"url": "env:PYXLE_DB_TEST_URL"}}
    )
    [plugin] = load_plugins([spec])
    ctx = PluginContext(settings=_FakeSettings(project_root=tmp_path))
    await run_startup([plugin], ctx)
    try:
        assert ctx.require("db.path") == target
        # ``db.url`` is the redacted string, never the raw env value.
        assert ctx.require("db.url") == f"sqlite:///{target}"
    finally:
        await run_shutdown([plugin], ctx)


async def test_url_env_indirection_unset_raises_configuration_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("PYXLE_DB_TEST_MISSING", raising=False)
    spec = PluginSpec.from_config_entry(
        {"name": "pyxle-db", "settings": {"url": "env:PYXLE_DB_TEST_MISSING"}}
    )
    [plugin] = load_plugins([spec])
    ctx = PluginContext(settings=_FakeSettings(project_root=tmp_path))
    with pytest.raises(ConfigurationError, match="PYXLE_DB_TEST_MISSING"):
        await plugin.on_startup(ctx)


async def test_url_env_indirection_without_name_raises(tmp_path: Path) -> None:
    spec = PluginSpec.from_config_entry(
        {"name": "pyxle-db", "settings": {"url": "env:"}}
    )
    [plugin] = load_plugins([spec])
    ctx = PluginContext(settings=_FakeSettings(project_root=tmp_path))
    with pytest.raises(ConfigurationError, match="names no variable"):
        await plugin.on_startup(ctx)


def test_server_url_passes_through_untouched(tmp_path: Path) -> None:
    """Server URLs must reach :func:`pyxle_db.connect` verbatim — no path
    resolution, no directory creation — and still win over ``path``."""
    url = "postgresql://app:s3cret@db.internal:5432/app?sslmode=require"
    target = _database_target({"path": "ignored.db", "url": url}, tmp_path)
    assert target == url


async def test_shutdown_closes_database_via_aclose(tmp_path: Path) -> None:
    spec = PluginSpec.from_config_entry("pyxle-db")
    [plugin] = load_plugins([spec])
    ctx = PluginContext(settings=_FakeSettings(project_root=tmp_path))
    await run_startup([plugin], ctx)
    db: Database = ctx.require("db.database")

    closed = False
    original_aclose = db.aclose

    async def spy() -> None:
        nonlocal closed
        closed = True
        await original_aclose()

    db.aclose = spy  # type: ignore[method-assign]
    await run_shutdown([plugin], ctx)
    assert closed


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


async def test_orm_settings_register_engine_and_session_factory(tmp_path: Path) -> None:
    spec = PluginSpec.from_config_entry(
        {
            "name": "pyxle-db",
            "settings": {"path": "orm.db", "orm": {"pool": {"poolSize": 7}}},
        }
    )
    [plugin] = load_plugins([spec])
    ctx = PluginContext(settings=_FakeSettings(project_root=tmp_path))
    await run_startup([plugin], ctx)
    try:
        from pyxle_db.orm import Engine

        engine = ctx.require("db.orm.engine")
        assert isinstance(engine, Engine)
        assert ctx.has("db.orm.session_factory")
        # The plugin still opened the explicit-SQL handle too.
        assert ctx.has("db.database")
    finally:
        await run_shutdown([plugin], ctx)


async def test_no_orm_settings_skips_engine(tmp_path: Path) -> None:
    spec = PluginSpec.from_config_entry({"name": "pyxle-db", "settings": {"path": "x.db"}})
    [plugin] = load_plugins([spec])
    ctx = PluginContext(settings=_FakeSettings(project_root=tmp_path))
    await run_startup([plugin], ctx)
    try:
        assert not ctx.has("db.orm.engine")
        assert ctx.has("db.auto_transactions")
    finally:
        await run_shutdown([plugin], ctx)
