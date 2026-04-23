"""End-to-end plugin-system test for pyxle-db + pyxle-auth together.

Exercises the full lifecycle path exactly as a real Pyxle app would:

1. Build PluginSpecs from config-shaped data.
2. ``load_plugins`` resolves pyxle-db and pyxle-auth to their classes.
3. ``run_startup`` runs db first, then auth (which pulls db's service
   off the context).
4. ``run_shutdown`` tears them down in reverse.

Covers the service naming conventions and the settings→AuthSettings
translation layer so either side can refactor safely.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from pyxle.plugins import (
    PluginContext,
    PluginError,
    PluginServiceError,
    PluginSpec,
    load_plugins,
    run_shutdown,
    run_startup,
)
from pyxle_auth import AuthService


@pytest.fixture
def anyio_backend() -> str:  # pragma: no cover - fixture wiring
    return "asyncio"


class _FakeSettings:
    """Minimal stand-in for DevServerSettings — plugins read only
    ``project_root`` off it. Lets us drive the full flow from pytest
    without pulling the whole Pyxle devserver stack in."""

    def __init__(self, project_root: Path) -> None:
        self.project_root = project_root


@pytest.mark.anyio
async def test_db_and_auth_startup_end_to_end(tmp_path: Path) -> None:
    # Config as a user would write it in ``pyxle.config.json``.
    config_entries = [
        {"name": "pyxle-db", "settings": {"path": "data/app.db"}},
        {
            "name": "pyxle-auth",
            "settings": {
                # Use the cheap test argon params so the schema setup
                # doesn't spend real wall-clock time.
                "argonTimeCost": 1,
                "argonMemoryKib": 8,
                "argonParallelism": 1,
                "cookieSecure": False,
                "strict": False,
                "ensureSchema": True,
            },
        },
    ]

    specs = [PluginSpec.from_config_entry(e) for e in config_entries]
    plugins = load_plugins(specs)
    assert [p.name for p in plugins] == ["pyxle-db", "pyxle-auth"]

    ctx = PluginContext(settings=_FakeSettings(project_root=tmp_path))
    await run_startup(plugins, ctx)

    # pyxle-db registered services
    assert ctx.has("db.database")
    assert (tmp_path / "data" / "app.db").parent.is_dir()

    # pyxle-auth registered services
    auth: AuthService = ctx.require("auth.service")
    settings = ctx.require("auth.settings")

    # Full sign-up smoke test proves the schema is in place and the
    # service is genuinely usable via the plugin registration path.
    user, cookie = await auth.sign_up(
        email="alice@example.com", password="correcthorse"
    )
    assert user.email == "alice@example.com"
    assert cookie.value

    # Shutdown runs in reverse. The DB's close is idempotent so we
    # can't easily observe "was it called" without monkey-patching;
    # we settle for "shutdown didn't raise".
    await run_shutdown(plugins, ctx)


@pytest.mark.anyio
async def test_auth_without_db_raises(tmp_path: Path) -> None:
    """Running pyxle-auth without pyxle-db in front produces a
    useful error — not a generic KeyError."""
    spec = PluginSpec.from_config_entry(
        {
            "name": "pyxle-auth",
            "settings": {
                "argonTimeCost": 1,
                "argonMemoryKib": 8,
                "argonParallelism": 1,
                "cookieSecure": False,
                "strict": False,
            },
        }
    )
    [plugin] = load_plugins([spec])
    ctx = PluginContext(settings=_FakeSettings(project_root=tmp_path))
    with pytest.raises(PluginError, match="pyxle-db"):
        await run_startup([plugin], ctx)


@pytest.mark.anyio
async def test_unknown_settings_key_surfaces_clearly(tmp_path: Path) -> None:
    # A plugin-authoring typo should be loud, not silent.
    entries = [
        "pyxle-db",
        {
            "name": "pyxle-auth",
            "settings": {
                "argonTimeCost": 1,
                "argonMemoryKib": 8,
                "argonParallelism": 1,
                "cookieSecure": False,
                "strict": False,
                "cookeiSecure": True,  # intentional typo
            },
        },
    ]
    specs = [PluginSpec.from_config_entry(e) for e in entries]
    plugins = load_plugins(specs)
    ctx = PluginContext(settings=_FakeSettings(project_root=tmp_path))
    with pytest.raises(PluginError, match="cookeiSecure"):
        await run_startup(plugins, ctx)


@pytest.mark.anyio
async def test_get_auth_service_and_settings_shortcuts(tmp_path: Path) -> None:
    """Django-style import helpers return the same instances
    ``request.app.state.pyxle_plugins.require(...)`` would, once the
    devserver's lifespan has installed the active context."""
    from pyxle.plugins import set_active_context
    from pyxle_auth import AuthService, AuthSettings, get_auth_service, get_auth_settings

    entries = [
        {"name": "pyxle-db", "settings": {"path": "app.db"}},
        {
            "name": "pyxle-auth",
            "settings": {
                "argonTimeCost": 1,
                "argonMemoryKib": 8,
                "argonParallelism": 1,
                "cookieSecure": False,
                "strict": False,
            },
        },
    ]
    specs = [PluginSpec.from_config_entry(e) for e in entries]
    plugins = load_plugins(specs)
    ctx = PluginContext(settings=_FakeSettings(project_root=tmp_path))
    await run_startup(plugins, ctx)
    set_active_context(ctx)
    try:
        # Shortcut returns the exact instance the registry holds.
        assert get_auth_service() is ctx.require("auth.service")
        assert isinstance(get_auth_service(), AuthService)
        # Same for settings.
        assert get_auth_settings() is ctx.require("auth.settings")
        assert isinstance(get_auth_settings(), AuthSettings)
    finally:
        set_active_context(None)
