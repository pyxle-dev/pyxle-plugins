"""Plugin lifecycle: startup registers the services; config is validated."""

from __future__ import annotations

import pytest

from pyxle.plugins import PluginContext, PluginServiceError, set_active_context
from pyxle_mail import MailService, MailSettings
from pyxle_mail.plugin import PyxleMailPlugin


class _FakeAppSettings:
    """Minimal stand-in — the mail plugin reads nothing off it."""
    def __init__(self) -> None:
        self.project_root = "/tmp"


def _ctx() -> PluginContext:
    return PluginContext(settings=_FakeAppSettings())


def _clear_env(monkeypatch):
    for k in list(__import__("os").environ):
        if k.startswith("PYXLE_MAIL_"):
            monkeypatch.delenv(k, raising=False)


async def test_startup_registers_service_and_settings(monkeypatch):
    _clear_env(monkeypatch)
    ctx = _ctx()
    plugin = PyxleMailPlugin()
    plugin.settings = {"fromAddress": "hi@p.dev", "fromName": "Pyxle"}
    await plugin.on_startup(ctx)

    svc = ctx.require("mail.service")
    assert isinstance(svc, MailService)
    assert svc.provider_name == "console"          # default
    assert isinstance(ctx.require("mail.settings"), MailSettings)


async def test_unknown_config_key_is_loud(monkeypatch):
    _clear_env(monkeypatch)
    plugin = PyxleMailPlugin()
    plugin.settings = {"fromAdress": "typo@p.dev"}  # misspelled
    with pytest.raises(PluginServiceError, match="fromAdress"):
        await plugin.on_startup(_ctx())


async def test_misconfigured_provider_fails_startup(monkeypatch):
    _clear_env(monkeypatch)
    plugin = PyxleMailPlugin()
    plugin.settings = {"provider": "resend"}  # no from, no key
    with pytest.raises(Exception):
        await plugin.on_startup(_ctx())


async def test_get_mail_service_shortcut(monkeypatch):
    _clear_env(monkeypatch)
    ctx = _ctx()
    plugin = PyxleMailPlugin()
    plugin.settings = {}
    await plugin.on_startup(ctx)
    set_active_context(ctx)
    try:
        from pyxle_mail import get_mail_service
        assert get_mail_service() is ctx.require("mail.service")
    finally:
        set_active_context(None)
