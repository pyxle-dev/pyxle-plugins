"""The pyxle-mail plugin: build a provider from config, register ``mail.service``.

Declare it in ``pyxle.config.json::plugins``. It depends on nothing else — no
database, no other plugin — so its position in the list doesn't matter. With
no configuration it registers a console (dry-run) service so local dev works
out of the box; misconfiguring a real provider fails loud at startup.
"""

from __future__ import annotations

import logging
from typing import Any, Mapping

from pyxle.plugins import PluginContext, PluginServiceError, PyxlePlugin

from pyxle_mail._version import __version__
from pyxle_mail.service import MailService
from pyxle_mail.settings import MailSettings

__all__ = ["PyxleMailPlugin", "plugin"]

_logger = logging.getLogger("pyxle_mail")

# Translate camelCase config keys to MailSettings fields, rejecting typos.
from pyxle_mail.settings import _SETTINGS_MAP  # noqa: E402  (single source of truth)


def _build_settings(user_settings: Mapping[str, Any]) -> MailSettings:
    overrides: dict[str, Any] = {}
    unknown: list[str] = []
    for key, value in user_settings.items():
        mapped = _SETTINGS_MAP.get(key)
        if mapped is None:
            unknown.append(key)
            continue
        overrides[mapped] = value
    if unknown:
        raise PluginServiceError(
            f"pyxle-mail: unknown settings keys in plugin config: {sorted(unknown)}. "
            f"Supported: {sorted(_SETTINGS_MAP)}."
        )
    return MailSettings.from_env(overrides)


class PyxleMailPlugin(PyxlePlugin):
    name = "pyxle-mail"
    version = __version__

    async def on_startup(self, ctx: PluginContext) -> None:
        settings = _build_settings(self.settings or {})
        provider = settings.build_provider()
        ctx.register("mail.service", MailService(provider, settings))
        ctx.register("mail.settings", settings)
        _logger.info(
            "pyxle-mail: service ready (provider=%s%s, from=%s)",
            provider.name,
            ", dry-run" if settings.dry_run else "",
            settings.from_address or "<unset>",
        )
        # The console provider accepts every message and delivers none of it.
        # That is the right default for local development and a silent outage in
        # production, and until now the only trace of it was an INFO line — below
        # the root logger's default level, so it never appeared at all. An
        # explicit ``dryRun`` is a deliberate choice and stays quiet; falling
        # back to console because nothing was configured does not.
        if provider.name == "console" and not settings.dry_run:
            _logger.warning(
                "pyxle-mail: no provider configured — using 'console', which logs "
                "messages instead of sending them. Every send will report success "
                "and deliver nothing. Set PYXLE_MAIL_PROVIDER=smtp or resend (plus "
                "PYXLE_MAIL_FROM) to send real mail, or set dryRun to silence this."
            )


# Convention: Pyxle's loader imports ``plugin`` from this module.
plugin = PyxleMailPlugin
