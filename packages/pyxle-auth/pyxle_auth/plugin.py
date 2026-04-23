"""Pyxle plugin entry point for ``pyxle-auth``.

Depends on ``pyxle-db`` being listed BEFORE this plugin in the host
app's :mod:`pyxle.config` ``plugins`` array — the auth service needs a
live :class:`pyxle_db.Database` registered on the plugin context.

Registered services:

* ``auth.service`` — an :class:`AuthService` ready to call from
  ``@action`` handlers (sign-in, sign-up, session resolution).
* ``auth.settings`` — the resolved :class:`AuthSettings` for apps that
  want to read cookie name / lifetime / rate-limit caps from the same
  source of truth.

Config shape (both sugar forms accepted)::

    {
      "plugins": [
        "pyxle-db",
        {
          "name": "pyxle-auth",
          "settings": {
            "cookieDomain": ".pyxle.app",
            "cookieSecure": true,
            "sessionTtlSeconds": 2592000,
            "requireEmailVerified": false,
            "ensureSchema": true
          }
        }
      ]
    }

Settings keys (all optional):

* ``cookieName`` — session cookie name. Default ``pyxle_session``.
* ``cookieDomain`` — e.g. ``.pyxle.app``. Default unset (host-bound).
* ``cookieSecure`` — ``True`` in production. Default ``True`` (strict).
* ``cookieSameSite`` — ``Lax`` / ``Strict`` / ``None``. Default ``Lax``.
* ``sessionTtlSeconds`` — sliding session lifetime. Default 30d.
* ``sessionAbsoluteMaxSeconds`` — hard cap. Default 90d.
* ``requireEmailVerified`` — gate sign-in on verified email. Default ``False``.
* ``rateLimitSignInPerHour`` — per-identifier cap. Default 10.
* ``rateLimitSignUpPerHour`` — per-IP cap. Default 5.
* ``strict`` — if ``False``, relax the "secure cookie required"
  invariant so dev servers work over plain HTTP. Default ``True``.
* ``ensureSchema`` — if ``True``, run :meth:`AuthService.ensure_schema`
  at startup. Default ``True``. Set ``False`` if your host app's own
  migrations file already creates the ``users`` / ``sessions`` tables.
"""

from __future__ import annotations

import logging
from typing import Any, Mapping

from pyxle.plugins import PluginContext, PluginServiceError, PyxlePlugin

from pyxle_auth import AuthService, AuthSettings


_logger = logging.getLogger("pyxle_auth.plugin")


# Map ``pyxle.config.json`` camelCase settings keys to the
# :class:`AuthSettings` snake_case fields. Kept as a table so the
# translation layer is declarative — adding a new field is a one-line
# edit here and the plugin picks it up.
_SETTINGS_MAP: Mapping[str, str] = {
    "argonTimeCost": "argon_time_cost",
    "argonMemoryKib": "argon_memory_kib",
    "argonParallelism": "argon_parallelism",
    "passwordMinLength": "password_min_length",
    "passwordMaxLength": "password_max_length",
    "sessionTtlSeconds": "session_lifetime_seconds",
    "sessionAbsoluteMaxSeconds": "session_absolute_max_seconds",
    "cookieName": "cookie_name",
    "cookieSecure": "cookie_secure",
    "cookieSameSite": "cookie_samesite",
    "cookieDomain": "cookie_domain",
    "cookiePath": "cookie_path",
    "rateLimitSignInPerHour": "rate_limit_sign_in_per_hour",
    "rateLimitSignUpPerHour": "rate_limit_sign_up_per_hour",
    "requireEmailVerified": "require_email_verified",
    "strict": "strict",
}


class PyxleAuthPlugin(PyxlePlugin):
    name = "pyxle-auth"
    version = "0.1.0"

    async def on_startup(self, ctx: PluginContext) -> None:
        try:
            database = ctx.require("db.database")
        except PluginServiceError as exc:
            raise PluginServiceError(
                "pyxle-auth requires 'db.database' from the pyxle-db "
                "plugin — list \"pyxle-db\" BEFORE \"pyxle-auth\" in "
                "pyxle.config.json::plugins."
            ) from exc

        user_settings = dict(self.settings or {})
        ensure_schema = bool(user_settings.pop("ensureSchema", True))

        auth_settings = _build_auth_settings(user_settings)
        service = AuthService(database, auth_settings)
        if ensure_schema:
            await service.ensure_schema()

        ctx.register("auth.service", service)
        ctx.register("auth.settings", auth_settings)

        _logger.info(
            "pyxle-auth: AuthService ready (cookie=%s, ttl=%ds, strict=%s)",
            auth_settings.cookie_name,
            auth_settings.session_lifetime_seconds,
            auth_settings.strict,
        )


def _build_auth_settings(user_settings: Mapping[str, Any]) -> AuthSettings:
    """Translate camelCase config keys into :class:`AuthSettings` kwargs.

    Unknown keys raise with a clear message — a typo like
    ``"cookeiSecure"`` would otherwise silently fall through to the
    AuthSettings default and leave the plugin author wondering why
    their setting isn't taking effect.
    """
    kwargs: dict[str, Any] = {}
    unknown: list[str] = []
    for key, value in user_settings.items():
        mapped = _SETTINGS_MAP.get(key)
        if mapped is None:
            unknown.append(key)
            continue
        kwargs[mapped] = value
    if unknown:
        raise PluginServiceError(
            f"pyxle-auth: unknown settings keys in plugin config: {sorted(unknown)}. "
            f"Supported: {sorted(_SETTINGS_MAP)}."
        )
    return AuthSettings(**kwargs)


# Convention: Pyxle's loader imports ``plugin`` from this module.
plugin = PyxleAuthPlugin
