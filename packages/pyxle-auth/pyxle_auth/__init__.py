"""pyxle-auth — email+password session authentication for Pyxle apps.

Public surface:

* :class:`AuthService` — high-level API: sign up, sign in, resolve
  session, sign out.
* :class:`AuthSettings` — knobs (password cost, session lifetime,
  rate-limit buckets, cookie attributes). Load from env via
  :meth:`AuthSettings.from_env`.
* :class:`User`, :class:`Session` — returned dataclasses.
* :class:`SessionCookie` — helper carrying the cookie name/value plus
  recommended attributes; expand with :meth:`SessionCookie.kwargs`.
* Errors: :class:`AuthError`, :class:`InvalidCredentials`,
  :class:`RateLimited`, :class:`AccountExists`, :class:`EmailNotVerified`.
"""

from __future__ import annotations

from pyxle_auth.errors import (
    AccountExists,
    AuthError,
    EmailNotVerified,
    InvalidCredentials,
    RateLimited,
    WeakPassword,
)
from pyxle_auth.models import Session, SessionCookie, User
from pyxle_auth.service import AuthService
from pyxle_auth.settings import AuthSettings


def get_auth_service() -> AuthService:
    """Return the :class:`AuthService` the active ``pyxle-auth`` plugin set up.

    Short form for app code::

        from pyxle_auth import get_auth_service

        @action
        async def sign_in(request):
            body = await request.json()
            auth = get_auth_service()
            user, cookie = await auth.sign_in(
                email=body["email"], password=body["password"],
                ip=request.client.host, user_agent=request.headers.get("user-agent", ""),
            )
            ...

    Requires ``pyxle-auth`` to be listed in ``pyxle.config.json::plugins``.
    Raises :class:`pyxle.plugins.PluginServiceError` otherwise.
    """
    from pyxle.plugins import plugin as _plugin

    return _plugin("auth.service")


def get_auth_settings() -> AuthSettings:
    """Return the :class:`AuthSettings` the active ``pyxle-auth`` plugin uses.

    Useful for reading the cookie name / TTL / strict flag off the
    same source of truth the service uses, e.g. when building a sign-out
    response manually::

        from pyxle_auth import get_auth_settings

        settings = get_auth_settings()
        response.delete_cookie(settings.cookie_name)
    """
    from pyxle.plugins import plugin as _plugin

    return _plugin("auth.settings")


__all__ = [
    "AuthError",
    "AuthService",
    "AuthSettings",
    "AccountExists",
    "EmailNotVerified",
    "InvalidCredentials",
    "RateLimited",
    "Session",
    "SessionCookie",
    "User",
    "WeakPassword",
    "get_auth_service",
    "get_auth_settings",
]

__version__ = "0.1.0"
