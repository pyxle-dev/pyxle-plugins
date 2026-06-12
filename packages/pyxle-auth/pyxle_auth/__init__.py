"""pyxle-auth — Django-grade authentication for Pyxle apps.

Public surface:

* :class:`AuthService` — sign up, sign in, resolve session, sign out,
  password change/reset, email verification.
* :class:`AuthSettings` — knobs (password cost, session lifetime,
  token TTLs, rate-limit buckets, cookie attributes). Load from env
  via :meth:`AuthSettings.from_env`.
* :class:`User`, :class:`Session`, :class:`SessionInfo` — returned
  dataclasses.
* :class:`SessionCookie` — helper carrying the cookie name/value plus
  recommended attributes; expand with :meth:`SessionCookie.kwargs`.
* :class:`TokenService` / :class:`TokenClaim` — single-use,
  purpose-scoped tokens (password reset, email verification, invites).
* :class:`ApiTokenService` / :class:`ApiToken` — long-lived, scoped
  ``pyxle_pat_`` personal access tokens.
* :class:`RoleService` — roles, permissions, grants (RBAC).
* Guards — :func:`current_user`, :func:`require_user_page`,
  :func:`require_user_action`, :func:`require_permission_page`,
  :func:`require_permission_action`, :func:`bearer_token`.
* Errors: :class:`AuthError`, :class:`InvalidCredentials`,
  :class:`RateLimited`, :class:`AccountExists`, :class:`WeakPassword`,
  :class:`EmailNotVerified`, :class:`InvalidToken`,
  :class:`RoleNotFound`, :class:`TokenLimitReached`.
"""

from __future__ import annotations

from pyxle_auth.api_tokens import (
    TOKEN_PREFIX,
    ApiToken,
    ApiTokenService,
    TokenLimitReached,
)
from pyxle_auth.errors import (
    AccountExists,
    AuthError,
    EmailNotVerified,
    InvalidCredentials,
    InvalidToken,
    RateLimited,
    WeakPassword,
)
from pyxle_auth.guards import (
    bearer_token,
    current_user,
    require_permission_action,
    require_permission_page,
    require_user_action,
    require_user_page,
)
from pyxle_auth.models import Session, SessionCookie, SessionInfo, User
from pyxle_auth.rbac import RoleNotFound, RoleService
from pyxle_auth.service import AuthService
from pyxle_auth.settings import AuthSettings
from pyxle_auth.tokens import TokenClaim, TokenService


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
    "TOKEN_PREFIX",
    "AccountExists",
    "ApiToken",
    "ApiTokenService",
    "AuthError",
    "AuthService",
    "AuthSettings",
    "EmailNotVerified",
    "InvalidCredentials",
    "InvalidToken",
    "RateLimited",
    "RoleNotFound",
    "RoleService",
    "Session",
    "SessionCookie",
    "SessionInfo",
    "TokenClaim",
    "TokenLimitReached",
    "TokenService",
    "User",
    "WeakPassword",
    "bearer_token",
    "current_user",
    "get_auth_service",
    "get_auth_settings",
    "require_permission_action",
    "require_permission_page",
    "require_user_action",
    "require_user_page",
]

__version__ = "0.2.0"
