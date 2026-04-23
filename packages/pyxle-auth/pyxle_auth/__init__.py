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
]

__version__ = "0.1.0"
