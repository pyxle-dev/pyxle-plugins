"""Structured errors for the OAuth flow.

All inherit from :class:`pyxle_auth.errors.AuthError` so app code that already
branches on ``AuthError`` keeps working. The middleware maps them to redirects
or JSON; nothing here leaks provider tokens or internal state.
"""

from __future__ import annotations

from pyxle_auth.errors import AuthError


class OAuthError(AuthError):
    """Base class for OAuth-flow failures."""


class OAuthConfigError(OAuthError):
    """A provider is misconfigured — unknown name, missing client id/secret,
    or no signing secret for the state cookie. Raised at startup or when a
    request targets an unconfigured provider."""


class OAuthStateError(OAuthError):
    """The state cookie was missing, tampered with, expired, replayed, or did
    not match the ``state`` echoed by the provider. Deliberately
    indistinguishable — a probing caller learns nothing about which check
    failed."""

    def __init__(self, message: str = "OAuth state is missing or invalid.") -> None:
        super().__init__(message)


class OAuthExchangeError(OAuthError):
    """The provider rejected the authorization code, or the token / userinfo
    response was malformed. The provider's raw error is logged server-side,
    never surfaced to the browser."""


class OAuthEmailUnverified(OAuthError):
    """The provider authenticated the user but their email is unverified, so
    we refuse to link the identity to an existing local account (that would be
    an account-takeover vector)."""

    def __init__(
        self, message: str = "Your email with this provider is not verified."
    ) -> None:
        super().__init__(message)


__all__ = [
    "OAuthError",
    "OAuthConfigError",
    "OAuthStateError",
    "OAuthExchangeError",
    "OAuthEmailUnverified",
]
