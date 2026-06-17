"""OAuth 2.0 / OIDC sign-in for pyxle-auth.

Public surface:

* :class:`OAuthProvider` — a configured provider; :func:`OAuthProvider.from_env`
  builds the built-ins (Google, GitHub, Discord) with env-only credentials.
* :class:`OAuthService` — code exchange, identity fetch, account linking, and
  session issuance.
* :class:`OAuthMiddleware` / :class:`OAuthFlowConfig` — the path-prefix
  middleware that serves ``{prefix}/oauth/{provider}/{start,callback}``.
* Errors: :class:`OAuthError`, :class:`OAuthConfigError`,
  :class:`OAuthStateError`, :class:`OAuthExchangeError`,
  :class:`OAuthEmailUnverified`.

Requires the ``[oauth]`` extra (``httpx``).
"""

from __future__ import annotations

from pyxle_auth.oauth.errors import (
    OAuthConfigError,
    OAuthEmailUnverified,
    OAuthError,
    OAuthExchangeError,
    OAuthStateError,
)
from pyxle_auth.oauth.middleware import OAuthFlowConfig, OAuthMiddleware
from pyxle_auth.oauth.providers import BUILTIN_PROVIDERS, OAuthProvider
from pyxle_auth.oauth.service import OAuthIdentity, OAuthService

__all__ = [
    "BUILTIN_PROVIDERS",
    "OAuthConfigError",
    "OAuthEmailUnverified",
    "OAuthError",
    "OAuthExchangeError",
    "OAuthFlowConfig",
    "OAuthIdentity",
    "OAuthMiddleware",
    "OAuthProvider",
    "OAuthService",
    "OAuthStateError",
]
