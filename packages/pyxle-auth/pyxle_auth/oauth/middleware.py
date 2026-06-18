"""The OAuth path-prefix middleware: ``start`` and ``callback``.

Because Pyxle plugins contribute middleware, not routes, the two OAuth
endpoints are served by terminating the request inside this middleware:

* ``GET {prefix}/oauth/{provider}/start?next=/dashboard`` — mint a PKCE
  verifier + a random nonce, stash them in a signed HttpOnly ``state`` cookie,
  and 302 the browser to the provider's consent screen.
* ``GET {prefix}/oauth/{provider}/callback?code&state`` — validate the state
  cookie (signature, expiry, single-use) and that the echoed ``state`` equals
  the cookie's nonce, exchange the code, resolve the user, set the session
  cookie, and 302 to the (same-origin-only) ``next``.

The callback is a ``GET`` and so is *not* covered by the framework's CSRF
middleware — the signed state cookie + nonce match is the login-CSRF defense.
Every failure clears the state cookie and redirects to ``failureRedirect`` with
an ``?oauth_error=<reason>`` the app can render; no provider error or token ever
reaches the browser.
"""

from __future__ import annotations

import hmac
import logging
import time
from dataclasses import dataclass
from typing import Any

from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, Response
from starlette.types import ASGIApp, Receive, Scope, Send

from pyxle_auth.oauth import state as oauth_state
from pyxle_auth.oauth.errors import (
    OAuthConfigError,
    OAuthEmailUnverified,
    OAuthError,
)
from pyxle_auth.oauth.pkce import challenge_for, generate_verifier
from pyxle_auth.oauth.state import OAuthState, generate_nonce
from pyxle_auth.oauth.util import sanitize_next

_logger = logging.getLogger("pyxle_auth.oauth.middleware")

# Service keys (registered by PyxleAuthPlugin when OAuth is configured).
_OAUTH_SERVICE = "auth.oauth"
_OAUTH_CONFIG = "auth.oauth.config"


@dataclass(frozen=True, slots=True)
class OAuthFlowConfig:
    """Everything the middleware needs that isn't on the service itself."""

    state_secret: bytes
    auth_path_prefix: str
    state_cookie_name: str = "pyxle_oauth_state"
    state_ttl_seconds: int = 600  # 10 minutes — the consent screen round-trip
    cookie_secure: bool = True
    cookie_domain: str | None = None
    redirect_base_url: str | None = None  # override origin (proxy / custom domain)
    failure_redirect: str = "/"
    default_next: str = "/"


class OAuthMiddleware:
    """Serve ``{prefix}/oauth/{provider}/{start,callback}``; pass everything
    else through.

    Pure-ASGI (not ``BaseHTTPMiddleware``) so the pass-through path forwards the
    request untouched and never buffers a streamed response. OAuth requests are
    always terminated here with a redirect, so they never stream.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        response = await self._handle(Request(scope, receive))
        if response is not None:
            await response(scope, receive, send)
            return
        await self.app(scope, receive, send)

    async def _handle(self, request: Request) -> Response | None:
        """Return a Response for an OAuth endpoint, or ``None`` to pass through."""
        ctx = getattr(request.app.state, "pyxle_plugins", None)
        service = ctx.get(_OAUTH_SERVICE) if ctx is not None else None
        config: OAuthFlowConfig | None = (
            ctx.get(_OAUTH_CONFIG) if ctx is not None else None
        )
        if service is None or config is None:
            return None  # OAuth not configured — inert.

        oauth_base = config.auth_path_prefix + "/oauth"
        path = request.url.path
        if not path.startswith(oauth_base + "/"):
            return None

        parts = path[len(oauth_base) + 1 :].split("/")
        if len(parts) != 2:
            return None
        provider_name, action = parts
        if action not in ("start", "callback"):
            return None
        if request.method != "GET":
            return JSONResponse(
                {"ok": False, "error": "Method not allowed"},
                status_code=405,
                headers={"Allow": "GET"},
            )

        if action == "start":
            return await self._start(request, service, config, provider_name, oauth_base)
        return await self._callback(request, service, config, provider_name, oauth_base)

    async def _start(
        self,
        request: Request,
        service: Any,
        config: OAuthFlowConfig,
        provider_name: str,
        oauth_base: str,
    ) -> Response:
        try:
            provider = service.provider(provider_name)
        except OAuthConfigError:
            return self._fail(config, "unknown_provider")

        next_path = sanitize_next(
            request.query_params.get("next"), default=config.default_next
        )
        verifier = generate_verifier()
        nonce = generate_nonce()
        redirect_uri = self._redirect_uri(request, config, provider.name, oauth_base)
        auth_url = provider.authorization_url(
            redirect_uri=redirect_uri,
            state=nonce,
            code_challenge=challenge_for(verifier),
        )
        cookie_value = oauth_state.issue(
            OAuthState(
                provider=provider.name,
                nonce=nonce,
                verifier=verifier,
                next=next_path,
                issued_at=int(time.time()),
            ),
            secret=config.state_secret,
        )
        response: Response = RedirectResponse(auth_url, status_code=302)
        self._set_state_cookie(response, config, oauth_base, cookie_value)
        return response

    async def _callback(
        self,
        request: Request,
        service: Any,
        config: OAuthFlowConfig,
        provider_name: str,
        oauth_base: str,
    ) -> Response:
        state = oauth_state.verify(
            request.cookies.get(config.state_cookie_name),
            secret=config.state_secret,
            max_age_seconds=config.state_ttl_seconds,
        )
        if state is None or state.provider != provider_name.lower():
            return self._fail(config, "state", oauth_base=oauth_base)

        # The value the provider echoed must equal the cookie's nonce.
        returned_state = request.query_params.get("state", "")
        if not hmac.compare_digest(returned_state, state.nonce):
            return self._fail(config, "state", oauth_base=oauth_base)

        if request.query_params.get("error"):
            # The user denied consent, or the provider refused.
            return self._fail(config, "denied", oauth_base=oauth_base, next_path=state.next)

        code = request.query_params.get("code")
        if not code:
            return self._fail(config, "state", oauth_base=oauth_base)

        redirect_uri = self._redirect_uri(request, config, provider_name, oauth_base)
        try:
            _user, session_cookie = await service.complete(
                provider_name,
                code=code,
                redirect_uri=redirect_uri,
                code_verifier=state.verifier,
                ip=_client_ip(request),
                user_agent=request.headers.get("user-agent"),
            )
        except OAuthEmailUnverified:
            return self._fail(
                config, "email_unverified", oauth_base=oauth_base, next_path=state.next
            )
        except OAuthError as exc:
            _logger.warning("oauth: callback failed for %s: %s", provider_name, exc)
            return self._fail(config, "exchange", oauth_base=oauth_base, next_path=state.next)

        # Success: redirect to the same-origin next (re-sanitized as
        # defense-in-depth even though it was validated and signed at start),
        # set the session cookie, and burn the single-use state cookie.
        target = sanitize_next(state.next, default=config.default_next)
        response: Response = RedirectResponse(target, status_code=302)
        response.set_cookie(**session_cookie.kwargs())
        self._clear_state_cookie(response, config, oauth_base)
        return response

    # ---- helpers ---------------------------------------------------------------

    def _redirect_uri(
        self,
        request: Request,
        config: OAuthFlowConfig,
        provider_name: str,
        oauth_base: str,
    ) -> str:
        if config.redirect_base_url:
            base = config.redirect_base_url.rstrip("/")
        else:
            base = f"{request.url.scheme}://{request.url.netloc}"
        return f"{base}{oauth_base}/{provider_name.lower()}/callback"

    def _set_state_cookie(
        self,
        response: Response,
        config: OAuthFlowConfig,
        oauth_base: str,
        value: str,
    ) -> None:
        # SameSite=Lax (not Strict): the callback is a top-level GET navigation
        # FROM the provider's domain, and Strict would drop the cookie there and
        # break every sign-in. Scoped to the oauth path so it rides on nothing
        # else.
        response.set_cookie(
            config.state_cookie_name,
            value,
            max_age=config.state_ttl_seconds,
            httponly=True,
            secure=config.cookie_secure,
            samesite="lax",
            path=oauth_base,
            domain=config.cookie_domain,
        )

    def _clear_state_cookie(
        self, response: Response, config: OAuthFlowConfig, oauth_base: str
    ) -> None:
        response.delete_cookie(
            config.state_cookie_name, path=oauth_base, domain=config.cookie_domain
        )

    def _fail(
        self,
        config: OAuthFlowConfig,
        reason: str,
        *,
        oauth_base: str | None = None,
        next_path: str | None = None,
    ) -> Response:
        """Redirect to the failure target with ``?oauth_error=<reason>`` and the
        state cookie cleared. ``reason`` is a fixed enum string, never user
        input."""
        target = sanitize_next(next_path, default=config.failure_redirect)
        sep = "&" if "?" in target else "?"
        response: Response = RedirectResponse(
            f"{target}{sep}oauth_error={reason}", status_code=302
        )
        if oauth_base is not None:
            self._clear_state_cookie(response, config, oauth_base)
        return response


def _client_ip(request: Request) -> str | None:
    client = request.client
    return client.host if client is not None else None


__all__ = ["OAuthMiddleware", "OAuthFlowConfig"]
