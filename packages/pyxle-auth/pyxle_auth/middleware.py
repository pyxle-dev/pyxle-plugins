"""Request-scoped user injection and the auth HTTP endpoints.

``AuthSessionMiddleware`` is contributed by
:class:`~pyxle_auth.plugin.PyxleAuthPlugin` through Pyxle's public
plugin-middleware seam (no core monkey-patching). Per request it:

* resolves the session cookie and sets ``request.user`` — a
  :class:`~pyxle_auth.models.User` or ``None`` — so loaders, actions, and
  downstream middleware see the signed-in user without wiring anything;
* exposes the auth state to the SSR document via the conventional
  ``scope['pyxle.auth']`` key, which Pyxle core seeds into
  ``window.__PYXLE_AUTH__`` for the client ``useAuth`` hook;
* serves the endpoints the ``useAuth`` hook talks to:
  - ``GET  {prefix}/me`` — the current user as JSON (safe method).
  - ``POST {prefix}/login`` — sign in with email + password *(opt-out)*.
  - ``POST {prefix}/signup`` — create an account *(opt-out)*.
  - ``POST {prefix}/logout`` — revoke the session and clear the cookie.

**Why these endpoints live in middleware.** Pyxle plugins contribute
middleware, not routes — there is no route-contribution seam — so an endpoint
a plugin must own is a path-prefix middleware that terminates the request
before ``call_next``. The prefix is :attr:`AuthSettings.auth_path_prefix`
(default ``/auth``). ``login`` / ``signup`` are gated by
:attr:`AuthSettings.enable_credentials_api` (default on); apps rolling custom
sign-in flows turn them off and keep ``/me`` + ``/logout``.

**CSRF.** Every state-changing endpoint here (``login`` / ``signup`` /
``logout``) is covered by core's CSRF middleware, which is installed *outside*
the plugin stack and therefore runs first — the client must echo the CSRF
token (the ``useAuth`` hook does). ``GET {prefix}/me`` is a safe method.

**Resolution cost.** A request without the session cookie does zero database
work (``request.user`` is ``None``). A request that carries the cookie performs
the same indexed point-lookup :func:`pyxle_auth.guards.current_user` would, and
the guards reuse the value (cached on the ASGI scope under ``user``), so a
guarded loader never resolves the session twice.
"""

from __future__ import annotations

import logging
from typing import Any

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp

from pyxle_auth.errors import (
    AccountExists,
    AuthError,
    EmailNotVerified,
    InvalidCredentials,
    InvalidToken,
    RateLimited,
    WeakPassword,
)

_logger = logging.getLogger("pyxle_auth.middleware")

# Service keys the plugin registers (see plugin.py).
_AUTH_SERVICE = "auth.service"
_JWT_SERVICE = "auth.jwt"

# Conventional ASGI-scope key Pyxle core reads to seed window.__PYXLE_AUTH__.
# Mirrors how the CSRF middleware publishes scope['pyxle.csrf_token'].
_AUTH_SCOPE_KEY = "pyxle.auth"


def user_to_json(user: Any) -> dict[str, Any] | None:
    """Public-safe projection of a :class:`~pyxle_auth.models.User`.

    Never includes anything secret — the ``User`` dataclass carries no
    password hash. This shape is the contract both the ``useAuth`` client hook
    and the SSR ``window.__PYXLE_AUTH__`` seed consume; keep them in lockstep.
    """
    if user is None:
        return None
    return {
        "id": user.id,
        "email": user.email,
        "emailVerified": user.email_verified_at is not None,
        "plan": user.plan,
        "createdAt": user.created_at.isoformat(),
    }


class AuthSessionMiddleware(BaseHTTPMiddleware):
    """Populate ``request.user`` and serve the auth HTTP endpoints."""

    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)

    async def dispatch(self, request: Request, call_next: Any) -> Response:
        ctx = getattr(request.app.state, "pyxle_plugins", None)
        service = ctx.get(_AUTH_SERVICE) if ctx is not None else None
        if service is None:
            # Middleware installed but no auth service registered — pass through
            # without touching request.user (matches PyxleDbMiddleware's seam).
            return await call_next(request)

        settings = service.settings
        prefix = settings.auth_path_prefix
        path = request.url.path

        if path == prefix + "/me":
            if request.method == "GET":
                user = await self._populate(request, service, settings)
                return JSONResponse({"user": user_to_json(user)})
            return _method_not_allowed("GET")
        if path == prefix + "/logout":
            if request.method == "POST":
                return await self._logout(request, service, settings)
            return _method_not_allowed("POST")
        if settings.enable_credentials_api:
            if path == prefix + "/login":
                if request.method == "POST":
                    return await self._login(request, service, settings)
                return _method_not_allowed("POST")
            if path == prefix + "/signup":
                if request.method == "POST":
                    return await self._signup(request, service, settings)
                return _method_not_allowed("POST")

        # JWT token endpoints — served only when the JWT service is configured.
        jwt_service = ctx.get(_JWT_SERVICE) if ctx is not None else None
        if jwt_service is not None:
            if path == prefix + "/token":
                if request.method == "POST":
                    return await self._token(request, service, jwt_service)
                return _method_not_allowed("POST")
            if path == prefix + "/token/refresh":
                if request.method == "POST":
                    return await self._token_refresh(request, jwt_service)
                return _method_not_allowed("POST")

        # Ambient population for every other request: loaders, actions, and
        # templates read request.user; the SSR document reads scope['pyxle.auth'].
        await self._populate(request, service, settings)
        return await call_next(request)

    @staticmethod
    async def _populate(request: Request, service: Any, settings: Any) -> Any:
        """Resolve the session cookie and cache the user on the ASGI scope.

        Zero database work when the cookie is absent. The :class:`User` (or
        ``None``) is stored under ``scope['user']`` so Starlette's native
        ``request.user`` returns it and the guards reuse it; the JSON seed plus
        endpoint map is stored under ``scope['pyxle.auth']`` for the SSR
        document.
        """
        cookie_value = request.cookies.get(settings.cookie_name)
        if not cookie_value:
            user = None
        else:
            user = await service.resolve_session(
                cookie_value=cookie_value, extend=True
            )
        request.scope["user"] = user
        request.scope[_AUTH_SCOPE_KEY] = _auth_seed(user, settings)
        return user

    @staticmethod
    async def _logout(request: Request, service: Any, settings: Any) -> Response:
        """Revoke the session and clear the browser cookie. Idempotent."""
        cookie_value = request.cookies.get(settings.cookie_name, "")
        session_cookie = await service.sign_out(cookie_value=cookie_value)
        response: Response = JSONResponse({"ok": True})
        response.set_cookie(**session_cookie.kwargs())
        return response

    async def _login(self, request: Request, service: Any, settings: Any) -> Response:
        body = await _json_body(request)
        if body is None:
            return _bad_request("Expected a JSON body.")
        email = body.get("email")
        password = body.get("password")
        if not isinstance(email, str) or not isinstance(password, str):
            return _bad_request("Both 'email' and 'password' are required.")
        try:
            user, cookie = await service.sign_in(
                email=email,
                password=password,
                ip=_client_ip(request),
                user_agent=request.headers.get("user-agent"),
            )
        except AuthError as exc:
            return _auth_error_response(exc)
        return _authenticated_response(user, cookie)

    async def _signup(self, request: Request, service: Any, settings: Any) -> Response:
        body = await _json_body(request)
        if body is None:
            return _bad_request("Expected a JSON body.")
        email = body.get("email")
        password = body.get("password")
        if not isinstance(email, str) or not isinstance(password, str):
            return _bad_request("Both 'email' and 'password' are required.")
        try:
            user, cookie = await service.sign_up(
                email=email,
                password=password,
                ip=_client_ip(request),
                user_agent=request.headers.get("user-agent"),
            )
        except AuthError as exc:
            return _auth_error_response(exc)
        return _authenticated_response(user, cookie, status_code=201)

    async def _token(self, request: Request, service: Any, jwt_service: Any) -> Response:
        """Issue a JWT access + refresh pair from email + password (API/mobile).

        Reuses the rate-limited, enumeration-safe credential check; no session
        cookie is issued. This endpoint authenticates from the request body, so
        it is not vulnerable to CSRF — but core CSRF still guards POSTs, so add
        ``{prefix}/token`` to ``csrf.exempt_paths`` for non-browser clients.
        """
        body = await _json_body(request)
        if body is None:
            return _bad_request("Expected a JSON body.")
        email = body.get("email")
        password = body.get("password")
        if not isinstance(email, str) or not isinstance(password, str):
            return _bad_request("Both 'email' and 'password' are required.")
        try:
            user = await service.verify_credentials(
                email=email, password=password, ip=_client_ip(request)
            )
        except AuthError as exc:
            return _auth_error_response(exc)
        pair = await jwt_service.issue_pair(user_id=user.id)
        return _token_pair_response(pair, user=user)

    async def _token_refresh(self, request: Request, jwt_service: Any) -> Response:
        """Rotate a refresh token into a new pair (reuse → family revoke)."""
        body = await _json_body(request)
        if body is None:
            return _bad_request("Expected a JSON body.")
        refresh = body.get("refreshToken") or body.get("refresh_token")
        if not isinstance(refresh, str) or not refresh:
            return _bad_request("'refreshToken' is required.")
        try:
            pair = await jwt_service.refresh(refresh)
        except InvalidToken:
            return JSONResponse(
                {
                    "ok": False,
                    "error": "Invalid or expired refresh token.",
                    "code": "invalid_refresh",
                },
                status_code=401,
            )
        return _token_pair_response(pair)


# ---------------------------------------------------------------------------
# Helpers


def _auth_seed(user: Any, settings: Any) -> dict[str, Any]:
    """The ``window.__PYXLE_AUTH__`` blob: the user plus the endpoint map.

    The endpoint map lets the client hook find the (possibly relocated)
    endpoints without hard-coding the default prefix; ``login`` / ``signup``
    are advertised only when the credentials API is enabled.
    """
    prefix = settings.auth_path_prefix
    endpoints: dict[str, str] = {
        "me": prefix + "/me",
        "logout": prefix + "/logout",
    }
    if settings.enable_credentials_api:
        endpoints["login"] = prefix + "/login"
        endpoints["signup"] = prefix + "/signup"
    return {"user": user_to_json(user), "endpoints": endpoints}


async def _json_body(request: Request) -> dict[str, Any] | None:
    """Parse a JSON object body, or ``None`` if it is missing/not an object."""
    try:
        body = await request.json()
    except Exception:
        return None
    return body if isinstance(body, dict) else None


def _client_ip(request: Request) -> str | None:
    client = request.client
    return client.host if client is not None else None


def _authenticated_response(
    user: Any, cookie: Any, *, status_code: int = 200
) -> Response:
    """Set the session cookie and return the user projection."""
    response: Response = JSONResponse(
        {"ok": True, "user": user_to_json(user)}, status_code=status_code
    )
    response.set_cookie(**cookie.kwargs())
    return response


def _token_pair_response(pair: Any, *, user: Any = None) -> Response:
    """Serialize a JWT :class:`TokenPair` (camelCase for the client)."""
    payload: dict[str, Any] = {
        "ok": True,
        "accessToken": pair.access_token,
        "refreshToken": pair.refresh_token,
        "tokenType": pair.token_type,
        "expiresIn": pair.access_expires_in,
    }
    if user is not None:
        payload["user"] = user_to_json(user)
    return JSONResponse(payload)


def _auth_error_response(exc: AuthError) -> Response:
    """Map an :class:`AuthError` to a structured JSON response.

    The status codes are the conventional ones the ``useAuth`` hook branches
    on; the messages come straight from the (deliberately
    enumeration-safe) error classes.
    """
    if isinstance(exc, RateLimited):
        return JSONResponse(
            {"ok": False, "error": str(exc), "code": "rate_limited"},
            status_code=429,
            headers={"Retry-After": str(exc.retry_after_seconds)},
        )
    if isinstance(exc, InvalidCredentials):
        return JSONResponse(
            {"ok": False, "error": str(exc), "code": "invalid_credentials"},
            status_code=401,
        )
    if isinstance(exc, AccountExists):
        return JSONResponse(
            {"ok": False, "error": str(exc), "code": "account_exists"},
            status_code=409,
        )
    if isinstance(exc, WeakPassword):
        return JSONResponse(
            {"ok": False, "error": str(exc), "code": "weak_password"},
            status_code=422,
        )
    if isinstance(exc, EmailNotVerified):
        return JSONResponse(
            {"ok": False, "error": str(exc), "code": "email_not_verified"},
            status_code=403,
        )
    # Any other AuthError (e.g. a malformed email) is a client-side problem.
    return JSONResponse(
        {"ok": False, "error": str(exc), "code": "auth_error"},
        status_code=400,
    )


def _bad_request(message: str) -> Response:
    return JSONResponse({"ok": False, "error": message}, status_code=400)


def _method_not_allowed(allow: str) -> Response:
    """405 for a request to an auth endpoint with the wrong HTTP method."""
    return JSONResponse(
        {"ok": False, "error": "Method not allowed"},
        status_code=405,
        headers={"Allow": allow},
    )


__all__ = ["AuthSessionMiddleware", "user_to_json"]
