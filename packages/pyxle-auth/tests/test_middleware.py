"""Tests for AuthSessionMiddleware — request.user injection + /me + /logout.

``AuthSessionMiddleware`` is a pure-ASGI app, driven here through a tiny
in-process ASGI harness (``_DriveMiddleware`` + ``_drive``) rather than a
TestClient, so the async SQLite connection the :class:`AuthService` holds and
the handler run on the *same* event loop — TestClient spins its own loop, which
aiosqlite connections are bound to (the same constraint pyxle-db's middleware
tests document).

The harness mirrors pyxle-db's ``_drive``: it wraps a ``(request) -> Response``
handler as the inner ASGI app, drives ``AuthSessionMiddleware(inner)`` against a
built scope, and captures the response the middleware emits (status, headers,
body) so the assertions read like the dispatcher's real behaviour. A request
the middleware passes *through* runs the inner handler (ambient population); a
request it *terminates* (an auth endpoint) never reaches the inner handler.
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any, Awaitable, Callable

import pytest
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from pyxle.plugins import PluginContext

from pyxle_auth import AuthService, AuthSettings
from pyxle_auth.middleware import AuthSessionMiddleware, user_to_json

Handler = Callable[[Request], Awaitable[Response]]


class _CapturedResponse:
    """The response the middleware emitted onto the ASGI ``send`` channel.

    Exposes just the surface the assertions read off a Starlette ``Response``:
    ``status_code``, a case-insensitive ``headers`` mapping, ``raw_headers``
    (list of ``(bytes, bytes)`` — multiple ``set-cookie`` rows preserved), and
    the joined ``body`` as ``bytes``.
    """

    def __init__(
        self, status: int, raw_headers: list[tuple[bytes, bytes]], body: bytes
    ) -> None:
        self.status_code = status
        self.raw_headers = raw_headers
        self.body = body

    @property
    def headers(self) -> dict[str, str]:
        # Last value wins for a repeated header (matches Starlette's single-value
        # access); the tests that need every set-cookie use raw_headers.
        return {
            key.decode("latin-1").lower(): value.decode("latin-1")
            for key, value in self.raw_headers
        }


class _DriveMiddleware:
    """Drives a request through ``AuthSessionMiddleware`` as pure ASGI.

    ``dispatch(request, call_next)`` keeps the call sites identical to the old
    ``BaseHTTPMiddleware`` interface: it wraps ``call_next`` as the inner ASGI
    app, runs ``AuthSessionMiddleware(inner)`` against the request's own
    scope/receive, and returns the captured response. The ``request``'s scope is
    shared, so assertions on ``request.user`` / ``request.scope[...]`` populated
    by the middleware still hold afterwards.
    """

    async def dispatch(self, request: Request, call_next: Handler) -> _CapturedResponse:
        scope = request.scope
        receive = request.receive

        async def inner(scope: dict, receive: Any, send: Any) -> None:
            inner_request = Request(scope, receive)
            response = await call_next(inner_request)
            await response(scope, receive, send)

        captured: dict[str, Any] = {"status": 0, "headers": [], "body": b""}

        async def send(message: dict) -> None:
            if message["type"] == "http.response.start":
                captured["status"] = message["status"]
                captured["headers"] = list(message.get("headers", []))
            elif message["type"] == "http.response.body":
                captured["body"] += message.get("body", b"")

        await AuthSessionMiddleware(inner)(scope, receive, send)
        return _CapturedResponse(
            captured["status"], captured["headers"], captured["body"]
        )


@pytest.fixture
def middleware() -> _DriveMiddleware:
    return _DriveMiddleware()


def _ctx(auth: AuthService | None) -> PluginContext:
    ctx = PluginContext()
    if auth is not None:
        ctx.register("auth.service", auth)
    return ctx


def _request(
    ctx: PluginContext,
    *,
    method: str = "GET",
    path: str = "/",
    cookies: dict[str, str] | None = None,
) -> Request:
    headers: list[tuple[bytes, bytes]] = []
    if cookies:
        blob = "; ".join(f"{k}={v}" for k, v in cookies.items())
        headers.append((b"cookie", blob.encode("latin-1")))
    app = SimpleNamespace(state=SimpleNamespace(pyxle_plugins=ctx))

    async def receive() -> dict:
        return {"type": "http.request", "body": b"", "more_body": False}

    scope = {
        "type": "http",
        "method": method,
        "path": path,
        "headers": headers,
        "query_string": b"",
        "app": app,
        "state": {},
    }
    return Request(scope, receive)


async def _sign_up(auth: AuthService) -> tuple[str, str]:
    """Create an account and return ``(user_id, raw_cookie_value)``."""
    user, cookie = await auth.sign_up(
        email="alice@example.com",
        password="correct horse battery staple",
        ip="203.0.113.1",
        user_agent="pytest",
    )
    return user.id, cookie.value


def _body(response: _CapturedResponse) -> dict:
    return json.loads(bytes(response.body).decode("utf-8"))


# ---------------------------------------------------------------------------
# Ambient population — request.user


async def test_anonymous_request_sets_user_none_without_db(
    auth: AuthService, middleware: _DriveMiddleware
) -> None:
    ctx = _ctx(auth)
    captured: dict = {}

    async def call_next(request: Request) -> Response:
        captured["user"] = request.user  # native Starlette property
        return JSONResponse({"ok": True})

    resp = await middleware.dispatch(_request(ctx, path="/dashboard"), call_next)
    assert resp.status_code == 200
    assert captured["user"] is None


async def test_valid_cookie_populates_request_user(
    auth: AuthService, middleware: _DriveMiddleware
) -> None:
    user_id, cookie = await _sign_up(auth)
    ctx = _ctx(auth)
    captured: dict = {}

    async def call_next(request: Request) -> Response:
        captured["user"] = request.user
        return JSONResponse({"ok": True})

    await middleware.dispatch(
        _request(ctx, path="/dashboard", cookies={"pyxle_session": cookie}),
        call_next,
    )
    assert captured["user"] is not None
    assert captured["user"].id == user_id
    assert captured["user"].email == "alice@example.com"


async def test_forged_cookie_resolves_to_none(
    auth: AuthService, middleware: _DriveMiddleware
) -> None:
    ctx = _ctx(auth)
    captured: dict = {}

    async def call_next(request: Request) -> Response:
        captured["user"] = request.user
        return JSONResponse({"ok": True})

    await middleware.dispatch(
        _request(ctx, path="/dashboard", cookies={"pyxle_session": "not-a-real-token"}),
        call_next,
    )
    assert captured["user"] is None


async def test_no_auth_service_passes_through(
    middleware: _DriveMiddleware,
) -> None:
    ctx = _ctx(None)  # auth.service not registered
    captured: dict = {}

    async def call_next(request: Request) -> Response:
        # No service → middleware must not touch the scope's user slot.
        captured["has_user"] = "user" in request.scope
        return JSONResponse({"ok": True})

    resp = await middleware.dispatch(_request(ctx, path="/anything"), call_next)
    assert resp.status_code == 200
    assert captured["has_user"] is False


# ---------------------------------------------------------------------------
# GET {prefix}/me


async def test_me_anonymous_returns_null_user(
    auth: AuthService, middleware: _DriveMiddleware
) -> None:
    ctx = _ctx(auth)

    async def call_next(request: Request) -> Response:  # pragma: no cover
        raise AssertionError("/auth/me must terminate in the middleware")

    resp = await middleware.dispatch(_request(ctx, path="/auth/me"), call_next)
    assert resp.status_code == 200
    assert _body(resp) == {"user": None}


async def test_me_signed_in_returns_user_projection(
    auth: AuthService, middleware: _DriveMiddleware
) -> None:
    user_id, cookie = await _sign_up(auth)
    ctx = _ctx(auth)

    async def call_next(request: Request) -> Response:  # pragma: no cover
        raise AssertionError("/auth/me must terminate in the middleware")

    resp = await middleware.dispatch(
        _request(ctx, path="/auth/me", cookies={"pyxle_session": cookie}),
        call_next,
    )
    assert resp.status_code == 200
    user = _body(resp)["user"]
    assert user["id"] == user_id
    assert user["email"] == "alice@example.com"
    assert user["emailVerified"] is False
    assert user["plan"] == "free"
    assert "createdAt" in user
    # The public projection never leaks a password hash or any secret.
    assert "password_hash" not in user
    assert "passwordHash" not in user


async def test_me_rejects_post(
    auth: AuthService, middleware: _DriveMiddleware
) -> None:
    ctx = _ctx(auth)

    async def call_next(request: Request) -> Response:  # pragma: no cover
        raise AssertionError("wrong-method /auth/me must not fall through")

    resp = await middleware.dispatch(
        _request(ctx, method="POST", path="/auth/me"), call_next
    )
    assert resp.status_code == 405
    assert resp.headers["allow"] == "GET"


# ---------------------------------------------------------------------------
# POST {prefix}/logout


async def test_logout_revokes_session_and_clears_cookie(
    auth: AuthService, middleware: _DriveMiddleware
) -> None:
    _, cookie = await _sign_up(auth)
    ctx = _ctx(auth)

    async def call_next(request: Request) -> Response:  # pragma: no cover
        raise AssertionError("/auth/logout must terminate in the middleware")

    resp = await middleware.dispatch(
        _request(
            ctx, method="POST", path="/auth/logout", cookies={"pyxle_session": cookie}
        ),
        call_next,
    )
    assert resp.status_code == 200
    assert _body(resp) == {"ok": True}

    # The browser cookie is cleared (Max-Age=0).
    set_cookie = resp.headers["set-cookie"]
    assert "pyxle_session=" in set_cookie
    assert "Max-Age=0" in set_cookie

    # The session is gone server-side: the same cookie no longer resolves.
    assert await auth.resolve_session(cookie_value=cookie) is None


async def test_logout_is_idempotent_when_anonymous(
    auth: AuthService, middleware: _DriveMiddleware
) -> None:
    ctx = _ctx(auth)

    async def call_next(request: Request) -> Response:  # pragma: no cover
        raise AssertionError("/auth/logout must terminate in the middleware")

    resp = await middleware.dispatch(
        _request(ctx, method="POST", path="/auth/logout"), call_next
    )
    assert resp.status_code == 200
    assert _body(resp) == {"ok": True}


async def test_logout_rejects_get(
    auth: AuthService, middleware: _DriveMiddleware
) -> None:
    ctx = _ctx(auth)

    async def call_next(request: Request) -> Response:  # pragma: no cover
        raise AssertionError("wrong-method /auth/logout must not fall through")

    resp = await middleware.dispatch(_request(ctx, path="/auth/logout"), call_next)
    assert resp.status_code == 405
    assert resp.headers["allow"] == "POST"


# ---------------------------------------------------------------------------
# POST {prefix}/login + {prefix}/signup (the credentials API)


def _request_json(
    ctx: PluginContext,
    *,
    method: str = "POST",
    path: str = "/auth/login",
    body: dict | None = None,
) -> Request:
    payload = json.dumps(body or {}).encode("utf-8")
    app = SimpleNamespace(state=SimpleNamespace(pyxle_plugins=ctx))

    async def receive() -> dict:
        return {"type": "http.request", "body": payload, "more_body": False}

    scope = {
        "type": "http",
        "method": method,
        "path": path,
        "headers": [(b"content-type", b"application/json")],
        "query_string": b"",
        "client": ("203.0.113.9", 5555),
        "app": app,
        "state": {},
    }
    return Request(scope, receive)


async def test_signup_creates_account_and_sets_cookie(
    auth: AuthService, middleware: _DriveMiddleware
) -> None:
    ctx = _ctx(auth)

    async def call_next(request: Request) -> Response:  # pragma: no cover
        raise AssertionError("/auth/signup must terminate in the middleware")

    resp = await middleware.dispatch(
        _request_json(
            ctx,
            path="/auth/signup",
            body={"email": "new@example.com", "password": "correct horse battery"},
        ),
        call_next,
    )
    assert resp.status_code == 201
    payload = _body(resp)
    assert payload["ok"] is True
    assert payload["user"]["email"] == "new@example.com"
    assert "pyxle_session=" in resp.headers["set-cookie"]
    # The account is real: it now resolves on sign-in.
    user, _ = await auth.sign_in(
        email="new@example.com", password="correct horse battery"
    )
    assert user.email == "new@example.com"


async def test_login_succeeds_with_valid_credentials(
    auth: AuthService, middleware: _DriveMiddleware
) -> None:
    await _sign_up(auth)
    ctx = _ctx(auth)

    async def call_next(request: Request) -> Response:  # pragma: no cover
        raise AssertionError("/auth/login must terminate in the middleware")

    resp = await middleware.dispatch(
        _request_json(
            ctx,
            path="/auth/login",
            body={
                "email": "alice@example.com",
                "password": "correct horse battery staple",
            },
        ),
        call_next,
    )
    assert resp.status_code == 200
    assert _body(resp)["user"]["email"] == "alice@example.com"
    assert "pyxle_session=" in resp.headers["set-cookie"]


async def test_login_wrong_password_is_401(
    auth: AuthService, middleware: _DriveMiddleware
) -> None:
    await _sign_up(auth)
    ctx = _ctx(auth)

    async def call_next(request: Request) -> Response:  # pragma: no cover
        raise AssertionError("/auth/login must terminate in the middleware")

    resp = await middleware.dispatch(
        _request_json(
            ctx,
            path="/auth/login",
            body={"email": "alice@example.com", "password": "wrong-password"},
        ),
        call_next,
    )
    assert resp.status_code == 401
    payload = _body(resp)
    assert payload["ok"] is False
    assert payload["code"] == "invalid_credentials"
    # Enumeration-safe: the message must not reveal whether the email exists.
    assert "exist" not in payload["error"].lower()


async def test_login_unknown_email_is_401_same_as_wrong_password(
    auth: AuthService, middleware: _DriveMiddleware
) -> None:
    ctx = _ctx(auth)

    async def call_next(request: Request) -> Response:  # pragma: no cover
        raise AssertionError("/auth/login must terminate in the middleware")

    resp = await middleware.dispatch(
        _request_json(
            ctx,
            path="/auth/login",
            body={"email": "ghost@example.com", "password": "whatever-they-typed"},
        ),
        call_next,
    )
    assert resp.status_code == 401
    assert _body(resp)["code"] == "invalid_credentials"


async def test_signup_duplicate_email_is_409(
    auth: AuthService, middleware: _DriveMiddleware
) -> None:
    await _sign_up(auth)
    ctx = _ctx(auth)

    async def call_next(request: Request) -> Response:  # pragma: no cover
        raise AssertionError("/auth/signup must terminate in the middleware")

    resp = await middleware.dispatch(
        _request_json(
            ctx,
            path="/auth/signup",
            body={"email": "alice@example.com", "password": "another good password"},
        ),
        call_next,
    )
    assert resp.status_code == 409
    assert _body(resp)["code"] == "account_exists"


async def test_signup_weak_password_is_422(
    auth: AuthService, middleware: _DriveMiddleware
) -> None:
    ctx = _ctx(auth)

    async def call_next(request: Request) -> Response:  # pragma: no cover
        raise AssertionError("/auth/signup must terminate in the middleware")

    resp = await middleware.dispatch(
        _request_json(
            ctx,
            path="/auth/signup",
            body={"email": "tiny@example.com", "password": "short"},
        ),
        call_next,
    )
    assert resp.status_code == 422
    assert _body(resp)["code"] == "weak_password"


async def test_login_missing_fields_is_400(
    auth: AuthService, middleware: _DriveMiddleware
) -> None:
    ctx = _ctx(auth)

    async def call_next(request: Request) -> Response:  # pragma: no cover
        raise AssertionError("/auth/login must terminate in the middleware")

    resp = await middleware.dispatch(
        _request_json(ctx, path="/auth/login", body={"email": "x@example.com"}),
        call_next,
    )
    assert resp.status_code == 400
    assert _body(resp)["ok"] is False


async def test_credentials_api_can_be_disabled(
    db, settings, middleware: _DriveMiddleware
) -> None:
    from dataclasses import replace

    no_creds = replace(settings, enable_credentials_api=False)
    auth = AuthService(db, no_creds)
    await auth.ensure_schema()
    ctx = _ctx(auth)

    # With the credentials API off, /auth/login is not an owned endpoint —
    # it falls through to the app (which here is the pass-through call_next).
    fell_through: dict = {}

    async def call_next(request: Request) -> Response:
        fell_through["hit"] = True
        return JSONResponse({"ok": True}, status_code=404)

    resp = await middleware.dispatch(
        _request_json(ctx, path="/auth/login", body={"email": "a@b.c", "password": "x"}),
        call_next,
    )
    assert fell_through.get("hit") is True
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# JWT token endpoints (POST /token, /token/refresh)


async def _ctx_with_jwt(auth: AuthService):
    from pyxle_auth.jwt_tokens import JWTService

    jwt = JWTService(auth._db, secret="mw-jwt-secret", access_ttl_seconds=900)
    await jwt.ensure_schema()
    ctx = PluginContext()
    ctx.register("auth.service", auth)
    ctx.register("auth.jwt", jwt)
    return ctx, jwt


async def test_token_endpoint_issues_pair(
    auth: AuthService, middleware: _DriveMiddleware
) -> None:
    await _sign_up(auth)
    ctx, jwt = await _ctx_with_jwt(auth)

    async def call_next(request: Request) -> Response:  # pragma: no cover
        raise AssertionError("/auth/token must terminate in the middleware")

    resp = await middleware.dispatch(
        _request_json(
            ctx,
            path="/auth/token",
            body={
                "email": "alice@example.com",
                "password": "correct horse battery staple",
            },
        ),
        call_next,
    )
    assert resp.status_code == 200
    payload = _body(resp)
    assert payload["ok"] is True
    assert jwt.verify_access(payload["accessToken"]) is not None
    assert payload["refreshToken"]
    assert payload["tokenType"] == "Bearer"
    assert payload["user"]["email"] == "alice@example.com"


async def test_token_endpoint_wrong_password_is_401(
    auth: AuthService, middleware: _DriveMiddleware
) -> None:
    await _sign_up(auth)
    ctx, _ = await _ctx_with_jwt(auth)

    async def call_next(request: Request) -> Response:  # pragma: no cover
        raise AssertionError("/auth/token must terminate in the middleware")

    resp = await middleware.dispatch(
        _request_json(
            ctx,
            path="/auth/token",
            body={"email": "alice@example.com", "password": "nope"},
        ),
        call_next,
    )
    assert resp.status_code == 401
    assert _body(resp)["code"] == "invalid_credentials"


async def test_token_refresh_rotates(
    auth: AuthService, middleware: _DriveMiddleware
) -> None:
    user, _ = await auth.sign_up(email="rot@example.com", password="correct horse staple")
    ctx, jwt = await _ctx_with_jwt(auth)
    pair = await jwt.issue_pair(user_id=user.id)

    async def call_next(request: Request) -> Response:  # pragma: no cover
        raise AssertionError("/auth/token/refresh must terminate in the middleware")

    resp = await middleware.dispatch(
        _request_json(
            ctx, path="/auth/token/refresh", body={"refreshToken": pair.refresh_token}
        ),
        call_next,
    )
    assert resp.status_code == 200
    payload = _body(resp)
    assert payload["refreshToken"] != pair.refresh_token
    assert jwt.verify_access(payload["accessToken"]) is not None


async def test_token_refresh_invalid_is_401(
    auth: AuthService, middleware: _DriveMiddleware
) -> None:
    ctx, _ = await _ctx_with_jwt(auth)

    async def call_next(request: Request) -> Response:  # pragma: no cover
        raise AssertionError("/auth/token/refresh must terminate in the middleware")

    resp = await middleware.dispatch(
        _request_json(ctx, path="/auth/token/refresh", body={"refreshToken": "bogus"}),
        call_next,
    )
    assert resp.status_code == 401
    assert _body(resp)["code"] == "invalid_refresh"


async def test_token_endpoint_absent_when_jwt_not_configured(
    auth: AuthService, middleware: _DriveMiddleware
) -> None:
    # No auth.jwt registered → /token is not an owned endpoint, falls through.
    ctx = _ctx(auth)
    fell_through: dict = {}

    async def call_next(request: Request) -> Response:
        fell_through["hit"] = True
        return JSONResponse({"ok": True}, status_code=404)

    resp = await middleware.dispatch(
        _request_json(ctx, path="/auth/token", body={"email": "a@b.c", "password": "x"}),
        call_next,
    )
    assert fell_through.get("hit") is True
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# SSR seed (scope['pyxle.auth'])


async def test_scope_seed_anonymous(
    auth: AuthService, middleware: _DriveMiddleware
) -> None:
    ctx = _ctx(auth)
    captured: dict = {}

    async def call_next(request: Request) -> Response:
        captured["seed"] = request.scope.get("pyxle.auth")
        return JSONResponse({"ok": True})

    await middleware.dispatch(_request(ctx, path="/dashboard"), call_next)
    seed = captured["seed"]
    assert seed["user"] is None
    assert seed["endpoints"]["me"] == "/auth/me"
    assert seed["endpoints"]["logout"] == "/auth/logout"
    assert seed["endpoints"]["login"] == "/auth/login"
    assert seed["endpoints"]["signup"] == "/auth/signup"


async def test_scope_seed_signed_in(
    auth: AuthService, middleware: _DriveMiddleware
) -> None:
    _, cookie = await _sign_up(auth)
    ctx = _ctx(auth)
    captured: dict = {}

    async def call_next(request: Request) -> Response:
        captured["seed"] = request.scope.get("pyxle.auth")
        return JSONResponse({"ok": True})

    await middleware.dispatch(
        _request(ctx, path="/dashboard", cookies={"pyxle_session": cookie}),
        call_next,
    )
    assert captured["seed"]["user"]["email"] == "alice@example.com"


async def test_scope_seed_omits_credentials_endpoints_when_disabled(
    db, settings, middleware: _DriveMiddleware
) -> None:
    from dataclasses import replace

    no_creds = replace(settings, enable_credentials_api=False)
    auth = AuthService(db, no_creds)
    await auth.ensure_schema()
    ctx = _ctx(auth)
    captured: dict = {}

    async def call_next(request: Request) -> Response:
        captured["seed"] = request.scope.get("pyxle.auth")
        return JSONResponse({"ok": True})

    await middleware.dispatch(_request(ctx, path="/dashboard"), call_next)
    endpoints = captured["seed"]["endpoints"]
    assert "login" not in endpoints
    assert "signup" not in endpoints
    assert endpoints["me"] == "/auth/me"


# ---------------------------------------------------------------------------
# Configurable prefix


async def test_custom_prefix_moves_endpoints(
    db, settings, middleware: _DriveMiddleware
) -> None:
    from dataclasses import replace

    moved = replace(settings, auth_path_prefix="/api/auth")
    auth = AuthService(db, moved)
    await auth.ensure_schema()
    ctx = _ctx(auth)

    async def terminate(request: Request) -> Response:  # pragma: no cover
        raise AssertionError("endpoint must terminate in the middleware")

    # The moved path is served...
    resp = await middleware.dispatch(_request(ctx, path="/api/auth/me"), terminate)
    assert resp.status_code == 200
    assert _body(resp) == {"user": None}

    # ...and the default path is now just an ordinary request (falls through).
    fell_through: dict = {}

    async def call_next(request: Request) -> Response:
        fell_through["hit"] = True
        return JSONResponse({"ok": True})

    resp = await middleware.dispatch(_request(ctx, path="/auth/me"), call_next)
    assert fell_through.get("hit") is True


# ---------------------------------------------------------------------------
# Integration with the guards' per-request cache


async def test_guard_reuses_request_user_from_middleware(
    auth: AuthService, middleware: _DriveMiddleware
) -> None:
    """A guarded loader running after the middleware must not re-resolve."""
    from pyxle_auth.guards import current_user

    _, cookie = await _sign_up(auth)
    ctx = _ctx(auth)

    # Count how many times the service actually resolves a session.
    calls = {"n": 0}
    real_resolve = auth.resolve_session

    async def counting_resolve(*, cookie_value: str, extend: bool = True):
        calls["n"] += 1
        return await real_resolve(cookie_value=cookie_value, extend=extend)

    auth.resolve_session = counting_resolve  # type: ignore[method-assign]

    captured: dict = {}

    async def call_next(request: Request) -> Response:
        # The middleware already resolved; current_user reuses the cache.
        captured["a"] = await current_user(request, service=None)
        captured["b"] = await current_user(request, service=None)
        return JSONResponse({"ok": True})

    # Register the service in the active plugin context so the guard's default
    # discovery (service=None) finds it.
    import pyxle.plugins

    pyxle.plugins.set_active_context(ctx)
    try:
        await middleware.dispatch(
            _request(ctx, path="/dashboard", cookies={"pyxle_session": cookie}),
            call_next,
        )
    finally:
        pyxle.plugins.set_active_context(None)

    assert captured["a"] is not None
    assert captured["a"] is captured["b"]
    assert calls["n"] == 1  # middleware resolved once; both guard calls reused


# ---------------------------------------------------------------------------
# user_to_json projection


def test_user_to_json_none_is_none() -> None:
    assert user_to_json(None) is None


def test_user_to_json_marks_verified_email() -> None:
    from datetime import datetime, timezone

    from pyxle_auth.models import User

    verified = User(
        id="u1",
        email="bob@example.com",
        username=None,
        email_verified_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        plan="pro",
    )
    out = user_to_json(verified)
    assert out == {
        "id": "u1",
        "email": "bob@example.com",
        "username": None,
        "emailVerified": True,
        "plan": "pro",
        "createdAt": "2026-01-01T00:00:00+00:00",
    }


# ---------------------------------------------------------------------------
# Username-mode endpoints (flexible identity, 0.4.0)
# ---------------------------------------------------------------------------


@pytest.fixture
async def username_auth(db: Any) -> AuthService:
    svc = AuthService(
        db, AuthSettings(strict=False, identifier="username").for_tests()
    )
    await svc.ensure_schema()
    return svc


async def _reject_call_next(request: Request) -> Response:  # pragma: no cover
    raise AssertionError("auth endpoint must terminate in the middleware")


async def test_signup_via_username_endpoint(
    username_auth: AuthService, middleware: _DriveMiddleware
) -> None:
    ctx = _ctx(username_auth)
    resp = await middleware.dispatch(
        _request_json(
            ctx,
            path="/auth/signup",
            body={"username": "Ada", "password": "correct horse battery"},
        ),
        _reject_call_next,
    )
    assert resp.status_code == 201
    payload = _body(resp)
    assert payload["user"]["username"] == "ada"
    assert payload["user"]["email"] is None
    assert "pyxle_session=" in resp.headers["set-cookie"]


async def test_signup_username_endpoint_requires_username_field(
    username_auth: AuthService, middleware: _DriveMiddleware
) -> None:
    ctx = _ctx(username_auth)
    resp = await middleware.dispatch(
        _request_json(
            ctx,
            path="/auth/signup",
            body={"email": "x@y.com", "password": "correct horse battery"},
        ),
        _reject_call_next,
    )
    assert resp.status_code == 400  # the configured identifier ('username') is missing


async def test_login_via_username_endpoint_is_case_insensitive(
    username_auth: AuthService, middleware: _DriveMiddleware
) -> None:
    await username_auth.sign_up(username="ada", password="correct horse battery")
    ctx = _ctx(username_auth)
    resp = await middleware.dispatch(
        _request_json(
            ctx,
            path="/auth/login",
            body={"username": "ADA", "password": "correct horse battery"},
        ),
        _reject_call_next,
    )
    assert resp.status_code == 200
    assert _body(resp)["user"]["username"] == "ada"


async def test_username_available_endpoint(
    username_auth: AuthService, middleware: _DriveMiddleware
) -> None:
    await username_auth.sign_up(username="taken", password="correct horse battery")
    ctx = _ctx(username_auth)
    app = SimpleNamespace(state=SimpleNamespace(pyxle_plugins=ctx))

    async def receive() -> dict:
        return {"type": "http.request", "body": b"", "more_body": False}

    def get(query: bytes) -> Request:
        scope = {
            "type": "http",
            "method": "GET",
            "path": "/auth/username-available",
            "headers": [],
            "query_string": query,
            "client": ("203.0.113.9", 5555),
            "app": app,
            "state": {},
        }
        return Request(scope, receive)

    r_free = await middleware.dispatch(get(b"u=freehandle"), _reject_call_next)
    assert r_free.status_code == 200
    assert _body(r_free)["available"] is True

    r_taken = await middleware.dispatch(get(b"u=taken"), _reject_call_next)
    assert _body(r_taken)["available"] is False

    r_reserved = await middleware.dispatch(get(b"u=admin"), _reject_call_next)
    body = _body(r_reserved)
    assert body["available"] is False and "reserved" in body.get("reason", "").lower()
