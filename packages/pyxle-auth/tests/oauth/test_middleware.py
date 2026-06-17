"""OAuthMiddleware — the full HTTP security matrix for start + callback.

The middleware is driven directly (``await mw.dispatch(request, call_next)``)
so the AuthService's async SQLite connection and the handler share one event
loop. The callback's state cookie is forged with the *real* signing secret in
tests (the attacker can't, in production) so we can exercise the callback in
isolation; the hostile cases use a wrong secret / wrong nonce / tampering.
"""

from __future__ import annotations

import time
from types import SimpleNamespace
from urllib.parse import parse_qs, urlparse

import pytest
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from pyxle.plugins import PluginContext

from pyxle_auth import AuthService
from pyxle_auth.oauth import state as oauth_state
from pyxle_auth.oauth.middleware import OAuthFlowConfig, OAuthMiddleware
from pyxle_auth.oauth.providers import OAuthProvider
from pyxle_auth.oauth.service import OAuthService
from pyxle_auth.oauth.state import OAuthState

from tests.oauth._fakes import FakeClient, FakeResponse, factory_for

GOOGLE_TOKEN = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO = "https://openidconnect.googleapis.com/v1/userinfo"
STATE_SECRET = b"middleware-test-secret-32-bytes-0"


async def _dummy_asgi(scope, receive, send):  # pragma: no cover - never called
    raise AssertionError("dispatch is invoked directly")


@pytest.fixture
def middleware() -> OAuthMiddleware:
    return OAuthMiddleware(_dummy_asgi)


def _config(**overrides) -> OAuthFlowConfig:
    base = dict(
        state_secret=STATE_SECRET,
        auth_path_prefix="/auth",
        cookie_secure=False,
        failure_redirect="/login",
    )
    base.update(overrides)
    return OAuthFlowConfig(**base)


async def _service(auth: AuthService, client: FakeClient) -> OAuthService:
    provider = OAuthProvider.from_env("google", client_id="gid", client_secret="gsecret")
    svc = OAuthService(
        auth._db, auth, {"google": provider}, http_client_factory=factory_for(client)
    )
    await svc.ensure_schema()
    return svc


def _ctx(service: OAuthService | None, config: OAuthFlowConfig | None) -> PluginContext:
    ctx = PluginContext()
    if service is not None:
        ctx.register("auth.oauth", service)
    if config is not None:
        ctx.register("auth.oauth.config", config)
    return ctx


def _request(
    ctx: PluginContext,
    *,
    method: str = "GET",
    path: str,
    query: str = "",
    cookies: dict[str, str] | None = None,
) -> Request:
    headers: list[tuple[bytes, bytes]] = [(b"host", b"app.example.com")]
    if cookies:
        blob = "; ".join(f"{k}={v}" for k, v in cookies.items())
        headers.append((b"cookie", blob.encode("latin-1")))
    app = SimpleNamespace(state=SimpleNamespace(pyxle_plugins=ctx))
    scope = {
        "type": "http",
        "method": method,
        "scheme": "https",
        "path": path,
        "query_string": query.encode("latin-1"),
        "headers": headers,
        "client": ("203.0.113.7", 4444),
        "app": app,
        "state": {},
    }
    return Request(scope)


def _set_cookie_header(response: Response) -> str:
    for key, value in response.raw_headers:
        if key == b"set-cookie":
            return value.decode("latin-1")
    return ""


def _all_set_cookies(response: Response) -> list[str]:
    return [
        value.decode("latin-1")
        for key, value in response.raw_headers
        if key == b"set-cookie"
    ]


def _forge_state_cookie(
    *, provider="google", nonce="the-nonce", verifier="the-verifier", next="/dash", config=None
) -> str:
    cfg = config or _config()
    return oauth_state.issue(
        OAuthState(
            provider=provider,
            nonce=nonce,
            verifier=verifier,
            next=next,
            issued_at=int(time.time()),
        ),
        secret=cfg.state_secret,
    )


def _google_client(*, sub="g-1", email="alice@example.com", verified=True) -> FakeClient:
    return FakeClient(
        post={GOOGLE_TOKEN: FakeResponse(200, {"access_token": "at"})},
        get={
            GOOGLE_USERINFO: FakeResponse(
                200, {"sub": sub, "email": email, "email_verified": verified}
            )
        },
    )


# ---------------------------------------------------------------------------
# Pass-through


async def test_inert_when_not_configured(middleware: OAuthMiddleware) -> None:
    ctx = _ctx(None, None)

    async def call_next(request: Request) -> Response:
        return JSONResponse({"ok": True})

    resp = await middleware.dispatch(_request(ctx, path="/auth/oauth/google/start"), call_next)
    assert resp.status_code == 200


async def test_non_oauth_path_passes_through(auth: AuthService, middleware: OAuthMiddleware) -> None:
    ctx = _ctx(await _service(auth, _google_client()), _config())
    hit: dict = {}

    async def call_next(request: Request) -> Response:
        hit["x"] = True
        return JSONResponse({"ok": True})

    await middleware.dispatch(_request(ctx, path="/dashboard"), call_next)
    assert hit.get("x") is True


# ---------------------------------------------------------------------------
# start


async def test_start_redirects_to_provider_with_pkce_and_sets_state_cookie(
    auth: AuthService, middleware: OAuthMiddleware
) -> None:
    ctx = _ctx(await _service(auth, _google_client()), _config())

    async def call_next(request):  # pragma: no cover
        raise AssertionError("start must terminate")

    resp = await middleware.dispatch(
        _request(ctx, path="/auth/oauth/google/start", query="next=%2Fdashboard"),
        call_next,
    )
    assert resp.status_code == 302
    location = resp.headers["location"]
    assert location.startswith("https://accounts.google.com/o/oauth2/v2/auth?")
    params = parse_qs(urlparse(location).query)
    assert params["code_challenge_method"] == ["S256"]
    assert "code_challenge" in params
    assert params["redirect_uri"] == [
        "https://app.example.com/auth/oauth/google/callback"
    ]
    # The state cookie is HttpOnly, Lax, scoped to the oauth path.
    cookie = _set_cookie_header(resp)
    assert "pyxle_oauth_state=" in cookie
    assert "HttpOnly" in cookie
    assert "samesite=lax" in cookie.lower()
    assert "Path=/auth/oauth" in cookie
    # The URL state nonce equals the nonce signed into the cookie.
    cookie_value = cookie.split("pyxle_oauth_state=", 1)[1].split(";", 1)[0]
    decoded = oauth_state.verify(cookie_value, secret=STATE_SECRET, max_age_seconds=600)
    assert decoded is not None
    assert params["state"] == [decoded.nonce]


async def test_start_sanitizes_open_redirect_next(
    auth: AuthService, middleware: OAuthMiddleware
) -> None:
    ctx = _ctx(await _service(auth, _google_client()), _config())

    async def call_next(request):  # pragma: no cover
        raise AssertionError("start must terminate")

    resp = await middleware.dispatch(
        _request(ctx, path="/auth/oauth/google/start", query="next=https%3A%2F%2Fevil.com"),
        call_next,
    )
    cookie = _set_cookie_header(resp)
    cookie_value = cookie.split("pyxle_oauth_state=", 1)[1].split(";", 1)[0]
    decoded = oauth_state.verify(cookie_value, secret=STATE_SECRET, max_age_seconds=600)
    assert decoded is not None
    assert decoded.next == "/"  # the off-origin next was dropped


async def test_start_unknown_provider_redirects_to_failure(
    auth: AuthService, middleware: OAuthMiddleware
) -> None:
    ctx = _ctx(await _service(auth, _google_client()), _config())

    async def call_next(request):  # pragma: no cover
        raise AssertionError("start must terminate")

    resp = await middleware.dispatch(
        _request(ctx, path="/auth/oauth/github/start"), call_next
    )
    assert resp.status_code == 302
    assert resp.headers["location"] == "/login?oauth_error=unknown_provider"


async def test_start_rejects_post(auth: AuthService, middleware: OAuthMiddleware) -> None:
    ctx = _ctx(await _service(auth, _google_client()), _config())

    async def call_next(request):  # pragma: no cover
        raise AssertionError("must not pass through")

    resp = await middleware.dispatch(
        _request(ctx, method="POST", path="/auth/oauth/google/start"), call_next
    )
    assert resp.status_code == 405


# ---------------------------------------------------------------------------
# callback — success


async def test_callback_success_signs_in_and_redirects(
    auth: AuthService, middleware: OAuthMiddleware
) -> None:
    config = _config()
    ctx = _ctx(await _service(auth, _google_client(email="newuser@example.com")), config)
    cookie = _forge_state_cookie(nonce="N1", verifier="V1", next="/dash", config=config)

    async def call_next(request):  # pragma: no cover
        raise AssertionError("callback must terminate")

    resp = await middleware.dispatch(
        _request(
            ctx,
            path="/auth/oauth/google/callback",
            query="code=auth-code&state=N1",
            cookies={"pyxle_oauth_state": cookie},
        ),
        call_next,
    )
    assert resp.status_code == 302
    assert resp.headers["location"] == "/dash"
    cookies = _all_set_cookies(resp)
    # The session cookie is set and the state cookie is cleared (Max-Age=0).
    assert any("pyxle_session=" in c and "Max-Age=0" not in c for c in cookies)
    assert any("pyxle_oauth_state=" in c and "Max-Age=0" in c for c in cookies)
    # The user really exists now.
    assert await auth.get_user_by_email(email="newuser@example.com") is not None


# ---------------------------------------------------------------------------
# callback — hostile cases


async def test_callback_missing_state_cookie_fails(
    auth: AuthService, middleware: OAuthMiddleware
) -> None:
    ctx = _ctx(await _service(auth, _google_client()), _config())

    async def call_next(request):  # pragma: no cover
        raise AssertionError("callback must terminate")

    resp = await middleware.dispatch(
        _request(ctx, path="/auth/oauth/google/callback", query="code=c&state=N1"),
        call_next,
    )
    assert resp.status_code == 302
    assert resp.headers["location"] == "/login?oauth_error=state"


async def test_callback_nonce_mismatch_fails(
    auth: AuthService, middleware: OAuthMiddleware
) -> None:
    config = _config()
    ctx = _ctx(await _service(auth, _google_client()), config)
    cookie = _forge_state_cookie(nonce="REAL", config=config)

    async def call_next(request):  # pragma: no cover
        raise AssertionError("callback must terminate")

    # The echoed state does NOT match the cookie's nonce → login-CSRF blocked.
    resp = await middleware.dispatch(
        _request(
            ctx,
            path="/auth/oauth/google/callback",
            query="code=c&state=ATTACKER",
            cookies={"pyxle_oauth_state": cookie},
        ),
        call_next,
    )
    assert resp.headers["location"] == "/login?oauth_error=state"


async def test_callback_tampered_cookie_fails(
    auth: AuthService, middleware: OAuthMiddleware
) -> None:
    config = _config()
    ctx = _ctx(await _service(auth, _google_client()), config)
    cookie = _forge_state_cookie(nonce="N1", config=config)
    tampered = cookie[:-2] + ("AA" if not cookie.endswith("AA") else "BB")

    async def call_next(request):  # pragma: no cover
        raise AssertionError("callback must terminate")

    resp = await middleware.dispatch(
        _request(
            ctx,
            path="/auth/oauth/google/callback",
            query="code=c&state=N1",
            cookies={"pyxle_oauth_state": tampered},
        ),
        call_next,
    )
    assert resp.headers["location"] == "/login?oauth_error=state"


async def test_callback_wrong_secret_cookie_fails(
    auth: AuthService, middleware: OAuthMiddleware
) -> None:
    config = _config()
    ctx = _ctx(await _service(auth, _google_client()), config)
    # A cookie signed with a different secret (attacker can't sign with ours).
    forged = oauth_state.issue(
        OAuthState(provider="google", nonce="N1", verifier="V", next="/dash", issued_at=int(time.time())),
        secret=b"attacker-secret-not-the-servers",
    )

    async def call_next(request):  # pragma: no cover
        raise AssertionError("callback must terminate")

    resp = await middleware.dispatch(
        _request(
            ctx,
            path="/auth/oauth/google/callback",
            query="code=c&state=N1",
            cookies={"pyxle_oauth_state": forged},
        ),
        call_next,
    )
    assert resp.headers["location"] == "/login?oauth_error=state"


async def test_callback_provider_mismatch_fails(
    auth: AuthService, middleware: OAuthMiddleware
) -> None:
    config = _config()
    ctx = _ctx(await _service(auth, _google_client()), config)
    # Cookie is for google, but the callback path is github.
    cookie = _forge_state_cookie(provider="google", nonce="N1", config=config)

    async def call_next(request):  # pragma: no cover
        raise AssertionError("callback must terminate")

    resp = await middleware.dispatch(
        _request(
            ctx,
            path="/auth/oauth/github/callback",
            query="code=c&state=N1",
            cookies={"pyxle_oauth_state": cookie},
        ),
        call_next,
    )
    assert resp.headers["location"] == "/login?oauth_error=state"


async def test_callback_provider_error_param_fails_with_next(
    auth: AuthService, middleware: OAuthMiddleware
) -> None:
    config = _config()
    ctx = _ctx(await _service(auth, _google_client()), config)
    cookie = _forge_state_cookie(nonce="N1", next="/back", config=config)

    async def call_next(request):  # pragma: no cover
        raise AssertionError("callback must terminate")

    # The user denied consent at the provider.
    resp = await middleware.dispatch(
        _request(
            ctx,
            path="/auth/oauth/google/callback",
            query="error=access_denied&state=N1",
            cookies={"pyxle_oauth_state": cookie},
        ),
        call_next,
    )
    assert resp.headers["location"] == "/back?oauth_error=denied"


async def test_callback_unverified_email_fails(
    auth: AuthService, middleware: OAuthMiddleware
) -> None:
    config = _config()
    # New identity whose email the provider has NOT verified.
    client = _google_client(sub="attacker", email="victim@example.com", verified=False)
    ctx = _ctx(await _service(auth, client), config)
    cookie = _forge_state_cookie(nonce="N1", next="/dash", config=config)

    async def call_next(request):  # pragma: no cover
        raise AssertionError("callback must terminate")

    resp = await middleware.dispatch(
        _request(
            ctx,
            path="/auth/oauth/google/callback",
            query="code=c&state=N1",
            cookies={"pyxle_oauth_state": cookie},
        ),
        call_next,
    )
    assert resp.headers["location"] == "/dash?oauth_error=email_unverified"


async def test_callback_replay_after_use_fails(
    auth: AuthService, middleware: OAuthMiddleware
) -> None:
    """The state cookie is single-use: a successful callback clears it, so a
    replay (no cookie) fails. We model the replay as the same request without
    the now-cleared cookie."""
    config = _config()
    ctx = _ctx(await _service(auth, _google_client(email="once@example.com")), config)
    cookie = _forge_state_cookie(nonce="N1", config=config)

    async def call_next(request):  # pragma: no cover
        raise AssertionError("callback must terminate")

    first = await middleware.dispatch(
        _request(
            ctx,
            path="/auth/oauth/google/callback",
            query="code=c&state=N1",
            cookies={"pyxle_oauth_state": cookie},
        ),
        call_next,
    )
    assert first.status_code == 302
    assert "oauth_error" not in first.headers["location"]
    # The response cleared the cookie; a replay arrives without it → fails.
    replay = await middleware.dispatch(
        _request(ctx, path="/auth/oauth/google/callback", query="code=c&state=N1"),
        call_next,
    )
    assert replay.headers["location"] == "/login?oauth_error=state"


async def test_callback_open_redirect_next_is_neutralized(
    auth: AuthService, middleware: OAuthMiddleware
) -> None:
    """Even a (forged) cookie carrying an off-origin next is neutralized on the
    success redirect — defense-in-depth if the signing secret ever leaks."""
    config = _config()
    ctx = _ctx(await _service(auth, _google_client(email="ok@example.com")), config)
    cookie = _forge_state_cookie(nonce="N1", next="//evil.com/phish", config=config)

    async def call_next(request):  # pragma: no cover
        raise AssertionError("callback must terminate")

    resp = await middleware.dispatch(
        _request(
            ctx,
            path="/auth/oauth/google/callback",
            query="code=c&state=N1",
            cookies={"pyxle_oauth_state": cookie},
        ),
        call_next,
    )
    assert resp.headers["location"] == "/"  # not //evil.com
