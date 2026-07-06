"""Request guards — the one-liners that protect Pyxle loaders and actions.

.. code-block:: python

    from pyxle_auth.guards import current_user, require_user_page, require_user_action

    @server
    async def load(request):
        user = await require_user_page(request)          # 401 LoaderError when signed out
        return {"id": user.id, "name": user.username or user.email}

    @action
    async def save(request):
        user = await require_user_action(request)        # 401 ActionError when signed out
        ...

Two flavours exist because Pyxle's error channels differ: a loader failure
renders the nearest ``error.pyxl`` boundary (``LoaderError``), an action
failure returns structured JSON to ``useAction`` (``ActionError``). Both
guards share one resolution path.

Service discovery: by default the guards read the ``auth.service`` entry the
plugin registers at startup. Pass ``service=`` explicitly in tests or in
apps that wire :class:`pyxle_auth.AuthService` by hand.
"""

from __future__ import annotations

from typing import Any, Awaitable, Protocol

from pyxle.runtime import ActionError, LoaderError

from pyxle_auth.models import User

__all__ = [
    "current_user",
    "require_user_page",
    "require_user_action",
    "require_permission_page",
    "require_permission_action",
    "login_required",
    "login_required_action",
    "permission_required",
    "permission_required_action",
    "bearer_token",
    "bearer_user",
    "authenticate",
    "PERMISSION_SERVICE_NAME",
    "AUTH_SERVICE_NAME",
    "JWT_SERVICE_NAME",
    "API_TOKEN_SERVICE_NAME",
]

AUTH_SERVICE_NAME = "auth.service"
PERMISSION_SERVICE_NAME = "auth.rbac"
JWT_SERVICE_NAME = "auth.jwt"
API_TOKEN_SERVICE_NAME = "auth.api_tokens"

# Distinguishes "AuthSessionMiddleware cached an explicit None (anonymous)"
# from "nothing has resolved this request's user yet".
_UNSET: Any = object()


class _SessionResolver(Protocol):
    settings: Any

    def resolve_session(
        self, *, cookie_value: str, extend: bool = True
    ) -> Awaitable[User | None]: ...


class _PermissionChecker(Protocol):
    def has_permission(self, *, user_id: str, permission: str) -> Awaitable[bool]: ...


def _service_from_context(name: str) -> Any:
    from pyxle.plugins import plugin  # lazy: keep import-time deps minimal

    # plugin(name) without a default RAISES when the service is missing —
    # pass an explicit default so we can raise our actionable error instead.
    found = plugin(name, None)
    if found is None:
        raise RuntimeError(
            f"No {name!r} service registered. Either list pyxle-auth in "
            "pyxle.config.json plugins, or pass service= explicitly."
        )
    return found


def _optional_service(name: str) -> Any:
    """Return a registered service, or ``None`` — for optional ones (JWT)."""
    from pyxle.plugins import plugin

    return plugin(name, None)


async def current_user(
    request: Any, *, service: _SessionResolver | None = None, extend: bool = True
) -> User | None:
    """The signed-in user for this request, or ``None``.

    Reads the session cookie named by the service's settings and resolves
    it. Never raises on anonymous requests — branch on the result.

    When :class:`~pyxle_auth.middleware.AuthSessionMiddleware` is active it has
    already resolved this request's user and cached it on the ASGI scope (the
    value behind Starlette's ``request.user``); the default call reuses that
    instead of hitting the database again, and repeated guard calls within one
    request resolve at most once. Passing an explicit ``service`` or
    ``extend=False`` forces a fresh resolution and skips the cache.
    """
    # Only the default ambient path participates in the per-request cache.
    scope = (
        getattr(request, "scope", None) if service is None and extend else None
    )
    if scope is not None:
        cached = scope.get("user", _UNSET)
        if cached is not _UNSET:
            return cached

    svc = service if service is not None else _service_from_context(AUTH_SERVICE_NAME)
    cookie_value = request.cookies.get(svc.settings.cookie_name)
    if not cookie_value:
        user = None
    else:
        user = await svc.resolve_session(cookie_value=cookie_value, extend=extend)

    if scope is not None:
        scope["user"] = user
    return user


async def require_user_page(
    request: Any, *, service: _SessionResolver | None = None
) -> User:
    """Guard a ``@server`` loader. Raises ``LoaderError(401)`` when anonymous."""
    user = await current_user(request, service=service)
    if user is None:
        raise LoaderError(
            "Sign in to view this page.",
            status_code=401,
            data={"reason": "auth_required"},
        )
    return user


async def require_user_action(
    request: Any, *, service: _SessionResolver | None = None
) -> User:
    """Guard an ``@action``. Raises ``ActionError(401)`` when anonymous."""
    user = await current_user(request, service=service)
    if user is None:
        raise ActionError(
            "Sign in to do that.",
            status_code=401,
            data={"reason": "auth_required"},
        )
    return user


async def _require_permission(
    request: Any,
    permission: str,
    *,
    service: _SessionResolver | None,
    rbac: _PermissionChecker | None,
    error: type[Exception],
    message: str,
) -> User:
    if not permission or not permission.strip():
        raise ValueError("permission must be a non-empty string")
    if error is LoaderError:
        user = await require_user_page(request, service=service)
    else:
        user = await require_user_action(request, service=service)
    checker = (
        rbac if rbac is not None else _service_from_context(PERMISSION_SERVICE_NAME)
    )
    allowed = await checker.has_permission(user_id=user.id, permission=permission)
    if not allowed:
        raise error(  # type: ignore[call-arg]  # both error types share this signature
            message,
            status_code=403,
            data={"reason": "permission_denied", "permission": permission},
        )
    return user


async def require_permission_page(
    request: Any,
    permission: str,
    *,
    service: _SessionResolver | None = None,
    rbac: _PermissionChecker | None = None,
) -> User:
    """Loader guard: signed in AND holding ``permission``, else 401/403."""
    return await _require_permission(
        request,
        permission,
        service=service,
        rbac=rbac,
        error=LoaderError,
        message="You don't have access to this page.",
    )


async def require_permission_action(
    request: Any,
    permission: str,
    *,
    service: _SessionResolver | None = None,
    rbac: _PermissionChecker | None = None,
) -> User:
    """Action guard: signed in AND holding ``permission``, else 401/403."""
    return await _require_permission(
        request,
        permission,
        service=service,
        rbac=rbac,
        error=ActionError,
        message="You don't have permission to do that.",
    )


def bearer_token(request: Any) -> str | None:
    """Extract a ``Authorization: Bearer <token>`` value, or ``None``.

    For API routes authenticating with
    :class:`pyxle_auth.api_tokens.ApiTokenService`. Tolerates exactly one
    space and a case-insensitive scheme; rejects empty and oversized values.
    """
    header = request.headers.get("authorization")
    if not header:
        return None
    parts = header.strip().split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    token = parts[1].strip()
    if not token or len(token) > 256:
        return None
    return token


async def bearer_user(
    request: Any,
    *,
    auth: Any = None,
    jwt: Any = None,
    api_tokens: Any = None,
    required_scope: str | None = None,
) -> User | None:
    """Resolve an ``Authorization: Bearer`` token to a user, or ``None``.

    Tries a **JWT access token first, then a personal access token** — the
    design's bearer order. The two never collide: a PAT (``pyxle_pat_…``) is
    not a valid JWT, and a JWT is not a PAT. ``required_scope`` is enforced on
    the PAT path. Returns ``None`` when there is no bearer header or it doesn't
    validate; never raises on a bad token.

    Services are read from the plugin context by default; pass them explicitly
    in tests or hand-wired apps.
    """
    raw = bearer_token(request)
    if raw is None:
        return None
    auth_svc = auth if auth is not None else _service_from_context(AUTH_SERVICE_NAME)

    jwt_svc = jwt if jwt is not None else _optional_service(JWT_SERVICE_NAME)
    if jwt_svc is not None:
        claims = jwt_svc.verify_access(raw)
        if claims is not None:
            user = await auth_svc.get_user(user_id=claims["sub"])
            if user is not None:
                return user

    pat_svc = (
        api_tokens if api_tokens is not None else _optional_service(API_TOKEN_SERVICE_NAME)
    )
    if pat_svc is not None:
        token = await pat_svc.resolve(raw_token=raw, required_scope=required_scope)
        if token is not None:
            return await auth_svc.get_user(user_id=token.user_id)

    return None


async def authenticate(
    request: Any,
    *,
    service: _SessionResolver | None = None,
    auth: Any = None,
    jwt: Any = None,
    api_tokens: Any = None,
    required_scope: str | None = None,
) -> User | None:
    """The unified resolver: **session cookie → JWT bearer → PAT bearer**.

    For endpoints that accept either a browser session or an API token. Returns
    the user from the first method that validates, or ``None``. Branch on the
    result, or wrap with :func:`require_user_action` semantics in your handler.
    """
    user = await current_user(request, service=service)
    if user is not None:
        return user
    return await bearer_user(
        request,
        auth=auth,
        jwt=jwt,
        api_tokens=api_tokens,
        required_scope=required_scope,
    )


# --- Roadmap-named aliases --------------------------------------------------
#
# The roadmap calls for a ``login_required`` guard. In Pyxle the idiomatic form
# is an awaitable guard called at the top of a loader/action (a wrapping
# decorator would violate the framework's "decorators add metadata, not
# behaviour" rule), so these are thin, explicit aliases of the guards above —
# not new behaviour. ``login_required`` guards a loader; the ``_action`` form
# guards an action.

#: Loader guard: require a signed-in user (alias of :func:`require_user_page`).
login_required = require_user_page

#: Action guard: require a signed-in user (alias of :func:`require_user_action`).
login_required_action = require_user_action

#: Loader guard: require a signed-in user holding a permission
#: (alias of :func:`require_permission_page`).
permission_required = require_permission_page

#: Action guard: require a permission (alias of :func:`require_permission_action`).
permission_required_action = require_permission_action
