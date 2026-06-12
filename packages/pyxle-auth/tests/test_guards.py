"""Hostile tests for :mod:`pyxle_auth.guards`.

The guards are the last line between an anonymous request and a protected
loader/action. These tests verify the error channel discipline (LoaderError
for pages, ActionError for actions — never crossed), the 401-before-403
ordering, service discovery through the plugin context, and the
``Authorization`` header parser's tolerance and limits.

No real HTTP stack: requests are minimal fakes (``.cookies`` / ``.headers``
dicts), the auth service is an async fake keyed by cookie value, and the
plugin context is either monkeypatched or a real ``PluginContext``.
"""

from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace
from typing import Any, Iterator, Mapping

import pytest

import pyxle.plugins
from pyxle.runtime import ActionError, LoaderError

from pyxle_auth.guards import (
    AUTH_SERVICE_NAME,
    PERMISSION_SERVICE_NAME,
    bearer_token,
    current_user,
    require_permission_action,
    require_permission_page,
    require_user_action,
    require_user_page,
)
from pyxle_auth.models import User

COOKIE_NAME = "pyxle_session"


def _make_user(user_id: str = "u1") -> User:
    return User(
        id=user_id,
        email="alice@example.com",
        email_verified_at=None,
        created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        plan="free",
    )


class FakeRequest:
    """The minimal surface the guards touch: ``.cookies`` and ``.headers``."""

    def __init__(
        self,
        cookies: Mapping[str, str] | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> None:
        self.cookies = dict(cookies or {})
        self.headers = dict(headers or {})


class FakeAuthService:
    """Session resolver keyed by cookie value; records every call."""

    def __init__(self, sessions: Mapping[str, User]) -> None:
        self.settings = SimpleNamespace(cookie_name=COOKIE_NAME)
        self._sessions = dict(sessions)
        self.calls: list[tuple[str, bool]] = []

    async def resolve_session(
        self, *, cookie_value: str, extend: bool = True
    ) -> User | None:
        self.calls.append((cookie_value, extend))
        return self._sessions.get(cookie_value)


class FakeRbac:
    """Permission checker with a fixed grant set; records every call."""

    def __init__(self, granted: set[str]) -> None:
        self._granted = set(granted)
        self.calls: list[tuple[str, str]] = []

    async def has_permission(self, *, user_id: str, permission: str) -> bool:
        self.calls.append((user_id, permission))
        return permission in self._granted


@pytest.fixture
def user() -> User:
    return _make_user()


@pytest.fixture
def auth(user: User) -> FakeAuthService:
    return FakeAuthService({"valid-cookie": user})


@pytest.fixture
def signed_in(user: User) -> FakeRequest:
    return FakeRequest(cookies={COOKIE_NAME: "valid-cookie"})


@pytest.fixture
def anonymous() -> FakeRequest:
    return FakeRequest()


# ---------------------------------------------------------------------------
# current_user


async def test_current_user_without_cookie_is_none(
    anonymous: FakeRequest, auth: FakeAuthService
) -> None:
    assert await current_user(anonymous, service=auth) is None
    # No cookie means no DB round-trip — and no oracle to time.
    assert auth.calls == []


async def test_current_user_with_empty_cookie_value_is_none(
    auth: FakeAuthService,
) -> None:
    request = FakeRequest(cookies={COOKIE_NAME: ""})
    assert await current_user(request, service=auth) is None
    assert auth.calls == []


async def test_current_user_resolves_cookie(
    signed_in: FakeRequest, auth: FakeAuthService, user: User
) -> None:
    assert await current_user(signed_in, service=auth) is user
    assert auth.calls == [("valid-cookie", True)]  # extend defaults to True


async def test_current_user_passes_extend_through(
    signed_in: FakeRequest, auth: FakeAuthService
) -> None:
    await current_user(signed_in, service=auth, extend=False)
    assert auth.calls == [("valid-cookie", False)]


async def test_current_user_with_unknown_cookie_is_none(
    auth: FakeAuthService,
) -> None:
    request = FakeRequest(cookies={COOKIE_NAME: "forged-cookie"})
    assert await current_user(request, service=auth) is None


# ---------------------------------------------------------------------------
# require_user_page / require_user_action — 401 channel discipline


async def test_require_user_page_raises_loader_401_when_anonymous(
    anonymous: FakeRequest, auth: FakeAuthService
) -> None:
    with pytest.raises(LoaderError) as exc_info:
        await require_user_page(anonymous, service=auth)
    assert exc_info.value.status_code == 401
    assert exc_info.value.data == {"reason": "auth_required"}
    assert not isinstance(exc_info.value, ActionError)


async def test_require_user_page_returns_user_when_signed_in(
    signed_in: FakeRequest, auth: FakeAuthService, user: User
) -> None:
    assert await require_user_page(signed_in, service=auth) is user


async def test_require_user_action_raises_action_401_when_anonymous(
    anonymous: FakeRequest, auth: FakeAuthService
) -> None:
    with pytest.raises(ActionError) as exc_info:
        await require_user_action(anonymous, service=auth)
    assert exc_info.value.status_code == 401
    assert exc_info.value.data == {"reason": "auth_required"}
    assert not isinstance(exc_info.value, LoaderError)


async def test_require_user_action_returns_user_when_signed_in(
    signed_in: FakeRequest, auth: FakeAuthService, user: User
) -> None:
    assert await require_user_action(signed_in, service=auth) is user


# ---------------------------------------------------------------------------
# require_permission_* — 401 before 403, data carries the permission


async def test_permission_page_anonymous_is_401_and_rbac_untouched(
    anonymous: FakeRequest, auth: FakeAuthService
) -> None:
    rbac = FakeRbac({"billing:write"})
    with pytest.raises(LoaderError) as exc_info:
        await require_permission_page(
            anonymous, "billing:write", service=auth, rbac=rbac
        )
    # Anonymity is a 401, never a 403 — and the permission system must not
    # be consulted for unauthenticated requests.
    assert exc_info.value.status_code == 401
    assert rbac.calls == []


async def test_permission_page_denied_is_403_with_permission_in_data(
    signed_in: FakeRequest, auth: FakeAuthService
) -> None:
    rbac = FakeRbac(set())
    with pytest.raises(LoaderError) as exc_info:
        await require_permission_page(
            signed_in, "billing:write", service=auth, rbac=rbac
        )
    assert exc_info.value.status_code == 403
    assert exc_info.value.data["reason"] == "permission_denied"
    assert exc_info.value.data["permission"] == "billing:write"


async def test_permission_page_granted_returns_user(
    signed_in: FakeRequest, auth: FakeAuthService, user: User
) -> None:
    rbac = FakeRbac({"billing:write"})
    result = await require_permission_page(
        signed_in, "billing:write", service=auth, rbac=rbac
    )
    assert result is user
    assert rbac.calls == [(user.id, "billing:write")]


async def test_permission_action_anonymous_is_action_401(
    anonymous: FakeRequest, auth: FakeAuthService
) -> None:
    rbac = FakeRbac({"deploy"})
    with pytest.raises(ActionError) as exc_info:
        await require_permission_action(anonymous, "deploy", service=auth, rbac=rbac)
    assert exc_info.value.status_code == 401
    assert not isinstance(exc_info.value, LoaderError)


async def test_permission_action_denied_is_action_403(
    signed_in: FakeRequest, auth: FakeAuthService
) -> None:
    rbac = FakeRbac({"read"})
    with pytest.raises(ActionError) as exc_info:
        await require_permission_action(signed_in, "deploy", service=auth, rbac=rbac)
    assert exc_info.value.status_code == 403
    assert exc_info.value.data["permission"] == "deploy"
    assert not isinstance(exc_info.value, LoaderError)


async def test_permission_action_granted_returns_user(
    signed_in: FakeRequest, auth: FakeAuthService, user: User
) -> None:
    rbac = FakeRbac({"deploy"})
    assert (
        await require_permission_action(signed_in, "deploy", service=auth, rbac=rbac)
        is user
    )


@pytest.mark.parametrize("permission", ["", "   "])
async def test_permission_guards_reject_blank_permission(
    signed_in: FakeRequest, auth: FakeAuthService, permission: str
) -> None:
    rbac = FakeRbac(set())
    with pytest.raises(ValueError):
        await require_permission_page(signed_in, permission, service=auth, rbac=rbac)
    with pytest.raises(ValueError):
        await require_permission_action(signed_in, permission, service=auth, rbac=rbac)


# ---------------------------------------------------------------------------
# Service discovery — plugin context vs explicit overrides


async def test_explicit_service_and_rbac_bypass_plugin_context(
    signed_in: FakeRequest, auth: FakeAuthService, user: User, monkeypatch: pytest.MonkeyPatch
) -> None:
    def exploding_plugin(name: str, default: Any = None) -> Any:
        raise AssertionError(f"plugin context consulted for {name!r}")

    monkeypatch.setattr(pyxle.plugins, "plugin", exploding_plugin)
    rbac = FakeRbac({"deploy"})
    result = await require_permission_page(
        signed_in, "deploy", service=auth, rbac=rbac
    )
    assert result is user


async def test_guards_discover_both_services_from_plugin_context(
    signed_in: FakeRequest, auth: FakeAuthService, user: User, monkeypatch: pytest.MonkeyPatch
) -> None:
    rbac = FakeRbac({"deploy"})
    registry = {AUTH_SERVICE_NAME: auth, PERMISSION_SERVICE_NAME: rbac}
    requested: list[str] = []

    def fake_plugin(name: str, default: Any = None) -> Any:
        requested.append(name)
        return registry.get(name)

    monkeypatch.setattr(pyxle.plugins, "plugin", fake_plugin)
    result = await require_permission_action(signed_in, "deploy")
    assert result is user
    assert AUTH_SERVICE_NAME in requested
    assert PERMISSION_SERVICE_NAME in requested
    assert auth.calls == [("valid-cookie", True)]
    assert rbac.calls == [(user.id, "deploy")]


@pytest.fixture
def real_context() -> Iterator[pyxle.plugins.PluginContext]:
    ctx = pyxle.plugins.PluginContext()
    pyxle.plugins.set_active_context(ctx)
    try:
        yield ctx
    finally:
        pyxle.plugins.set_active_context(None)


async def test_guards_work_with_a_real_plugin_context(
    signed_in: FakeRequest,
    auth: FakeAuthService,
    user: User,
    real_context: pyxle.plugins.PluginContext,
) -> None:
    real_context.register(AUTH_SERVICE_NAME, auth)
    real_context.register(PERMISSION_SERVICE_NAME, FakeRbac({"deploy"}))
    assert await current_user(signed_in) is user
    assert await require_permission_action(signed_in, "deploy") is user


async def test_missing_auth_service_error_mentions_pyxle_config(
    signed_in: FakeRequest, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        pyxle.plugins, "plugin", lambda name, default=None: None
    )
    with pytest.raises(RuntimeError, match=r"pyxle\.config\.json"):
        await current_user(signed_in)


async def test_missing_rbac_service_error_names_the_service(
    signed_in: FakeRequest, auth: FakeAuthService, monkeypatch: pytest.MonkeyPatch
) -> None:
    registry = {AUTH_SERVICE_NAME: auth}
    monkeypatch.setattr(
        pyxle.plugins, "plugin", lambda name, default=None: registry.get(name)
    )
    with pytest.raises(RuntimeError, match=PERMISSION_SERVICE_NAME):
        await require_permission_page(signed_in, "deploy")


async def test_missing_service_via_real_context_gives_actionable_error(
    signed_in: FakeRequest, real_context: pyxle.plugins.PluginContext
) -> None:
    """KNOWN BUG — kept failing deliberately.

    ``guards._service_from_context`` calls ``plugin(name)`` with no
    default. With a real plugin context, ``pyxle.plugins.plugin`` then
    delegates to ``PluginContext.require``, which raises
    ``PluginServiceError("Service 'auth.service' not registered...")``
    when the service is missing — so the guard's ``found is None`` branch,
    the one carrying the actionable "list pyxle-auth in pyxle.config.json
    plugins, or pass service= explicitly" message, is unreachable in any
    real app. Fix in canon: call ``plugin(name, None)``.

    Repro: empty ``PluginContext`` installed via ``set_active_context``,
    then any guard without ``service=``.
    """
    with pytest.raises(RuntimeError, match=r"pyxle\.config\.json"):
        await current_user(signed_in)


# ---------------------------------------------------------------------------
# bearer_token


def test_bearer_token_happy_path() -> None:
    request = FakeRequest(headers={"authorization": "Bearer pyxle_pat_abc123"})
    assert bearer_token(request) == "pyxle_pat_abc123"


@pytest.mark.parametrize("scheme", ["bearer", "BEARER", "BeArEr"])
def test_bearer_token_scheme_is_case_insensitive(scheme: str) -> None:
    request = FakeRequest(headers={"authorization": f"{scheme} tok"})
    assert bearer_token(request) == "tok"


def test_bearer_token_missing_header_is_none() -> None:
    assert bearer_token(FakeRequest()) is None


@pytest.mark.parametrize(
    "header",
    ["", "Bearer", "Bearer ", "Bearer    ", "Basic dXNlcjpwYXNz", "Bearertok", "tok"],
    ids=["empty", "scheme-only", "no-token", "blank-token", "basic", "no-space", "bare"],
)
def test_bearer_token_rejects_malformed_headers(header: str) -> None:
    request = FakeRequest(headers={"authorization": header})
    assert bearer_token(request) is None


def test_bearer_token_rejects_oversized_token() -> None:
    request = FakeRequest(headers={"authorization": "Bearer " + "x" * 257})
    assert bearer_token(request) is None


def test_bearer_token_accepts_max_length_token() -> None:
    request = FakeRequest(headers={"authorization": "Bearer " + "x" * 256})
    assert bearer_token(request) == "x" * 256


def test_bearer_token_tolerates_surrounding_whitespace() -> None:
    request = FakeRequest(headers={"authorization": "  Bearer tok  "})
    assert bearer_token(request) == "tok"


def test_bearer_token_tolerates_extra_space_before_token() -> None:
    request = FakeRequest(headers={"authorization": "Bearer  tok"})
    assert bearer_token(request) == "tok"
