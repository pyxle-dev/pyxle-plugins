"""Tests for the flexible-identity feature (0.4.0): username-mode auth.

Covers the three new layers — the pure ``normalise_username`` policy, the
``AuthSettings.identifier`` switch + username knobs, and the ``AuthService``
running in username mode — plus a guard that email mode is untouched. The
migration itself is exercised on real engines in ``test_live_backends.py``.
"""

from __future__ import annotations

import pytest

from pyxle_auth import AuthService, AuthSettings
from pyxle_auth._identity import DEFAULT_RESERVED_USERNAMES, normalise_username
from pyxle_auth.errors import AccountExists, AuthError, InvalidCredentials
from pyxle_db import Database

_POLICY = dict(min_length=3, max_length=30, pattern=r"^[a-z0-9_-]+$")


# ---------------------------------------------------------------------------
# normalise_username — the pure policy
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("  Ada_Lovelace  ", "ada_lovelace"),  # trims + lowercases
        ("dev-99", "dev-99"),
        ("UPPER", "upper"),
    ],
)
def test_normalise_username_canonicalises(raw: str, expected: str) -> None:
    assert normalise_username(raw, **_POLICY) == expected


@pytest.mark.parametrize(
    "bad",
    ["ab", "x" * 31, "has space", "bang!", "Ünïcode", "", "   "],
)
def test_normalise_username_rejects_invalid(bad: str) -> None:
    with pytest.raises(AuthError):
        normalise_username(bad, **_POLICY)


@pytest.mark.parametrize("name", ["admin", "ADMIN", "Root", "api", "login"])
def test_normalise_username_rejects_reserved(name: str) -> None:
    with pytest.raises(AuthError, match="reserved"):
        normalise_username(name, **_POLICY)


def test_reserved_set_is_substantial_and_lowercase() -> None:
    assert len(DEFAULT_RESERVED_USERNAMES) >= 50
    assert all(n == n.lower() for n in DEFAULT_RESERVED_USERNAMES)


def test_reserved_block_list_is_configurable() -> None:
    # An app can clear the block-list entirely…
    assert normalise_username("admin", **_POLICY, reserved=frozenset()) == "admin"
    # …or supply its own.
    with pytest.raises(AuthError, match="reserved"):
        normalise_username("ceo", **_POLICY, reserved={"ceo"})


# ---------------------------------------------------------------------------
# AuthSettings.identifier
# ---------------------------------------------------------------------------


def test_default_identifier_is_email_for_backward_compat() -> None:
    assert AuthSettings(strict=False).identifier == "email"


def test_identifier_must_be_email_or_username() -> None:
    with pytest.raises(ValueError, match="identifier"):
        AuthSettings(strict=False, identifier="phone")


def test_username_length_bounds_validated() -> None:
    with pytest.raises(ValueError):
        AuthSettings(strict=False, username_min_length=0)
    with pytest.raises(ValueError):
        AuthSettings(strict=False, username_min_length=5, username_max_length=4)


def test_identifier_reads_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PYXLE_AUTH_IDENTIFIER", "username")
    assert AuthSettings.from_env(strict=False).identifier == "username"


# ---------------------------------------------------------------------------
# AuthService in username mode
# ---------------------------------------------------------------------------


@pytest.fixture
async def uauth(db: Database) -> AuthService:
    svc = AuthService(
        db, AuthSettings(strict=False, identifier="username").for_tests()
    )
    await svc.ensure_schema()
    return svc


async def test_username_signup_stores_lowercased_no_email(uauth: AuthService) -> None:
    user, cookie = await uauth.sign_up(username="Ada_Lovelace", password="correct horse staple")
    assert user.username == "ada_lovelace"
    assert user.email is None
    assert cookie.value


async def test_username_signin_is_case_insensitive(uauth: AuthService) -> None:
    created, _ = await uauth.sign_up(username="ada", password="correct horse staple")
    user = await uauth.verify_credentials(username="ADA", password="correct horse staple")
    assert user.id == created.id


async def test_username_wrong_password_is_invalid_credentials(uauth: AuthService) -> None:
    await uauth.sign_up(username="ada", password="correct horse staple")
    with pytest.raises(InvalidCredentials):
        await uauth.verify_credentials(username="ada", password="wrong guess here")


async def test_unknown_username_is_invalid_credentials(uauth: AuthService) -> None:
    with pytest.raises(InvalidCredentials):
        await uauth.verify_credentials(username="nobody", password="whatever pass")


async def test_duplicate_username_rejected_case_insensitively(uauth: AuthService) -> None:
    await uauth.sign_up(username="ada", password="correct horse staple")
    with pytest.raises(AccountExists):
        await uauth.sign_up(username="ADA", password="another good password")


async def test_signup_rejects_reserved_and_malformed(uauth: AuthService) -> None:
    with pytest.raises(AuthError):
        await uauth.sign_up(username="admin", password="correct horse staple")
    with pytest.raises(AuthError):
        await uauth.sign_up(username="no spaces", password="correct horse staple")


async def test_signup_requires_username_in_username_mode(uauth: AuthService) -> None:
    with pytest.raises(AuthError):
        await uauth.sign_up(email="someone@example.com", password="correct horse staple")


async def test_username_available(uauth: AuthService) -> None:
    assert await uauth.username_available("free_handle") is True
    await uauth.sign_up(username="taken", password="correct horse staple")
    assert await uauth.username_available("TAKEN") is False  # case-insensitive
    with pytest.raises(AuthError):
        await uauth.username_available("admin")  # reserved isn't "available"


async def test_username_mode_accepts_optional_email(uauth: AuthService) -> None:
    # Apps may still collect an email in username mode (e.g. for future reset).
    user, _ = await uauth.sign_up(
        username="ada", email="Ada@Example.com", password="correct horse staple"
    )
    assert user.username == "ada" and user.email == "ada@example.com"


# ---------------------------------------------------------------------------
# Email mode is untouched
# ---------------------------------------------------------------------------


async def test_email_mode_still_works(auth: AuthService) -> None:
    user, _ = await auth.sign_up(email="grace@example.com", password="correct horse staple")
    assert user.email == "grace@example.com" and user.username is None
    back = await auth.verify_credentials(email="grace@example.com", password="correct horse staple")
    assert back.id == user.id


# ---------------------------------------------------------------------------
# Security-review fixes (0.4.0)
# ---------------------------------------------------------------------------


async def test_duplicate_error_message_names_username_not_email(uauth: AuthService) -> None:
    # In username mode the "already exists" error must say username — never
    # leak/confuse with "email" (which the user never supplied).
    await uauth.sign_up(username="ada", password="correct horse staple")
    with pytest.raises(AccountExists) as exc:
        await uauth.sign_up(username="ada", password="another good password")
    assert "username" in str(exc.value).lower()
    assert "email" not in str(exc.value).lower()


async def test_duplicate_error_message_says_email_in_email_mode(auth: AuthService) -> None:
    await auth.sign_up(email="grace@example.com", password="correct horse staple")
    with pytest.raises(AccountExists) as exc:
        await auth.sign_up(email="grace@example.com", password="another good password")
    assert "email" in str(exc.value).lower()


async def test_require_email_verified_does_not_lock_out_usernameonly(db: Database) -> None:
    # A username-only account has no email to verify — requiring verification
    # must not make it permanently unable to sign in.
    svc = AuthService(
        db,
        AuthSettings(
            strict=False, identifier="username", require_email_verified=True
        ).for_tests(),
    )
    await svc.ensure_schema()
    user, _ = await svc.sign_up(username="ada", password="correct horse staple")
    signed_in = await svc.verify_credentials(username="ada", password="correct horse staple")
    assert signed_in.id == user.id  # not blocked


async def test_username_available_rate_limited_per_ip(db: Database) -> None:
    from pyxle_auth.errors import RateLimited

    svc = AuthService(
        db,
        AuthSettings(
            strict=False, identifier="username", rate_limit_username_check_per_hour=2
        ).for_tests(),
    )
    await svc.ensure_schema()
    assert await svc.username_available("one", ip="9.9.9.9") is True
    assert await svc.username_available("two", ip="9.9.9.9") is True
    with pytest.raises(RateLimited):
        await svc.username_available("three", ip="9.9.9.9")
    # A different IP is unaffected; no-IP internal calls are never throttled.
    assert await svc.username_available("four", ip="8.8.8.8") is True
    assert await svc.username_available("five") is True


def test_invalid_username_pattern_rejected_at_construction() -> None:
    with pytest.raises(ValueError, match="username_pattern"):
        AuthSettings(strict=False, username_pattern="(unclosed")
