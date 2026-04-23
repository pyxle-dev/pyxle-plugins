from __future__ import annotations

import asyncio

import pytest

from pyxle_auth import (
    AccountExists,
    AuthError,
    AuthService,
    AuthSettings,
    EmailNotVerified,
    InvalidCredentials,
    RateLimited,
    WeakPassword,
)
from pyxle_db import Database


# ---------------------------------------------------------------------------
# Sign-up happy path


async def test_sign_up_creates_user_and_session(auth: AuthService) -> None:
    user, cookie = await auth.sign_up(
        email="Alice@Example.COM  ",
        password="correct-horse-battery-staple",
        ip="1.2.3.4",
        user_agent="ua",
    )
    assert user.email == "alice@example.com"  # normalised
    assert user.plan == "free"
    assert cookie.value, "cookie value must not be empty"

    # Cookie resolves back to the same user.
    resolved = await auth.resolve_session(cookie_value=cookie.value)
    assert resolved is not None
    assert resolved.id == user.id


async def test_sign_up_rejects_duplicate(auth: AuthService) -> None:
    await auth.sign_up(email="a@b.com", password="passw0rd-1234")
    with pytest.raises(AccountExists):
        await auth.sign_up(email="a@b.com", password="passw0rd-1234")


async def test_sign_up_rejects_duplicate_with_different_case(
    auth: AuthService,
) -> None:
    await auth.sign_up(email="a@b.com", password="passw0rd-1234")
    with pytest.raises(AccountExists):
        await auth.sign_up(email="A@B.com", password="passw0rd-1234")


async def test_sign_up_rejects_invalid_email(auth: AuthService) -> None:
    with pytest.raises(AuthError, match="valid email"):
        await auth.sign_up(email="nope", password="passw0rd-1234")


async def test_sign_up_rejects_weak_password(auth: AuthService) -> None:
    with pytest.raises(WeakPassword):
        await auth.sign_up(email="a@b.com", password="short")


async def test_sign_up_rate_limit(
    db: Database, settings: AuthSettings
) -> None:
    s = AuthSettings(
        strict=False,
        cookie_secure=False,
        argon_time_cost=1,
        argon_memory_kib=8,
        argon_parallelism=1,
        rate_limit_sign_up_per_hour=2,
    )
    auth = AuthService(db, s)
    await auth.ensure_schema()
    for i in range(2):
        await auth.sign_up(email=f"u{i}@b.com", password="passw0rd-1234", ip="1.1.1.1")
    with pytest.raises(RateLimited):
        await auth.sign_up(email="u3@b.com", password="passw0rd-1234", ip="1.1.1.1")


# ---------------------------------------------------------------------------
# Sign-in


async def test_sign_in_roundtrip(auth: AuthService) -> None:
    await auth.sign_up(email="a@b.com", password="passw0rd-1234")
    user, cookie = await auth.sign_in(
        email="a@b.com", password="passw0rd-1234", ip="1.1.1.1"
    )
    resolved = await auth.resolve_session(cookie_value=cookie.value)
    assert resolved is not None
    assert resolved.id == user.id


async def test_sign_in_wrong_password(auth: AuthService) -> None:
    await auth.sign_up(email="a@b.com", password="passw0rd-1234")
    with pytest.raises(InvalidCredentials):
        await auth.sign_in(email="a@b.com", password="nope-nope-1234")


async def test_sign_in_unknown_email_same_error(auth: AuthService) -> None:
    # Should not leak "no such user" vs "wrong password".
    with pytest.raises(InvalidCredentials):
        await auth.sign_in(email="nobody@b.com", password="whatever-1234")


async def test_sign_in_rate_limit_by_ip(
    db: Database,
) -> None:
    s = AuthSettings(
        strict=False,
        cookie_secure=False,
        argon_time_cost=1,
        argon_memory_kib=8,
        argon_parallelism=1,
        rate_limit_sign_in_per_hour=2,
    )
    auth = AuthService(db, s)
    await auth.ensure_schema()
    await auth.sign_up(email="a@b.com", password="passw0rd-1234")

    for _ in range(2):
        with pytest.raises(InvalidCredentials):
            await auth.sign_in(
                email="a@b.com", password="WRONG1234", ip="9.9.9.9"
            )
    with pytest.raises(RateLimited):
        await auth.sign_in(
            email="a@b.com", password="passw0rd-1234", ip="9.9.9.9"
        )


async def test_successful_sign_in_resets_bucket(
    db: Database,
) -> None:
    s = AuthSettings(
        strict=False,
        cookie_secure=False,
        argon_time_cost=1,
        argon_memory_kib=8,
        argon_parallelism=1,
        rate_limit_sign_in_per_hour=3,
    )
    auth = AuthService(db, s)
    await auth.ensure_schema()
    await auth.sign_up(email="a@b.com", password="passw0rd-1234")

    # two bad attempts
    for _ in range(2):
        with pytest.raises(InvalidCredentials):
            await auth.sign_in(
                email="a@b.com", password="WRONG1234", ip="9.9.9.9"
            )

    # one good attempt — clears the counter
    await auth.sign_in(email="a@b.com", password="passw0rd-1234", ip="9.9.9.9")

    # three more bad attempts should NOT trip the limiter immediately
    # (reset happened).
    for _ in range(2):
        with pytest.raises(InvalidCredentials):
            await auth.sign_in(
                email="a@b.com", password="WRONG1234", ip="9.9.9.9"
            )


# ---------------------------------------------------------------------------
# Session lifecycle


async def test_resolve_unknown_cookie_returns_none(auth: AuthService) -> None:
    assert await auth.resolve_session(cookie_value="nope") is None
    assert await auth.resolve_session(cookie_value="") is None


async def test_sign_out_revokes_session(auth: AuthService) -> None:
    _, cookie = await auth.sign_up(email="a@b.com", password="passw0rd-1234")
    assert await auth.resolve_session(cookie_value=cookie.value) is not None

    delete_cookie = await auth.sign_out(cookie_value=cookie.value)
    assert delete_cookie.value == ""
    assert delete_cookie.max_age == 0

    assert await auth.resolve_session(cookie_value=cookie.value) is None


async def test_revoke_all_logs_every_device_out(auth: AuthService) -> None:
    _, c1 = await auth.sign_up(email="a@b.com", password="passw0rd-1234")
    _, c2 = await auth.sign_in(email="a@b.com", password="passw0rd-1234")
    assert await auth.resolve_session(cookie_value=c1.value) is not None
    assert await auth.resolve_session(cookie_value=c2.value) is not None

    user = await auth.get_user_by_email(email="a@b.com")
    assert user is not None
    revoked = await auth.revoke_all_sessions(user_id=user.id)
    assert revoked == 2
    assert await auth.resolve_session(cookie_value=c1.value) is None
    assert await auth.resolve_session(cookie_value=c2.value) is None


# ---------------------------------------------------------------------------
# Password change


async def test_change_password_happy_path(auth: AuthService) -> None:
    user, _ = await auth.sign_up(email="a@b.com", password="passw0rd-1234")
    await auth.change_password(
        user_id=user.id,
        current_password="passw0rd-1234",
        new_password="new-password-9876",
    )
    with pytest.raises(InvalidCredentials):
        await auth.sign_in(email="a@b.com", password="passw0rd-1234")
    await auth.sign_in(email="a@b.com", password="new-password-9876")


async def test_change_password_wrong_current(auth: AuthService) -> None:
    user, _ = await auth.sign_up(email="a@b.com", password="passw0rd-1234")
    with pytest.raises(InvalidCredentials):
        await auth.change_password(
            user_id=user.id,
            current_password="WRONG1234",
            new_password="new-password-9876",
        )


async def test_change_password_revokes_sessions(auth: AuthService) -> None:
    _, c1 = await auth.sign_up(email="a@b.com", password="passw0rd-1234")
    user = await auth.get_user_by_email(email="a@b.com")
    assert user is not None
    await auth.change_password(
        user_id=user.id,
        current_password="passw0rd-1234",
        new_password="new-password-9876",
    )
    assert await auth.resolve_session(cookie_value=c1.value) is None


# ---------------------------------------------------------------------------
# Email verification gate


async def test_email_verification_gate(db: Database) -> None:
    s = AuthSettings(
        strict=False,
        cookie_secure=False,
        argon_time_cost=1,
        argon_memory_kib=8,
        argon_parallelism=1,
        require_email_verified=True,
    )
    auth = AuthService(db, s)
    await auth.ensure_schema()
    await auth.sign_up(email="a@b.com", password="passw0rd-1234")

    with pytest.raises(EmailNotVerified):
        await auth.sign_in(email="a@b.com", password="passw0rd-1234")

    user = await auth.get_user_by_email(email="a@b.com")
    assert user is not None
    await auth.mark_email_verified(user_id=user.id)

    _, cookie = await auth.sign_in(email="a@b.com", password="passw0rd-1234")
    assert cookie.value
