from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest

import pyxle_auth
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
from pyxle_auth.errors import InvalidToken
from pyxle_auth.models import _now_utc
from pyxle_db import Database, connect


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
# Session listing / per-session revocation


async def test_list_sessions_newest_first_with_current_flag(
    auth: AuthService,
) -> None:
    user, c1 = await auth.sign_up(
        email="a@b.com", password="passw0rd-1234", ip="1.1.1.1", user_agent="laptop"
    )
    _, c2 = await auth.sign_in(
        email="a@b.com", password="passw0rd-1234", ip="2.2.2.2", user_agent="phone"
    )

    sessions = await auth.list_sessions(
        user_id=user.id, current_cookie_value=c2.value
    )
    assert len(sessions) == 2
    # Newest first; the second device is the caller's current session.
    assert sessions[0].created_at >= sessions[1].created_at
    assert [s.current for s in sessions].count(True) == 1
    current = next(s for s in sessions if s.current)
    assert current.user_agent == "phone"
    assert current.ip == "2.2.2.2"
    # ids are token hashes, never the raw cookie value.
    assert all(s.id not in (c1.value, c2.value) for s in sessions)


async def test_list_sessions_without_current_cookie(auth: AuthService) -> None:
    user, _ = await auth.sign_up(email="a@b.com", password="passw0rd-1234")
    sessions = await auth.list_sessions(user_id=user.id)
    assert len(sessions) == 1
    assert sessions[0].current is False


async def test_list_sessions_excludes_expired_and_overaged(
    auth: AuthService, db: Database, settings: AuthSettings
) -> None:
    user, _ = await auth.sign_up(email="a@b.com", password="passw0rd-1234")
    now = _now_utc()
    # An expired session and one past the absolute age cap, inserted
    # directly so the test doesn't depend on wall-clock sleeping.
    await db.execute(
        "INSERT INTO sessions (token_sha256, user_id, created_at, expires_at) "
        "VALUES (?, ?, ?, ?)",
        ("deadbeef" * 8, user.id, now - timedelta(days=2), now - timedelta(days=1)),
    )
    overaged_created = now - timedelta(
        seconds=settings.session_absolute_max_seconds + 3600
    )
    await db.execute(
        "INSERT INTO sessions (token_sha256, user_id, created_at, expires_at) "
        "VALUES (?, ?, ?, ?)",
        ("cafef00d" * 8, user.id, overaged_created, now + timedelta(days=1)),
    )

    sessions = await auth.list_sessions(user_id=user.id)
    assert len(sessions) == 1  # only the live sign-up session


async def test_revoke_session_kills_that_device(auth: AuthService) -> None:
    user, c1 = await auth.sign_up(email="a@b.com", password="passw0rd-1234")
    _, c2 = await auth.sign_in(email="a@b.com", password="passw0rd-1234")

    sessions = await auth.list_sessions(
        user_id=user.id, current_cookie_value=c2.value
    )
    other = next(s for s in sessions if not s.current)

    assert await auth.revoke_session(user_id=user.id, session_id=other.id) is True
    assert await auth.resolve_session(cookie_value=c1.value) is None
    assert await auth.resolve_session(cookie_value=c2.value) is not None
    # Idempotent: a second revoke finds nothing.
    assert await auth.revoke_session(user_id=user.id, session_id=other.id) is False


async def test_revoke_session_is_scoped_to_owner(auth: AuthService) -> None:
    """User A cannot revoke user B's session, even with a leaked id."""
    user_a, _ = await auth.sign_up(email="a@b.com", password="passw0rd-1234")
    user_b, cookie_b = await auth.sign_up(email="b@b.com", password="passw0rd-1234")

    [session_b] = await auth.list_sessions(user_id=user_b.id)
    assert (
        await auth.revoke_session(user_id=user_a.id, session_id=session_b.id)
        is False
    )
    # B's session is untouched.
    assert await auth.resolve_session(cookie_value=cookie_b.value) is not None


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
# Password reset


async def test_password_reset_roundtrip(auth: AuthService) -> None:
    await auth.sign_up(email="a@b.com", password="passw0rd-1234")

    result = await auth.request_password_reset(email="A@B.com ", ip="1.1.1.1")
    assert result is not None
    user, raw_token = result
    assert user.email == "a@b.com"
    assert raw_token

    reset_user = await auth.reset_password(
        raw_token=raw_token, new_password="brand-new-password-1"
    )
    assert reset_user.id == user.id

    with pytest.raises(InvalidCredentials):
        await auth.sign_in(email="a@b.com", password="passw0rd-1234")
    await auth.sign_in(email="a@b.com", password="brand-new-password-1")


async def test_password_reset_unknown_email_returns_none(
    auth: AuthService,
) -> None:
    # No exception, no token, nothing to distinguish from the hit path.
    assert await auth.request_password_reset(email="nobody@b.com") is None


async def test_password_reset_rate_limited_per_email(auth: AuthService) -> None:
    await auth.sign_up(email="a@b.com", password="passw0rd-1234")
    for _ in range(3):
        assert await auth.request_password_reset(email="a@b.com") is not None
    with pytest.raises(RateLimited):
        await auth.request_password_reset(email="a@b.com")


async def test_password_reset_rate_limits_unknown_emails_identically(
    auth: AuthService,
) -> None:
    """The limiter must not reveal account existence either: unknown
    emails hit the same 3/hour wall."""
    for _ in range(3):
        assert await auth.request_password_reset(email="ghost@b.com") is None
    with pytest.raises(RateLimited):
        await auth.request_password_reset(email="ghost@b.com")


async def test_password_reset_token_is_single_use(auth: AuthService) -> None:
    await auth.sign_up(email="a@b.com", password="passw0rd-1234")
    result = await auth.request_password_reset(email="a@b.com")
    assert result is not None
    _, raw_token = result

    await auth.reset_password(raw_token=raw_token, new_password="new-password-111")
    with pytest.raises(InvalidToken):
        await auth.reset_password(
            raw_token=raw_token, new_password="new-password-222"
        )


async def test_password_reset_rejects_garbage_token(auth: AuthService) -> None:
    with pytest.raises(InvalidToken):
        await auth.reset_password(
            raw_token="not-a-real-token", new_password="new-password-111"
        )


async def test_requesting_again_invalidates_previous_reset_link(
    auth: AuthService,
) -> None:
    await auth.sign_up(email="a@b.com", password="passw0rd-1234")
    first = await auth.request_password_reset(email="a@b.com")
    second = await auth.request_password_reset(email="a@b.com")
    assert first is not None and second is not None

    with pytest.raises(InvalidToken):
        await auth.reset_password(
            raw_token=first[1], new_password="new-password-111"
        )
    await auth.reset_password(raw_token=second[1], new_password="new-password-111")


async def test_password_reset_revokes_all_sessions(auth: AuthService) -> None:
    _, c1 = await auth.sign_up(email="a@b.com", password="passw0rd-1234")
    _, c2 = await auth.sign_in(email="a@b.com", password="passw0rd-1234")

    result = await auth.request_password_reset(email="a@b.com")
    assert result is not None
    await auth.reset_password(
        raw_token=result[1], new_password="new-password-111"
    )

    assert await auth.resolve_session(cookie_value=c1.value) is None
    assert await auth.resolve_session(cookie_value=c2.value) is None


async def test_weak_password_does_not_burn_reset_token(
    auth: AuthService,
) -> None:
    """Policy runs before consumption, so the user can fix their
    password and submit the same link again."""
    await auth.sign_up(email="a@b.com", password="passw0rd-1234")
    result = await auth.request_password_reset(email="a@b.com")
    assert result is not None
    _, raw_token = result

    with pytest.raises(WeakPassword):
        await auth.reset_password(raw_token=raw_token, new_password="short")
    # Token still valid.
    await auth.reset_password(raw_token=raw_token, new_password="long-enough-pw-1")


# ---------------------------------------------------------------------------
# Email verification


async def test_email_verification_roundtrip(auth: AuthService) -> None:
    user, _ = await auth.sign_up(email="a@b.com", password="passw0rd-1234")
    assert user.email_verified_at is None

    raw_token = await auth.request_email_verification(user_id=user.id)
    verified = await auth.confirm_email(raw_token=raw_token)
    assert verified.id == user.id
    assert verified.email_verified_at is not None


async def test_email_verification_token_is_single_use(auth: AuthService) -> None:
    user, _ = await auth.sign_up(email="a@b.com", password="passw0rd-1234")
    raw_token = await auth.request_email_verification(user_id=user.id)
    await auth.confirm_email(raw_token=raw_token)
    with pytest.raises(InvalidToken):
        await auth.confirm_email(raw_token=raw_token)


async def test_email_verification_rejects_garbage_token(
    auth: AuthService,
) -> None:
    with pytest.raises(InvalidToken):
        await auth.confirm_email(raw_token="nope")


async def test_email_verification_for_unknown_user_raises(
    auth: AuthService,
) -> None:
    with pytest.raises(AuthError):
        await auth.request_email_verification(user_id="missing")


async def test_tokens_are_purpose_scoped(auth: AuthService) -> None:
    """A verification token can never reset a password, and vice versa."""
    user, _ = await auth.sign_up(email="a@b.com", password="passw0rd-1234")

    verify_token = await auth.request_email_verification(user_id=user.id)
    with pytest.raises(InvalidToken):
        await auth.reset_password(
            raw_token=verify_token, new_password="new-password-111"
        )

    result = await auth.request_password_reset(email="a@b.com")
    assert result is not None
    with pytest.raises(InvalidToken):
        await auth.confirm_email(raw_token=result[1])


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
    raw_token = await auth.request_email_verification(user_id=user.id)
    await auth.confirm_email(raw_token=raw_token)

    _, cookie = await auth.sign_in(email="a@b.com", password="passw0rd-1234")
    assert cookie.value


# ---------------------------------------------------------------------------
# Shipped migration file


async def test_migration_file_bootstraps_full_schema(
    tmp_path: Path, settings: AuthSettings
) -> None:
    """The shipped migrations file alone supports every service flow —
    no ensure_schema() call anywhere."""
    migrations_dir = Path(pyxle_auth.__file__).parent / "migrations"
    db = await connect(tmp_path / "migrated.db", migrations_dir=migrations_dir)
    try:
        auth = AuthService(db, settings)

        user, cookie = await auth.sign_up(
            email="a@b.com", password="passw0rd-1234", ip="1.1.1.1"
        )
        resolved = await auth.resolve_session(cookie_value=cookie.value)
        assert resolved is not None and resolved.id == user.id

        result = await auth.request_password_reset(email="a@b.com")
        assert result is not None
        await auth.reset_password(
            raw_token=result[1], new_password="new-password-111"
        )

        # Tables owned by the other services exist with the agreed shape.
        assert await db.fetchall(
            "SELECT id, token_sha256, user_id, name, scopes, created_at, "
            "expires_at, last_used_at, revoked_at FROM api_tokens"
        ) == []
        assert await db.fetchall(
            "SELECT name, permissions, created_at FROM roles"
        ) == []
        assert await db.fetchall(
            "SELECT user_id, role_name, granted_at FROM user_roles"
        ) == []
    finally:
        await db.aclose()


class TestTheSecureFlagFollowsTheConnection:
    """A `Secure` cookie is discarded by the browser over plain HTTP.

    Setting it there does not protect anything — a connection with no
    confidentiality has no cookie confidentiality to lose — but it does mean no
    session cookie is stored at all. The user signs in successfully, is
    redirected, has no session, and is returned to the sign-in page **with no
    error**. Self-hosted deployments hit this constantly: a LAN address, a
    homelab, anything behind a proxy that omits `X-Forwarded-Proto`.
    """

    @staticmethod
    def _cookie():
        from pyxle_auth.models import SessionCookie

        return SessionCookie(name="s", value="v", max_age=60, secure=True)

    @staticmethod
    def _request(scheme="http", headers=None):
        class _Url:
            def __init__(self, scheme):
                self.scheme = scheme

        class _Request:
            def __init__(self, scheme, headers):
                self.url = _Url(scheme)
                self.headers = headers or {}

        return _Request(scheme, headers)

    def test_plain_http_drops_the_flag_so_the_cookie_survives(self):
        assert self._cookie().for_request(self._request("http")).secure is False

    def test_https_keeps_it(self):
        assert self._cookie().for_request(self._request("https")).secure is True

    def test_a_tls_terminating_proxy_is_believed(self):
        """The common production shape: the browser spoke HTTPS, the proxy
        speaks plain HTTP to us, and the scheme alone would say otherwise."""
        request = self._request("http", {"x-forwarded-proto": "https"})
        assert self._cookie().for_request(request).secure is True

    def test_a_forwarded_chain_reads_the_first_hop(self):
        request = self._request("http", {"x-forwarded-proto": "https, http"})
        assert self._cookie().for_request(request).secure is True

    def test_a_cookie_that_was_never_secure_is_returned_unchanged(self):
        from pyxle_auth.models import SessionCookie

        cookie = SessionCookie(name="s", value="v", max_age=60, secure=False)
        assert cookie.for_request(self._request("https")) is cookie

    def test_nothing_else_about_the_cookie_changes(self):
        """Downgrading Secure must not quietly drop HttpOnly or SameSite —
        those are the flags actually protecting the session here."""
        downgraded = self._cookie().for_request(self._request("http"))

        assert downgraded.http_only is True
        assert downgraded.samesite == "Lax"
        assert downgraded.value == "v"
        assert downgraded.max_age == 60
