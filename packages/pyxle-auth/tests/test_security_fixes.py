"""Regression tests for the v0.2 security-review findings.

Each test pins a fix from the adversarial audit so it cannot silently
regress: sign-in lockout resistance, over-length password rejection,
password-reset timing parity, and the strict-mode argon2 floors.
"""

from __future__ import annotations

import pytest

from pyxle_auth.errors import InvalidCredentials, RateLimited
from pyxle_auth.service import AuthService, _RESET_SENTINEL_USER_ID
from pyxle_auth.settings import AuthSettings


@pytest.fixture
async def service(db):
    svc = AuthService(db, AuthSettings(strict=False).for_tests())
    await svc.ensure_schema()
    return svc


# ── finding: per-email rate-limit lockout DoS ────────────────────────────────


async def test_correct_password_is_never_blocked_by_email_bucket(service):
    """A flood of wrong-password attempts against a victim's email must not
    lock the legitimate owner out — a correct password always wins."""
    await service.sign_up(email="victim@example.com", password="Sup3r-secret!")

    limit = service._settings.rate_limit_sign_in_per_hour
    # Attacker exhausts the per-email bucket from assorted IPs with wrong pws.
    for i in range(limit + 3):
        with pytest.raises((InvalidCredentials, RateLimited)):
            await service.sign_in(
                email="victim@example.com", password="wrong", ip=f"10.0.0.{i}"
            )

    # The owner, with the correct password, still gets in (from yet another IP
    # so the IP bucket is fresh) — no lockout.
    user, cookie = await service.sign_in(
        email="victim@example.com", password="Sup3r-secret!", ip="203.0.113.9"
    )
    assert user.email == "victim@example.com"
    assert cookie.value


async def test_single_ip_is_still_throttled(service):
    """The IP bucket must still stop a single source hammering sign-in."""
    await service.sign_up(email="u@example.com", password="Sup3r-secret!")
    limit = service._settings.rate_limit_sign_in_per_hour
    blocked = False
    for _ in range(limit + 2):
        try:
            await service.sign_in(email="u@example.com", password="x", ip="1.2.3.4")
        except RateLimited:
            blocked = True
            break
        except InvalidCredentials:
            pass
    assert blocked, "a single IP must hit RateLimited"


# ── finding: argon2 DoS via unbounded password ───────────────────────────────


async def test_oversized_password_rejected_before_hashing(service, monkeypatch):
    """An over-length password must be refused before any argon2 work, on
    both the known- and unknown-email paths. We swap the whole hasher for a
    sentinel that explodes if touched, proving verify is never reached."""
    await service.sign_up(email="real@example.com", password="Sup3r-secret!")
    huge = "a" * (service._settings.password_max_length + 1)

    class _Boom:
        def verify(self, *a, **k):
            raise AssertionError("verify() must not run for an over-length password")

    monkeypatch.setattr(service, "_hasher", _Boom())

    with pytest.raises(InvalidCredentials):
        await service.sign_in(email="real@example.com", password=huge, ip="9.9.9.9")
    with pytest.raises(InvalidCredentials):
        await service.sign_in(email="nobody@example.com", password=huge, ip="9.9.9.8")


# ── finding: password-reset timing enumeration ───────────────────────────────


async def test_reset_miss_path_writes_a_sentinel_token(service, db):
    """The unknown-email path must perform the same committed token write as
    the hit path (timing parity) — verified by the sentinel row existing."""
    result = await service.request_password_reset(
        email="ghost@example.com", ip="5.5.5.5"
    )
    assert result is None
    row = await db.fetchone(
        "SELECT COUNT(*) AS n FROM auth_tokens WHERE user_id = ?",
        (_RESET_SENTINEL_USER_ID,),
    )
    assert int(row["n"]) >= 1


async def test_reset_misses_reuse_one_sentinel_row(service, db):
    """Repeated misses must not accumulate rows — revoke_existing reuses the
    single sentinel so the table can't be grown by probing."""
    for i in range(4):
        await service.request_password_reset(email=f"ghost{i}@example.com")
    row = await db.fetchone(
        "SELECT COUNT(*) AS n FROM auth_tokens "
        "WHERE user_id = ? AND used_at IS NULL",
        (_RESET_SENTINEL_USER_ID,),
    )
    assert int(row["n"]) == 1


# ── finding: argon2 strength floors in strict mode ───────────────────────────


def test_strict_mode_rejects_weak_argon_params():
    with pytest.raises(ValueError, match="argon_memory_kib"):
        AuthSettings(strict=True, cookie_secure=True, argon_memory_kib=1024)
    with pytest.raises(ValueError, match="argon_time_cost"):
        AuthSettings(strict=True, cookie_secure=True, argon_time_cost=1)


def test_non_strict_mode_allows_fast_params_for_tests():
    # for_tests() uses weak params on purpose — must construct cleanly.
    settings = AuthSettings(strict=False).for_tests()
    assert settings.strict is False
    assert settings.argon_time_cost >= 1
