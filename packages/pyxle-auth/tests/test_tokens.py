"""Hostile tests for :mod:`pyxle_auth.tokens`.

Single-use tokens back password reset and email verification — the flows
that hand over an account if anything here bends. Every test assumes the
adversary controls the inputs: replayed tokens, cross-purpose replays,
garbage values, clock edges, and racing consumers.

Time is controlled by monkeypatching the module's ``_utcnow`` — the single
clock call site for both ``issue`` and ``consume``.
"""

from __future__ import annotations

import asyncio
import hashlib
import string
from datetime import datetime, timedelta, timezone
from typing import AsyncIterator

import pytest

import pyxle_auth.tokens as tokens_module
from pyxle_auth.tokens import TokenService
from pyxle_db import Database
from pyxle_db.database import Transaction

T0 = datetime(2026, 6, 11, 12, 0, 0, tzinfo=timezone.utc)

_URLSAFE_ALPHABET = set(string.ascii_letters + string.digits + "-_")


@pytest.fixture
async def db() -> AsyncIterator[Database]:
    database = Database(":memory:")
    try:
        yield database
    finally:
        await database.aclose()


@pytest.fixture
async def service(db: Database) -> TokenService:
    svc = TokenService(db)
    await svc.ensure_schema()
    return svc


def _freeze(monkeypatch: pytest.MonkeyPatch, at: datetime) -> None:
    monkeypatch.setattr(tokens_module, "_utcnow", lambda: at)


def _sha256(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Issuance


async def test_issue_returns_distinct_high_entropy_values(
    service: TokenService,
) -> None:
    raws = [
        await service.issue(
            purpose="password-reset", user_id="u1", revoke_existing=False
        )
        for _ in range(20)
    ]
    # All distinct — a single collision here would be catastrophic.
    assert len(set(raws)) == 20
    for raw in raws:
        # 32 bytes of urlsafe base64 -> 43 chars, urlsafe alphabet only.
        assert len(raw) >= 43
        assert set(raw) <= _URLSAFE_ALPHABET


async def test_raw_token_is_never_stored(db: Database, service: TokenService) -> None:
    raw = await service.issue(purpose="password-reset", user_id="u1")
    rows = await db.fetchall("SELECT * FROM auth_tokens")
    assert len(rows) == 1
    for value in rows[0]:
        # The plaintext must not appear anywhere in the row, in any column.
        assert not (isinstance(value, str) and raw in value)
    assert rows[0]["token_sha256"] == _sha256(raw)


async def test_issue_strips_purpose_to_canonical_form(service: TokenService) -> None:
    raw = await service.issue(purpose="  password-reset  ", user_id="u1")
    claim = await service.consume(purpose="password-reset", raw_token=raw)
    assert claim is not None
    assert claim.purpose == "password-reset"


@pytest.mark.parametrize("purpose", ["", "   ", None])
async def test_issue_rejects_bad_purpose(service: TokenService, purpose: object) -> None:
    with pytest.raises(ValueError):
        await service.issue(purpose=purpose, user_id="u1")  # type: ignore[arg-type]


@pytest.mark.parametrize("user_id", ["", None])
async def test_issue_rejects_bad_user_id(service: TokenService, user_id: object) -> None:
    with pytest.raises(ValueError):
        await service.issue(purpose="password-reset", user_id=user_id)  # type: ignore[arg-type]


@pytest.mark.parametrize("ttl", [0, -1, -3600])
async def test_issue_rejects_non_positive_ttl(service: TokenService, ttl: int) -> None:
    with pytest.raises(ValueError):
        await service.issue(purpose="password-reset", user_id="u1", ttl_seconds=ttl)


@pytest.mark.parametrize("default_ttl", [0, -10])
async def test_constructor_rejects_non_positive_default_ttl(
    db: Database, default_ttl: int
) -> None:
    with pytest.raises(ValueError):
        TokenService(db, default_ttl_seconds=default_ttl)


# ---------------------------------------------------------------------------
# Consumption — single use, purpose scoping, expiry


async def test_consume_succeeds_once_then_none_forever(service: TokenService) -> None:
    raw = await service.issue(purpose="email-verify", user_id="u7")
    claim = await service.consume(purpose="email-verify", raw_token=raw)
    assert claim is not None
    assert claim.user_id == "u7"
    assert claim.purpose == "email-verify"
    # Replays are dead, no matter how many times.
    assert await service.consume(purpose="email-verify", raw_token=raw) is None
    assert await service.consume(purpose="email-verify", raw_token=raw) is None


async def test_claim_carries_aware_timestamps(
    service: TokenService, monkeypatch: pytest.MonkeyPatch
) -> None:
    _freeze(monkeypatch, T0)
    raw = await service.issue(purpose="invite", user_id="u1", ttl_seconds=600)
    claim = await service.consume(purpose="invite", raw_token=raw)
    assert claim is not None
    assert claim.issued_at == T0
    assert claim.expires_at == T0 + timedelta(seconds=600)
    assert claim.issued_at.tzinfo is not None
    assert claim.expires_at.tzinfo is not None


async def test_wrong_purpose_returns_none_and_does_not_burn(
    service: TokenService,
) -> None:
    raw = await service.issue(purpose="password-reset", user_id="u1")
    # A reset token must never redeem as an email-verification token...
    assert await service.consume(purpose="email-verify", raw_token=raw) is None
    # ...and the failed cross-purpose attempt must not consume it.
    assert await service.consume(purpose="password-reset", raw_token=raw) is not None


async def test_expired_token_returns_none(
    service: TokenService, monkeypatch: pytest.MonkeyPatch
) -> None:
    _freeze(monkeypatch, T0)
    raw = await service.issue(purpose="password-reset", user_id="u1", ttl_seconds=1)
    _freeze(monkeypatch, T0 + timedelta(seconds=2))
    assert await service.consume(purpose="password-reset", raw_token=raw) is None


async def test_expiry_boundary_is_exclusive(
    service: TokenService, monkeypatch: pytest.MonkeyPatch
) -> None:
    _freeze(monkeypatch, T0)
    at_edge = await service.issue(purpose="edge-at", user_id="u1", ttl_seconds=60)
    before_edge = await service.issue(purpose="edge-before", user_id="u1", ttl_seconds=60)

    _freeze(monkeypatch, T0 + timedelta(seconds=59))
    assert await service.consume(purpose="edge-before", raw_token=before_edge) is not None

    # Exactly at expires_at the token is already dead (expires_at <= now).
    _freeze(monkeypatch, T0 + timedelta(seconds=60))
    assert await service.consume(purpose="edge-at", raw_token=at_edge) is None


@pytest.mark.parametrize(
    "garbage",
    ["", None, 0, 123, b"raw-bytes", "x" * 257, "x" * 100_000, object()],
    ids=["empty", "none", "zero", "int", "bytes", "oversize-257", "oversize-huge", "object"],
)
async def test_consume_garbage_returns_none_without_exceptions(
    service: TokenService, garbage: object
) -> None:
    assert await service.consume(purpose="password-reset", raw_token=garbage) is None  # type: ignore[arg-type]


async def test_consume_accepts_max_length_unknown_token(service: TokenService) -> None:
    # 256 chars is within bounds — must miss cleanly, not raise.
    assert (
        await service.consume(purpose="password-reset", raw_token="x" * 256) is None
    )


# ---------------------------------------------------------------------------
# revoke_existing — scoped to (user, purpose) only


async def test_revoke_existing_burns_same_purpose_only(service: TokenService) -> None:
    verify = await service.issue(purpose="email-verify", user_id="u1")
    reset_1 = await service.issue(purpose="password-reset", user_id="u1")
    reset_2 = await service.issue(purpose="password-reset", user_id="u1")

    # The second reset burned the first...
    assert await service.consume(purpose="password-reset", raw_token=reset_1) is None
    # ...but the pending email-verify token must survive a reset request.
    assert await service.consume(purpose="email-verify", raw_token=verify) is not None
    assert await service.consume(purpose="password-reset", raw_token=reset_2) is not None


async def test_revoke_existing_is_scoped_to_the_user(service: TokenService) -> None:
    alice = await service.issue(purpose="password-reset", user_id="alice")
    await service.issue(purpose="password-reset", user_id="bob")
    # Bob requesting a reset must not invalidate Alice's link.
    assert await service.consume(purpose="password-reset", raw_token=alice) is not None


async def test_revoke_existing_false_keeps_previous_tokens(
    service: TokenService,
) -> None:
    first = await service.issue(
        purpose="magic-link", user_id="u1", revoke_existing=False
    )
    second = await service.issue(
        purpose="magic-link", user_id="u1", revoke_existing=False
    )
    assert await service.consume(purpose="magic-link", raw_token=first) is not None
    assert await service.consume(purpose="magic-link", raw_token=second) is not None


# ---------------------------------------------------------------------------
# Concurrency — at most one claim per token, ever


async def test_concurrent_consume_yields_exactly_one_claim(
    service: TokenService,
) -> None:
    raw = await service.issue(purpose="password-reset", user_id="u1")
    results = await asyncio.gather(
        *(
            service.consume(purpose="password-reset", raw_token=raw)
            for _ in range(5)
        )
    )
    claims = [r for r in results if r is not None]
    assert len(claims) == 1


async def test_lost_update_race_returns_none(
    db: Database, service: TokenService, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Simulate the SELECT/UPDATE race: a rival consumer burns the token
    between our read and our guarded UPDATE. The guard's ``used_at IS
    NULL`` predicate must make our consume lose cleanly (return None),
    never double-claim."""
    raw = await service.issue(purpose="password-reset", user_id="u1")
    real_execute = Transaction.execute
    burn_marker = "token_sha256 = ? AND used_at IS NULL"

    async def racing_execute(self: Transaction, sql: str, params: object = None) -> int:
        if "SET used_at" in sql and burn_marker in sql:
            # The rival wins the race first, inside the same transaction.
            await real_execute(self, sql, params)  # type: ignore[arg-type]
        return await real_execute(self, sql, params)  # type: ignore[arg-type]

    monkeypatch.setattr(Transaction, "execute", racing_execute)
    assert await service.consume(purpose="password-reset", raw_token=raw) is None

    row = await db.fetchone(
        "SELECT used_at FROM auth_tokens WHERE token_sha256 = ?", (_sha256(raw),)
    )
    assert row is not None
    assert row["used_at"] is not None  # burned exactly once, by the "rival"


# ---------------------------------------------------------------------------
# Sweeping


async def test_sweep_expired_removes_only_old_rows(
    db: Database, service: TokenService, monkeypatch: pytest.MonkeyPatch
) -> None:
    user = "u1"

    _freeze(monkeypatch, T0 - timedelta(days=3))
    await service.issue(purpose="old-expired", user_id=user, ttl_seconds=60)
    old_used = await service.issue(purpose="old-used", user_id=user, ttl_seconds=3600)
    assert await service.consume(purpose="old-used", raw_token=old_used) is not None

    _freeze(monkeypatch, T0 - timedelta(hours=2))
    recently_expired = await service.issue(
        purpose="recent-expired", user_id=user, ttl_seconds=60
    )
    recent_used = await service.issue(
        purpose="recent-used", user_id=user, ttl_seconds=3 * 3600
    )
    assert await service.consume(purpose="recent-used", raw_token=recent_used) is not None

    _freeze(monkeypatch, T0)
    fresh = await service.issue(purpose="fresh", user_id=user, ttl_seconds=3600)

    removed = await service.sweep_expired()
    assert removed == 2  # only the two rows older than the one-day cutoff

    rows = await db.fetchall("SELECT purpose FROM auth_tokens ORDER BY purpose")
    assert [r["purpose"] for r in rows] == ["fresh", "recent-expired", "recent-used"]

    # Surviving recently-expired row is still unredeemable — consume
    # enforces expiry itself; the sweep is purely hygiene.
    assert (
        await service.consume(purpose="recent-expired", raw_token=recently_expired)
        is None
    )
    assert await service.consume(purpose="fresh", raw_token=fresh) is not None


async def test_sweep_on_empty_table_returns_zero(service: TokenService) -> None:
    assert await service.sweep_expired() == 0
