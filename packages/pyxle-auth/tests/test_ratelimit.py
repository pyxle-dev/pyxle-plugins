from __future__ import annotations

import pytest

from pyxle_auth.ratelimit import RateLimiter
from pyxle_db import Database


@pytest.fixture
async def limiter(db: Database) -> RateLimiter:
    rl = RateLimiter(db)
    await rl.ensure_schema()
    return rl


async def test_allows_until_limit(limiter: RateLimiter) -> None:
    for i in range(3):
        r = await limiter.check_and_increment(
            scope="test", identifier="a", limit=3
        )
        assert r.allowed is True
        assert r.remaining == 2 - i


async def test_denies_when_exceeded(limiter: RateLimiter) -> None:
    for _ in range(3):
        await limiter.check_and_increment(scope="test", identifier="a", limit=3)
    r = await limiter.check_and_increment(scope="test", identifier="a", limit=3)
    assert r.allowed is False
    assert r.remaining == 0
    assert r.retry_after_seconds > 0


async def test_independent_identifiers(limiter: RateLimiter) -> None:
    for _ in range(3):
        await limiter.check_and_increment(scope="test", identifier="a", limit=3)
    # A different identifier starts fresh.
    r = await limiter.check_and_increment(scope="test", identifier="b", limit=3)
    assert r.allowed is True


async def test_reset_clears_buckets(limiter: RateLimiter) -> None:
    for _ in range(3):
        await limiter.check_and_increment(scope="test", identifier="a", limit=3)
    await limiter.reset(scope="test", identifier="a")
    r = await limiter.check_and_increment(scope="test", identifier="a", limit=3)
    assert r.allowed is True


async def test_sweep_only_removes_expired(
    db: Database, limiter: RateLimiter
) -> None:
    """Sweep removes expired buckets and leaves live ones alone.

    We bypass :meth:`check_and_increment` so the test doesn't depend on
    wall-clock sleeping — one row is inserted with a past ``expires_at``,
    one with a future one.
    """
    async with db.transaction() as tx:
        tx.execute(
            """
            INSERT INTO ratelimit_buckets (key, count, expires_at)
            VALUES ('t:expired:0', 3, 1)
            """
        )
        tx.execute(
            """
            INSERT INTO ratelimit_buckets (key, count, expires_at)
            VALUES ('t:fresh:0', 1, 9999999999)
            """
        )

    deleted = await limiter.sweep_expired()
    assert deleted == 1

    rows = await db.fetchall("SELECT key FROM ratelimit_buckets ORDER BY key")
    assert [r["key"] for r in rows] == ["t:fresh:0"]
