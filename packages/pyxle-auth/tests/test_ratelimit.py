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


async def test_reset_treats_like_wildcards_literally(
    limiter: RateLimiter, db: Database
) -> None:
    """An identifier containing ``_`` or ``%`` (legal in email local
    parts) must only ever reset its own buckets — the LIKE pattern is
    escaped, so ``a_b@x.com`` cannot clear ``axb@x.com``'s counter."""
    for _ in range(3):
        await limiter.check_and_increment(
            scope="test", identifier="axb@x.com", limit=3
        )
    await limiter.check_and_increment(scope="test", identifier="a_b@x.com", limit=3)

    await limiter.reset(scope="test", identifier="a_b@x.com")

    rows = await db.fetchall("SELECT bucket_key FROM ratelimit_buckets")
    keys = [r["bucket_key"] for r in rows]
    assert len(keys) == 1
    assert keys[0].startswith("test:axb@x.com:")


async def test_sweep_only_removes_expired(
    db: Database, limiter: RateLimiter
) -> None:
    """Sweep removes expired buckets and leaves live ones alone.

    We bypass :meth:`check_and_increment` so the test doesn't depend on
    wall-clock sleeping — one row is inserted with a past ``expires_at``,
    one with a future one.
    """
    async with db.transaction() as tx:
        await tx.execute(
            """
            INSERT INTO ratelimit_buckets (bucket_key, count, expires_at)
            VALUES ('t:expired:0', 3, 1)
            """
        )
        await tx.execute(
            """
            INSERT INTO ratelimit_buckets (bucket_key, count, expires_at)
            VALUES ('t:fresh:0', 1, 9999999999)
            """
        )

    deleted = await limiter.sweep_expired()
    assert deleted == 1

    rows = await db.fetchall(
        "SELECT bucket_key FROM ratelimit_buckets ORDER BY bucket_key"
    )
    assert [r["bucket_key"] for r in rows] == ["t:fresh:0"]
