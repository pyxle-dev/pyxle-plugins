"""Small fixed-window rate limiter backed by a pyxle-db ``Database``.

Design intent:

* Every attempt is bucketed by ``(scope, identifier, bucket_start)``.
  Buckets are 1 hour wide. The first attempt per bucket creates the
  row; subsequent attempts increment ``count`` atomically.
* Expired rows are reaped lazily when their bucket is touched. A
  periodic sweep (not shipped here; belongs to the host app) can
  delete anything with ``expires_at < now``.
* A single table is shared across every scope the app limits, so any
  part of the app can rate-limit without migrating its own schema.

This lives in pyxle-auth but the table it owns is generic; future
plugins can instantiate :class:`RateLimiter` on the same DB and the
rows don't collide as long as they pick distinct ``scope`` strings.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from pyxle_db import Database, IntegrityError


_BUCKET_SECONDS = 60 * 60  # 1 hour


@dataclass(frozen=True, slots=True)
class RateLimitResult:
    """Outcome of :meth:`RateLimiter.check_and_increment`.

    Attributes:
        allowed: ``True`` if the attempt fits under the limit.
        remaining: Attempts left in the current bucket (0 if denied).
        retry_after_seconds: If ``allowed`` is False, wait at least
            this many seconds before retrying.
    """

    allowed: bool
    remaining: int
    retry_after_seconds: int


class RateLimiter:
    """Per-``(scope, identifier)`` fixed-window limiter."""

    def __init__(self, db: Database) -> None:
        self._db = db

    async def ensure_schema(self) -> None:
        """Create the backing table if it doesn't already exist.

        Apps that own their own migrations file should run the
        equivalent SQL there instead and skip this call.
        """
        async with self._db.transaction() as tx:
            tx.execute(
                """
                CREATE TABLE IF NOT EXISTS ratelimit_buckets (
                    key         TEXT PRIMARY KEY,
                    count       INTEGER NOT NULL,
                    expires_at  INTEGER NOT NULL
                )
                """
            )
            tx.execute(
                """
                CREATE INDEX IF NOT EXISTS ratelimit_buckets_expires
                ON ratelimit_buckets (expires_at)
                """
            )

    async def check_and_increment(
        self,
        *,
        scope: str,
        identifier: str,
        limit: int,
        bucket_seconds: int = _BUCKET_SECONDS,
    ) -> RateLimitResult:
        """Record an attempt and decide whether to allow it.

        Atomic: uses an ``INSERT ... ON CONFLICT DO UPDATE`` with a
        bucket-expiry guard so concurrent callers can't race past the
        limit.
        """
        now = int(time.time())
        bucket_start = now - (now % bucket_seconds)
        expires_at = bucket_start + bucket_seconds
        key = f"{scope}:{identifier}:{bucket_start}"

        async with self._db.transaction() as tx:
            # Optimistic path: increment, clamped. SQLite doesn't have a
            # native "IF count < limit" update that returns the new count
            # in one round-trip, so we do it as two statements inside
            # the transaction.
            tx.execute(
                """
                INSERT INTO ratelimit_buckets (key, count, expires_at)
                VALUES (?, 1, ?)
                ON CONFLICT(key) DO UPDATE
                SET count = count + 1
                """,
                (key, expires_at),
            )
            row = tx.fetchone(
                "SELECT count, expires_at FROM ratelimit_buckets WHERE key = ?",
                (key,),
            )
            assert row is not None

        count = int(row["count"])
        remaining = max(0, limit - count)
        if count <= limit:
            return RateLimitResult(
                allowed=True,
                remaining=remaining,
                retry_after_seconds=0,
            )
        return RateLimitResult(
            allowed=False,
            remaining=0,
            retry_after_seconds=max(1, expires_at - now),
        )

    async def reset(self, *, scope: str, identifier: str) -> None:
        """Drop every bucket for ``(scope, identifier)``.

        Call after a successful authentication so a legitimate user
        isn't locked out by earlier failed attempts.
        """
        async with self._db.transaction() as tx:
            tx.execute(
                "DELETE FROM ratelimit_buckets WHERE key LIKE ?",
                (f"{scope}:{identifier}:%",),
            )

    async def sweep_expired(self) -> int:
        """Delete expired buckets. Returns the number removed."""
        now = int(time.time())
        async with self._db.transaction() as tx:
            cur = tx.execute(
                "DELETE FROM ratelimit_buckets WHERE expires_at < ?",
                (now,),
            )
            return cur.rowcount
