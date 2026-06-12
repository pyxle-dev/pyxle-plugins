"""Small fixed-window rate limiter backed by a pyxle-db ``Database``.

Design intent:

* Every attempt is bucketed by ``(scope, identifier, bucket_start)``.
  Buckets are 1 hour wide. The first attempt per bucket creates the
  row; subsequent attempts increment ``count`` atomically.
* Expired rows linger until :meth:`RateLimiter.sweep_expired` removes
  them — correctness never depends on the sweep because bucket keys
  embed their window's start time.
* A single table is shared across every scope the app limits, so any
  part of the app can rate-limit without migrating its own schema.

This lives in pyxle-auth but the table it owns is generic; future
plugins can instantiate :class:`RateLimiter` on the same DB and the
rows don't collide as long as they pick distinct ``scope`` strings.

Portability (pyxle-db 0.2 runs on SQLite, PostgreSQL, and MySQL):

* The column is ``bucket_key`` — ``KEY`` is a reserved word in MySQL.
* The increment is a guarded UPDATE + INSERT inside one transaction
  instead of ``INSERT ... ON CONFLICT`` (a SQLite/PostgreSQL-ism).
* :meth:`reset` escapes LIKE wildcards, so an identifier containing
  ``%`` or ``_`` (legal in email local parts) only ever matches itself.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from pyxle_auth._ddl import ensure_index
from pyxle_db import DatabaseLike, IntegrityError


_BUCKET_SECONDS = 60 * 60  # 1 hour


def _escape_like(text: str) -> str:
    """Escape ``%``/``_`` (and the escape char itself) for a LIKE pattern
    using ``!`` as the escape character — chosen over backslash because
    MySQL gives backslashes meaning inside string literals."""
    return text.replace("!", "!!").replace("%", "!%").replace("_", "!_")


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

    def __init__(self, db: DatabaseLike) -> None:
        self._db = db

    async def ensure_schema(self) -> None:
        """Create the backing table if it doesn't already exist.

        Apps that own their own migrations file should apply
        ``pyxle_auth/migrations/0001-pyxle-auth-core.sql`` there instead
        and skip this call.
        """
        async with self._db.transaction() as tx:
            await tx.execute(
                """
                CREATE TABLE IF NOT EXISTS ratelimit_buckets (
                    bucket_key VARCHAR(320) PRIMARY KEY,
                    count      INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL
                )
                """
            )
        await ensure_index(
            self._db,
            name="ratelimit_buckets_expires",
            table="ratelimit_buckets",
            columns="expires_at",
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

        Atomic: the increment runs inside a transaction, so concurrent
        callers can't race past the limit.
        """
        now = int(time.time())
        bucket_start = now - (now % bucket_seconds)
        expires_at = bucket_start + bucket_seconds
        key = f"{scope}:{identifier}:{bucket_start}"

        count = await self._increment(key, expires_at)
        if count <= limit:
            return RateLimitResult(
                allowed=True,
                remaining=max(0, limit - count),
                retry_after_seconds=0,
            )
        return RateLimitResult(
            allowed=False,
            remaining=0,
            retry_after_seconds=max(1, expires_at - now),
        )

    async def _increment(self, key: str, expires_at: int) -> int:
        """Bump the bucket's counter, creating the row on first attempt,
        and return the new count.

        Written as a guarded UPDATE + INSERT because ``ON CONFLICT`` is
        not portable to MySQL. The one cross-backend race — two
        transactions both observing a missing row — surfaces as an
        :class:`IntegrityError` on the loser's INSERT; by then the row
        exists, so a single retry takes the UPDATE path. (SQLite never
        races here: its transactions open with ``BEGIN IMMEDIATE``,
        serialising writers.)
        """
        try:
            return await self._increment_once(key, expires_at)
        except IntegrityError:
            return await self._increment_once(key, expires_at)

    async def _increment_once(self, key: str, expires_at: int) -> int:
        async with self._db.transaction() as tx:
            updated = await tx.execute(
                "UPDATE ratelimit_buckets SET count = count + 1 "
                "WHERE bucket_key = ?",
                (key,),
            )
            if updated == 0:
                await tx.execute(
                    "INSERT INTO ratelimit_buckets (bucket_key, count, expires_at) "
                    "VALUES (?, 1, ?)",
                    (key, expires_at),
                )
                return 1
            row = await tx.get(
                "SELECT count FROM ratelimit_buckets WHERE bucket_key = ?",
                (key,),
            )
            return int(row["count"])

    async def reset(self, *, scope: str, identifier: str) -> None:
        """Drop every bucket for ``(scope, identifier)``.

        Call after a successful authentication so a legitimate user
        isn't locked out by earlier failed attempts.
        """
        pattern = _escape_like(f"{scope}:{identifier}:") + "%"
        await self._db.execute(
            "DELETE FROM ratelimit_buckets WHERE bucket_key LIKE ? ESCAPE '!'",
            (pattern,),
        )

    async def sweep_expired(self) -> int:
        """Delete expired buckets. Returns the number removed."""
        now = int(time.time())
        return await self._db.execute(
            "DELETE FROM ratelimit_buckets WHERE expires_at < ?",
            (now,),
        )
