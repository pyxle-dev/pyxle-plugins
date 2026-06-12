"""Single-use, expiring, purpose-scoped tokens.

The shared machinery behind password-reset and email-verification flows
(and anything else an app needs — invite links, magic links):

* 256 bits of ``secrets`` randomness per token.
* Only the SHA-256 of the token is stored; the raw value exists once, in
  the return value of :meth:`TokenService.issue`, for the app to deliver
  (the library never sends email — bring your own mailer, Django-style).
* Lookup is by hash — a constant-time comparison by construction, since
  attackers cannot produce hash preimages to probe prefixes.
* ``consume`` burns the token atomically: two racing requests can't both
  redeem it (the UPDATE is guarded on ``used_at IS NULL``).
* Purposes namespace tokens: a password-reset token can never be replayed
  as an email-verification token.

Schema (created by :meth:`ensure_schema`, or via the shipped migrations)::

    auth_tokens (
        token_sha256 TEXT PRIMARY KEY,
        purpose      TEXT NOT NULL,
        user_id      TEXT NOT NULL,
        created_at   TIMESTAMP NOT NULL,
        expires_at   TIMESTAMP NOT NULL,
        used_at      TIMESTAMP NULL
    )
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from pyxle_db import DatabaseLike

from pyxle_auth._ddl import ensure_index, timestamp_type

__all__ = ["TokenClaim", "TokenService"]


_SCHEMA_TEMPLATE = """
CREATE TABLE IF NOT EXISTS auth_tokens (
    token_sha256 VARCHAR(64) PRIMARY KEY,
    purpose      VARCHAR(64) NOT NULL,
    user_id      VARCHAR(64) NOT NULL,
    created_at   {ts} NOT NULL,
    expires_at   {ts} NOT NULL,
    used_at      {ts}
)
"""




def _hash(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True)
class TokenClaim:
    """A successfully consumed token."""

    user_id: str
    purpose: str
    issued_at: datetime
    expires_at: datetime


class TokenService:
    """Issue and redeem single-use tokens. One instance per app."""

    def __init__(self, db: DatabaseLike, *, default_ttl_seconds: int = 1800) -> None:
        if default_ttl_seconds <= 0:
            raise ValueError("default_ttl_seconds must be positive")
        self._db = db
        self._default_ttl = default_ttl_seconds

    async def ensure_schema(self) -> None:
        ts = timestamp_type(self._db.dialect.name)
        await self._db.execute(_SCHEMA_TEMPLATE.format(ts=ts))
        await ensure_index(
            self._db,
            name="idx_auth_tokens_user",
            table="auth_tokens",
            columns="user_id, purpose",
        )

    async def issue(
        self,
        *,
        purpose: str,
        user_id: str,
        ttl_seconds: int | None = None,
        revoke_existing: bool = True,
    ) -> str:
        """Mint a token and return its raw value (shown exactly once).

        ``revoke_existing`` (default) burns the user's previous unused
        tokens for the same purpose — requesting a second password-reset
        email invalidates the first link, which is what users expect and
        what limits the window of a leaked mailbox.
        """
        if not purpose or not purpose.strip():
            raise ValueError("purpose must be a non-empty string")
        if not user_id:
            raise ValueError("user_id must be a non-empty string")
        ttl = self._default_ttl if ttl_seconds is None else ttl_seconds
        if ttl <= 0:
            raise ValueError("ttl_seconds must be positive")

        raw = secrets.token_urlsafe(32)  # 256 bits
        now = _utcnow()
        async with self._db.transaction() as tx:
            if revoke_existing:
                await tx.execute(
                    "UPDATE auth_tokens SET used_at = ? "
                    "WHERE user_id = ? AND purpose = ? AND used_at IS NULL",
                    (now, user_id, purpose.strip()),
                )
            await tx.execute(
                "INSERT INTO auth_tokens "
                "(token_sha256, purpose, user_id, created_at, expires_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (_hash(raw), purpose.strip(), user_id, now, now + timedelta(seconds=ttl)),
            )
        return raw

    async def consume(self, *, purpose: str, raw_token: str) -> TokenClaim | None:
        """Redeem a token. Returns the claim, or ``None`` for anything
        invalid — wrong purpose, unknown, expired, or already used. The
        caller cannot distinguish *why* it failed; neither can an attacker.
        """
        if not raw_token or not isinstance(raw_token, str) or len(raw_token) > 256:
            return None
        token_hash = _hash(raw_token)
        now = _utcnow()
        async with self._db.transaction() as tx:
            row = await tx.fetchone(
                "SELECT user_id, purpose, created_at, expires_at, used_at "
                "FROM auth_tokens WHERE token_sha256 = ? AND purpose = ?",
                # issue() stores the stripped purpose — match it symmetrically.
                (token_hash, purpose.strip() if isinstance(purpose, str) else purpose),
            )
            if row is None or row["used_at"] is not None:
                return None
            expires_at = _aware(row["expires_at"])
            if expires_at <= now:
                return None
            # Burn atomically; the guard re-checks used_at so a concurrent
            # consumer of the same token loses the race cleanly.
            affected = await tx.execute(
                "UPDATE auth_tokens SET used_at = ? "
                "WHERE token_sha256 = ? AND used_at IS NULL",
                (now, token_hash),
            )
            if affected == 0:
                return None
            return TokenClaim(
                user_id=row["user_id"],
                purpose=row["purpose"],
                issued_at=_aware(row["created_at"]),
                expires_at=expires_at,
            )

    async def sweep_expired(self) -> int:
        """Delete expired/used tokens older than a day. Returns rows removed.
        Run opportunistically (e.g. at startup); correctness never depends
        on it — ``consume`` enforces expiry itself.
        """
        cutoff = _utcnow() - timedelta(days=1)
        async with self._db.transaction() as tx:
            return await tx.execute(
                "DELETE FROM auth_tokens WHERE expires_at < ? "
                "OR (used_at IS NOT NULL AND used_at < ?)",
                (cutoff, cutoff),
            )


def _aware(value: datetime) -> datetime:
    """Backends return aware datetimes; tolerate naive ones as UTC anyway."""
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value
