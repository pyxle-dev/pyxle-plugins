"""Long-lived, scoped API tokens (personal access tokens).

For programmatic access — CLIs, CI deploys, integrations:

* Format: ``pyxle_pat_<43 urlsafe chars>`` (256 bits of randomness). The
  recognisable prefix lets secret scanners (and humans) identify leaks.
* Only the SHA-256 is stored. The raw token is returned exactly once from
  :meth:`ApiTokenService.create`.
* Scopes are plain strings chosen by the app (``"deploy"``,
  ``"projects:read"``). :meth:`resolve` checks membership; an app that
  needs hierarchies can layer them on top.
* ``last_used_at`` is updated at most once per minute to keep reads cheap.

Schema::

    api_tokens (
        id            TEXT PRIMARY KEY,
        token_sha256  TEXT NOT NULL UNIQUE,
        user_id       TEXT NOT NULL,
        name          TEXT NOT NULL,
        scopes        TEXT NOT NULL,          -- space-separated
        created_at    TIMESTAMP NOT NULL,
        expires_at    TIMESTAMP,              -- NULL = non-expiring
        last_used_at  TIMESTAMP,
        revoked_at    TIMESTAMP
    )
"""

from __future__ import annotations

import hashlib
import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from pyxle_db import DatabaseLike

from pyxle_auth._ddl import ensure_index, timestamp_type

__all__ = ["ApiToken", "ApiTokenService", "TokenLimitReached", "TOKEN_PREFIX"]

TOKEN_PREFIX = "pyxle_pat_"


_MAX_NAME_LENGTH = 100
_MAX_SCOPES = 32

_SCHEMA_TEMPLATE = """
CREATE TABLE IF NOT EXISTS api_tokens (
    id            VARCHAR(64) PRIMARY KEY,
    token_sha256  VARCHAR(64) NOT NULL UNIQUE,
    user_id       VARCHAR(64) NOT NULL,
    name          TEXT NOT NULL,
    scopes        TEXT NOT NULL,
    created_at    {ts} NOT NULL,
    expires_at    {ts},
    last_used_at  {ts},
    revoked_at    {ts}
)
"""



def _hash(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _aware(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


@dataclass(frozen=True)
class ApiToken:
    """Token metadata — never contains the secret."""

    id: str
    user_id: str
    name: str
    scopes: tuple[str, ...]
    created_at: datetime
    expires_at: datetime | None
    last_used_at: datetime | None
    revoked_at: datetime | None

    @property
    def active(self) -> bool:
        if self.revoked_at is not None:
            return False
        if self.expires_at is not None and self.expires_at <= _utcnow():
            return False
        return True

    def has_scope(self, scope: str) -> bool:
        return scope in self.scopes


def _validate_scopes(scopes: tuple[str, ...] | list[str]) -> tuple[str, ...]:
    if not scopes:
        raise ValueError("At least one scope is required")
    if len(scopes) > _MAX_SCOPES:
        raise ValueError(f"At most {_MAX_SCOPES} scopes per token")
    cleaned: list[str] = []
    for scope in scopes:
        s = scope.strip()
        if not s or " " in s or len(s) > 64:
            raise ValueError(f"Invalid scope: {scope!r}")
        if s not in cleaned:
            cleaned.append(s)
    return tuple(cleaned)


class ApiTokenService:
    def __init__(self, db: DatabaseLike) -> None:
        self._db = db

    async def ensure_schema(self) -> None:
        ts = timestamp_type(self._db.dialect.name)
        await self._db.execute(_SCHEMA_TEMPLATE.format(ts=ts))
        await ensure_index(
            self._db, name="idx_api_tokens_user", table="api_tokens", columns="user_id"
        )

    async def create(
        self,
        *,
        user_id: str,
        name: str,
        scopes: list[str] | tuple[str, ...],
        expires_in_days: int | None = None,
        max_tokens_per_user: int | None = None,
    ) -> tuple[ApiToken, str]:
        """Mint a token. Returns ``(metadata, raw_token)`` — the raw value
        is shown once and never recoverable; store only the metadata.

        ``max_tokens_per_user`` lets the app enforce a plan limit at the
        same atomicity level as the insert (count + insert share the
        transaction, so racing creates cannot exceed the cap).
        """
        if not user_id:
            raise ValueError("user_id is required")
        clean_name = (name or "").strip()
        if not clean_name or len(clean_name) > _MAX_NAME_LENGTH:
            raise ValueError(f"Token name must be 1–{_MAX_NAME_LENGTH} characters")
        clean_scopes = _validate_scopes(tuple(scopes))
        if expires_in_days is not None and expires_in_days <= 0:
            raise ValueError("expires_in_days must be positive when given")

        raw = TOKEN_PREFIX + secrets.token_urlsafe(32)
        now = _utcnow()
        expires_at = (
            now + timedelta(days=expires_in_days) if expires_in_days else None
        )
        token = ApiToken(
            id=uuid.uuid4().hex,
            user_id=user_id,
            name=clean_name,
            scopes=clean_scopes,
            created_at=now,
            expires_at=expires_at,
            last_used_at=None,
            revoked_at=None,
        )
        async with self._db.transaction() as tx:
            if max_tokens_per_user is not None:
                # Serialize concurrent creates for THIS user before counting.
                # SQLite already serializes all writes (BEGIN IMMEDIATE), but
                # on PostgreSQL/MySQL two transactions could each COUNT the
                # old total and both INSERT, slipping past the cap — so take a
                # row lock on the owning user first. (Auth owns the users
                # table, so the lock target always exists.)
                if self._db.dialect.name in ("postgresql", "mysql"):
                    await tx.execute(
                        "SELECT id FROM users WHERE id = ? FOR UPDATE", (user_id,)
                    )
                # Count only LIVE tokens — expired ones are dead weight and
                # shouldn't block a user from minting a replacement.
                row = await tx.fetchone(
                    "SELECT COUNT(*) AS n FROM api_tokens "
                    "WHERE user_id = ? AND revoked_at IS NULL "
                    "AND (expires_at IS NULL OR expires_at > ?)",
                    (user_id, now),
                )
                if row is not None and int(row["n"]) >= max_tokens_per_user:
                    raise TokenLimitReached(max_tokens_per_user)
            await tx.execute(
                "INSERT INTO api_tokens "
                "(id, token_sha256, user_id, name, scopes, created_at, expires_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    token.id,
                    _hash(raw),
                    user_id,
                    clean_name,
                    " ".join(clean_scopes),
                    now,
                    expires_at,
                ),
            )
        return token, raw

    async def resolve(
        self, *, raw_token: str, required_scope: str | None = None
    ) -> ApiToken | None:
        """Authenticate a presented token.

        Returns the metadata when the token is known, unrevoked, unexpired,
        and (when asked) carries ``required_scope``. Returns ``None`` for
        every failure mode indistinguishably.
        """
        if (
            not raw_token
            or not isinstance(raw_token, str)
            or not raw_token.startswith(TOKEN_PREFIX)
            or len(raw_token) > 256
        ):
            return None
        row = await self._db.fetchone(
            "SELECT id, user_id, name, scopes, created_at, expires_at, "
            "last_used_at, revoked_at FROM api_tokens WHERE token_sha256 = ?",
            (_hash(raw_token),),
        )
        if row is None:
            return None
        token = _from_row(row)
        if not token.active:
            return None
        if required_scope is not None and not token.has_scope(required_scope):
            return None
        await self._touch(token)
        return token

    async def _touch(self, token: ApiToken) -> None:
        """Record use, throttled to once a minute."""
        now = _utcnow()
        if token.last_used_at is not None and (now - token.last_used_at) < timedelta(
            minutes=1
        ):
            return
        await self._db.execute(
            "UPDATE api_tokens SET last_used_at = ? WHERE id = ?",
            (now, token.id),
        )

    async def list_for_user(self, *, user_id: str) -> list[ApiToken]:
        rows = await self._db.fetchall(
            "SELECT id, user_id, name, scopes, created_at, expires_at, "
            "last_used_at, revoked_at FROM api_tokens "
            "WHERE user_id = ? AND revoked_at IS NULL ORDER BY created_at DESC",
            (user_id,),
        )
        return [_from_row(r) for r in rows]

    async def revoke(self, *, user_id: str, token_id: str) -> bool:
        """Revoke one token. Scoped by owner — a user can never revoke
        another user's token, even with a leaked id. Idempotent."""
        affected = 0
        async with self._db.transaction() as tx:
            affected = await tx.execute(
                "UPDATE api_tokens SET revoked_at = ? "
                "WHERE id = ? AND user_id = ? AND revoked_at IS NULL",
                (_utcnow(), token_id, user_id),
            )
        return affected > 0

    async def revoke_all(self, *, user_id: str) -> int:
        async with self._db.transaction() as tx:
            return await tx.execute(
                "UPDATE api_tokens SET revoked_at = ? "
                "WHERE user_id = ? AND revoked_at IS NULL",
                (_utcnow(), user_id),
            )


class TokenLimitReached(Exception):
    """The per-user token cap was hit (app-configured plan limit)."""

    def __init__(self, limit: int) -> None:
        super().__init__(f"API token limit reached ({limit}). Revoke one first.")
        self.limit = limit


def _from_row(row: object) -> ApiToken:
    return ApiToken(
        id=row["id"],  # type: ignore[index]
        user_id=row["user_id"],  # type: ignore[index]
        name=row["name"],  # type: ignore[index]
        scopes=tuple((row["scopes"] or "").split()),  # type: ignore[index]
        created_at=_aware(row["created_at"]),  # type: ignore[index,arg-type]
        expires_at=_aware(row["expires_at"]),  # type: ignore[index]
        last_used_at=_aware(row["last_used_at"]),  # type: ignore[index]
        revoked_at=_aware(row["revoked_at"]),  # type: ignore[index]
    )
