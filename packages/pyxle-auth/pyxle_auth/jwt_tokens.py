"""JWT access tokens + rotating opaque refresh tokens.

For API and mobile clients that authenticate with a ``Authorization: Bearer``
header instead of a session cookie.

* **Access token** — a short-lived signed JWT (HS256 by default) carrying
  ``sub`` (the user id), ``exp``, ``iat``, ``type="access"``, and a ``jti``.
  Stateless: verified by signature, never looked up in the database.
* **Refresh token** — a long-lived **opaque** 256-bit random string, stored
  only as its SHA-256 hash. It is **not** a JWT: a refresh token is a stored
  credential, so making it stateless would forfeit revocation.

**Rotation with reuse detection.** Every refresh issues a *new* refresh token
and marks the presented one used. All tokens descended from one sign-in share a
``family_id``. If an already-used (rotated) refresh token is presented again —
the fingerprint of a stolen token being replayed — the **entire family is
revoked**, logging out the attacker and the victim, who then re-authenticates.
This is the OAuth 2.0 refresh-token-rotation BCP applied to first-party tokens.

``pyjwt`` is the ``[jwt]`` extra, imported lazily so the rest of pyxle-auth
never needs it.
"""

from __future__ import annotations

import hashlib
import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from pyxle_db import DatabaseLike

from pyxle_auth._ddl import ensure_index, timestamp_type
from pyxle_auth.errors import InvalidToken
from pyxle_auth.models import _now_utc

_ACCESS_TYPE = "access"
_REFRESH_BYTES = 32  # 256-bit opaque refresh token


@dataclass(frozen=True, slots=True)
class TokenPair:
    """An issued access + refresh pair."""

    access_token: str
    refresh_token: str
    access_expires_in: int  # seconds until the access token expires
    token_type: str = "Bearer"


def _sha256(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


class JWTService:
    """Issues, verifies, and rotates JWT access + refresh tokens."""

    def __init__(
        self,
        db: DatabaseLike,
        *,
        secret: str | bytes,
        access_ttl_seconds: int = 900,        # 15 minutes
        refresh_ttl_seconds: int = 2_592_000,  # 30 days
        algorithm: str = "HS256",
        issuer: str | None = None,
    ) -> None:
        if not secret:
            raise ValueError("JWTService requires a non-empty signing secret")
        self._db = db
        self._secret = secret
        self._access_ttl = access_ttl_seconds
        self._refresh_ttl = refresh_ttl_seconds
        self._algorithm = algorithm
        self._issuer = issuer

    # ---- schema ----------------------------------------------------------------

    async def ensure_schema(self) -> None:
        ts = timestamp_type(self._db.dialect.name)
        await self._db.execute(
            """
            CREATE TABLE IF NOT EXISTS jwt_refresh_tokens (
                token_sha256 VARCHAR(64) PRIMARY KEY,
                family_id    VARCHAR(64) NOT NULL,
                user_id      VARCHAR(64) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                issued_at    {ts} NOT NULL,
                expires_at   {ts} NOT NULL,
                used_at      {ts},
                revoked_at   {ts}
            )
            """.format(ts=ts)
        )
        await ensure_index(
            self._db, name="jwt_refresh_family", table="jwt_refresh_tokens", columns="family_id"
        )
        await ensure_index(
            self._db, name="jwt_refresh_user", table="jwt_refresh_tokens", columns="user_id"
        )

    # ---- issue -----------------------------------------------------------------

    async def issue_pair(self, *, user_id: str) -> TokenPair:
        """Start a new token family for ``user_id`` and return the first pair."""
        return await self._issue(user_id=user_id, family_id=uuid.uuid4().hex)

    async def _issue(self, *, user_id: str, family_id: str) -> TokenPair:
        access = self._encode_access(user_id)
        raw_refresh = secrets.token_urlsafe(_REFRESH_BYTES)
        now = _now_utc()
        await self._db.execute(
            """
            INSERT INTO jwt_refresh_tokens
                (token_sha256, family_id, user_id, issued_at, expires_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                _sha256(raw_refresh),
                family_id,
                user_id,
                now,
                now + timedelta(seconds=self._refresh_ttl),
            ),
        )
        return TokenPair(
            access_token=access,
            refresh_token=raw_refresh,
            access_expires_in=self._access_ttl,
        )

    def _encode_access(self, user_id: str) -> str:
        import jwt  # lazy: the [jwt] extra

        now = _now_utc()
        payload: dict[str, object] = {
            "sub": user_id,
            "type": _ACCESS_TYPE,
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(seconds=self._access_ttl)).timestamp()),
            "jti": uuid.uuid4().hex,
        }
        if self._issuer:
            payload["iss"] = self._issuer
        return jwt.encode(payload, self._secret, algorithm=self._algorithm)

    # ---- verify ----------------------------------------------------------------

    def verify_access(self, token: str) -> dict | None:
        """Validate an access token's signature and claims, or return ``None``.

        Stateless — no database hit. Rejects a missing signature, a wrong
        algorithm, an expired token, a missing required claim, or a non-access
        token type.
        """
        import jwt  # lazy: the [jwt] extra

        if not token:
            return None
        options = {"require": ["exp", "iat", "sub"]}
        try:
            if self._issuer:
                claims = jwt.decode(
                    token,
                    self._secret,
                    algorithms=[self._algorithm],
                    options=options,
                    issuer=self._issuer,
                )
            else:
                claims = jwt.decode(
                    token, self._secret, algorithms=[self._algorithm], options=options
                )
        except jwt.PyJWTError:
            return None
        if claims.get("type") != _ACCESS_TYPE:
            return None
        return claims

    # ---- refresh (rotation + reuse detection) ----------------------------------

    async def refresh(self, refresh_token: str) -> TokenPair:
        """Rotate a refresh token: return a new pair, invalidate the old token.

        Raises :class:`InvalidToken` for an unknown, expired, or revoked token.
        Presenting an already-rotated token revokes the whole family (theft
        detection) and also raises.
        """
        token_hash = _sha256(refresh_token)
        row = await self._db.fetchone(
            """
            SELECT family_id, user_id, expires_at, used_at, revoked_at
            FROM jwt_refresh_tokens WHERE token_sha256 = ?
            """,
            (token_hash,),
        )
        if row is None or row["revoked_at"] is not None:
            raise InvalidToken()
        if _aware(row["expires_at"]) < _now_utc():
            raise InvalidToken()
        if row["used_at"] is not None:
            # Reuse of a rotated token → likely theft. Burn the family.
            await self.revoke_family(family_id=row["family_id"])
            raise InvalidToken()

        # Atomically claim the rotation: mark used iff still unused and live.
        # Only one concurrent caller can win; a loser sees affected == 0 and is
        # treated as reuse.
        affected = await self._db.execute(
            """
            UPDATE jwt_refresh_tokens SET used_at = ?
            WHERE token_sha256 = ? AND used_at IS NULL AND revoked_at IS NULL
            """,
            (_now_utc(), token_hash),
        )
        if affected == 0:
            await self.revoke_family(family_id=row["family_id"])
            raise InvalidToken()

        return await self._issue(user_id=row["user_id"], family_id=row["family_id"])

    # ---- revoke ----------------------------------------------------------------

    async def revoke_family(self, *, family_id: str) -> int:
        """Revoke every still-live token in a family. Returns the count."""
        return await self._db.execute(
            "UPDATE jwt_refresh_tokens SET revoked_at = ? WHERE family_id = ? AND revoked_at IS NULL",
            (_now_utc(), family_id),
        )

    async def revoke_all_for_user(self, *, user_id: str) -> int:
        """Revoke every refresh token for a user (e.g. on password change)."""
        return await self._db.execute(
            "UPDATE jwt_refresh_tokens SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL",
            (_now_utc(), user_id),
        )


__all__ = ["JWTService", "TokenPair"]
