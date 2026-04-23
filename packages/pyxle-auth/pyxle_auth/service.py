"""High-level authentication API.

:class:`AuthService` is the one type most request handlers interact
with. It owns:

* password hashing (argon2id)
* session issuance, resolution, extension, revocation
* per-identifier rate limiting

The service owns its own schema: :meth:`ensure_schema` creates the
``users`` and ``sessions`` tables if they don't exist. Apps that run
their own migrations file should apply the equivalent SQL there and
skip calling :meth:`ensure_schema` at runtime.

Security choices worth calling out:

* The session cookie value is 32 random bytes from ``secrets.token_urlsafe``
  (256 bits of entropy). The **raw** token is what the browser holds.
  The row stored in ``sessions`` is the SHA-256 hash of that token, so
  a database leak alone is not enough to resurrect sessions — an
  attacker would also need the plaintext.
* Passwords are hashed with argon2id, parameters configurable via
  :class:`AuthSettings`. ``verify`` is always called on an uncovered
  path so timing doesn't leak account existence. The "user doesn't
  exist" branch still runs a single dummy ``verify`` against a
  pre-computed hash to equalise wall-clock time.
* Emails are normalised (lowercased, stripped) on both write and read.
  Case differences never create two accounts.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError

from pyxle_db import Database, IntegrityError, NotFoundError

from pyxle_auth.errors import (
    AccountExists,
    AuthError,
    EmailNotVerified,
    InvalidCredentials,
    RateLimited,
    WeakPassword,
)
from pyxle_auth.models import Session, SessionCookie, User, _now_utc
from pyxle_auth.ratelimit import RateLimiter
from pyxle_auth.settings import AuthSettings


# ---------------------------------------------------------------------------
# Email normalisation


def _normalise_email(raw: str) -> str:
    """Lowercase, strip, reject if empty or absurd length.

    We intentionally do NOT try to validate RFC 5321 here — an
    ``@``-separated non-empty domain is enough to prevent trivially
    broken inputs, and over-strict server-side validation just rejects
    valid addresses nobody expected.
    """
    email = raw.strip().lower()
    if not email or "@" not in email or email.startswith("@") or email.endswith("@"):
        raise AuthError("Please enter a valid email address.")
    if len(email) > 254:
        # RFC 5321 4.5.3.1.3 — local part + @ + domain must fit in 254.
        raise AuthError("Email is too long.")
    return email


def _hash_token(raw: str) -> str:
    """SHA-256 hex digest. Used for session tokens and email verify tokens."""
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _generate_user_id() -> str:
    """Sortable user id — UUID4 hex. 32 chars, URL-safe."""
    return uuid.uuid4().hex


# ---------------------------------------------------------------------------
# Service


class AuthService:
    """Owns password hashing, session lifecycle, and rate limiting.

    Thread-unsafe to share a single :class:`PasswordHasher` across
    processes is not a concern — argon2-cffi's hasher is stateless.
    """

    def __init__(self, db: Database, settings: AuthSettings) -> None:
        self._db = db
        self._settings = settings
        self._hasher = PasswordHasher(
            time_cost=settings.argon_time_cost,
            memory_cost=settings.argon_memory_kib,
            parallelism=settings.argon_parallelism,
        )
        self._ratelimiter = RateLimiter(db)
        # A pre-computed hash used to keep sign-in wall-clock time
        # constant when the email doesn't exist. Recomputed once per
        # process; value itself doesn't matter.
        self._timing_hash = self._hasher.hash("0" * 32)

    # ---- schema ----------------------------------------------------------------

    async def ensure_schema(self) -> None:
        """Create our tables if they don't exist.

        Apps preferring to own migrations can skip this.
        """
        await self._ratelimiter.ensure_schema()
        async with self._db.transaction() as tx:
            tx.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id                TEXT PRIMARY KEY,
                    email             TEXT UNIQUE NOT NULL,
                    password_hash     TEXT NOT NULL,
                    email_verified_at TIMESTAMP,
                    created_at        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    plan              TEXT NOT NULL DEFAULT 'free'
                )
                """
            )
            tx.execute(
                """
                CREATE TABLE IF NOT EXISTS sessions (
                    token_sha256 TEXT PRIMARY KEY,
                    user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    created_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    expires_at   TIMESTAMP NOT NULL,
                    user_agent   TEXT,
                    ip           TEXT
                )
                """
            )
            tx.execute(
                "CREATE INDEX IF NOT EXISTS sessions_user ON sessions(user_id)"
            )
            tx.execute(
                "CREATE INDEX IF NOT EXISTS sessions_expires ON sessions(expires_at)"
            )

    # ---- sign-up ---------------------------------------------------------------

    async def sign_up(
        self,
        *,
        email: str,
        password: str,
        ip: str | None = None,
        user_agent: str | None = None,
    ) -> tuple[User, SessionCookie]:
        """Create an account and return the user + a session cookie.

        Raises:
            :class:`AccountExists` if ``email`` already has a user.
            :class:`WeakPassword` if the password violates policy.
            :class:`RateLimited` if the caller (by IP) exceeded the hourly cap.
        """
        email_n = _normalise_email(email)
        self._check_password_policy(password)

        if ip is not None:
            rl = await self._ratelimiter.check_and_increment(
                scope="auth:sign-up",
                identifier=ip,
                limit=self._settings.rate_limit_sign_up_per_hour,
            )
            if not rl.allowed:
                raise RateLimited(rl.retry_after_seconds)

        password_hash = self._hasher.hash(password)
        user_id = _generate_user_id()

        try:
            async with self._db.transaction() as tx:
                tx.execute(
                    """
                    INSERT INTO users (id, email, password_hash)
                    VALUES (?, ?, ?)
                    """,
                    (user_id, email_n, password_hash),
                )
        except IntegrityError:
            # UNIQUE(email)
            raise AccountExists() from None

        user = await self._load_user_by_id(user_id)
        assert user is not None
        session_cookie = await self._issue_session(
            user_id=user.id,
            ip=ip,
            user_agent=user_agent,
        )
        return user, session_cookie

    # ---- sign-in ---------------------------------------------------------------

    async def sign_in(
        self,
        *,
        email: str,
        password: str,
        ip: str | None = None,
        user_agent: str | None = None,
    ) -> tuple[User, SessionCookie]:
        """Verify credentials and return a fresh session.

        Rate-limited by both ``ip`` and ``email`` independently; either
        can trip the limiter.
        """
        email_n = _normalise_email(email)

        for scope, identifier in (
            ("auth:sign-in:ip", ip),
            ("auth:sign-in:email", email_n),
        ):
            if identifier is None:
                continue
            rl = await self._ratelimiter.check_and_increment(
                scope=scope,
                identifier=identifier,
                limit=self._settings.rate_limit_sign_in_per_hour,
            )
            if not rl.allowed:
                raise RateLimited(rl.retry_after_seconds)

        row = await self._db.fetchone(
            "SELECT id, password_hash, email_verified_at FROM users WHERE email = ?",
            (email_n,),
        )
        if row is None:
            # Constant-time dummy verify so we don't leak account existence
            # via response-time differences.
            try:
                self._hasher.verify(self._timing_hash, password)
            except VerifyMismatchError:
                pass
            raise InvalidCredentials()

        try:
            self._hasher.verify(row["password_hash"], password)
        except (VerifyMismatchError, InvalidHashError):
            raise InvalidCredentials() from None

        # Opportunistic rehash: if our argon2 params have moved on since
        # this password was hashed, write a refreshed hash in the
        # background.
        if self._hasher.check_needs_rehash(row["password_hash"]):
            new_hash = self._hasher.hash(password)
            await self._db.execute(
                "UPDATE users SET password_hash = ? WHERE id = ?",
                (new_hash, row["id"]),
            )

        if (
            self._settings.require_email_verified
            and row["email_verified_at"] is None
        ):
            raise EmailNotVerified("Please verify your email before signing in.")

        # Legitimate sign-in clears the IP+email buckets so this user
        # isn't locked out next hour.
        if ip is not None:
            await self._ratelimiter.reset(scope="auth:sign-in:ip", identifier=ip)
        await self._ratelimiter.reset(scope="auth:sign-in:email", identifier=email_n)

        user = await self._load_user_by_id(row["id"])
        assert user is not None
        session_cookie = await self._issue_session(
            user_id=user.id,
            ip=ip,
            user_agent=user_agent,
        )
        return user, session_cookie

    # ---- resolve / refresh -----------------------------------------------------

    async def resolve_session(
        self,
        *,
        cookie_value: str,
        extend: bool = True,
    ) -> User | None:
        """Look up a session from the cookie. Returns None if invalid.

        Expired or revoked sessions return None without raising. Valid
        sessions have their expiration extended when ``extend=True``.
        """
        if not cookie_value:
            return None
        token_hash = _hash_token(cookie_value)
        now = _now_utc()
        row = await self._db.fetchone(
            """
            SELECT s.token_sha256, s.user_id, s.created_at, s.expires_at,
                   s.user_agent, s.ip
            FROM sessions s
            WHERE s.token_sha256 = ?
            """,
            (token_hash,),
        )
        if row is None:
            return None

        expires_at = _coerce_dt(row["expires_at"])
        created_at = _coerce_dt(row["created_at"])
        if expires_at < now:
            # Lazy cleanup of the expired row.
            await self._db.execute(
                "DELETE FROM sessions WHERE token_sha256 = ?",
                (token_hash,),
            )
            return None

        # Absolute max-age check.
        absolute_deadline = created_at + timedelta(
            seconds=self._settings.session_absolute_max_seconds
        )
        if now > absolute_deadline:
            await self._db.execute(
                "DELETE FROM sessions WHERE token_sha256 = ?",
                (token_hash,),
            )
            return None

        if extend:
            new_expiry = min(
                now + timedelta(seconds=self._settings.session_lifetime_seconds),
                absolute_deadline,
            )
            # Only touch the row if the extension is meaningful (>60s new time).
            if (new_expiry - expires_at).total_seconds() > 60:
                await self._db.execute(
                    "UPDATE sessions SET expires_at = ? WHERE token_sha256 = ?",
                    (new_expiry, token_hash),
                )

        return await self._load_user_by_id(row["user_id"])

    # ---- sign-out --------------------------------------------------------------

    async def sign_out(self, *, cookie_value: str) -> SessionCookie:
        """Revoke the session and return a cookie that clears the browser's."""
        token_hash = _hash_token(cookie_value) if cookie_value else None
        if token_hash is not None:
            await self._db.execute(
                "DELETE FROM sessions WHERE token_sha256 = ?",
                (token_hash,),
            )
        return self._delete_cookie()

    async def revoke_all_sessions(self, *, user_id: str) -> int:
        """Revoke every session for the given user. Returns count deleted.

        Useful after a password change: the user's other devices should
        lose their sessions.
        """
        async with self._db.transaction() as tx:
            cur = tx.execute(
                "DELETE FROM sessions WHERE user_id = ?",
                (user_id,),
            )
            return cur.rowcount

    # ---- password change -------------------------------------------------------

    async def change_password(
        self,
        *,
        user_id: str,
        current_password: str,
        new_password: str,
    ) -> None:
        """Verify current password, then replace hash. Revokes other sessions."""
        self._check_password_policy(new_password)
        row = await self._db.fetchone(
            "SELECT password_hash FROM users WHERE id = ?", (user_id,)
        )
        if row is None:
            raise InvalidCredentials()
        try:
            self._hasher.verify(row["password_hash"], current_password)
        except (VerifyMismatchError, InvalidHashError):
            raise InvalidCredentials() from None
        new_hash = self._hasher.hash(new_password)
        async with self._db.transaction() as tx:
            tx.execute(
                "UPDATE users SET password_hash = ? WHERE id = ?",
                (new_hash, user_id),
            )
            # Revoke every session (including the caller's) — they'll
            # need to sign in again with the new password.
            tx.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))

    # ---- introspection ---------------------------------------------------------

    async def get_user(self, *, user_id: str) -> User | None:
        return await self._load_user_by_id(user_id)

    async def get_user_by_email(self, *, email: str) -> User | None:
        email_n = _normalise_email(email)
        row = await self._db.fetchone(
            "SELECT id FROM users WHERE email = ?", (email_n,)
        )
        if row is None:
            return None
        return await self._load_user_by_id(row["id"])

    # ---- email verification ----------------------------------------------------

    async def mark_email_verified(self, *, user_id: str) -> None:
        """Stamp ``email_verified_at`` to now.

        Email flows (token issuance, send, confirm) are the host app's
        responsibility; we only expose the DB mutation here.
        """
        await self._db.execute(
            "UPDATE users SET email_verified_at = ? WHERE id = ?",
            (_now_utc(), user_id),
        )

    # ---- helpers ---------------------------------------------------------------

    def _check_password_policy(self, password: str) -> None:
        if len(password) < self._settings.password_min_length:
            raise WeakPassword(
                f"Password must be at least {self._settings.password_min_length} characters."
            )
        if len(password) > self._settings.password_max_length:
            raise WeakPassword("Password is too long.")

    async def _load_user_by_id(self, user_id: str) -> User | None:
        row = await self._db.fetchone(
            """
            SELECT id, email, email_verified_at, created_at, plan
            FROM users WHERE id = ?
            """,
            (user_id,),
        )
        if row is None:
            return None
        return User(
            id=row["id"],
            email=row["email"],
            email_verified_at=_coerce_dt_nullable(row["email_verified_at"]),
            created_at=_coerce_dt(row["created_at"]),
            plan=row["plan"],
        )

    async def _issue_session(
        self,
        *,
        user_id: str,
        ip: str | None,
        user_agent: str | None,
    ) -> SessionCookie:
        raw_token = secrets.token_urlsafe(32)
        token_hash = _hash_token(raw_token)
        now = _now_utc()
        expires_at = now + timedelta(seconds=self._settings.session_lifetime_seconds)

        await self._db.execute(
            """
            INSERT INTO sessions
                (token_sha256, user_id, created_at, expires_at, user_agent, ip)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (token_hash, user_id, now, expires_at, user_agent, ip),
        )
        return SessionCookie(
            name=self._settings.cookie_name,
            value=raw_token,
            max_age=self._settings.session_lifetime_seconds,
            secure=self._settings.cookie_secure,
            http_only=True,
            samesite=self._settings.cookie_samesite,
            path=self._settings.cookie_path,
            domain=self._settings.cookie_domain,
        )

    def _delete_cookie(self) -> SessionCookie:
        return SessionCookie(
            name=self._settings.cookie_name,
            value="",
            max_age=0,
            secure=self._settings.cookie_secure,
            http_only=True,
            samesite=self._settings.cookie_samesite,
            path=self._settings.cookie_path,
            domain=self._settings.cookie_domain,
        )


# ---------------------------------------------------------------------------
# SQLite returns TIMESTAMP columns sometimes as ``str`` and sometimes as
# ``datetime`` depending on how the row was inserted. Normalise.


def _coerce_dt(value: Any) -> datetime:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value
    if isinstance(value, str):
        # SQLite stores timestamps as ISO-8601 strings by default.
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            # CURRENT_TIMESTAMP uses "YYYY-MM-DD HH:MM:SS"
            parsed = datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed
    raise TypeError(f"Cannot coerce {type(value).__name__} to datetime")


def _coerce_dt_nullable(value: Any) -> datetime | None:
    if value is None:
        return None
    return _coerce_dt(value)
