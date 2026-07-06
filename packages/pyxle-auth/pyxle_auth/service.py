"""High-level authentication API.

:class:`AuthService` is the one type most request handlers interact
with. It owns:

* password hashing (argon2id)
* session issuance, resolution, extension, listing, revocation
* per-identifier rate limiting
* password-reset and email-verification flows, built on the single-use
  tokens in :mod:`pyxle_auth.tokens` (the library never sends email —
  the raw token is returned for the app's mailer, Django-style)

The service owns its own schema: :meth:`ensure_schema` creates the
``users`` and ``sessions`` tables (plus the rate-limit and auth-token
tables its collaborators own) if they don't exist. Apps that run their
own migrations should apply
``pyxle_auth/migrations/0001-pyxle-auth-core.sql`` there instead and
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
* :meth:`request_password_reset` is equally enumeration-proof: unknown
  emails return ``None`` after burning the same token-generation cost
  the hit path pays, and the rate limiter counts both cases.
* Emails are normalised (lowercased, stripped) on both write and read.
  Case differences never create two accounts.

SQL is written once in canonical qmark style and stays portable across
pyxle-db's SQLite/PostgreSQL/MySQL backends: positional parameters only,
explicit values instead of column DEFAULTs, no upsert dialects.
"""

from __future__ import annotations

import hashlib
import secrets
import uuid
from datetime import datetime, timedelta, timezone

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError

from pyxle_db import DatabaseLike, IntegrityError

from pyxle_auth._ddl import ensure_index, timestamp_type
from pyxle_auth._identity import normalise_username
from pyxle_auth.errors import (
    AccountExists,
    AuthError,
    EmailNotVerified,
    InvalidCredentials,
    InvalidToken,
    RateLimited,
    WeakPassword,
)
from pyxle_auth.models import SessionCookie, SessionInfo, User, _now_utc
from pyxle_auth.ratelimit import RateLimiter
from pyxle_auth.settings import AuthSettings
from pyxle_auth.tokens import TokenService


# ---------------------------------------------------------------------------
# Constants

_DEFAULT_PLAN = "free"

_PURPOSE_PASSWORD_RESET = "password_reset"
_PURPOSE_EMAIL_VERIFY = "email_verify"

# Stand-in user id for the password-reset miss path, so an unknown email
# does the same committed token write a real one does (timing parity). The
# NUL prefix can never collide with a real uuid4-hex user id.
_RESET_SENTINEL_USER_ID = "\x00pwreset-sentinel"

# Hourly cap on password-reset requests, per email and (when given) per
# IP. Deliberately tighter than sign-in: each allowed request emails a
# live account-takeover link.
_PASSWORD_RESET_PER_HOUR = 3

# Fallbacks for the matching AuthSettings fields, read via getattr so
# this module works against settings objects predating the fields.
_DEFAULT_PASSWORD_RESET_TTL = 1800
_DEFAULT_EMAIL_VERIFY_TTL = 86400


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
    """SHA-256 hex digest — how session tokens are stored at rest."""
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _generate_user_id() -> str:
    """Sortable user id — UUID4 hex. 32 chars, URL-safe."""
    return uuid.uuid4().hex


# ---------------------------------------------------------------------------
# Service


class AuthService:
    """Owns password hashing, session lifecycle, rate limiting, and the
    password-reset / email-verification token flows.

    Thread-unsafe to share a single :class:`PasswordHasher` across
    processes is not a concern — argon2-cffi's hasher is stateless.
    """

    def __init__(self, db: DatabaseLike, settings: AuthSettings) -> None:
        self._db = db
        self._settings = settings
        self._hasher = PasswordHasher(
            time_cost=settings.argon_time_cost,
            memory_cost=settings.argon_memory_kib,
            parallelism=settings.argon_parallelism,
        )
        self._ratelimiter = RateLimiter(db)
        # Public on purpose: apps with bespoke flows (invites, magic
        # links) issue their own purposes on the same token table.
        self.tokens: TokenService = TokenService(db)
        # A pre-computed hash used to keep sign-in wall-clock time
        # constant when the email doesn't exist. Recomputed once per
        # process; value itself doesn't matter.
        self._timing_hash = self._hasher.hash("0" * 32)

    @property
    def settings(self) -> AuthSettings:
        """The resolved settings — read by :mod:`pyxle_auth.guards` for
        the cookie name, and handy for apps building responses by hand."""
        return self._settings

    # ---- schema ----------------------------------------------------------------

    async def ensure_schema(self) -> None:
        """Create our tables if they don't exist.

        Apps preferring to own migrations can skip this and apply
        ``pyxle_auth/migrations/0001-pyxle-auth-core.sql`` instead.
        """
        await self._ratelimiter.ensure_schema()
        await self.tokens.ensure_schema()
        ts = timestamp_type(self._db.dialect.name)
        async with self._db.transaction() as tx:
            await tx.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id                VARCHAR(64) PRIMARY KEY,
                    email             VARCHAR(255) UNIQUE,
                    username          VARCHAR(64) UNIQUE,
                    password_hash     TEXT NOT NULL,
                    email_verified_at {ts},
                    created_at        {ts} NOT NULL,
                    plan              TEXT NOT NULL
                )
                """.format(ts=ts)
            )
            await tx.execute(
                """
                CREATE TABLE IF NOT EXISTS sessions (
                    token_sha256 VARCHAR(64) PRIMARY KEY,
                    user_id      VARCHAR(64) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    created_at   {ts} NOT NULL,
                    expires_at   {ts} NOT NULL,
                    user_agent   TEXT,
                    ip           TEXT
                )
                """.format(ts=ts)
            )
        await ensure_index(
            self._db, name="sessions_user", table="sessions", columns="user_id"
        )
        await ensure_index(
            self._db, name="sessions_expires", table="sessions", columns="expires_at"
        )

    # ---- sign-up ---------------------------------------------------------------

    def _normalise_username(self, raw: str) -> str:
        """Validate + normalise a username against this service's policy."""
        return normalise_username(
            raw,
            min_length=self._settings.username_min_length,
            max_length=self._settings.username_max_length,
            pattern=self._settings.username_pattern,
            reserved=self._settings.username_reserved,
        )

    def _resolve_signup_identifiers(
        self, *, email: str | None, username: str | None
    ) -> tuple[str | None, str | None]:
        """Validate sign-up identifiers, returning ``(email, username)`` normalised.

        The configured primary identifier (:attr:`AuthSettings.identifier`) is
        required; the other is accepted and stored when supplied — so a
        username-mode app may still collect an optional email. Raises
        :class:`AuthError` if the primary is missing or any value is invalid.
        """
        email_n = _normalise_email(email) if email else None
        username_n = self._normalise_username(username) if username else None
        if self._settings.identifier == "username":
            if username_n is None:
                raise AuthError("Please choose a username.")
        elif email_n is None:
            raise AuthError("Please enter an email address.")
        return email_n, username_n

    async def sign_up(
        self,
        *,
        password: str,
        email: str | None = None,
        username: str | None = None,
        ip: str | None = None,
        user_agent: str | None = None,
    ) -> tuple[User, SessionCookie]:
        """Create an account and return the user + a session cookie.

        Pass the identifier your app is configured for: an ``email`` (default),
        a ``username`` (when ``AuthSettings.identifier == "username"``), or both
        (the configured one is required, the other optional).

        Raises:
            :class:`AccountExists` if the email or username is already taken.
            :class:`WeakPassword` if the password violates policy.
            :class:`RateLimited` if the caller (by IP) exceeded the hourly cap.
            :class:`AuthError` if the required identifier is missing/invalid.
        """
        email_n, username_n = self._resolve_signup_identifiers(
            email=email, username=username
        )
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
            await self._db.execute(
                """
                INSERT INTO users (id, email, username, password_hash, created_at, plan)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (user_id, email_n, username_n, password_hash, _now_utc(), _DEFAULT_PLAN),
            )
        except IntegrityError:
            # UNIQUE(email) or UNIQUE(username) — identifier already taken. The
            # message names the configured identifier so it's correct in both
            # modes (never says "email" for a username collision).
            raise AccountExists(identifier=self._settings.identifier) from None

        user = await self._load_user_by_id(user_id)
        assert user is not None
        session_cookie = await self._issue_session(
            user_id=user.id,
            ip=ip,
            user_agent=user_agent,
        )
        return user, session_cookie

    async def username_available(
        self, username: str, *, ip: str | None = None
    ) -> bool:
        """Return ``True`` if *username* is valid **and** not yet taken.

        Validates against the configured policy first — raising
        :class:`AuthError` (with the reason) if the handle is malformed or
        reserved — then checks the table. Availability is intentionally public:
        a user must know whether a handle is free before claiming it.

        Pass ``ip`` (the public HTTP endpoint does) to rate-limit checks
        per-IP — enough for a debounced picker, but enough friction to make
        bulk enumeration of the user list impractical. Raises
        :class:`RateLimited` when the per-IP cap is exceeded.
        """
        if ip is not None:
            rl = await self._ratelimiter.check_and_increment(
                scope="auth:username-check",
                identifier=ip,
                limit=self._settings.rate_limit_username_check_per_hour,
            )
            if not rl.allowed:
                raise RateLimited(rl.retry_after_seconds)
        username_n = self._normalise_username(username)
        row = await self._db.fetchone(
            "SELECT 1 FROM users WHERE username = ?", (username_n,)
        )
        return row is None

    # ---- sign-in ---------------------------------------------------------------

    async def sign_in(
        self,
        *,
        password: str,
        email: str | None = None,
        username: str | None = None,
        ip: str | None = None,
        user_agent: str | None = None,
    ) -> tuple[User, SessionCookie]:
        """Verify credentials and return a fresh session.

        Pass the configured login identifier — ``email`` (default) or
        ``username``. Rate-limited by both ``ip`` and the identifier
        independently; either can trip the limiter.
        """
        user = await self.verify_credentials(
            email=email, username=username, password=password, ip=ip
        )
        session_cookie = await self._issue_session(
            user_id=user.id,
            ip=ip,
            user_agent=user_agent,
        )
        return user, session_cookie

    def _login_lookup(
        self, *, email: str | None, username: str | None
    ) -> tuple[str, str]:
        """Resolve the ``(column, value)`` to match at sign-in.

        Uses the configured identifier. Unlike sign-up this does NOT run the
        full username policy — a malformed handle simply matches no row and
        surfaces as :class:`InvalidCredentials`, so sign-in never leaks the
        username rules and stays enumeration-safe. Email keeps its existing
        light normalisation.
        """
        if self._settings.identifier == "username":
            value = (username or "").strip().lower()
            if not value:
                raise InvalidCredentials()
            return "username", value
        if not email:
            raise InvalidCredentials()
        return "email", _normalise_email(email)

    async def verify_credentials(
        self,
        *,
        password: str,
        email: str | None = None,
        username: str | None = None,
        ip: str | None = None,
    ) -> User:
        """Verify the configured identifier + password, returning the :class:`User`.

        The rate-limited, constant-time, enumeration-safe core that
        :meth:`sign_in` builds on — split out so callers that authenticate
        for something OTHER than a browser session (a JWT pair, an API
        handshake) get the exact same protections without issuing a session.
        Raises :class:`InvalidCredentials`, :class:`RateLimited`, or
        :class:`EmailNotVerified` exactly as :meth:`sign_in` does.
        """
        column, ident_n = self._login_lookup(email=email, username=username)

        # Reject over-length passwords BEFORE any argon2 work. A password
        # longer than the policy max can never match a stored hash (sign_up
        # enforces the same cap), so this leaks nothing — but it stops an
        # attacker amplifying CPU by feeding multi-megabyte passwords into
        # the verifier (the dummy-verify path below would hash them too).
        if len(password) > self._settings.password_max_length:
            raise InvalidCredentials()

        # The IP bucket throttles a single abusive source pre-verify. The
        # per-identifier bucket is checked too, but a CORRECT password always
        # wins (below), so flooding a victim's account with wrong guesses can
        # never lock the legitimate owner out of their own account.
        if ip is not None:
            ip_rl = await self._ratelimiter.check_and_increment(
                scope="auth:sign-in:ip",
                identifier=ip,
                limit=self._settings.rate_limit_sign_in_per_hour,
            )
            if not ip_rl.allowed:
                raise RateLimited(ip_rl.retry_after_seconds)
        ident_rl = await self._ratelimiter.check_and_increment(
            scope=f"auth:sign-in:{column}",
            identifier=ident_n,
            limit=self._settings.rate_limit_sign_in_per_hour,
        )
        ident_limited = not ident_rl.allowed

        # ``column`` is one of our own literals ("email"/"username"), never
        # user input, so the interpolation here is injection-safe.
        row = await self._db.fetchone(
            f"SELECT id, email, password_hash, email_verified_at FROM users WHERE {column} = ?",
            (ident_n,),
        )
        if row is None:
            # Constant-time dummy verify so we don't leak account existence
            # via response-time differences.
            try:
                self._hasher.verify(self._timing_hash, password)
            except VerifyMismatchError:
                pass
            # No real account to protect; an exhausted identifier bucket may
            # surface as RateLimited, otherwise it's a normal bad login.
            if ident_limited:
                raise RateLimited(ident_rl.retry_after_seconds)
            raise InvalidCredentials()

        try:
            self._hasher.verify(row["password_hash"], password)
        except (VerifyMismatchError, InvalidHashError):
            # Wrong password: NOW the identifier bucket may block, throttling a
            # distributed guessing campaign against this one account.
            if ident_limited:
                raise RateLimited(ident_rl.retry_after_seconds) from None
            raise InvalidCredentials() from None

        # Correct password from here on — the identifier bucket is deliberately
        # NOT consulted, so the owner is never locked out by others' failures.

        # Opportunistic rehash: if our argon2 params have moved on since
        # this password was hashed, write a refreshed hash in the
        # background.
        if self._hasher.check_needs_rehash(row["password_hash"]):
            new_hash = self._hasher.hash(password)
            await self._db.execute(
                "UPDATE users SET password_hash = ? WHERE id = ?",
                (new_hash, row["id"]),
            )

        # Email verification only gates accounts that HAVE an email. A
        # username-only account (email NULL) can never verify an email it
        # doesn't have, so requiring verification must not lock it out.
        if (
            self._settings.require_email_verified
            and row["email"] is not None
            and row["email_verified_at"] is None
        ):
            raise EmailNotVerified("Please verify your email before signing in.")

        # Legitimate sign-in clears the IP + identifier buckets so this user
        # isn't locked out next hour.
        if ip is not None:
            await self._ratelimiter.reset(scope="auth:sign-in:ip", identifier=ip)
        await self._ratelimiter.reset(
            scope=f"auth:sign-in:{column}", identifier=ident_n
        )

        user = await self._load_user_by_id(row["id"])
        assert user is not None
        return user

    # ---- external identity (OAuth / SSO) ---------------------------------------

    async def start_session(
        self,
        *,
        user_id: str,
        ip: str | None = None,
        user_agent: str | None = None,
    ) -> SessionCookie:
        """Issue a session for an ALREADY-AUTHENTICATED user.

        For flows that establish identity without a password — OAuth sign-in,
        magic links, admin impersonation. The caller is responsible for having
        authenticated the user; this only mints the session cookie (same
        sliding-expiry, hashed-at-rest token as :meth:`sign_in`).
        """
        return await self._issue_session(
            user_id=user_id, ip=ip, user_agent=user_agent
        )

    async def create_external_user(
        self,
        *,
        email: str,
        email_verified: bool = False,
    ) -> User:
        """Create a passwordless account (OAuth / SSO).

        The account stores an **unusable** password hash — a hash of a random
        secret nobody holds — so it can never be signed into with a password
        until the user sets one via the reset flow. ``email_verified`` stamps
        ``email_verified_at`` (OAuth providers vouch for the address). Raises
        :class:`AccountExists` if the email already has an account.
        """
        email_n = _normalise_email(email)
        user_id = _generate_user_id()
        unusable_hash = self._hasher.hash(secrets.token_urlsafe(32))
        verified_at = _now_utc() if email_verified else None
        try:
            await self._db.execute(
                """
                INSERT INTO users
                    (id, email, password_hash, email_verified_at, created_at, plan)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (user_id, email_n, unusable_hash, verified_at, _now_utc(), _DEFAULT_PLAN),
            )
        except IntegrityError:
            raise AccountExists() from None
        user = await self._load_user_by_id(user_id)
        assert user is not None
        return user

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

        expires_at = _aware(row["expires_at"])
        created_at = _aware(row["created_at"])
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
        if cookie_value:
            await self._db.execute(
                "DELETE FROM sessions WHERE token_sha256 = ?",
                (_hash_token(cookie_value),),
            )
        return self._delete_cookie()

    async def revoke_all_sessions(self, *, user_id: str) -> int:
        """Revoke every session for the given user. Returns count deleted.

        Useful after a password change: the user's other devices should
        lose their sessions.
        """
        return await self._db.execute(
            "DELETE FROM sessions WHERE user_id = ?",
            (user_id,),
        )

    # ---- session management ------------------------------------------------------

    async def list_sessions(
        self,
        *,
        user_id: str,
        current_cookie_value: str | None = None,
    ) -> list[SessionInfo]:
        """Active sessions for a user's "devices" screen, newest first.

        Sessions :meth:`resolve_session` would refuse — expired, or past
        the absolute age cap — are excluded. Pass the caller's own
        session cookie as ``current_cookie_value`` to have their row
        flagged ``current=True``.
        """
        now = _now_utc()
        current_hash = (
            _hash_token(current_cookie_value) if current_cookie_value else None
        )
        rows = await self._db.fetchall(
            """
            SELECT token_sha256, created_at, expires_at, user_agent, ip
            FROM sessions
            WHERE user_id = ? AND expires_at > ?
            ORDER BY created_at DESC
            """,
            (user_id, now),
        )
        absolute_max = timedelta(
            seconds=self._settings.session_absolute_max_seconds
        )
        return [
            SessionInfo(
                id=row["token_sha256"],
                created_at=_aware(row["created_at"]),
                expires_at=_aware(row["expires_at"]),
                user_agent=row["user_agent"],
                ip=row["ip"],
                current=row["token_sha256"] == current_hash,
            )
            for row in rows
            if _aware(row["created_at"]) + absolute_max >= now
        ]

    async def revoke_session(self, *, user_id: str, session_id: str) -> bool:
        """Revoke one session by its :attr:`SessionInfo.id`.

        Scoped by owner — a user can never revoke another user's
        session, even with a leaked id. Idempotent: returns ``False``
        when nothing matched.
        """
        affected = await self._db.execute(
            "DELETE FROM sessions WHERE token_sha256 = ? AND user_id = ?",
            (session_id, user_id),
        )
        return affected > 0

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
            await tx.execute(
                "UPDATE users SET password_hash = ? WHERE id = ?",
                (new_hash, user_id),
            )
            # Revoke every session (including the caller's) — they'll
            # need to sign in again with the new password.
            await tx.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))

    # ---- password reset ----------------------------------------------------------

    async def request_password_reset(
        self,
        *,
        email: str,
        ip: str | None = None,
    ) -> tuple[User, str] | None:
        """Begin a password reset. Returns ``(user, raw_token)`` or ``None``.

        The raw token goes to the app's mailer (we never send email);
        the user completes the flow via :meth:`reset_password`. Token
        TTL comes from ``AuthSettings.password_reset_ttl_seconds``
        (default 30 minutes), and requesting again invalidates earlier
        unused reset tokens.

        ``None`` means no account matches — render the exact same
        "check your inbox" response in both cases so the endpoint can't
        be used to probe for accounts. The miss path burns the same
        token-generation cost the hit path pays, keeping response times
        aligned, and the rate limiter counts both outcomes.

        Raises :class:`RateLimited` past 3 requests/hour per email
        (scope ``pwreset``) or — when ``ip`` is given — per IP (scope
        ``pwreset:ip``), mirroring sign-in's dual-bucket defence.
        """
        email_n = _normalise_email(email)

        for scope, identifier in (("pwreset", email_n), ("pwreset:ip", ip)):
            if identifier is None:
                continue
            rl = await self._ratelimiter.check_and_increment(
                scope=scope,
                identifier=identifier,
                limit=getattr(
                    self._settings,
                    "rate_limit_password_reset_per_hour",
                    _PASSWORD_RESET_PER_HOUR,
                ),
            )
            if not rl.allowed:
                raise RateLimited(rl.retry_after_seconds)

        ttl = getattr(
            self._settings, "password_reset_ttl_seconds", _DEFAULT_PASSWORD_RESET_TTL
        )
        row = await self._db.fetchone(
            "SELECT id FROM users WHERE email = ?", (email_n,)
        )
        if row is None:
            # Unknown email: perform the SAME committed write the hit path
            # pays — an SELECT + a token UPDATE+INSERT transaction — against
            # a sentinel user id, so response timing can't reveal account
            # existence. ``revoke_existing`` means every miss reuses one
            # sentinel row (it never accumulates), and the row references no
            # real user so a consumed sentinel token resolves to nobody.
            await self._load_user_by_id(_RESET_SENTINEL_USER_ID)
            await self.tokens.issue(
                purpose=_PURPOSE_PASSWORD_RESET,
                user_id=_RESET_SENTINEL_USER_ID,
                ttl_seconds=ttl,
            )
            return None

        user = await self._load_user_by_id(row["id"])
        assert user is not None
        raw_token = await self.tokens.issue(
            purpose=_PURPOSE_PASSWORD_RESET,
            user_id=user.id,
            ttl_seconds=ttl,
        )
        return user, raw_token

    async def reset_password(self, *, raw_token: str, new_password: str) -> User:
        """Complete a password reset: burn the token, set the new hash,
        and revoke every session (whoever triggered the reset usually
        suspects the old password is in someone else's hands).

        The policy check runs *before* token consumption so a weak
        password doesn't waste the single-use token — the user can fix
        their password and submit the same link again.

        Raises :class:`InvalidToken` for an unknown, expired, used, or
        wrong-purpose token, and :class:`WeakPassword` on policy failure.
        """
        self._check_password_policy(new_password)
        claim = await self.tokens.consume(
            purpose=_PURPOSE_PASSWORD_RESET, raw_token=raw_token
        )
        if claim is None:
            raise InvalidToken()

        new_hash = self._hasher.hash(new_password)
        async with self._db.transaction() as tx:
            affected = await tx.execute(
                "UPDATE users SET password_hash = ? WHERE id = ?",
                (new_hash, claim.user_id),
            )
            if affected == 0:
                # The account vanished between issue and redeem.
                raise InvalidToken()
            await tx.execute(
                "DELETE FROM sessions WHERE user_id = ?", (claim.user_id,)
            )

        user = await self._load_user_by_id(claim.user_id)
        assert user is not None  # the UPDATE above proved the row exists
        return user

    # ---- email verification ----------------------------------------------------

    async def request_email_verification(self, *, user_id: str) -> str:
        """Mint an email-verification token for the app's mailer.

        TTL comes from ``AuthSettings.email_verify_ttl_seconds``
        (default 24 hours). The user completes the flow via
        :meth:`confirm_email`. Raises :class:`AuthError` for an unknown
        ``user_id`` — callers hold one from a live session, so a miss is
        a programming error, not an enumeration channel.
        """
        user = await self._load_user_by_id(user_id)
        if user is None:
            raise AuthError("No such user.")
        ttl = getattr(
            self._settings, "email_verify_ttl_seconds", _DEFAULT_EMAIL_VERIFY_TTL
        )
        return await self.tokens.issue(
            purpose=_PURPOSE_EMAIL_VERIFY,
            user_id=user_id,
            ttl_seconds=ttl,
        )

    async def confirm_email(self, *, raw_token: str) -> User:
        """Burn an email-verification token and stamp the user verified.

        Raises :class:`InvalidToken` for an unknown, expired, used, or
        wrong-purpose token.
        """
        claim = await self.tokens.consume(
            purpose=_PURPOSE_EMAIL_VERIFY, raw_token=raw_token
        )
        if claim is None:
            raise InvalidToken()
        await self.mark_email_verified(user_id=claim.user_id)
        user = await self._load_user_by_id(claim.user_id)
        if user is None:
            # The account vanished between issue and redeem.
            raise InvalidToken()
        return user

    async def mark_email_verified(self, *, user_id: str) -> None:
        """Stamp ``email_verified_at`` to now.

        :meth:`confirm_email` calls this for the token flow; it stays
        public for apps verifying through other channels (OAuth-linked
        addresses, admin override).
        """
        await self._db.execute(
            "UPDATE users SET email_verified_at = ? WHERE id = ?",
            (_now_utc(), user_id),
        )

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
            SELECT id, email, username, email_verified_at, created_at, plan
            FROM users WHERE id = ?
            """,
            (user_id,),
        )
        if row is None:
            return None
        return User(
            id=row["id"],
            email=row["email"],
            username=row["username"],
            email_verified_at=_aware_or_none(row["email_verified_at"]),
            created_at=_aware(row["created_at"]),
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
# pyxle-db backends return TIMESTAMP columns as timezone-aware UTC
# datetimes (backend contract rule 4); tolerate naive values as UTC
# anyway, matching the other pyxle-auth services.


def _aware(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def _aware_or_none(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return _aware(value)
