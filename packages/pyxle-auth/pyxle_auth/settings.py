"""Configuration for pyxle-auth.

Every tunable is a field on :class:`AuthSettings`. Production apps use
:meth:`AuthSettings.from_env` to pull values from the process
environment; tests construct directly with weaker params so the suite
doesn't spend half a second hashing passwords per test.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, replace
from typing import Any, Mapping

from ._identity import DEFAULT_RESERVED_USERNAMES


# ---------------------------------------------------------------------------
# Cookie defaults
#
# ``SameSite=Lax`` is the safe default: it stops a third-party site from
# issuing a cross-site request with the cookie attached, while still
# allowing top-level navigation (so clicking a link from GitHub to
# Pyxle Cloud keeps the user logged in). ``None`` is only useful for
# embedded cross-site flows we don't support at MVP.


@dataclass(frozen=True, slots=True)
class AuthSettings:
    """Knobs for an :class:`AuthService`.

    Production defaults are conservative. Override for tests or for
    service tiers that need different session lifetimes.

    Attributes:
        argon_time_cost: Argon2 ``t`` parameter. Higher = slower = safer.
        argon_memory_kib: Argon2 ``m`` parameter (memory, KiB).
        argon_parallelism: Argon2 ``p`` parameter.
        password_min_length: Passwords below this are rejected at sign-up.
        password_max_length: Reject pathological inputs. Argon2 itself
            imposes no upper limit but an oversized POST body is suspect.
        session_lifetime_seconds: Cookie Max-Age and DB expires_at.
        session_absolute_max_seconds: Hard cap from the creation time; a
            session is refused once it exceeds this even if the sliding
            lifetime would extend it.
        cookie_name: The cookie carrying the session token.
        cookie_secure: Set ``Secure`` on the cookie. Force ``True`` in prod.
        cookie_samesite: ``Lax`` (default), ``Strict``, or ``None``.
        cookie_domain: ``None`` to bind to the current host only, or a
            domain string to share across subdomains (e.g. ``.pyxle.app``).
        auth_path_prefix: URL prefix the session middleware serves its
            endpoints under. Default ``/auth``.
        enable_credentials_api: Serve ``POST {prefix}/login`` and
            ``POST {prefix}/signup``. Default ``True``.
        enable_signup: Serve ``POST {prefix}/signup`` (and, for username
            identity, ``GET {prefix}/username-available``). Default ``True``.
            Set ``False`` for an invite-only or single-operator app: sign-in
            keeps working, self-registration does not.
        password_reset_ttl_seconds: Lifetime of a password-reset token.
            Short by design — the link sits in an inbox.
        email_verify_ttl_seconds: Lifetime of an email-verification token.
            Generous (a day) — verification is low-risk and users dawdle.
        rate_limit_sign_in_per_hour: Attempts per identifier+scope.
        rate_limit_sign_up_per_hour: Same, for sign-up.
        rate_limit_password_reset_per_hour: Reset requests per identifier.
            Low cap — each request emails the account owner.
        require_email_verified: If True, sign-in rejects unverified users.
    """

    # Argon2id parameters
    argon_time_cost: int = 3
    argon_memory_kib: int = 65536
    argon_parallelism: int = 2

    # Password policy
    password_min_length: int = 8
    password_max_length: int = 1024

    # Session lifetime
    session_lifetime_seconds: int = 60 * 60 * 24 * 30        # 30 days sliding
    session_absolute_max_seconds: int = 60 * 60 * 24 * 90    # 90 days absolute

    # Cookie attributes
    cookie_name: str = "pyxle_session"
    cookie_secure: bool = True
    cookie_samesite: str = "Lax"
    cookie_domain: str | None = None
    cookie_path: str = "/"

    # URL prefix under which AuthSessionMiddleware serves its endpoints
    # (``{prefix}/me``, ``{prefix}/login``, ``{prefix}/signup``,
    # ``{prefix}/logout``). Configurable so an app that already owns ``/auth``
    # pages can move them aside.
    auth_path_prefix: str = "/auth"

    # Whether the session middleware serves the credential endpoints
    # ``POST {prefix}/login`` and ``POST {prefix}/signup``. On by default
    # (batteries-included; the client ``useAuth`` hook calls them). Turn off
    # to roll your own sign-in/sign-up actions — ``/me`` and ``/logout`` stay
    # available either way.
    enable_credentials_api: bool = True

    # Whether ``POST {prefix}/signup`` is served. Independent of the flag above
    # so an app can keep sign-in while closing self-registration — an
    # invite-only tool, an internal dashboard, a status page whose only
    # accounts are its operators. Turning the credentials API off disables
    # signup regardless; this narrows it without taking login with it.
    enable_signup: bool = True

    # Token lifetimes (password reset / email verification)
    password_reset_ttl_seconds: int = 1800       # 30 minutes
    email_verify_ttl_seconds: int = 86400        # 24 hours

    # Rate limits
    rate_limit_sign_in_per_hour: int = 10
    rate_limit_sign_up_per_hour: int = 5
    rate_limit_password_reset_per_hour: int = 3
    # Per-IP cap on the public username-availability endpoint. Generous enough
    # for a debounced "as you type" picker, tight enough to make bulk
    # enumeration of the user list impractical.
    rate_limit_username_check_per_hour: int = 120

    # Email verification
    require_email_verified: bool = False

    # ---- Identity model ----------------------------------------------------
    # Which credential identifies a user at sign-in.
    #   "email"    (default) — the historical behaviour; every existing app is
    #              unaffected. Sign-up/sign-in take an email; verification and
    #              password-reset flows are available.
    #   "username" — a unique, lowercase username is the credential. No email
    #              is required (apps may still collect one optionally, e.g. for
    #              future reset); email verification / reset simply go unused.
    # The schema carries both columns (each UNIQUE, nullable) so this is a pure
    # config switch, and leaves room for a future "either" (login with either)
    # mode without another migration.
    identifier: str = "email"

    # Username policy — consulted whenever a username is validated (sign-up in
    # username mode, or any app that collects a username). Usernames are
    # lowercase-normalised, so uniqueness is case-insensitive on every backend.
    username_min_length: int = 3
    username_max_length: int = 30
    username_pattern: str = r"^[a-z0-9_-]+$"
    username_reserved: frozenset[str] = DEFAULT_RESERVED_USERNAMES

    # Whether we're in a strict production posture. Currently only
    # enforces ``cookie_secure=True`` at construction time.
    strict: bool = True

    def __post_init__(self) -> None:
        if self.session_absolute_max_seconds < self.session_lifetime_seconds:
            raise ValueError(
                "session_absolute_max_seconds must be >= session_lifetime_seconds"
            )
        if self.cookie_samesite not in ("Lax", "Strict", "None"):
            raise ValueError(
                f"cookie_samesite must be Lax/Strict/None, got {self.cookie_samesite!r}"
            )
        if self.cookie_samesite == "None" and not self.cookie_secure:
            raise ValueError(
                "SameSite=None requires Secure=True; browsers drop the cookie otherwise"
            )
        if (
            not self.auth_path_prefix.startswith("/")
            or len(self.auth_path_prefix) < 2
            or self.auth_path_prefix.endswith("/")
        ):
            raise ValueError(
                "auth_path_prefix must be an absolute path with no trailing "
                f'slash (e.g. "/auth"), got {self.auth_path_prefix!r}'
            )
        if self.strict and not self.cookie_secure:
            raise ValueError(
                "cookie_secure must be True in strict mode. "
                "Set strict=False for tests."
            )
        if self.password_reset_ttl_seconds <= 0:
            raise ValueError("password_reset_ttl_seconds must be positive")
        if self.email_verify_ttl_seconds <= 0:
            raise ValueError("email_verify_ttl_seconds must be positive")
        if self.rate_limit_password_reset_per_hour <= 0:
            raise ValueError("rate_limit_password_reset_per_hour must be positive")
        if self.password_max_length <= self.password_min_length:
            raise ValueError("password_max_length must exceed password_min_length")
        if self.identifier not in ("email", "username"):
            raise ValueError(
                f'identifier must be "email" or "username", got {self.identifier!r}'
            )
        if self.username_min_length < 1:
            raise ValueError("username_min_length must be >= 1")
        if self.username_max_length < self.username_min_length:
            raise ValueError(
                "username_max_length must be >= username_min_length"
            )
        # Fail loud at boot on an invalid username_pattern instead of crashing
        # on the first sign-up (or the public availability endpoint) with a
        # raw re.error. (A catastrophic-backtracking pattern is a config-author
        # footgun, not an attacker vector — the pattern is never user input.)
        try:
            re.compile(self.username_pattern)
        except re.error as exc:
            raise ValueError(
                f"username_pattern is not a valid regular expression: {exc}"
            ) from exc
        if self.rate_limit_username_check_per_hour <= 0:
            raise ValueError("rate_limit_username_check_per_hour must be positive")
        # Argon2 strength floors (OWASP argon2id guidance). Enforced only in
        # strict mode so for_tests() can use fast/weak parameters; a real
        # deployment with a fat-fingered PYXLE_AUTH_ARGON_* env fails loudly
        # at startup instead of silently shipping weak hashing.
        if self.strict:
            if self.argon_time_cost < 2:
                raise ValueError("argon_time_cost must be >= 2 in strict mode")
            if self.argon_memory_kib < 19456:
                raise ValueError(
                    "argon_memory_kib must be >= 19456 (19 MiB, OWASP minimum) "
                    "in strict mode"
                )
            if self.argon_parallelism < 1:
                raise ValueError("argon_parallelism must be >= 1")

    # ---- loaders ---------------------------------------------------------------

    @classmethod
    def from_env(
        cls,
        *,
        strict: bool = True,
        overrides: Mapping[str, Any] | None = None,
    ) -> "AuthSettings":
        """Read overrides from the environment. Missing keys use defaults.

        ``overrides`` maps field names to values that beat the
        environment — the pyxle-auth plugin passes the (translated)
        ``pyxle.config.json`` settings here, so config wins over env.
        The merged result is validated once, in ``__post_init__``.
        """

        def _int(key: str, default: int) -> int:
            raw = os.environ.get(key)
            if raw is None:
                return default
            return int(raw)

        def _bool(key: str, default: bool) -> bool:
            raw = os.environ.get(key)
            if raw is None:
                return default
            return raw.strip().lower() in ("1", "true", "yes", "on")

        cookie_secure = _bool("PYXLE_AUTH_COOKIE_SECURE", strict)
        cookie_domain = os.environ.get("PYXLE_AUTH_COOKIE_DOMAIN") or None

        kwargs: dict[str, Any] = dict(
            argon_time_cost=_int("PYXLE_AUTH_ARGON_T", 3),
            argon_memory_kib=_int("PYXLE_AUTH_ARGON_M", 65536),
            argon_parallelism=_int("PYXLE_AUTH_ARGON_P", 2),
            password_min_length=_int("PYXLE_AUTH_PW_MIN", 8),
            session_lifetime_seconds=_int(
                "PYXLE_AUTH_SESSION_TTL", 60 * 60 * 24 * 30
            ),
            session_absolute_max_seconds=_int(
                "PYXLE_AUTH_SESSION_ABS_MAX", 60 * 60 * 24 * 90
            ),
            cookie_name=os.environ.get("PYXLE_AUTH_COOKIE_NAME", "pyxle_session"),
            cookie_secure=cookie_secure,
            cookie_samesite=os.environ.get("PYXLE_AUTH_COOKIE_SAMESITE", "Lax"),
            cookie_domain=cookie_domain,
            auth_path_prefix=os.environ.get("PYXLE_AUTH_PATH_PREFIX", "/auth"),
            enable_credentials_api=_bool(
                "PYXLE_AUTH_ENABLE_CREDENTIALS_API", True
            ),
            enable_signup=_bool("PYXLE_AUTH_ENABLE_SIGNUP", True),
            password_reset_ttl_seconds=_int(
                "PYXLE_AUTH_PASSWORD_RESET_TTL_SECONDS", 1800
            ),
            email_verify_ttl_seconds=_int(
                "PYXLE_AUTH_EMAIL_VERIFY_TTL_SECONDS", 86400
            ),
            rate_limit_sign_in_per_hour=_int(
                "PYXLE_AUTH_RL_SIGN_IN_PER_HOUR", 10
            ),
            rate_limit_sign_up_per_hour=_int(
                "PYXLE_AUTH_RL_SIGN_UP_PER_HOUR", 5
            ),
            rate_limit_username_check_per_hour=_int(
                "PYXLE_AUTH_RL_USERNAME_CHECK_PER_HOUR", 120
            ),
            rate_limit_password_reset_per_hour=_int(
                "PYXLE_AUTH_RATE_LIMIT_PASSWORD_RESET_PER_HOUR", 3
            ),
            require_email_verified=_bool("PYXLE_AUTH_REQUIRE_VERIFIED", False),
            identifier=(
                os.environ.get("PYXLE_AUTH_IDENTIFIER", "email").strip().lower()
                or "email"
            ),
            username_min_length=_int("PYXLE_AUTH_USERNAME_MIN", 3),
            username_max_length=_int("PYXLE_AUTH_USERNAME_MAX", 30),
            strict=strict,
        )
        if overrides:
            kwargs.update(overrides)
        return cls(**kwargs)

    def for_tests(self) -> "AuthSettings":
        """Return a copy tuned for fast tests — weak argon, insecure
        cookie, short token TTLs."""
        return replace(
            self,
            argon_time_cost=1,
            argon_memory_kib=8,
            argon_parallelism=1,
            cookie_secure=False,
            password_reset_ttl_seconds=60,
            email_verify_ttl_seconds=60,
            strict=False,
        )
