"""Configuration for pyxle-auth.

Every tunable is a field on :class:`AuthSettings`. Production apps use
:meth:`AuthSettings.from_env` to pull values from the process
environment; tests construct directly with weaker params so the suite
doesn't spend half a second hashing passwords per test.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field, replace


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
        rate_limit_sign_in_per_hour: Attempts per identifier+scope.
        rate_limit_sign_up_per_hour: Same, for sign-up.
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

    # Rate limits
    rate_limit_sign_in_per_hour: int = 10
    rate_limit_sign_up_per_hour: int = 5

    # Email verification
    require_email_verified: bool = False

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
        if self.strict and not self.cookie_secure:
            raise ValueError(
                "cookie_secure must be True in strict mode. "
                "Set strict=False for tests."
            )

    # ---- loaders ---------------------------------------------------------------

    @classmethod
    def from_env(cls, *, strict: bool = True) -> "AuthSettings":
        """Read overrides from the environment. Missing keys use defaults."""

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

        return cls(
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
            rate_limit_sign_in_per_hour=_int(
                "PYXLE_AUTH_RL_SIGN_IN_PER_HOUR", 10
            ),
            rate_limit_sign_up_per_hour=_int(
                "PYXLE_AUTH_RL_SIGN_UP_PER_HOUR", 5
            ),
            require_email_verified=_bool("PYXLE_AUTH_REQUIRE_VERIFIED", False),
            strict=strict,
        )

    def for_tests(self) -> "AuthSettings":
        """Return a copy tuned for fast tests — weak argon, insecure cookie."""
        return replace(
            self,
            argon_time_cost=1,
            argon_memory_kib=8,
            argon_parallelism=1,
            cookie_secure=False,
            strict=False,
        )
