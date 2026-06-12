"""Structured error types for pyxle-auth.

These are the errors a request handler is expected to branch on. Every
other failure (DB down, clock jump, etc.) surfaces as a plain
:class:`AuthError`.
"""

from __future__ import annotations


class AuthError(Exception):
    """Base class for every pyxle-auth error."""


class InvalidCredentials(AuthError):
    """Email or password was wrong, or the user doesn't exist.

    The message is deliberately indistinguishable between the two cases
    to avoid user-enumeration leaks.
    """

    def __init__(self) -> None:
        super().__init__("Invalid email or password.")


class AccountExists(AuthError):
    """Sign-up attempted with an email that already has an account."""

    def __init__(self) -> None:
        super().__init__("An account with this email already exists.")


class RateLimited(AuthError):
    """The caller exceeded a rate-limit bucket.

    ``retry_after_seconds`` is advisory — callers that want to return a
    ``Retry-After`` header on 429 can read it.
    """

    def __init__(self, retry_after_seconds: int) -> None:
        super().__init__(
            f"Too many attempts. Try again in {retry_after_seconds} seconds."
        )
        self.retry_after_seconds = retry_after_seconds


class WeakPassword(AuthError):
    """Sign-up or password-change rejected for a policy failure."""


class InvalidToken(AuthError):
    """A single-use token (password reset, email verification) was
    rejected — unknown, expired, already used, or minted for a different
    purpose. The cases are deliberately indistinguishable so a probing
    caller learns nothing from the error.
    """

    def __init__(self) -> None:
        super().__init__("This link is invalid or has expired.")


class EmailNotVerified(AuthError):
    """The account exists and the password matched, but the email
    hasn't been verified and the service requires verification.

    Raised only when ``AuthSettings.require_email_verified`` is set.
    """
