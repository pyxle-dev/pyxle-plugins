"""Exception hierarchy for pyxle-mail.

One base (:class:`MailError`) so application code can catch everything mail
related with a single ``except``, and specific subclasses for the cases a
handler might branch on.
"""

from __future__ import annotations

__all__ = ["MailError", "MailConfigError", "InvalidMessage", "SendError"]


class MailError(Exception):
    """Base class for every pyxle-mail error."""


class MailConfigError(MailError):
    """The plugin is misconfigured — a selected provider is missing a
    credential, or required settings are absent. Raised at startup so the
    app fails loud instead of discovering it on the first send."""


class InvalidMessage(MailError):
    """The message itself is unsendable — no recipient, no body, or a
    malformed address. Raised before any provider call."""


class SendError(MailError):
    """The provider rejected the message or the transport failed. Carries
    the provider name and, when available, the underlying cause."""

    def __init__(self, message: str, *, provider: str | None = None) -> None:
        super().__init__(message)
        self.provider = provider
