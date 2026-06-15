"""The zero-config provider: log the message, send nothing.

This is the default when no provider is configured, and what ``dry_run`` swaps
in. It mirrors how pyxle-db treats SQLite — the lazy path just works, so an
app developing locally sees its emails in the server log without an account,
API key, or SMTP server. Never use it in production (it delivers nothing).
"""

from __future__ import annotations

import logging
import uuid

from pyxle_mail.models import EmailMessage, SendResult

__all__ = ["ConsoleProvider"]

_logger = logging.getLogger("pyxle_mail")


class ConsoleProvider:
    """Logs a one-line summary and a body preview; delivers nothing."""

    name = "console"

    def __init__(self, *, body_preview_chars: int = 280) -> None:
        self._preview = body_preview_chars

    async def send(self, message: EmailMessage) -> SendResult:
        body = (message.text or message.html or "").strip().replace("\n", " ")
        preview = body[: self._preview] + ("…" if len(body) > self._preview else "")
        recipients = ", ".join(message.to)
        _logger.info(
            "[pyxle-mail:console] (not sent) to=%s | from=%s | subject=%s | %s",
            recipients,
            message.from_address or "<unset>",
            message.subject,
            preview,
        )
        return SendResult(
            message_id=f"console-{uuid.uuid4().hex}",
            provider=self.name,
            accepted=message.to,
        )
