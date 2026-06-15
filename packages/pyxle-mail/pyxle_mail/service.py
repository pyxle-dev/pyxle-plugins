"""The mail service — what application code calls.

``MailService`` is the consumer-facing surface (the analogue of pyxle-db's
``Database``): it owns the configured provider and the default sender, and
turns a keyword ``send(...)`` into a validated :class:`EmailMessage` that the
provider delivers. Apps reach it as the ``mail.service`` plugin service or via
:func:`pyxle_mail.get_mail_service`.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Mapping, Sequence

from pyxle_mail.contract import MailProvider
from pyxle_mail.models import EmailMessage, SendResult
from pyxle_mail.settings import MailSettings

__all__ = ["MailService", "get_mail_service"]


class MailService:
    """Send mail through a configured provider, with sender defaults applied."""

    def __init__(self, provider: MailProvider, settings: MailSettings) -> None:
        self._provider = provider
        self._settings = settings

    @property
    def provider_name(self) -> str:
        """The active provider's name — ``"console"`` when dry-run or
        unconfigured, else ``"smtp"`` / ``"resend"`` / a community name."""
        return self._provider.name

    @property
    def settings(self) -> MailSettings:
        return self._settings

    async def send(
        self,
        *,
        to: str | Sequence[str],
        subject: str,
        html: str | None = None,
        text: str | None = None,
        from_address: str | None = None,
        from_name: str | None = None,
        reply_to: str | None = None,
        cc: str | Sequence[str] | None = None,
        bcc: str | Sequence[str] | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> SendResult:
        """Build, validate, and deliver one email.

        The sender and reply-to fall back to the configured defaults. Raises
        :class:`pyxle_mail.InvalidMessage` for a bad message and
        :class:`pyxle_mail.SendError` if the provider rejects it.
        """
        message = EmailMessage.build(
            to=to,
            subject=subject,
            html=html,
            text=text,
            from_address=from_address or self._settings.from_address,
            from_name=from_name if from_name is not None else self._settings.from_name,
            reply_to=reply_to or self._settings.reply_to,
            cc=cc,
            bcc=bcc,
            headers=headers,
        )
        return await self.send_message(message)

    async def send_message(self, message: EmailMessage) -> SendResult:
        """Deliver an already-built :class:`EmailMessage`, applying the default
        sender if it has none. Lower-level than :meth:`send`; handy when a
        caller constructs the message itself."""
        if not message.from_address and self._settings.from_address:
            message = replace(
                message,
                from_address=self._settings.from_address,
                from_name=message.from_name or self._settings.from_name,
            )
        return await self._provider.send(message)


def get_mail_service() -> MailService:
    """Django-style shortcut for the registered ``mail.service``.

    Requires ``pyxle-mail`` in ``pyxle.config.json::plugins``; raises
    ``pyxle.plugins.PluginServiceError`` otherwise.
    """
    from pyxle.plugins import plugin as _plugin

    return _plugin("mail.service")
