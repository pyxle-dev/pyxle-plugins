"""The contract a mail backend satisfies — the mail capability's interface.

This is pyxle-mail's analogue of ``pyxle_db.DatabaseLike``: the swappable
piece is the **provider**. The user-facing :class:`pyxle_mail.MailService`
wraps a provider and is what apps call; a provider is what actually puts the
message on the wire. Anything implementing :class:`MailProvider` can back the
service — the bundled SMTP/Resend/console providers, or a community adapter
for SendGrid, Mailgun, SES, Postmark, …

Implement two members:

* ``name`` — a short identifier (``"smtp"``, ``"resend"``, …), used in logs
  and :class:`pyxle_mail.SendResult`.
* ``async def send(message) -> SendResult`` — deliver one
  :class:`pyxle_mail.EmailMessage`, or raise :class:`pyxle_mail.SendError`
  on rejection/transport failure. The message's ``from_address`` is already
  populated by the service.

The protocol is ``runtime_checkable``, so ``isinstance(obj, MailProvider)``
verifies member presence (signatures are checked statically only).
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from pyxle_mail.models import EmailMessage, SendResult

__all__ = ["MailProvider"]


@runtime_checkable
class MailProvider(Protocol):
    """The interface every mail backend implements."""

    name: str

    async def send(self, message: EmailMessage) -> SendResult: ...
