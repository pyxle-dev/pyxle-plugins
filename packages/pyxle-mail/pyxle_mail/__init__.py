"""pyxle-mail — email for Pyxle apps through one ``mail.service``.

Quickstart::

    # pyxle.config.json
    { "plugins": ["pyxle-mail"] }

    # any @action / @server / API route
    from pyxle_mail import get_mail_service

    await get_mail_service().send(
        to="user@example.com",
        subject="Welcome",
        html="<p>Glad you're here.</p>",
    )

With no config it logs instead of sending (dry-run console provider); set a
provider (SMTP or Resend, or any :class:`MailProvider`) for real delivery.
"""

from __future__ import annotations

from pyxle_mail.contract import MailProvider
from pyxle_mail.errors import InvalidMessage, MailConfigError, MailError, SendError
from pyxle_mail.models import EmailMessage, SendResult
from pyxle_mail.providers import ConsoleProvider, ResendProvider, SmtpProvider
from pyxle_mail.service import MailService, get_mail_service
from pyxle_mail.settings import MailSettings

__all__ = [
    "MailProvider",
    "MailService",
    "MailSettings",
    "EmailMessage",
    "SendResult",
    "ConsoleProvider",
    "SmtpProvider",
    "ResendProvider",
    "MailError",
    "MailConfigError",
    "InvalidMessage",
    "SendError",
    "get_mail_service",
]

__version__ = "0.1.0"
