"""Bundled :class:`pyxle_mail.MailProvider` implementations."""

from __future__ import annotations

from pyxle_mail.providers.console import ConsoleProvider
from pyxle_mail.providers.resend import ResendProvider
from pyxle_mail.providers.smtp import SmtpProvider

__all__ = ["ConsoleProvider", "ResendProvider", "SmtpProvider"]
