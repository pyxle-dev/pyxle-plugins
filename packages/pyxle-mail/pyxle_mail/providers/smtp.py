"""SMTP provider — works with any mail server, zero extra dependencies.

Uses the stdlib ``smtplib`` (which is blocking) inside ``asyncio.to_thread``
so it never stalls the event loop. Supports the three common transport modes:
implicit TLS (port 465), STARTTLS (port 587), and plaintext (dev servers like
MailHog on 1025).
"""

from __future__ import annotations

import asyncio
import email.policy
import smtplib
import uuid
from email.message import EmailMessage as _MimeMessage
from email.utils import format_datetime, make_msgid
from datetime import datetime, timezone

from pyxle_mail.errors import SendError
from pyxle_mail.models import EmailMessage, SendResult

__all__ = ["SmtpProvider"]

# SMTP line endings (CRLF) with the wrap length raised to the RFC 5322 998-octet
# hard limit. The default 78-char wrap has no whitespace to fold a long header on
# — List-Unsubscribe's <https://…?token=…> — so the stdlib falls back to RFC 2047
# encoded-words to break the line, producing an encoded List-Unsubscribe that
# Gmail/Yahoo can't parse (silently breaking one-click unsubscribe). A high limit
# keeps our short headers verbatim.
#
# We deliberately do NOT use max_line_length=0 ("never wrap"): that value also
# reaches set_content()'s quoted-printable body encoder, which rejects a line
# length below 4 — so any non-ASCII text body (an em-dash, a "·") raised
# "ValueError: maxlinelen must be at least 4". 998 satisfies both the header and
# the body encoder.
_HEADER_SAFE_POLICY = email.policy.SMTP.clone(max_line_length=998)


class SmtpProvider:
    """Deliver via an SMTP server.

    Parameters mirror what every SMTP host documents: ``host``/``port``,
    optional ``username``/``password``, and the transport mode. With
    ``use_ssl`` the connection is TLS from the start (465); otherwise
    ``use_tls`` upgrades via STARTTLS (587). Leave both false only for a local
    plaintext dev server.
    """

    name = "smtp"

    def __init__(
        self,
        *,
        host: str,
        port: int = 587,
        username: str | None = None,
        password: str | None = None,
        use_tls: bool = True,
        use_ssl: bool = False,
        timeout: float = 30.0,
    ) -> None:
        self._host = host
        self._port = port
        self._username = username
        self._password = password
        self._use_tls = use_tls
        self._use_ssl = use_ssl
        self._timeout = timeout

    def _build_mime(self, message: EmailMessage) -> tuple[_MimeMessage, str]:
        mime = _MimeMessage(policy=_HEADER_SAFE_POLICY)
        mime["From"] = message.formatted_from()
        mime["To"] = ", ".join(message.to)
        if message.cc:
            mime["Cc"] = ", ".join(message.cc)
        mime["Subject"] = message.subject
        if message.reply_to:
            mime["Reply-To"] = message.reply_to
        mime["Date"] = format_datetime(datetime.now(timezone.utc))
        msg_id = make_msgid()
        mime["Message-ID"] = msg_id
        for key, value in message.headers.items():
            mime[key] = value

        # text first, html second — receivers render the last part they can.
        if message.text:
            mime.set_content(message.text)
            if message.html:
                mime.add_alternative(message.html, subtype="html")
        else:
            mime.set_content(message.html or "", subtype="html")
        return mime, msg_id

    def _send_blocking(self, mime: _MimeMessage, all_recipients: list[str]) -> None:
        if self._use_ssl:
            smtp: smtplib.SMTP = smtplib.SMTP_SSL(self._host, self._port, timeout=self._timeout)
        else:
            smtp = smtplib.SMTP(self._host, self._port, timeout=self._timeout)
        try:
            smtp.ehlo()
            if self._use_tls and not self._use_ssl:
                smtp.starttls()
                smtp.ehlo()
            if self._username:
                smtp.login(self._username, self._password or "")
            smtp.send_message(mime, to_addrs=all_recipients)
        finally:
            try:
                smtp.quit()
            except smtplib.SMTPException:
                smtp.close()

    async def send(self, message: EmailMessage) -> SendResult:
        mime, msg_id = self._build_mime(message)
        # bcc recipients are passed to the envelope but never written as a header.
        all_recipients = list(message.to) + list(message.cc) + list(message.bcc)
        try:
            await asyncio.to_thread(self._send_blocking, mime, all_recipients)
        except (smtplib.SMTPException, OSError) as exc:
            raise SendError(f"SMTP delivery failed: {exc}", provider=self.name) from exc
        return SendResult(
            message_id=msg_id or f"smtp-{uuid.uuid4().hex}",
            provider=self.name,
            accepted=tuple(all_recipients),
        )
