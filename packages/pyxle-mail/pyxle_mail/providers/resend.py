"""Resend provider — the bundled API example (extra: ``pyxle-mail[resend]``).

Talks to Resend's REST API over httpx. httpx is imported lazily so the base
install (and the SMTP/console paths) never need it; you only pull it in by
installing the ``resend`` extra. This is also the reference for how a
community API adapter (SendGrid, Mailgun, Postmark, …) is shaped.
"""

from __future__ import annotations

from pyxle_mail.errors import MailConfigError, SendError
from pyxle_mail.models import EmailMessage, SendResult

__all__ = ["ResendProvider"]

_ENDPOINT = "https://api.resend.com/emails"


class ResendProvider:
    """Deliver via Resend. Needs an API key (``re_...``); a verified sender
    domain is required by Resend for anything but their test address."""

    name = "resend"

    def __init__(self, *, api_key: str, timeout: float = 30.0) -> None:
        if not api_key:
            raise MailConfigError("ResendProvider requires an api_key.")
        self._api_key = api_key
        self._timeout = timeout

    def _payload(self, message: EmailMessage) -> dict:
        payload: dict = {
            "from": message.formatted_from(),
            "to": list(message.to),
            "subject": message.subject,
        }
        if message.html:
            payload["html"] = message.html
        if message.text:
            payload["text"] = message.text
        if message.cc:
            payload["cc"] = list(message.cc)
        if message.bcc:
            payload["bcc"] = list(message.bcc)
        if message.reply_to:
            payload["reply_to"] = message.reply_to
        if message.headers:
            payload["headers"] = dict(message.headers)
        return payload

    async def send(self, message: EmailMessage) -> SendResult:
        try:
            import httpx
        except ModuleNotFoundError as exc:  # pragma: no cover - import guard
            raise MailConfigError(
                "The Resend provider needs httpx. Install it with "
                "`pip install 'pyxle-mail[resend]'`."
            ) from exc

        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
        }
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                response = await client.post(
                    _ENDPOINT, json=self._payload(message), headers=headers
                )
        except httpx.HTTPError as exc:
            raise SendError(f"Resend request failed: {exc}", provider=self.name) from exc

        if response.status_code >= 400:
            # Resend returns a JSON {message, name} error body; surface it,
            # but never echo the Authorization header.
            detail = response.text[:500]
            raise SendError(
                f"Resend rejected the message ({response.status_code}): {detail}",
                provider=self.name,
            )

        body = response.json() if response.content else {}
        return SendResult(
            message_id=str(body.get("id", "")),
            provider=self.name,
            accepted=message.to,
        )
