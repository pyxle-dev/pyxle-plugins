"""The data a provider sends and returns — both frozen, both portable.

:class:`EmailMessage` is what every :class:`pyxle_mail.MailProvider` accepts;
:class:`SendResult` is what it returns. Neither knows anything about a
specific provider, so the same message round-trips through SMTP, Resend, or a
community adapter unchanged.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Mapping, Sequence

from pyxle_mail.errors import InvalidMessage

__all__ = ["EmailMessage", "SendResult"]

# Deliberately permissive — full RFC 5322 validation rejects valid addresses
# nobody expects. We only catch the obviously-broken so a typo fails before
# it reaches the provider, not a malformed-but-plausible address.
_ADDRESS_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _normalise_recipients(value: str | Sequence[str] | None) -> tuple[str, ...]:
    if value is None:
        return ()
    items = (value,) if isinstance(value, str) else tuple(value)
    out: list[str] = []
    for raw in items:
        addr = raw.strip()
        if not addr:
            continue
        if not _ADDRESS_RE.match(addr):
            raise InvalidMessage(f"Not a valid email address: {raw!r}")
        out.append(addr)
    return tuple(out)


@dataclass(frozen=True, slots=True)
class EmailMessage:
    """One email, provider-agnostic.

    ``to``/``cc``/``bcc`` accept a single address or a sequence. At least one
    of ``html`` or ``text`` must be present. ``from_address`` may be omitted
    here and filled from :class:`pyxle_mail.MailSettings` by the service.
    ``headers`` carries extra headers verbatim — e.g. ``List-Unsubscribe``
    for one-click unsubscribe links.
    """

    to: tuple[str, ...]
    subject: str
    html: str | None = None
    text: str | None = None
    from_address: str | None = None
    from_name: str | None = None
    reply_to: str | None = None
    cc: tuple[str, ...] = ()
    bcc: tuple[str, ...] = ()
    headers: Mapping[str, str] = field(default_factory=dict)

    @classmethod
    def build(
        cls,
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
    ) -> "EmailMessage":
        """Validate and normalise inputs into an immutable message.

        Raises :class:`pyxle_mail.InvalidMessage` for no recipient, a bad
        address, an empty subject, or a body with neither html nor text.
        """
        recipients = _normalise_recipients(to)
        if not recipients:
            raise InvalidMessage("Message has no recipient.")
        if not subject or not subject.strip():
            raise InvalidMessage("Message has no subject.")
        if not (html and html.strip()) and not (text and text.strip()):
            raise InvalidMessage("Message has no body (set html, text, or both).")
        return cls(
            to=recipients,
            subject=subject,
            html=html,
            text=text,
            from_address=(from_address.strip() if from_address else None),
            from_name=from_name,
            reply_to=(reply_to.strip() if reply_to else None),
            cc=_normalise_recipients(cc),
            bcc=_normalise_recipients(bcc),
            headers=dict(headers or {}),
        )

    def formatted_from(self) -> str:
        """``"Name <addr>"`` when a display name is set, else the bare address.
        Assumes ``from_address`` is populated (the service fills the default)."""
        if not self.from_address:
            raise InvalidMessage("Message has no from address.")
        if self.from_name:
            return f"{self.from_name} <{self.from_address}>"
        return self.from_address


@dataclass(frozen=True, slots=True)
class SendResult:
    """What a provider reports back after accepting a message.

    ``message_id`` is the provider's id (Resend's id, an SMTP Message-ID, or a
    synthetic one for the console provider). ``provider`` is the provider name.
    ``accepted`` is the recipients the provider took responsibility for.
    """

    message_id: str
    provider: str
    accepted: tuple[str, ...]
