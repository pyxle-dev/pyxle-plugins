"""MailService — default application, validation, and the contract surface."""

from __future__ import annotations

import pytest

from pyxle_mail import (
    EmailMessage,
    InvalidMessage,
    MailService,
    MailSettings,
    SendResult,
)


class RecordingProvider:
    name = "recording"

    def __init__(self):
        self.sent: list[EmailMessage] = []

    async def send(self, message: EmailMessage) -> SendResult:
        self.sent.append(message)
        return SendResult(message_id="rec-1", provider=self.name, accepted=message.to)


def _svc(**settings):
    base = dict(from_address="hi@p.dev", from_name="Pyxle", reply_to="r@p.dev")
    base.update(settings)
    p = RecordingProvider()
    return MailService(p, MailSettings(**base)), p


async def test_send_applies_sender_defaults():
    svc, p = _svc()
    await svc.send(to="a@x.com", subject="S", text="t")
    msg = p.sent[0]
    assert msg.from_address == "hi@p.dev" and msg.from_name == "Pyxle"
    assert msg.reply_to == "r@p.dev"


async def test_send_explicit_overrides_defaults():
    svc, p = _svc()
    await svc.send(to="a@x.com", subject="S", text="t",
                   from_address="other@p.dev", reply_to="x@p.dev")
    msg = p.sent[0]
    assert msg.from_address == "other@p.dev" and msg.reply_to == "x@p.dev"


async def test_send_validation_propagates():
    svc, _ = _svc()
    with pytest.raises(InvalidMessage):
        await svc.send(to="a@x.com", subject="S")  # no body


async def test_send_message_fills_missing_from():
    svc, p = _svc()
    raw = EmailMessage.build(to="a@x.com", subject="S", text="t")  # no from
    await svc.send_message(raw)
    assert p.sent[0].from_address == "hi@p.dev"


async def test_send_message_keeps_explicit_from():
    svc, p = _svc()
    raw = EmailMessage.build(to="a@x.com", subject="S", text="t", from_address="keep@p.dev")
    await svc.send_message(raw)
    assert p.sent[0].from_address == "keep@p.dev"


async def test_provider_name_exposed():
    svc, _ = _svc()
    assert svc.provider_name == "recording"


async def test_returns_provider_result():
    svc, _ = _svc()
    r = await svc.send(to="a@x.com", subject="S", text="t")
    assert r.message_id == "rec-1" and r.accepted == ("a@x.com",)
