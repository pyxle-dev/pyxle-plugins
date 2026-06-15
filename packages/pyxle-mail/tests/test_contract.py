"""The MailProvider contract — bundled and foreign objects must satisfy it."""

from __future__ import annotations

from pyxle_mail import (
    ConsoleProvider,
    EmailMessage,
    MailProvider,
    ResendProvider,
    SendResult,
    SmtpProvider,
)


def test_bundled_providers_satisfy_contract():
    assert isinstance(ConsoleProvider(), MailProvider)
    assert isinstance(SmtpProvider(host="x"), MailProvider)
    assert isinstance(ResendProvider(api_key="re_k"), MailProvider)


def test_foreign_object_satisfies_contract():
    class MyProvider:
        name = "mine"

        async def send(self, message: EmailMessage) -> SendResult:
            return SendResult(message_id="x", provider=self.name, accepted=message.to)

    assert isinstance(MyProvider(), MailProvider)


def test_object_missing_send_is_not_a_provider():
    class NotAProvider:
        name = "nope"

    assert not isinstance(NotAProvider(), MailProvider)
