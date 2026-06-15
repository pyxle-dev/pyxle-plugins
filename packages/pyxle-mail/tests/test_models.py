"""EmailMessage validation/normalisation and SendResult."""

from __future__ import annotations

import pytest

from pyxle_mail import EmailMessage, InvalidMessage, SendResult


def test_build_normalises_recipients_and_strips():
    m = EmailMessage.build(
        to=["  a@x.com ", "b@x.com"], subject="Hi", text="t",
        cc="c@x.com", bcc=("d@x.com",),
    )
    assert m.to == ("a@x.com", "b@x.com")
    assert m.cc == ("c@x.com",) and m.bcc == ("d@x.com",)


def test_build_accepts_single_string_recipient():
    assert EmailMessage.build(to="a@x.com", subject="s", html="<p>x</p>").to == ("a@x.com",)


@pytest.mark.parametrize("kwargs", [
    dict(to="", subject="s", text="t"),                 # no recipient
    dict(to="   ", subject="s", text="t"),              # blank recipient
    dict(to="a@x.com", subject="", text="t"),           # no subject
    dict(to="a@x.com", subject="  ", text="t"),         # blank subject
    dict(to="a@x.com", subject="s"),                    # no body
    dict(to="a@x.com", subject="s", html="  ", text=""),  # empty body
    dict(to="not-an-email", subject="s", text="t"),     # bad address
    dict(to="a@x.com", subject="s", text="t", cc="also-bad"),  # bad cc
])
def test_build_rejects_invalid(kwargs):
    with pytest.raises(InvalidMessage):
        EmailMessage.build(**kwargs)


def test_formatted_from_with_and_without_name():
    m = EmailMessage.build(to="a@x.com", subject="s", text="t",
                           from_address="hi@p.dev", from_name="Pyxle")
    assert m.formatted_from() == "Pyxle <hi@p.dev>"
    m2 = EmailMessage.build(to="a@x.com", subject="s", text="t", from_address="hi@p.dev")
    assert m2.formatted_from() == "hi@p.dev"


def test_formatted_from_without_address_raises():
    with pytest.raises(InvalidMessage):
        EmailMessage.build(to="a@x.com", subject="s", text="t").formatted_from()


def test_message_is_frozen():
    m = EmailMessage.build(to="a@x.com", subject="s", text="t")
    with pytest.raises(Exception):
        m.subject = "changed"  # type: ignore[misc]


def test_send_result_fields():
    r = SendResult(message_id="id-1", provider="console", accepted=("a@x.com",))
    assert (r.message_id, r.provider, r.accepted) == ("id-1", "console", ("a@x.com",))
