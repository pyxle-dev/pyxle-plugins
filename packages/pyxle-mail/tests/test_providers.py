"""The three bundled providers — console, SMTP (faked), Resend (httpx mock)."""

from __future__ import annotations

import json
import smtplib

import httpx
import pytest

from pyxle_mail import (
    ConsoleProvider,
    EmailMessage,
    MailConfigError,
    ResendProvider,
    SendError,
    SmtpProvider,
)


def _msg(**over):
    base = dict(
        to="a@x.com", subject="S", html="<b>h</b>", text="t",
        from_address="hi@p.dev", from_name="Pyxle",
        headers={"List-Unsubscribe": "<https://p.dev/u?t=1>"},
    )
    base.update(over)
    return EmailMessage.build(**base)


# ── console ─────────────────────────────────────────────────────────────────


async def test_console_sends_nothing_and_logs(caplog):
    with caplog.at_level("INFO", logger="pyxle_mail"):
        r = await ConsoleProvider().send(_msg())
    assert r.provider == "console" and r.accepted == ("a@x.com",)
    assert r.message_id.startswith("console-")
    assert "not sent" in caplog.text and "a@x.com" in caplog.text


# ── smtp (stdlib faked, no server) ───────────────────────────────────────────


class _FakeSMTP:
    instances: list["_FakeSMTP"] = []

    def __init__(self, host, port, timeout=None):
        self.host, self.port = host, port
        self.calls: list = []
        self.sent = None
        _FakeSMTP.instances.append(self)

    def ehlo(self): self.calls.append("ehlo")
    def starttls(self): self.calls.append("starttls")
    def login(self, u, p): self.calls.append(("login", u, p))
    def send_message(self, mime, to_addrs=None): self.sent = (mime, to_addrs)
    def quit(self): self.calls.append("quit")
    def close(self): self.calls.append("close")


@pytest.fixture
def fake_smtp(monkeypatch):
    _FakeSMTP.instances = []
    monkeypatch.setattr(smtplib, "SMTP", _FakeSMTP)
    monkeypatch.setattr(smtplib, "SMTP_SSL", _FakeSMTP)
    return _FakeSMTP


async def test_smtp_starttls_login_and_envelope(fake_smtp):
    p = SmtpProvider(host="mail.x", port=587, username="u", password="pw", use_tls=True)
    r = await p.send(_msg(cc="c@x.com", bcc="d@x.com"))
    inst = fake_smtp.instances[0]
    assert "starttls" in inst.calls and ("login", "u", "pw") in inst.calls
    mime, to_addrs = inst.sent
    # bcc reaches the envelope but never appears as a header
    assert set(to_addrs) == {"a@x.com", "c@x.com", "d@x.com"}
    assert mime["Bcc"] is None and mime["Cc"] == "c@x.com"
    assert mime["List-Unsubscribe"] == "<https://p.dev/u?t=1>"
    assert r.provider == "smtp" and r.message_id.startswith("<")


async def test_smtp_no_starttls_when_plaintext(fake_smtp):
    await SmtpProvider(host="localhost", port=1025, use_tls=False).send(_msg())
    assert "starttls" not in fake_smtp.instances[0].calls


async def test_smtp_html_only_message(fake_smtp):
    await SmtpProvider(host="x").send(_msg(text=None))
    mime, _ = fake_smtp.instances[0].sent
    assert mime.get_content_type() == "text/html"


def test_smtp_list_unsubscribe_header_is_literal_not_encoded():
    """A long, space-less List-Unsubscribe URL must serialise verbatim, not as
    an RFC 2047 encoded-word — Gmail/Yahoo can't parse the latter and one-click
    unsubscribe silently breaks. Regression guard for the header policy."""
    url = "<https://pyxle.dev/api/unsubscribe?id=4242&token=026a3736e63abfdf9b09a68cbd411030>"
    mime, _ = SmtpProvider(host="x")._build_mime(
        _msg(headers={"List-Unsubscribe": url,
                      "List-Unsubscribe-Post": "List-Unsubscribe=One-Click"})
    )
    raw = mime.as_bytes().decode("utf-8", "replace")
    header_block = raw.split("\r\n\r\n", 1)[0]
    assert f"List-Unsubscribe: {url}" in raw
    assert "=?utf-8?q?=3C" not in header_block  # no encoded-word folding
    assert all(len(line) < 998 for line in header_block.split("\r\n"))


def test_smtp_non_ascii_text_body_encodes():
    """A text body with non-ASCII (em-dash, middle dot) must encode cleanly.

    With the header-safe policy at max_line_length=0, set_content()'s
    quoted-printable encoder raised "maxlinelen must be at least 4" for any
    non-ASCII body — the founder welcome email (em-dashes) hit this in the wild.
    Regression guard: the body round-trips and the long header stays literal."""
    body = "Hi — I built this. Reply any time · cheers."
    mime, _ = SmtpProvider(host="x")._build_mime(_msg(text=body, html="<p>hi</p>"))
    assert body in mime.get_body(preferencelist=("plain",)).get_content()
    raw = mime.as_bytes().decode("utf-8", "replace")
    assert "List-Unsubscribe: <https://p.dev/u?t=1>" in raw


async def test_smtp_wraps_failure_in_send_error(monkeypatch):
    class Boom(_FakeSMTP):
        def send_message(self, mime, to_addrs=None):
            raise smtplib.SMTPRecipientsRefused({"a@x.com": (550, b"nope")})
    monkeypatch.setattr(smtplib, "SMTP", Boom)
    with pytest.raises(SendError) as ei:
        await SmtpProvider(host="x", use_tls=False).send(_msg())
    assert ei.value.provider == "smtp"


# ── resend (httpx MockTransport, no network) ─────────────────────────────────


@pytest.fixture
def resend_mock(monkeypatch):
    captured: dict = {}
    state = {"status": 200, "body": {"id": "re_abc123"}, "raise": None}
    real_client = httpx.AsyncClient

    def handler(request: httpx.Request) -> httpx.Response:
        captured["request"] = request
        captured["json"] = json.loads(request.content)
        captured["auth"] = request.headers.get("authorization")
        if state["raise"]:
            raise state["raise"]
        return httpx.Response(state["status"], json=state["body"])

    def fake_client(**kw):
        return real_client(transport=httpx.MockTransport(handler), **kw)

    monkeypatch.setattr(httpx, "AsyncClient", fake_client)
    return captured, state


async def test_resend_success_payload_and_auth(resend_mock):
    captured, _ = resend_mock
    r = await ResendProvider(api_key="re_key").send(_msg(cc="c@x.com"))
    assert r.provider == "resend" and r.message_id == "re_abc123"
    assert captured["json"]["from"] == "Pyxle <hi@p.dev>"
    assert captured["json"]["to"] == ["a@x.com"] and captured["json"]["cc"] == ["c@x.com"]
    assert captured["json"]["headers"]["List-Unsubscribe"] == "<https://p.dev/u?t=1>"
    assert captured["auth"] == "Bearer re_key"


async def test_resend_error_status_raises_send_error(resend_mock):
    _, state = resend_mock
    state["status"], state["body"] = 422, {"message": "domain not verified", "name": "x"}
    with pytest.raises(SendError) as ei:
        await ResendProvider(api_key="re_key").send(_msg())
    assert "422" in str(ei.value) and "domain not verified" in str(ei.value)


async def test_resend_transport_error_raises_send_error(resend_mock):
    captured, state = resend_mock
    state["raise"] = httpx.ConnectError("boom")
    with pytest.raises(SendError):
        await ResendProvider(api_key="re_key").send(_msg())


def test_resend_requires_api_key():
    with pytest.raises(MailConfigError):
        ResendProvider(api_key="")
