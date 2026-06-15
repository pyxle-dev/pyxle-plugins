"""Live SMTP conformance — sends through a real SMTP server (e.g. Mailpit).

Skipped unless ``PYXLE_MAIL_TEST_SMTP_HOST`` is set. Locally::

    mailpit --smtp 127.0.0.1:1025 --listen 127.0.0.1:8025
    PYXLE_MAIL_TEST_SMTP_HOST=127.0.0.1 PYXLE_MAIL_TEST_SMTP_PORT=1025 pytest tests/test_live_smtp.py

If ``PYXLE_MAIL_TEST_MAILPIT_API`` is also set (e.g.
``http://127.0.0.1:8025``), the test reads the message back and asserts the
subject and the List-Unsubscribe header survived the round trip.
"""

from __future__ import annotations

import os
import uuid

import pytest

from pyxle_mail import MailService, MailSettings

HOST = os.environ.get("PYXLE_MAIL_TEST_SMTP_HOST", "")
PORT = int(os.environ.get("PYXLE_MAIL_TEST_SMTP_PORT", "1025"))
MAILPIT_API = os.environ.get("PYXLE_MAIL_TEST_MAILPIT_API", "")

pytestmark = pytest.mark.skipif(
    not HOST, reason="PYXLE_MAIL_TEST_SMTP_HOST is not set"
)


async def test_smtp_round_trip_through_real_server():
    settings = MailSettings.from_env({
        "provider": "smtp", "smtp_host": HOST, "smtp_port": PORT,
        "smtp_use_tls": False, "smtp_use_ssl": False,
        "from_address": "ci@pyxle.dev", "from_name": "Pyxle CI",
    })
    svc = MailService(settings.build_provider(), settings)

    tag = uuid.uuid4().hex
    subject = f"pyxle-mail live test {tag}"
    unsub = f"<https://pyxle.dev/unsubscribe?t={tag}>"
    result = await svc.send(
        to="subscriber@example.com",
        subject=subject,
        html=f"<p>Live test {tag}. <a href='https://pyxle.dev/u'>Unsubscribe</a></p>",
        text=f"Live test {tag}",
        headers={"List-Unsubscribe": unsub},
    )
    assert result.provider == "smtp"
    assert "subscriber@example.com" in result.accepted

    if not MAILPIT_API:
        return  # delivery asserted; skip read-back without the API

    import httpx

    async with httpx.AsyncClient(base_url=MAILPIT_API, timeout=10) as client:
        listing = (await client.get("/api/v1/search", params={"query": f"subject:{tag}"})).json()
        assert listing["messages"], f"message with tag {tag} not captured"
        msg_id = listing["messages"][0]["ID"]
        headers = (await client.get(f"/api/v1/message/{msg_id}/headers")).json()
        assert headers.get("List-Unsubscribe", [None])[0] == unsub
