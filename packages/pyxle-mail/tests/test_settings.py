"""MailSettings: env/config precedence, validation, provider construction."""

from __future__ import annotations

import pytest

from pyxle_mail import ConsoleProvider, MailConfigError, MailSettings, ResendProvider, SmtpProvider


def _clear_env(monkeypatch):
    for k in list(__import__("os").environ):
        if k.startswith("PYXLE_MAIL_"):
            monkeypatch.delenv(k, raising=False)


def test_defaults_are_console(monkeypatch):
    _clear_env(monkeypatch)
    s = MailSettings.from_env()
    assert s.provider == "console" and s.dry_run is False
    assert isinstance(s.build_provider(), ConsoleProvider)


def test_config_beats_env(monkeypatch):
    _clear_env(monkeypatch)
    monkeypatch.setenv("PYXLE_MAIL_FROM", "env@x.com")
    monkeypatch.setenv("PYXLE_MAIL_PROVIDER", "console")
    s = MailSettings.from_env({"from_address": "cfg@x.com"})
    assert s.from_address == "cfg@x.com"  # config wins


def test_env_fills_what_config_omits(monkeypatch):
    _clear_env(monkeypatch)
    monkeypatch.setenv("PYXLE_MAIL_REPLY_TO", "reply@x.com")
    s = MailSettings.from_env({"from_address": "cfg@x.com"})
    assert s.reply_to == "reply@x.com"


def test_dry_run_routes_to_console_regardless(monkeypatch):
    _clear_env(monkeypatch)
    s = MailSettings.from_env({"provider": "resend", "dry_run": True, "from_address": "a@x.com"})
    assert isinstance(s.build_provider(), ConsoleProvider)


def test_smtp_provider_built(monkeypatch):
    _clear_env(monkeypatch)
    s = MailSettings.from_env({"provider": "smtp", "smtp_host": "mail.x", "from_address": "a@x.com"})
    assert isinstance(s.build_provider(), SmtpProvider)


def test_resend_provider_built(monkeypatch):
    _clear_env(monkeypatch)
    s = MailSettings.from_env({"provider": "resend", "resend_api_key": "re_k", "from_address": "a@x.com"})
    assert isinstance(s.build_provider(), ResendProvider)


def test_unknown_provider_rejected(monkeypatch):
    _clear_env(monkeypatch)
    with pytest.raises(MailConfigError):
        MailSettings.from_env({"provider": "smtps"})


def test_real_provider_requires_from(monkeypatch):
    _clear_env(monkeypatch)
    with pytest.raises(MailConfigError):
        MailSettings.from_env({"provider": "resend", "resend_api_key": "re_k"})


def test_resend_without_key_fails_at_build(monkeypatch):
    _clear_env(monkeypatch)
    s = MailSettings.from_env({"provider": "resend", "from_address": "a@x.com"})
    with pytest.raises(MailConfigError):
        s.build_provider()


def test_smtp_without_host_fails_at_build(monkeypatch):
    _clear_env(monkeypatch)
    s = MailSettings.from_env({"provider": "smtp", "from_address": "a@x.com"})
    with pytest.raises(MailConfigError):
        s.build_provider()


def test_bool_and_int_coercion_from_env(monkeypatch):
    _clear_env(monkeypatch)
    monkeypatch.setenv("PYXLE_MAIL_DRY_RUN", "yes")
    monkeypatch.setenv("PYXLE_MAIL_SMTP_PORT", "465")
    monkeypatch.setenv("PYXLE_MAIL_SMTP_SSL", "true")
    s = MailSettings.from_env()
    assert s.dry_run is True and s.smtp_port == 465 and s.smtp_use_ssl is True
