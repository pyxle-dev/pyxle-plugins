"""Resolved mail configuration, and the provider it selects.

Precedence mirrors the other Pyxle plugins: a value in the plugin's
``settings`` block of ``pyxle.config.json`` beats a ``PYXLE_MAIL_*``
environment variable beats the default. Secrets (SMTP password, Resend API
key) should come from the environment — keep them out of the committed config.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Mapping

from pyxle_mail.contract import MailProvider
from pyxle_mail.errors import MailConfigError
from pyxle_mail.providers import ConsoleProvider, ResendProvider, SmtpProvider

__all__ = ["MailSettings"]

_VALID_PROVIDERS = ("console", "smtp", "resend")

# camelCase config key -> MailSettings field.
_SETTINGS_MAP: Mapping[str, str] = {
    "fromAddress": "from_address",
    "fromName": "from_name",
    "replyTo": "reply_to",
    "provider": "provider",
    "dryRun": "dry_run",
    "smtpHost": "smtp_host",
    "smtpPort": "smtp_port",
    "smtpUsername": "smtp_username",
    "smtpPassword": "smtp_password",
    "smtpUseTls": "smtp_use_tls",
    "smtpUseSsl": "smtp_use_ssl",
    "resendApiKey": "resend_api_key",
}


def _bool(raw: Any, default: bool) -> bool:
    if raw is None:
        return default
    if isinstance(raw, bool):
        return raw
    return str(raw).strip().lower() in ("1", "true", "yes", "on")


@dataclass(frozen=True, slots=True)
class MailSettings:
    """Everything the plugin needs to build a provider and a service."""

    from_address: str | None = None
    from_name: str | None = None
    reply_to: str | None = None
    provider: str = "console"
    dry_run: bool = False
    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_username: str | None = None
    smtp_password: str | None = None
    smtp_use_tls: bool = True
    smtp_use_ssl: bool = False
    resend_api_key: str | None = None

    @classmethod
    def from_env(cls, overrides: Mapping[str, Any] | None = None) -> "MailSettings":
        """Read ``PYXLE_MAIL_*`` env vars, then let ``overrides`` (the
        translated config block) win. Validates the provider name and, for a
        real provider, that a from-address is present — failing loud here so a
        misconfigured app refuses to boot rather than dying on first send."""
        env = os.environ.get
        merged: dict[str, Any] = dict(
            from_address=env("PYXLE_MAIL_FROM"),
            from_name=env("PYXLE_MAIL_FROM_NAME"),
            reply_to=env("PYXLE_MAIL_REPLY_TO"),
            provider=(env("PYXLE_MAIL_PROVIDER") or "console").strip().lower(),
            dry_run=_bool(env("PYXLE_MAIL_DRY_RUN"), False),
            smtp_host=env("PYXLE_MAIL_SMTP_HOST"),
            smtp_port=int(env("PYXLE_MAIL_SMTP_PORT") or 587),
            smtp_username=env("PYXLE_MAIL_SMTP_USERNAME"),
            smtp_password=env("PYXLE_MAIL_SMTP_PASSWORD"),
            smtp_use_tls=_bool(env("PYXLE_MAIL_SMTP_TLS"), True),
            smtp_use_ssl=_bool(env("PYXLE_MAIL_SMTP_SSL"), False),
            resend_api_key=env("PYXLE_MAIL_RESEND_API_KEY"),
        )
        for key, value in (overrides or {}).items():
            if value is not None:
                merged[key] = value
        merged["provider"] = str(merged["provider"]).strip().lower()
        merged["dry_run"] = _bool(merged["dry_run"], False)
        merged["smtp_port"] = int(merged["smtp_port"])

        if merged["provider"] not in _VALID_PROVIDERS:
            raise MailConfigError(
                f"Unknown mail provider {merged['provider']!r}. "
                f"Use one of {', '.join(_VALID_PROVIDERS)}."
            )
        settings = cls(**merged)
        # A real provider with no From can never send a valid message.
        if settings.provider != "console" and not settings.dry_run and not settings.from_address:
            raise MailConfigError(
                f"The {settings.provider!r} provider needs a from-address. "
                "Set PYXLE_MAIL_FROM (or fromAddress in pyxle.config.json)."
            )
        return settings

    def build_provider(self) -> MailProvider:
        """Construct the configured provider. ``dry_run`` always wins, routing
        every send to the console regardless of ``provider`` — the safe switch
        for staging or a first deploy."""
        if self.dry_run or self.provider == "console":
            return ConsoleProvider()
        if self.provider == "smtp":
            if not self.smtp_host:
                raise MailConfigError(
                    "The 'smtp' provider needs a host. Set PYXLE_MAIL_SMTP_HOST."
                )
            return SmtpProvider(
                host=self.smtp_host,
                port=self.smtp_port,
                username=self.smtp_username,
                password=self.smtp_password,
                use_tls=self.smtp_use_tls,
                use_ssl=self.smtp_use_ssl,
            )
        if self.provider == "resend":
            if not self.resend_api_key:
                raise MailConfigError(
                    "The 'resend' provider needs an API key. "
                    "Set PYXLE_MAIL_RESEND_API_KEY."
                )
            return ResendProvider(api_key=self.resend_api_key)
        raise MailConfigError(f"Unknown mail provider {self.provider!r}.")  # pragma: no cover
