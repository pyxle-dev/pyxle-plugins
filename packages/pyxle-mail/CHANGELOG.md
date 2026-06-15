# Changelog

All notable changes to `pyxle-mail` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-06-12

### Added

- First release. One `mail.service` over a swappable `MailProvider` contract.
- Bundled providers: **console** (logs instead of sending — the zero-config
  default and what `dryRun` swaps in), **SMTP** (stdlib, no extra deps, run off
  the event loop), and **Resend** (`pyxle-mail[resend]`, the bundled API example).
- `MailService.send(...)` with sender defaults, `EmailMessage`/`SendResult`
  models, and library-agnostic validation.
- `MailProvider` protocol (runtime-checkable) — the mail capability's interface;
  community adapters (SendGrid, Mailgun, SES, Postmark, …) implement it.
- Settings via `pyxle.config.json` (camelCase) or `PYXLE_MAIL_*` env, precedence
  config > env > default; fail-loud at startup on a misconfigured provider.
- `get_mail_service()` Django-style shortcut.
