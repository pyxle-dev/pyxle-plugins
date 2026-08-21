# Changelog

All notable changes to `pyxle-mail` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- The plugin now logs a `WARNING` at startup when it falls back to the `console`
  provider because nothing was configured. That provider accepts every message
  and delivers none of it; the only previous trace was an `INFO` line, which sits
  below the root logger's default level and so never appeared in production. An
  explicit `dryRun` stays quiet, since that is a deliberate choice.

### Changed

- `__version__` and the plugin's `version` are read from installed distribution
  metadata instead of restated in source, so they cannot drift from
  `pyproject.toml`.

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
