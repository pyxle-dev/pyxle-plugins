# pyxle-mail

Email for [Pyxle](https://pyxle.dev) apps through one `mail.service`. Write
`await mail.send(...)` once; deliver it over SMTP, Resend, or any provider that
implements the `MailProvider` contract — swap providers by config, not code.
With no configuration it **logs instead of sending**, so local dev works with
zero setup.

## Install

```bash
pip install pyxle-mail                # SMTP + console need nothing else
pip install "pyxle-mail[resend]"      # + httpx, for the Resend provider
```

## Quickstart

Declare the plugin (it depends on nothing, so order doesn't matter):

```json
{ "plugins": ["pyxle-db", "pyxle-auth", "pyxle-mail"] }
```

Send from any loader, action, or API route:

```python
from pyxle_mail import get_mail_service

@action
async def invite(request):
    await get_mail_service().send(
        to="user@example.com",
        subject="You're invited",
        html="<p>Welcome aboard.</p>",
        text="Welcome aboard.",
    )
    return {"ok": True}
```

Out of the box that **logs** the email (console provider) — no account, key, or
SMTP server. Configure a provider when you want real delivery.

## Providers

| Provider | When | Needs |
|---|---|---|
| `console` | Local dev, dry-run — logs a summary, sends nothing. **The default.** | nothing |
| `smtp` | Any mail server (Gmail, Fastmail, MailHog, a corporate relay). | host (+ usually user/password) |
| `resend` | [Resend](https://resend.com) — modern transactional API. | `pyxle-mail[resend]` + API key |

A provider is just an object with a `name` and `async send(message)`. Implement
`pyxle_mail.MailProvider` to add your own (SendGrid, Mailgun, SES, Postmark, …)
and pass it in — that's how the ecosystem grows providers without touching app
code.

## Settings

Configure in `pyxle.config.json` (camelCase) or with `PYXLE_MAIL_*` environment
variables. Precedence is **config > env > default**. Keep secrets (SMTP
password, API key) in the environment, not the committed config.

| Config key | Env variable | Default | What it does |
|---|---|---|---|
| `fromAddress` | `PYXLE_MAIL_FROM` | — | Default sender. **Required** for any real provider. |
| `fromName` | `PYXLE_MAIL_FROM_NAME` | — | Optional display name. |
| `replyTo` | `PYXLE_MAIL_REPLY_TO` | — | Default `Reply-To`. |
| `provider` | `PYXLE_MAIL_PROVIDER` | `"console"` | `console` \| `smtp` \| `resend`. |
| `dryRun` | `PYXLE_MAIL_DRY_RUN` | `false` | Force the console provider regardless of `provider` — the safe switch for staging. |
| `smtpHost` | `PYXLE_MAIL_SMTP_HOST` | — | SMTP server host. |
| `smtpPort` | `PYXLE_MAIL_SMTP_PORT` | `587` | SMTP port. |
| `smtpUsername` | `PYXLE_MAIL_SMTP_USERNAME` | — | SMTP auth user. |
| `smtpPassword` | `PYXLE_MAIL_SMTP_PASSWORD` | — | SMTP auth password (**env only**). |
| `smtpUseTls` | `PYXLE_MAIL_SMTP_TLS` | `true` | STARTTLS (port 587). |
| `smtpUseSsl` | `PYXLE_MAIL_SMTP_SSL` | `false` | Implicit TLS (port 465). |
| `resendApiKey` | `PYXLE_MAIL_RESEND_API_KEY` | — | Resend API key (**env only**). |

A misconfigured real provider (e.g. `provider: "resend"` with no key, or any
real provider with no `fromAddress`) **fails loud at startup** rather than on
the first send.

### Example: Resend in production

```bash
PYXLE_MAIL_PROVIDER=resend
PYXLE_MAIL_RESEND_API_KEY=re_...
PYXLE_MAIL_FROM=hello@yourdomain.com
PYXLE_MAIL_FROM_NAME="Your App"
```

Resend requires a verified sender domain (SPF/DKIM DNS records) before it will
deliver from anything but its test address.

## Sending mail

```python
mail = get_mail_service()

result = await mail.send(
    to=["a@example.com", "b@example.com"],   # str or list
    subject="Monthly digest",
    html="<h1>Hi</h1>",
    text="Hi",                               # at least one of html/text
    reply_to="support@yourdomain.com",
    headers={"List-Unsubscribe": "<https://you/u?t=…>"},   # one-click unsubscribe
)
result.message_id  # provider's id
result.provider    # "console" | "smtp" | "resend" | …
```

Bad input raises `InvalidMessage` (no recipient, no body, bad address); a
provider rejection or transport failure raises `SendError`. Both inherit
`MailError`.

## What pyxle-mail is not

- **Not a newsletter/campaign system.** It sends transactional and one-off
  mail. Audiences, scheduling, and analytics are out of scope.
- **Not a template engine.** Pass rendered HTML/text — use your own templating
  (Pyxle components, Jinja, f-strings).
- **Not a queue.** A `send` awaits the provider. For high volume or retries,
  enqueue with a background-jobs plugin and send from the worker.

## See also

- [pyxle-auth](https://pyxle.dev/docs/plugins/pyxle-auth) — its password-reset
  and verification flows hand you a token *for your mailer*; this is that mailer.
- [Plugin standards](https://pyxle.dev/docs/plugins/standards) and the
  [directory](https://pyxle.dev/plugins).
