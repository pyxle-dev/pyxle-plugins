# pyxle-auth

Django-grade authentication for [Pyxle](https://pyxle.dev) apps:
sessions, password reset and email verification flows, roles and
permissions, API tokens, and one-line request guards. Built on
[pyxle-db](https://github.com/pyxle-dev/pyxle-plugins/tree/main/packages/pyxle-db),
so the same code runs on SQLite, PostgreSQL, and MySQL. (Caveat: every query is portable across all three, but the *shipped schema files* target SQLite and PostgreSQL; MySQL needs a dialect-override migration — `0001-pyxle-auth-core.mysql.sql` — because MySQL requires key lengths on TEXT keys. On the roadmap; contributions welcome.)

- **Email *or* username identity** — set `identifier` to `"email"` (default)
  or `"username"`. Username mode needs no email: pick any available handle,
  case-insensitive and reserved-name guarded, with a `/username-available`
  check endpoint. (More below.)
- **Sessions** — argon2id-hashed passwords, server-side sessions with
  sliding expiry and an absolute cap, `HttpOnly; Secure; SameSite=Lax`
  cookies.
- **Password reset & email verification** — single-use, purpose-scoped,
  expiring tokens. The library never sends email; your app delivers the
  link through its own mailer.
- **RBAC** — roles, permissions, per-user grants, and
  `require_permission_*` guards.
- **API tokens** — long-lived `pyxle_pat_` personal access tokens with
  scopes, per-user caps, and revocation, for CLIs and CI.
- **Guards** — `require_user_page(request)` and friends protect a
  loader or action in one line.
- **Rate limits** — database-backed fixed-window buckets on sign-in,
  sign-up, and reset requests; they survive process restarts.

## Install

```bash
pip install pyxle-auth
```

## Quickstart

List `pyxle-db` **before** `pyxle-auth` in `pyxle.config.json` — the
auth services run on the database that plugin opens:

```json
{
  "plugins": [
    "pyxle-db",
    "pyxle-auth"
  ]
}
```

That's the whole wire-up. At startup the plugin applies its bundled
migrations (idempotent, checksum-tracked) and registers the services
listed [below](#plugin-services).

Protect a page with a guard in its `@server` loader:

```python
# pages/dashboard.pyxl — Python section
from pyxle.runtime import server
from pyxle_auth import require_user_page


@server
async def load(request):
    user = await require_user_page(request)   # 401 → error boundary when signed out
    return {"email": user.email}
```

Sign-in needs to put a `Set-Cookie` header on the response, so it lives
in an [API route](https://pyxle.dev/docs) (actions return plain JSON
payloads and can't attach cookies):

```python
# pages/api/sign_in.py
from starlette.requests import Request
from starlette.responses import JSONResponse

from pyxle_auth import AuthError, RateLimited, get_auth_service


async def endpoint(request: Request) -> JSONResponse:
    body = await request.json()
    auth = get_auth_service()
    try:
        user, cookie = await auth.sign_in(
            email=body["email"],
            password=body["password"],
            ip=request.client.host,
            user_agent=request.headers.get("user-agent", ""),
        )
    except RateLimited as exc:
        return JSONResponse(
            {"ok": False, "error": str(exc)},
            status_code=429,
            headers={"Retry-After": str(exc.retry_after_seconds)},
        )
    except AuthError as exc:
        # InvalidCredentials and friends share one deliberately vague
        # message — don't replace it with something more "helpful".
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=401)

    response = JSONResponse({"ok": True, "userId": user.id})
    response.set_cookie(**cookie.kwargs())
    return response
```

`sign_up` has the same shape. `sign_out(cookie_value=...)` returns a
cookie that clears the browser's copy — set it the same way.

## Identity model: email or username

By default users are identified by **email**, exactly as before. To build a
username-based app — pick any available handle, no email or phone — set
`identifier` to `"username"` in `pyxle.config.json`:

```json
{
  "plugins": [
    { "name": "pyxle-db", "settings": { "path": "data/app.db" } },
    { "name": "pyxle-auth", "settings": { "identifier": "username" } }
  ]
}
```

Now the credential endpoints, the `useAuth()` hook, and the services take a
`username` instead of an `email`:

```python
user, cookie = await auth.sign_up(username="ada", password="…")   # email optional
user           = await auth.verify_credentials(username="ADA", password="…")  # case-insensitive
free           = await auth.username_available("ada")             # False
```

- **Normalisation:** usernames are trimmed and lowercased, so uniqueness is
  case-insensitive on every backend (`Ada` == `ada`).
- **Policy (configurable):** `usernameMinLength` / `usernameMaxLength`
  (default 3–30), `usernamePattern` (default `^[a-z0-9_-]+$`), and a
  reserved-name block-list (≈90 system/route names like `admin`, `api`,
  `login` — override or clear it in code).
- **Availability is public** (but **per-IP rate-limited**, so it can't be used to
  bulk-scrape the user list): `GET {authPathPrefix}/username-available?u=<name>`
  returns `{"available": true|false}` so a picker can show it live. Sign-in
  stays enumeration-safe — a missing or malformed handle is just an
  `InvalidCredentials`, never a distinct error.
- **Optional email:** username mode may still accept an email at sign-up
  (e.g. for a future reset) — pass both; only the configured identifier is
  required.
- **Multiple accounts:** there's no per-person limit — anyone can register as
  many usernames as they like (tune `rateLimitSignUpPerHour` to taste).

`email` and `username` are both nullable, UNIQUE columns, so switching modes
is a config change, not a code rewrite. Existing email apps are untouched.

## Bring your own mailer

pyxle-auth never sends email. Flows that need delivery return a raw,
single-use token exactly once; your app puts it in a link and hands it
to whatever mailer it already uses:

```python
# pages/api/forgot_password.py
async def endpoint(request: Request) -> JSONResponse:
    body = await request.json()
    auth = get_auth_service()
    result = await auth.request_password_reset(
        email=body["email"], ip=request.client.host
    )
    if result is not None:
        user, token = result
        await my_mailer.send(
            to=user.email,
            subject="Reset your password",
            body=f"https://example.com/reset?token={token}",
        )
    # Same response whether the account exists or not — this endpoint
    # must not be usable to probe for accounts.
    return JSONResponse({"ok": True, "message": "Check your inbox."})
```

The user completes the flow with
`await auth.reset_password(raw_token=token, new_password=...)`, which
burns the token and revokes every session. Email verification mirrors
the pattern: `request_email_verification(user_id=...)` returns a token,
`confirm_email(raw_token=...)` redeems it. Both raise `InvalidToken`
for anything stale, used, unknown, or wrong-purpose —
indistinguishably.

For your own flows (invite links, magic links), the same machinery is
registered as `auth.tokens`: issue with a custom `purpose`, consume it
once, never store the raw value.

## Bring your own database

pyxle-auth binds to the **`db.database` plugin service**, not to the
pyxle-db package. The reference provider is pyxle-db, but any plugin (or
test fixture) that registers an object satisfying
`pyxle_db.DatabaseLike` works — an adapter over SQLAlchemy's async
engine, a bespoke driver wrapper, an in-memory fake.

The full contract a replacement must honour:

1. **Surface** — the five members of `pyxle_db.DatabaseLike`:
   `execute`, `fetchone`, `fetchall`, an async-context-manager
   `transaction()` (yielding the same query surface), and a `dialect`
   property returning a `pyxle_db.Dialect`. SQL arrives in canonical
   qmark style (`?` placeholders); rows go back as `pyxle_db.Row`.
2. **Errors** — unique-constraint violations must raise
   `pyxle_db.IntegrityError`. pyxle-auth converts it into domain
   behaviour (`AccountExists` on duplicate sign-up, idempotent role
   grants); raise your driver's own error type and those paths break.
3. **Dialect** — `dialect.name` drives portable DDL. `sqlite`,
   `postgresql`, and `mysql` have live-tested paths; any other name
   falls back to the SQLite/PostgreSQL-flavoured DDL (right for
   PostgreSQL-compatible engines, wrong for e.g. MSSQL).
4. **Datetimes** — reads return timezone-aware UTC; binds accept naive
   (assumed UTC) or aware (converted) datetimes.

`tests/test_database_contract.py` runs the entire auth lifecycle against
a wrapper that exposes *only* this surface — it is both the executable
specification and a template for writing your own adapter.

## Security properties

- **Password hashing** — argon2id, `t=3, m=64 MiB, p=2` by default
  (~300 ms on a 2020-era laptop), tunable via settings. Hashes are
  transparently upgraded on sign-in when parameters change.
- **Nothing secret at rest** — session cookies, reset/verification
  tokens, and API tokens all store only the SHA-256 of the secret. A
  leaked database cannot resurrect a session or replay a reset link.
- **Enumeration resistance** — sign-in failures share one message and
  run a dummy argon2 verify on unknown emails so timing stays flat;
  password-reset requests do token-shaped work and return the same
  shape whether the account exists or not; token redemption never says
  *why* it failed.
- **Single-use tokens** — redemption burns the token atomically, so two
  racing requests can't both succeed, and requesting a new reset link
  invalidates earlier unused ones.
- **Rate limits** — sign-in is capped per IP *and* per email (10/hour
  each), sign-up per IP (5/hour), reset requests per email and per IP
  (3/hour). Buckets live in the database and survive restarts.
- **Session lifecycle** — sliding expiry (30 days) under an absolute
  cap (90 days); password change and password reset revoke every
  session; `list_sessions`/`revoke_session` power a "your devices"
  screen.
- **Cookie posture** — `HttpOnly`, `Secure`, `SameSite=Lax` by default.
  Strict mode (the default) refuses to start with `cookie_secure=False`.

## Plugin services

| Service | Type | Use it for |
|---|---|---|
| `auth.service` | `AuthService` | Sign-up/in/out, sessions, password change/reset, email verification |
| `auth.rbac` | `RoleService` | Define roles, grant them, check permissions |
| `auth.tokens` | `TokenService` | Custom single-use token flows (invites, magic links) |
| `auth.api_tokens` | `ApiTokenService` | `pyxle_pat_` personal access tokens |
| `auth.settings` | `AuthSettings` | The resolved configuration (cookie name, TTLs, …) |

Reach them with `ctx.require(...)`, `pyxle.plugins.plugin(...)`, or the
typed helpers `get_auth_service()` / `get_auth_settings()`.

Guards resolve `auth.service` / `auth.rbac` automatically; pass
`service=` / `rbac=` explicitly in tests. For API routes authenticating
with personal access tokens, pair `bearer_token(request)` with
`ApiTokenService.resolve(raw_token=..., required_scope=...)`.

## Settings

Precedence: plugin `settings` in `pyxle.config.json` **>**
`PYXLE_AUTH_*` environment variables **>** defaults.

| Config key | Environment variable | Default | Meaning |
|---|---|---|---|
| `argonTimeCost` | `PYXLE_AUTH_ARGON_T` | `3` | Argon2 time cost |
| `argonMemoryKib` | `PYXLE_AUTH_ARGON_M` | `65536` | Argon2 memory (KiB) |
| `argonParallelism` | `PYXLE_AUTH_ARGON_P` | `2` | Argon2 parallelism |
| `passwordMinLength` | `PYXLE_AUTH_PW_MIN` | `8` | Reject shorter passwords |
| `passwordMaxLength` | — | `1024` | Reject pathological inputs |
| `sessionTtlSeconds` | `PYXLE_AUTH_SESSION_TTL` | `2592000` (30 d) | Sliding session lifetime |
| `sessionAbsoluteMaxSeconds` | `PYXLE_AUTH_SESSION_ABS_MAX` | `7776000` (90 d) | Hard cap from creation |
| `cookieName` | `PYXLE_AUTH_COOKIE_NAME` | `pyxle_session` | Session cookie name |
| `cookieSecure` | `PYXLE_AUTH_COOKIE_SECURE` | `true` | `Secure` cookie flag |
| `cookieSameSite` | `PYXLE_AUTH_COOKIE_SAMESITE` | `Lax` | `Lax` / `Strict` / `None` |
| `cookieDomain` | `PYXLE_AUTH_COOKIE_DOMAIN` | unset | Share across subdomains |
| `cookiePath` | — | `/` | Cookie path |
| `passwordResetTtlSeconds` | `PYXLE_AUTH_PASSWORD_RESET_TTL_SECONDS` | `1800` (30 min) | Reset-token lifetime |
| `emailVerifyTtlSeconds` | `PYXLE_AUTH_EMAIL_VERIFY_TTL_SECONDS` | `86400` (24 h) | Verify-token lifetime |
| `rateLimitSignInPerHour` | `PYXLE_AUTH_RL_SIGN_IN_PER_HOUR` | `10` | Per IP and per email |
| `rateLimitSignUpPerHour` | `PYXLE_AUTH_RL_SIGN_UP_PER_HOUR` | `5` | Per IP |
| `rateLimitUsernameCheckPerHour` | `PYXLE_AUTH_RL_USERNAME_CHECK_PER_HOUR` | `120` | Per IP, on `/username-available` |
| `rateLimitPasswordResetPerHour` | `PYXLE_AUTH_RATE_LIMIT_PASSWORD_RESET_PER_HOUR` | `3` | Per email and per IP |
| `requireEmailVerified` | `PYXLE_AUTH_REQUIRE_VERIFIED` | `false` | Gate sign-in on verification |
| `identifier` | `PYXLE_AUTH_IDENTIFIER` | `email` | Login identity: `email` or `username` |
| `usernameMinLength` | `PYXLE_AUTH_USERNAME_MIN` | `3` | Min username length (username mode) |
| `usernameMaxLength` | `PYXLE_AUTH_USERNAME_MAX` | `30` | Max username length (username mode) |
| `usernamePattern` | — | `^[a-z0-9_-]+$` | Allowed characters (matched after lowercasing) |
| `usernameReserved` | — | ≈90 names | Reserved-username block-list (override in code) |
| `strict` | — | `true` | Enforce `cookieSecure=true`; set `false` for HTTP dev servers |

Outside the plugin, load the same configuration with
`AuthSettings.from_env()`, and use `AuthSettings(...).for_tests()` in
test suites — it drops argon costs and TTLs so suites stay fast.

## Schema

The plugin owns its tables (`users`, `sessions`, `auth_tokens`,
`api_tokens`, `roles`, `user_roles`, `ratelimit_buckets`, plus
`oauth_identities` and `jwt_refresh_tokens` when those features are on):
bundled migrations are applied through `pyxle_db.Migrator` at startup,
followed by each service's idempotent `ensure_schema()`. Repeated startups
are no-ops. The SQL is portable qmark style throughout, so the plugin works
on every pyxle-db backend without per-database configuration.

`users.email` and `users.username` are both nullable, UNIQUE columns (an
account has whichever identifier its app configures). Migration
`0004-flexible-identity` adds `username` and relaxes `email` to nullable —
in place on PostgreSQL/MySQL, and via a session-preserving table rebuild on
SQLite — so upgrading from 0.3.x keeps every account and live session.

## Roadmap

Honest status — these are **not implemented yet**:

- Multi-factor authentication (TOTP, WebAuthn)
- "Either" identity mode (sign in with email *or* username interchangeably —
  the schema already supports it; only the resolver/UI wiring is pending)

If you need them today, the building blocks (sessions, `TokenService`,
guards) compose underneath whatever you bring; contributions are
welcome. (OAuth/OIDC sign-in and JWT access/refresh tokens shipped in 0.3.0.)

## License

MIT.
