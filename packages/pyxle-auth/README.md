# pyxle-auth

Email+password session auth for Pyxle apps.

## What you get

- Argon2id password hashing with sensible production parameters
  (overridable for tests).
- Server-side sessions stored in a `pyxle-db` database. Sliding
  expiration, absolute max-age, device fingerprinting hooks.
- Signed, rotation-safe, `HttpOnly; Secure; SameSite=Lax` cookies.
- Per-identifier rate limiter for sign-in / sign-up so credential
  stuffing is expensive and email-enumeration abuse is capped.
- Cookie-on, cookie-off and `with_user` request helpers so handlers
  don't need to re-parse auth on every request.

## Install

```bash
pip install pyxle-auth
```

## Minimum wire-up

```python
from pyxle_auth import AuthService, AuthSettings
from pyxle_db import connect

db = await connect("app.db", migrations_dir="migrations")
auth = AuthService(db, AuthSettings.from_env())
await auth.ensure_schema()  # no-op if migrations already include it
```

Then in a `@action`:

```python
from pyxle_auth import AuthError

@action
async def sign_in(request):
    body = await request.json()
    try:
        user, cookie = await auth.sign_in(
            email=body["email"],
            password=body["password"],
            ip=request.client.host,
            user_agent=request.headers.get("user-agent", ""),
        )
    except AuthError as exc:
        raise ActionError(str(exc))
    response = JSONResponse({"ok": True, "userId": user.id})
    response.set_cookie(**cookie.kwargs())
    return response
```

## Design notes

- Passwords are hashed with argon2id `t=3, m=65536, p=2` by default —
  ~300 ms on a 2020-era laptop. Override via `AuthSettings`.
- Session tokens are 32 random bytes (256 bits) base64url-encoded.
  The raw token is the cookie value; the row stored in the DB is the
  SHA-256 of the token, so a database leak doesn't let an attacker
  resurrect sessions.
- Rate limits are exponential-backoff friendly: every failed attempt
  extends the bucket. The limiter stores counts in the host DB so it
  survives process restarts.
- No email verification at MVP. Hook points exist via
  `AuthSettings.require_email_verified`.

## License

MIT.
