# pyxle-auth example: sign up / sign in / dashboard

A minimal Pyxle app that wires up `pyxle-auth` end to end:

- **`request.user`** populated automatically by the session middleware
  (read in `pages/index.pyxl`'s loader).
- **`useAuth()`** client hook for live user state + `login` / `signup` /
  `logout` (`pages/login.pyxl`, `pages/register.pyxl`, `pages/index.pyxl`).
- **`require_user_page`** guarding a loader (`pages/dashboard.pyxl`), with an
  `error.pyxl` that turns the 401 into a friendly "please sign in".
- The session user is **seeded into the server render**, so the navbar shows
  the right state on the first paint — no flash of "logged out".

## Run it

From this directory, with `pyxle`, `pyxle-db`, and `pyxle-auth` installed:

```bash
pyxle dev
```

Then open http://127.0.0.1:8000:

1. **Create account** → you're signed in and redirected to the dashboard.
2. **Sign out**, then **Sign in** again with the same credentials.
3. Visit **/dashboard** while signed out → the `require_user_page` guard
   raises a 401 and `error.pyxl` offers a sign-in link.

> This example sets `"strict": false` so it runs over plain HTTP. **In
> production**, leave strict mode on (the default) and serve over HTTPS so the
> session cookie gets the `Secure` flag. Relax strict per-environment via
> `PYXLE_AUTH_STRICT=false`, never in committed config.

## What to read next

- The plugin guide: `pyxle/docs/plugins/pyxle-auth.md`
- The client hook: `pyxle/docs/reference/client-api.md` → `useAuth()`

To add **OAuth** (Google/GitHub/Discord), install `pyxle-auth[oauth]`, set
`PYXLE_AUTH_OAUTH_<PROVIDER>_CLIENT_ID/SECRET` + `PYXLE_AUTH_SECRET`, add
`"oauth": { "providers": ["google"] }` to the plugin settings, and link to
`/auth/oauth/google/start`. For **JWT** API tokens, install `pyxle-auth[jwt]`,
add `"jwt": { "accessTtlSeconds": 900 }`, and exempt `/auth/token*` from CSRF.
