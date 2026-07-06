"""Pyxle plugin entry point for ``pyxle-auth``.

Depends on ``pyxle-db`` being listed BEFORE this plugin in the host
app's :mod:`pyxle.config` ``plugins`` array — every auth service runs
on the :class:`pyxle_db.Database` that plugin registers.

Registered services:

* ``auth.service`` — :class:`AuthService`: sign-up, sign-in, session
  resolution, password change/reset, email verification.
* ``auth.rbac`` — :class:`RoleService`: roles, permissions, grants.
* ``auth.tokens`` — :class:`TokenService`: single-use purpose-scoped
  tokens for app-defined flows (invite links, magic links).
* ``auth.api_tokens`` — :class:`ApiTokenService`: ``pyxle_pat_``
  personal access tokens with scopes.
* ``auth.settings`` — the resolved :class:`AuthSettings`, the same
  source of truth the services read.

The plugin also contributes :class:`pyxle_auth.middleware.AuthSessionMiddleware`,
which populates ``request.user`` on every request and serves the
``{authPathPrefix}/me``, ``/login``, ``/signup``, and ``/logout`` endpoints the
client ``useAuth`` hook talks to (``/login`` + ``/signup`` are gated by
``enableCredentialsApi``).

Config shape::

    {
      "plugins": [
        "pyxle-db",
        {
          "name": "pyxle-auth",
          "settings": {
            "cookieDomain": ".pyxle.app",
            "sessionTtlSeconds": 2592000,
            "passwordResetTtlSeconds": 1800,
            "requireEmailVerified": true
          }
        }
      ]
    }

Settings precedence: a key set in the plugin ``settings`` dict beats
the corresponding ``PYXLE_AUTH_*`` environment variable, which beats
the built-in default. All keys are optional:

* ``cookieName`` — session cookie name. Default ``pyxle_session``.
* ``cookieDomain`` — e.g. ``.pyxle.app``. Default unset (host-bound).
* ``cookieSecure`` — ``True`` in production. Default ``True`` (strict).
* ``cookieSameSite`` — ``Lax`` / ``Strict`` / ``None``. Default ``Lax``.
* ``cookiePath`` — cookie path. Default ``/``.
* ``authPathPrefix`` — URL prefix the session middleware serves its
  endpoints under. Default ``/auth``.
* ``enableCredentialsApi`` — serve ``POST {prefix}/login`` and
  ``POST {prefix}/signup``. Default ``True``.
* ``sessionTtlSeconds`` — sliding session lifetime. Default 30d.
* ``sessionAbsoluteMaxSeconds`` — hard cap. Default 90d.
* ``passwordResetTtlSeconds`` — reset-token lifetime. Default 1800.
* ``emailVerifyTtlSeconds`` — verify-token lifetime. Default 86400.
* ``requireEmailVerified`` — gate sign-in on verified email. Default ``False``.
* ``rateLimitSignInPerHour`` — per-identifier cap. Default 10.
* ``rateLimitSignUpPerHour`` — per-IP cap. Default 5.
* ``rateLimitPasswordResetPerHour`` — per-identifier cap. Default 3.
* ``passwordMinLength`` / ``passwordMaxLength`` — policy bounds.
* ``argonTimeCost`` / ``argonMemoryKib`` / ``argonParallelism`` — hashing cost.
* ``strict`` — if ``False``, relax the "secure cookie required"
  invariant so dev servers work over plain HTTP. Default ``True``.

Schema management: the plugin applies the migrations bundled with the
package (``pyxle_auth/migrations``) through :class:`pyxle_db.Migrator`,
then calls every service's idempotent ``ensure_schema()`` as
belt-and-braces — a database created by an older release still gains
any table the migration history predates.
"""

from __future__ import annotations

import logging
import os
import secrets
from pathlib import Path
from typing import Any, Mapping, Protocol, Sequence

from pyxle.plugins import PluginContext, PluginServiceError, PyxlePlugin

from pyxle_db import DatabaseLike, Migrator

from pyxle_auth.api_tokens import ApiTokenService
from pyxle_auth.rbac import RoleService
from pyxle_auth.service import AuthService
from pyxle_auth.settings import AuthSettings
from pyxle_auth.tokens import TokenService


_logger = logging.getLogger("pyxle_auth.plugin")


# Migrations shipped inside the wheel. Module-level so tests can point
# the plugin at a fixture directory.
_MIGRATIONS_DIR = Path(__file__).resolve().parent / "migrations"


# Map ``pyxle.config.json`` camelCase settings keys to the
# :class:`AuthSettings` snake_case fields. Kept as a table so the
# translation layer is declarative — adding a new field is a one-line
# edit here and the plugin picks it up.
_SETTINGS_MAP: Mapping[str, str] = {
    "argonTimeCost": "argon_time_cost",
    "argonMemoryKib": "argon_memory_kib",
    "argonParallelism": "argon_parallelism",
    "passwordMinLength": "password_min_length",
    "passwordMaxLength": "password_max_length",
    "sessionTtlSeconds": "session_lifetime_seconds",
    "sessionAbsoluteMaxSeconds": "session_absolute_max_seconds",
    "cookieName": "cookie_name",
    "cookieSecure": "cookie_secure",
    "cookieSameSite": "cookie_samesite",
    "cookieDomain": "cookie_domain",
    "cookiePath": "cookie_path",
    "authPathPrefix": "auth_path_prefix",
    "enableCredentialsApi": "enable_credentials_api",
    "passwordResetTtlSeconds": "password_reset_ttl_seconds",
    "emailVerifyTtlSeconds": "email_verify_ttl_seconds",
    "rateLimitSignInPerHour": "rate_limit_sign_in_per_hour",
    "rateLimitSignUpPerHour": "rate_limit_sign_up_per_hour",
    "rateLimitUsernameCheckPerHour": "rate_limit_username_check_per_hour",
    "rateLimitPasswordResetPerHour": "rate_limit_password_reset_per_hour",
    "requireEmailVerified": "require_email_verified",
    "identifier": "identifier",
    "usernameMinLength": "username_min_length",
    "usernameMaxLength": "username_max_length",
    "usernamePattern": "username_pattern",
    "strict": "strict",
}


class _SchemaOwner(Protocol):
    """A service that can create its own tables idempotently."""

    async def ensure_schema(self) -> None: ...


class PyxleAuthPlugin(PyxlePlugin):
    name = "pyxle-auth"
    version = "0.3.0"

    def middleware(self) -> Sequence[tuple[str, Mapping[str, Any]]]:
        """Contribute the OAuth + session middleware.

        ``OAuthMiddleware`` is outer so it terminates ``{prefix}/oauth/...``
        requests before the session middleware does any ambient work; both are
        inert when their service isn't registered. See
        :class:`pyxle_auth.oauth.middleware.OAuthMiddleware` and
        :class:`pyxle_auth.middleware.AuthSessionMiddleware`.
        """
        return [
            ("pyxle_auth.oauth.middleware:OAuthMiddleware", {}),
            ("pyxle_auth.middleware:AuthSessionMiddleware", {}),
        ]

    async def on_startup(self, ctx: PluginContext) -> None:
        try:
            # The contract is the SERVICE NAME, not the package: anything
            # registered as 'db.database' satisfying pyxle_db.DatabaseLike
            # (see that protocol's docstring for the full contract) works.
            # pyxle-db is the reference provider.
            database: DatabaseLike = ctx.require("db.database")
        except PluginServiceError as exc:
            raise PluginServiceError(
                "pyxle-auth requires a database service registered as "
                "'db.database' — the pyxle-db plugin provides one (any "
                "plugin registering a pyxle_db.DatabaseLike object works). "
                "List it BEFORE \"pyxle-auth\" in "
                "pyxle.config.json::plugins."
            ) from exc

        # ``oauth`` and ``jwt`` are config blocks, not AuthSettings fields;
        # split them out before the settings translation (which rejects unknown
        # keys).
        raw_settings = dict(self.settings or {})
        oauth_settings = raw_settings.pop("oauth", None)
        jwt_settings = raw_settings.pop("jwt", None)

        auth_settings = _build_auth_settings(raw_settings)
        service = AuthService(database, auth_settings)
        rbac = RoleService(database)
        tokens = TokenService(database)
        api_tokens = ApiTokenService(database)

        await _apply_schema(database, (service, rbac, tokens, api_tokens))

        ctx.register("auth.service", service)
        ctx.register("auth.rbac", rbac)
        ctx.register("auth.tokens", tokens)
        ctx.register("auth.api_tokens", api_tokens)
        ctx.register("auth.settings", auth_settings)

        if oauth_settings:
            await _start_oauth(
                ctx, database, service, auth_settings, oauth_settings
            )
        if jwt_settings is not None:
            await _start_jwt(ctx, database, auth_settings, jwt_settings)

        _logger.info(
            "pyxle-auth: services ready (cookie=%s, ttl=%ds, strict=%s)",
            auth_settings.cookie_name,
            auth_settings.session_lifetime_seconds,
            auth_settings.strict,
        )


async def _start_oauth(
    ctx: PluginContext,
    database: DatabaseLike,
    auth_service: AuthService,
    auth_settings: AuthSettings,
    oauth_settings: Any,
) -> None:
    """Build the OAuthService + flow config from the ``oauth`` settings block.

    Provider credentials come from the environment only
    (``PYXLE_AUTH_OAUTH_<PROVIDER>_CLIENT_*``); a missing one aborts startup
    with an actionable error. Imported here (not at module top) so apps that
    don't use OAuth never load the provider/middleware code.
    """
    from pyxle_auth.oauth.errors import OAuthConfigError
    from pyxle_auth.oauth.middleware import OAuthFlowConfig
    from pyxle_auth.oauth.providers import OAuthProvider
    from pyxle_auth.oauth.service import OAuthService

    if not isinstance(oauth_settings, Mapping):
        raise PluginServiceError(
            "pyxle-auth: the 'oauth' setting must be an object, e.g. "
            '{"providers": ["google"]}.'
        )
    names = oauth_settings.get("providers") or []
    if not names:
        return

    providers: dict[str, OAuthProvider] = {}
    for name in names:
        try:
            provider = OAuthProvider.from_env(str(name))
        except OAuthConfigError as exc:
            raise PluginServiceError(f"pyxle-auth: {exc}") from exc
        providers[provider.name] = provider

    oauth_service = OAuthService(database, auth_service, providers)
    await oauth_service.ensure_schema()

    config = OAuthFlowConfig(
        state_secret=_resolve_state_secret(auth_settings.strict),
        auth_path_prefix=auth_settings.auth_path_prefix,
        cookie_secure=auth_settings.cookie_secure,
        cookie_domain=auth_settings.cookie_domain,
        redirect_base_url=oauth_settings.get("redirectBaseUrl"),
        failure_redirect=str(oauth_settings.get("failureRedirect", "/")),
        state_ttl_seconds=int(oauth_settings.get("stateTtlSeconds", 600)),
    )
    ctx.register("auth.oauth", oauth_service)
    ctx.register("auth.oauth.config", config)
    _logger.info(
        "pyxle-auth: OAuth ready (providers=%s)", ", ".join(sorted(providers))
    )


async def _start_jwt(
    ctx: PluginContext,
    database: DatabaseLike,
    auth_settings: AuthSettings,
    jwt_settings: Any,
) -> None:
    """Build the JWTService from the ``jwt`` settings block.

    Signs with the same secret as the OAuth state cookie
    (``PYXLE_AUTH_SECRET`` / ``PYXLE_SECRET_KEY``). Imported here (not at module
    top) so apps that don't use JWT never load ``pyjwt``.
    """
    from pyxle_auth.jwt_tokens import JWTService

    if not isinstance(jwt_settings, Mapping):
        raise PluginServiceError(
            "pyxle-auth: the 'jwt' setting must be an object, e.g. "
            '{"accessTtlSeconds": 900}.'
        )
    access_ttl = int(jwt_settings.get("accessTtlSeconds", 900))
    jwt_service = JWTService(
        database,
        # The HMAC key — pyjwt accepts the raw bytes the secret resolver returns.
        secret=_resolve_state_secret(auth_settings.strict),
        access_ttl_seconds=access_ttl,
        refresh_ttl_seconds=int(jwt_settings.get("refreshTtlSeconds", 2_592_000)),
        issuer=jwt_settings.get("issuer"),
    )
    await jwt_service.ensure_schema()
    ctx.register("auth.jwt", jwt_service)
    _logger.info("pyxle-auth: JWT ready (access ttl=%ds)", access_ttl)


def _resolve_state_secret(strict: bool) -> bytes:
    """The HMAC key for the OAuth state cookie.

    Read from ``PYXLE_AUTH_SECRET`` (preferred) or the framework-wide
    ``PYXLE_SECRET_KEY``. In strict mode a missing secret aborts startup — an
    unsigned state cookie has no integrity. In dev (non-strict) an ephemeral
    key is generated, with a warning, so local OAuth works without setup (the
    cost: in-flight flows break across a restart).
    """
    raw = os.environ.get("PYXLE_AUTH_SECRET") or os.environ.get("PYXLE_SECRET_KEY")
    if raw:
        return raw.encode("utf-8")
    if strict:
        raise PluginServiceError(
            "pyxle-auth: OAuth needs a signing secret for the state cookie. "
            "Set PYXLE_AUTH_SECRET (or PYXLE_SECRET_KEY) in the environment."
        )
    _logger.warning(
        "pyxle-auth: no PYXLE_AUTH_SECRET/PYXLE_SECRET_KEY set — using an "
        "ephemeral OAuth state secret (dev only; in-flight sign-ins break on "
        "restart)."
    )
    return secrets.token_bytes(32)


async def _apply_schema(
    database: DatabaseLike, services: Sequence[_SchemaOwner]
) -> None:
    """Bundled migrations first, then every service's ``ensure_schema``.

    The migrations directory ships inside the package; when it is
    absent (a build that stripped data files), the idempotent
    ``ensure_schema`` calls alone still produce a working schema. They
    also run after migrations on purpose: ``CREATE TABLE IF NOT EXISTS``
    is a no-op on anything the migrations created, and it backfills
    tables on databases whose migration history predates them.
    """
    if _MIGRATIONS_DIR.is_dir():
        # Own tracking table so the host app's migrations (in the default
        # ``schema_migrations``) and ours coexist on one database without
        # either being seen as drift by the other's migrator.
        applied = await Migrator(
            database, _MIGRATIONS_DIR, tracking_table="schema_migrations_pyxle_auth"
        ).apply_all()
        if applied:
            _logger.info(
                "pyxle-auth: applied %d migration(s): %s",
                len(applied),
                ", ".join(migration.id for migration in applied),
            )
    for service in services:
        await service.ensure_schema()


def _build_auth_settings(user_settings: Mapping[str, Any]) -> AuthSettings:
    """Translate camelCase config keys and merge them over the environment.

    Unknown keys raise with a clear message — a typo like
    ``"cookeiSecure"`` would otherwise silently fall through to the
    AuthSettings default and leave the plugin author wondering why
    their setting isn't taking effect.
    """
    overrides: dict[str, Any] = {}
    unknown: list[str] = []
    for key, value in user_settings.items():
        mapped = _SETTINGS_MAP.get(key)
        if mapped is None:
            unknown.append(key)
            continue
        overrides[mapped] = value
    if unknown:
        raise PluginServiceError(
            f"pyxle-auth: unknown settings keys in plugin config: {sorted(unknown)}. "
            f"Supported: {sorted(_SETTINGS_MAP)}."
        )
    # `strict` resolves config > env > secure-default(True). Letting the
    # environment relax it (PYXLE_AUTH_STRICT=false) means a host app can
    # commit a production-safe config (no strict/cookieSecure keys → strict
    # defaults on) and relax it for local HTTP dev via the environment,
    # instead of pinning an insecure value into a file that ships to prod.
    if "strict" in overrides:
        strict = bool(overrides["strict"])
    else:
        strict = os.environ.get("PYXLE_AUTH_STRICT", "true").strip().lower() in (
            "1",
            "true",
            "yes",
            "on",
        )
    return AuthSettings.from_env(strict=strict, overrides=overrides)


# Convention: Pyxle's loader imports ``plugin`` from this module.
plugin = PyxleAuthPlugin
