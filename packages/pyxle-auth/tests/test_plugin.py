"""End-to-end plugin-system tests for pyxle-db + pyxle-auth together.

Exercises the full lifecycle path exactly as a real Pyxle app would:

1. Build PluginSpecs from config-shaped data.
2. ``load_plugins`` resolves pyxle-db and pyxle-auth to their classes.
3. ``run_startup`` runs db first, then auth (which pulls db's service
   off the context, builds every auth service, and applies schema).
4. ``run_shutdown`` tears them down in reverse.

Covers the service naming conventions, the settings translation layer
(config beats env), and both schema paths — bundled migrations and the
``ensure_schema`` fallback — so either side can refactor safely.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, AsyncIterator, Mapping

import pytest

import pyxle_auth.plugin as plugin_module
from pyxle.plugins import (
    PluginContext,
    PluginError,
    PluginSpec,
    load_plugins,
    run_shutdown,
    run_startup,
)
from pyxle_auth import (
    ApiTokenService,
    AuthService,
    AuthSettings,
    RoleService,
    TokenService,
)

# Cheap argon + insecure cookie so plugin tests don't burn wall-clock
# time hashing passwords. Mirrors AuthSettings.for_tests().
_TEST_AUTH_SETTINGS: Mapping[str, Any] = {
    "argonTimeCost": 1,
    "argonMemoryKib": 8,
    "argonParallelism": 1,
    "cookieSecure": False,
    "strict": False,
}


class _FakeSettings:
    """Minimal stand-in for DevServerSettings — plugins read only
    ``project_root`` off it. Lets us drive the full flow from pytest
    without pulling the whole Pyxle devserver stack in."""

    def __init__(self, project_root: Path) -> None:
        self.project_root = project_root


@asynccontextmanager
async def _running_plugins(
    project_root: Path, auth_settings: Mapping[str, Any] | None = None
) -> AsyncIterator[PluginContext]:
    """Start pyxle-db + pyxle-auth from config-shaped entries; always
    run the reverse-order shutdown, even when the test body raises."""
    entries: list[Any] = [
        {"name": "pyxle-db", "settings": {"path": "data/app.db"}},
        {
            "name": "pyxle-auth",
            "settings": {**_TEST_AUTH_SETTINGS, **(auth_settings or {})},
        },
    ]
    specs = [PluginSpec.from_config_entry(e) for e in entries]
    plugins = load_plugins(specs)
    ctx = PluginContext(settings=_FakeSettings(project_root=project_root))
    await run_startup(plugins, ctx)
    try:
        yield ctx
    finally:
        await run_shutdown(plugins, ctx)


async def test_startup_registers_every_auth_service(tmp_path: Path) -> None:
    async with _running_plugins(tmp_path) as ctx:
        assert ctx.has("db.database")
        assert isinstance(ctx.require("auth.service"), AuthService)
        assert isinstance(ctx.require("auth.rbac"), RoleService)
        assert isinstance(ctx.require("auth.tokens"), TokenService)
        assert isinstance(ctx.require("auth.api_tokens"), ApiTokenService)
        assert isinstance(ctx.require("auth.settings"), AuthSettings)


async def test_every_service_is_usable_after_startup(tmp_path: Path) -> None:
    """One round-trip per service proves the schema landed and the
    instances are wired to the same live database."""
    async with _running_plugins(tmp_path) as ctx:
        auth: AuthService = ctx.require("auth.service")
        user, cookie = await auth.sign_up(
            email="alice@example.com", password="correcthorse"
        )
        assert user.email == "alice@example.com"
        assert cookie.value

        tokens: TokenService = ctx.require("auth.tokens")
        raw = await tokens.issue(purpose="invite", user_id=user.id)
        claim = await tokens.consume(purpose="invite", raw_token=raw)
        assert claim is not None and claim.user_id == user.id

        rbac: RoleService = ctx.require("auth.rbac")
        await rbac.define_role(name="admin", permissions=["projects:read"])
        await rbac.grant_role(user_id=user.id, role_name="admin")
        assert await rbac.has_permission(
            user_id=user.id, permission="projects:read"
        )

        api_tokens: ApiTokenService = ctx.require("auth.api_tokens")
        token, raw_pat = await api_tokens.create(
            user_id=user.id, name="ci", scopes=["deploy"]
        )
        resolved = await api_tokens.resolve(
            raw_token=raw_pat, required_scope="deploy"
        )
        assert resolved is not None and resolved.id == token.id


async def test_auth_without_db_raises(tmp_path: Path) -> None:
    """Running pyxle-auth without pyxle-db in front produces a useful
    error telling the user to reorder plugins — not a generic KeyError."""
    spec = PluginSpec.from_config_entry(
        {"name": "pyxle-auth", "settings": dict(_TEST_AUTH_SETTINGS)}
    )
    [plugin] = load_plugins([spec])
    ctx = PluginContext(settings=_FakeSettings(project_root=tmp_path))
    with pytest.raises(PluginError, match=r"pyxle-db.*BEFORE.*pyxle-auth"):
        await run_startup([plugin], ctx)


async def test_unknown_settings_key_surfaces_clearly(tmp_path: Path) -> None:
    # A plugin-authoring typo should be loud, not silent.
    with pytest.raises(PluginError, match="cookeiSecure"):
        async with _running_plugins(tmp_path, {"cookeiSecure": True}):
            raise AssertionError("startup should have rejected the typo")


async def test_bundled_migrations_apply(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With a migrations directory present, the plugin records each
    migration in its OWN tracking table (schema_migrations_pyxle_auth, so it
    never collides with a host app's migrations) — and still runs
    ensure_schema after."""
    migrations = tmp_path / "auth-migrations"
    migrations.mkdir()
    (migrations / "0001-marker.sql").write_text(
        "CREATE TABLE auth_test_marker (id TEXT PRIMARY KEY);",
        encoding="utf-8",
    )
    monkeypatch.setattr(plugin_module, "_MIGRATIONS_DIR", migrations)

    async with _running_plugins(tmp_path) as ctx:
        db = ctx.require("db.database")
        applied = {
            row["id"]
            for row in await db.fetchall(
                "SELECT id FROM schema_migrations_pyxle_auth"
            )
        }
        assert "0001-marker" in applied
        # The migrated table is real and writable.
        assert (
            await db.execute(
                "INSERT INTO auth_test_marker (id) VALUES (?)", ("x",)
            )
            == 1
        )
        # ensure_schema ran as belt-and-braces: tables the marker
        # migration never created exist too.
        auth: AuthService = ctx.require("auth.service")
        user, _ = await auth.sign_up(
            email="bob@example.com", password="correcthorse"
        )
        assert user.id


async def test_ensure_schema_fallback_without_migrations_dir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No migrations directory: every service's ensure_schema() alone
    must still produce a fully working schema."""
    monkeypatch.setattr(
        plugin_module, "_MIGRATIONS_DIR", tmp_path / "does-not-exist"
    )
    async with _running_plugins(tmp_path) as ctx:
        auth: AuthService = ctx.require("auth.service")
        user, cookie = await auth.sign_up(
            email="carol@example.com", password="correcthorse"
        )
        assert cookie.value
        resolved = await auth.resolve_session(cookie_value=cookie.value)
        assert resolved is not None and resolved.id == user.id


async def test_config_settings_override_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Documented precedence: plugin settings dict > PYXLE_AUTH_* env >
    defaults."""
    monkeypatch.setenv("PYXLE_AUTH_PASSWORD_RESET_TTL_SECONDS", "999")
    monkeypatch.setenv("PYXLE_AUTH_EMAIL_VERIFY_TTL_SECONDS", "7777")
    async with _running_plugins(
        tmp_path, {"passwordResetTtlSeconds": 1234}
    ) as ctx:
        settings: AuthSettings = ctx.require("auth.settings")
        assert settings.password_reset_ttl_seconds == 1234  # config wins
        assert settings.email_verify_ttl_seconds == 7777  # env fills the rest
        assert settings.rate_limit_password_reset_per_hour == 3  # default


async def test_plugin_contributes_session_middleware() -> None:
    """The plugin advertises its middleware through the public seam — the only
    way a plugin can own request.user, the auth endpoints, and the OAuth flow
    (there is no route-contribution seam)."""
    from pyxle_auth.plugin import PyxleAuthPlugin

    specs = list(PyxleAuthPlugin().middleware())
    assert specs == [
        ("pyxle_auth.oauth.middleware:OAuthMiddleware", {}),
        ("pyxle_auth.middleware:AuthSessionMiddleware", {}),
    ]
    # OAuth is outer so it terminates /auth/oauth/* before the session layer.
    assert specs[0][0].endswith("OAuthMiddleware")


async def test_oauth_configured_registers_services(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("PYXLE_AUTH_OAUTH_GOOGLE_CLIENT_ID", "gid")
    monkeypatch.setenv("PYXLE_AUTH_OAUTH_GOOGLE_CLIENT_SECRET", "gsecret")
    async with _running_plugins(
        tmp_path, {"oauth": {"providers": ["google"], "failureRedirect": "/login"}}
    ) as ctx:
        service = ctx.require("auth.oauth")
        config = ctx.require("auth.oauth.config")
        assert "google" in service.providers
        assert config.auth_path_prefix == "/auth"
        assert config.failure_redirect == "/login"
        # The oauth_identities table exists and is empty.
        db = ctx.require("db.database")
        assert await db.fetchall("SELECT * FROM oauth_identities") == []


async def test_oauth_missing_credentials_aborts_startup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("PYXLE_AUTH_OAUTH_GITHUB_CLIENT_ID", raising=False)
    monkeypatch.delenv("PYXLE_AUTH_OAUTH_GITHUB_CLIENT_SECRET", raising=False)
    with pytest.raises(PluginError, match="missing credentials"):
        async with _running_plugins(tmp_path, {"oauth": {"providers": ["github"]}}):
            raise AssertionError("startup should have failed")


async def test_oauth_not_configured_leaves_services_absent(tmp_path: Path) -> None:
    async with _running_plugins(tmp_path) as ctx:
        assert ctx.get("auth.oauth") is None
        assert ctx.get("auth.oauth.config") is None


async def test_jwt_configured_registers_service(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("PYXLE_AUTH_SECRET", "a-signing-secret")
    async with _running_plugins(
        tmp_path, {"jwt": {"accessTtlSeconds": 600}}
    ) as ctx:
        jwt = ctx.require("auth.jwt")
        auth: AuthService = ctx.require("auth.service")
        user, _ = await auth.sign_up(email="api@example.com", password="correct horse staple")
        pair = await jwt.issue_pair(user_id=user.id)
        assert jwt.verify_access(pair.access_token) is not None
        # The jwt_refresh_tokens table exists.
        db = ctx.require("db.database")
        assert await db.fetchall("SELECT * FROM jwt_refresh_tokens WHERE used_at IS NOT NULL") == []


async def test_jwt_not_configured_leaves_service_absent(tmp_path: Path) -> None:
    async with _running_plugins(tmp_path) as ctx:
        assert ctx.get("auth.jwt") is None


def test_resolve_state_secret_reads_env(monkeypatch: pytest.MonkeyPatch) -> None:
    from pyxle_auth.plugin import _resolve_state_secret

    monkeypatch.setenv("PYXLE_AUTH_SECRET", "supersecret")
    assert _resolve_state_secret(strict=True) == b"supersecret"


def test_resolve_state_secret_strict_requires_a_secret(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from pyxle.plugins import PluginServiceError

    from pyxle_auth.plugin import _resolve_state_secret

    monkeypatch.delenv("PYXLE_AUTH_SECRET", raising=False)
    monkeypatch.delenv("PYXLE_SECRET_KEY", raising=False)
    with pytest.raises(PluginServiceError, match="signing secret"):
        _resolve_state_secret(strict=True)


def test_resolve_state_secret_dev_generates_ephemeral(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from pyxle_auth.plugin import _resolve_state_secret

    monkeypatch.delenv("PYXLE_AUTH_SECRET", raising=False)
    monkeypatch.delenv("PYXLE_SECRET_KEY", raising=False)
    secret = _resolve_state_secret(strict=False)
    assert isinstance(secret, bytes) and len(secret) >= 16


async def test_auth_path_prefix_flows_from_config(tmp_path: Path) -> None:
    async with _running_plugins(tmp_path, {"authPathPrefix": "/account"}) as ctx:
        settings: AuthSettings = ctx.require("auth.settings")
        assert settings.auth_path_prefix == "/account"


async def test_get_auth_service_and_settings_shortcuts(tmp_path: Path) -> None:
    """Django-style import helpers return the same instances
    ``request.app.state.pyxle_plugins.require(...)`` would, once the
    devserver's lifespan has installed the active context."""
    from pyxle.plugins import set_active_context
    from pyxle_auth import get_auth_service, get_auth_settings

    async with _running_plugins(tmp_path) as ctx:
        set_active_context(ctx)
        try:
            assert get_auth_service() is ctx.require("auth.service")
            assert get_auth_settings() is ctx.require("auth.settings")
        finally:
            set_active_context(None)


# ── strict resolves from env when config omits it (cloud fail-secure default) ──


def test_build_auth_settings_strict_defaults_true_without_config_or_env(monkeypatch):
    """No `strict` in config and no env → secure default (strict=True)."""
    from pyxle_auth.plugin import _build_auth_settings

    monkeypatch.delenv("PYXLE_AUTH_STRICT", raising=False)
    monkeypatch.setenv("PYXLE_AUTH_COOKIE_SECURE", "true")
    settings = _build_auth_settings({})
    assert settings.strict is True
    assert settings.cookie_secure is True


def test_build_auth_settings_strict_relaxes_via_env(monkeypatch):
    """Dev can relax strict from the environment without a config key — the
    fix that lets the committed config stay production-safe."""
    from pyxle_auth.plugin import _build_auth_settings

    monkeypatch.setenv("PYXLE_AUTH_STRICT", "false")
    monkeypatch.setenv("PYXLE_AUTH_COOKIE_SECURE", "false")
    settings = _build_auth_settings({})
    assert settings.strict is False
    assert settings.cookie_secure is False


def test_build_auth_settings_config_strict_beats_env(monkeypatch):
    """An explicit config `strict` still wins over the environment."""
    from pyxle_auth.plugin import _build_auth_settings

    monkeypatch.setenv("PYXLE_AUTH_STRICT", "false")
    settings = _build_auth_settings({"strict": True, "cookieSecure": True})
    assert settings.strict is True
