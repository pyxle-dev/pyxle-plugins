"""Live-backend round trips against real PostgreSQL / MySQL servers.

The whole package is dialect-portable *by claim*: the bundled migration and
every service's ``ensure_schema()`` emit DDL that must run unmodified on
SQLite, PostgreSQL, and MySQL, and the services' SQL goes through pyxle-db's
placeholder translation. SQLite alone cannot prove any of that, so these
tests run the genuine plugin schema path (:func:`pyxle_auth.plugin._apply_schema`)
and a full account lifecycle on real engines.

Skipped unless the engine URLs are provided — the SAME environment variables
pyxle-db's live suites use, so CI configures them once for both packages::

    PYXLE_DB_TEST_POSTGRES_URL=postgresql://user:pass@127.0.0.1:5432/pyxle_test
    PYXLE_DB_TEST_MYSQL_URL=mysql://user:pass@127.0.0.1:3306/pyxle_test

Every table is dropped afterwards so reruns start clean.
"""

from __future__ import annotations

import os
import uuid
from typing import AsyncIterator

import pytest

from pyxle_auth import (
    ApiTokenService,
    AuthService,
    AuthSettings,
    InvalidCredentials,
    RoleService,
    TokenService,
)
from pyxle_auth.plugin import _apply_schema
from pyxle_db import Database

POSTGRES_URL = os.environ.get("PYXLE_DB_TEST_POSTGRES_URL", "")
MYSQL_URL = os.environ.get("PYXLE_DB_TEST_MYSQL_URL", "")

# Reverse-dependency order so engines that enforce foreign keys on DROP
# (MySQL) accept it.
_ALL_TABLES = (
    "user_roles",
    "roles",
    "api_tokens",
    "auth_tokens",
    "ratelimit_buckets",
    "sessions",
    "users",
    "schema_migrations_pyxle_auth",
)


async def _drop_everything(db: Database) -> None:
    for table in _ALL_TABLES:
        await db.execute(f"DROP TABLE IF EXISTS {table}")


@pytest.fixture(
    params=[
        pytest.param(
            "postgresql",
            marks=pytest.mark.skipif(
                not POSTGRES_URL, reason="PYXLE_DB_TEST_POSTGRES_URL is not set"
            ),
        ),
        pytest.param(
            "mysql",
            marks=pytest.mark.skipif(
                not MYSQL_URL, reason="PYXLE_DB_TEST_MYSQL_URL is not set"
            ),
        ),
    ]
)
async def live_db(request: pytest.FixtureRequest) -> AsyncIterator[Database]:
    url = POSTGRES_URL if request.param == "postgresql" else MYSQL_URL
    db = Database.from_url(url)
    await db.connect()
    try:
        await _drop_everything(db)  # a crashed previous run must not leak in
        yield db
    finally:
        await _drop_everything(db)
        await db.aclose()


@pytest.fixture
def services(live_db: Database):  # type: ignore[no-untyped-def]
    settings = AuthSettings(strict=False).for_tests()
    return (
        AuthService(live_db, settings),
        RoleService(live_db),
        TokenService(live_db),
        ApiTokenService(live_db),
    )


async def test_schema_applies_and_is_idempotent(live_db: Database, services) -> None:  # type: ignore[no-untyped-def]
    """The plugin's real startup path — bundled migration + every
    ensure_schema — must run twice without drift on a live engine."""
    await _apply_schema(live_db, services)
    await _apply_schema(live_db, services)  # rerun = restart; must be a no-op
    applied = await live_db.fetchall("SELECT id FROM schema_migrations_pyxle_auth")
    assert [row["id"] for row in applied] == ["0001-pyxle-auth-core"]


async def test_full_account_lifecycle(live_db: Database, services) -> None:  # type: ignore[no-untyped-def]
    """One pass through every table: account, session, rate-limit rows,
    single-use tokens, RBAC, API tokens, password reset."""
    auth, rbac, tokens, api_tokens = services
    await _apply_schema(live_db, services)

    email = f"live-{uuid.uuid4().hex[:10]}@example.com"
    user, cookie = await auth.sign_up(email=email, password="correct horse staple")
    assert (await auth.resolve_session(cookie_value=cookie.value)).id == user.id

    # Credential checks behave on this engine, both ways.
    _, fresh = await auth.sign_in(email=email, password="correct horse staple")
    assert fresh.value
    with pytest.raises(InvalidCredentials):
        await auth.sign_in(email=email, password="wrong password entirely")

    # Single-use tokens: issue, consume once, refuse twice.
    raw = await tokens.issue(purpose="invite", user_id=user.id)
    claim = await tokens.consume(purpose="invite", raw_token=raw)
    assert claim is not None and claim.user_id == user.id
    assert await tokens.consume(purpose="invite", raw_token=raw) is None

    # RBAC with a wildcard grant.
    await rbac.define_role(name="admin", permissions=["projects.*"])
    await rbac.grant_role(user_id=user.id, role_name="admin")
    assert await rbac.has_permission(user_id=user.id, permission="projects.deploy")

    # Scoped API tokens.
    token, raw_pat = await api_tokens.create(user_id=user.id, name="ci", scopes=["deploy"])
    resolved = await api_tokens.resolve(raw_token=raw_pat, required_scope="deploy")
    assert resolved is not None and resolved.id == token.id
    assert await api_tokens.resolve(raw_token=raw_pat, required_scope="billing") is None

    # Password reset end-to-end, old password dead afterwards.
    issued = await auth.request_password_reset(email=email)
    assert issued is not None
    _, reset_raw = issued
    await auth.reset_password(raw_token=reset_raw, new_password="entirely new phrase")
    with pytest.raises(InvalidCredentials):
        await auth.sign_in(email=email, password="correct horse staple")
    _, after = await auth.sign_in(email=email, password="entirely new phrase")
    assert after.value
