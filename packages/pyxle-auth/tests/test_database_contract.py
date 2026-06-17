"""pyxle-auth against a database that is NOT ``pyxle_db.Database``.

The bring-your-own-database contract (``pyxle_db.DatabaseLike``) says any
object with the five-member surface — registered as the ``db.database``
plugin service, translating unique violations to ``pyxle_db.IntegrityError``
— can back pyxle-auth. This suite enforces that promise with a wrapper
that *deliberately* exposes only the protocol members while delegating to
a real SQLite database underneath: if any service grows a call to a
pyxle-db-only method (``executemany``, ``get``, ``connect``, …), these
tests fail with ``AttributeError`` instead of letting the contract rot.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, AsyncIterator, Sequence

import pytest

from pyxle.plugins import PluginContext
from pyxle_auth import (
    AccountExists,
    ApiTokenService,
    AuthService,
    AuthSettings,
    RoleService,
    TokenService,
)
from pyxle_auth.plugin import PyxleAuthPlugin
from pyxle_db import Database, DatabaseLike, Row, TransactionLike, connect

Params = Sequence[Any]


class _ContractTransaction:
    """Only the TransactionLike members — nothing else."""

    def __init__(self, inner: Any) -> None:
        self._inner = inner

    async def execute(self, sql: str, params: Params | None = None) -> int:
        return await self._inner.execute(sql, params)

    async def fetchone(self, sql: str, params: Params | None = None) -> Row | None:
        return await self._inner.fetchone(sql, params)

    async def fetchall(self, sql: str, params: Params | None = None) -> list[Row]:
        return await self._inner.fetchall(sql, params)


class _ContractTxCtx:
    def __init__(self, inner_ctx: Any) -> None:
        self._inner_ctx = inner_ctx

    async def __aenter__(self) -> _ContractTransaction:
        return _ContractTransaction(await self._inner_ctx.__aenter__())

    async def __aexit__(self, *exc_info: Any) -> Any:
        return await self._inner_ctx.__aexit__(*exc_info)


class ContractDatabase:
    """A third-party database layer in miniature.

    Implements exactly the ``DatabaseLike`` surface by delegating to a
    private real database — the same shape an adapter over SQLAlchemy or
    a bespoke driver would have. Intentionally NOT a subclass of
    ``pyxle_db.Database``.
    """

    def __init__(self, inner: Database) -> None:
        self._inner = inner

    @property
    def dialect(self):  # type: ignore[no-untyped-def]  # -> pyxle_db.Dialect
        return self._inner.dialect

    async def execute(self, sql: str, params: Params | None = None) -> int:
        return await self._inner.execute(sql, params)

    async def fetchone(self, sql: str, params: Params | None = None) -> Row | None:
        return await self._inner.fetchone(sql, params)

    async def fetchall(self, sql: str, params: Params | None = None) -> list[Row]:
        return await self._inner.fetchall(sql, params)

    def transaction(self) -> _ContractTxCtx:
        return _ContractTxCtx(self._inner.transaction())


@pytest.fixture
async def contract_db(tmp_path: Path) -> AsyncIterator[ContractDatabase]:
    inner = await connect(tmp_path / "contract.db")
    try:
        yield ContractDatabase(inner)
    finally:
        await inner.aclose()


def test_wrapper_satisfies_the_protocol_without_being_a_database(
    contract_db: ContractDatabase,
) -> None:
    assert not isinstance(contract_db, Database)
    assert isinstance(contract_db, DatabaseLike)
    assert isinstance(contract_db.transaction(), _ContractTxCtx)


async def test_transaction_object_satisfies_transaction_like(
    contract_db: ContractDatabase,
) -> None:
    async with contract_db.transaction() as tx:
        assert isinstance(tx, TransactionLike)


async def test_full_lifecycle_on_a_foreign_database(
    contract_db: ContractDatabase,
) -> None:
    """Every service, every IntegrityError-translation path, through the
    five-member surface only."""
    settings = AuthSettings(strict=False).for_tests()
    auth = AuthService(contract_db, settings)
    rbac = RoleService(contract_db)
    tokens = TokenService(contract_db)
    api_tokens = ApiTokenService(contract_db)
    for service in (auth, rbac, tokens, api_tokens):
        await service.ensure_schema()

    user, cookie = await auth.sign_up(email="ada@example.com", password="correct horse")
    assert (await auth.resolve_session(cookie_value=cookie.value)).id == user.id

    # Unique-violation translation: the wrapper re-raises pyxle_db's
    # IntegrityError, which sign_up converts to the domain error.
    with pytest.raises(AccountExists):
        await auth.sign_up(email="ada@example.com", password="another pass")

    # RBAC: double-grant runs the idempotent IntegrityError path.
    await rbac.define_role(name="admin", permissions=["projects.*"])
    await rbac.grant_role(user_id=user.id, role_name="admin")
    await rbac.grant_role(user_id=user.id, role_name="admin")
    assert await rbac.has_permission(user_id=user.id, permission="projects.deploy")

    raw = await tokens.issue(purpose="invite", user_id=user.id)
    claim = await tokens.consume(purpose="invite", raw_token=raw)
    assert claim is not None and claim.user_id == user.id

    _, raw_pat = await api_tokens.create(user_id=user.id, name="ci", scopes=["deploy"])
    resolved = await api_tokens.resolve(raw_token=raw_pat, required_scope="deploy")
    assert resolved is not None


class _FakeAppSettings:
    def __init__(self, project_root: Path) -> None:
        self.project_root = project_root


async def test_plugin_startup_accepts_any_db_database_service(
    contract_db: ContractDatabase, tmp_path: Path
) -> None:
    """The plugin binds to the SERVICE NAME 'db.database', not to the
    pyxle-db package: a foreign object satisfying the protocol carries the
    whole startup path, including the bundled-migration Migrator run."""
    ctx = PluginContext(settings=_FakeAppSettings(tmp_path))
    ctx.register("db.database", contract_db)

    plugin = PyxleAuthPlugin()
    plugin.settings = {
        "argonTimeCost": 1,
        "argonMemoryKib": 8,
        "argonParallelism": 1,
        "cookieSecure": False,
        "strict": False,
    }
    await plugin.on_startup(ctx)

    auth: AuthService = ctx.require("auth.service")
    user, cookie = await auth.sign_up(email="bob@example.com", password="correct horse")
    assert (await auth.resolve_session(cookie_value=cookie.value)).id == user.id

    # The bundled migrations ran against the foreign object, in order.
    applied = await contract_db.fetchall("SELECT id FROM schema_migrations_pyxle_auth")
    assert [row["id"] for row in applied] == [
        "0001-pyxle-auth-core",
        "0002-oauth-identities",
        "0003-jwt-refresh-tokens",
    ]