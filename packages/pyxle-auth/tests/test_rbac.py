"""Behavioural tests for :mod:`pyxle_auth.rbac` — roles, grants, and
wildcard permission checks against an in-memory SQLite database."""

from __future__ import annotations

import pytest

from pyxle_auth.rbac import RoleNotFound, RoleService
from pyxle_db import Database


@pytest.fixture
async def db() -> Database:
    """In-memory SQLite — overrides the file-backed conftest fixture."""
    database = Database(":memory:")
    await database.connect()
    try:
        yield database
    finally:
        await database.aclose()


@pytest.fixture
async def rbac(db: Database) -> RoleService:
    service = RoleService(db)
    await service.ensure_schema()
    return service


# ---------------------------------------------------------------------------
# Schema


async def test_ensure_schema_is_idempotent(rbac: RoleService) -> None:
    await rbac.ensure_schema()  # second run must not raise
    await rbac.define_role(name="admin", permissions=["*"])
    assert await rbac.has_permission(user_id="u1", permission="x") is False


# ---------------------------------------------------------------------------
# define_role


async def test_define_grant_check_round_trip(rbac: RoleService) -> None:
    await rbac.define_role(name="editor", permissions=["posts.read", "posts.write"])
    await rbac.grant_role(user_id="u1", role_name="editor")

    assert await rbac.roles_for(user_id="u1") == ["editor"]
    assert await rbac.has_permission(user_id="u1", permission="posts.read") is True
    assert await rbac.has_permission(user_id="u1", permission="posts.delete") is False


async def test_define_role_replaces_permissions(rbac: RoleService) -> None:
    await rbac.define_role(name="editor", permissions=["posts.read"])
    await rbac.grant_role(user_id="u1", role_name="editor")

    await rbac.define_role(name="editor", permissions=["media.upload"])

    # Replace, not merge: the old permission is gone, the new one is live.
    assert await rbac.has_permission(user_id="u1", permission="posts.read") is False
    assert await rbac.has_permission(user_id="u1", permission="media.upload") is True
    assert await rbac.permissions_for(user_id="u1") == frozenset({"media.upload"})


async def test_redefine_is_idempotent_and_preserves_created_at(
    rbac: RoleService, db: Database
) -> None:
    await rbac.define_role(name="editor", permissions=["posts.read"])
    before = await db.get("SELECT created_at FROM roles WHERE name = ?", ("editor",))

    await rbac.define_role(name="editor", permissions=["posts.read"])  # no change
    await rbac.define_role(name="editor", permissions=["posts.write"])  # change

    after = await db.get(
        "SELECT permissions, created_at FROM roles WHERE name = ?", ("editor",)
    )
    assert after["created_at"] == before["created_at"]
    assert after["permissions"] == "posts.write"

    rows = await db.fetchall("SELECT name FROM roles")
    assert len(rows) == 1  # upsert never duplicates the row


async def test_permissions_stored_space_separated_and_deduped(
    rbac: RoleService, db: Database
) -> None:
    await rbac.define_role(
        name="editor",
        permissions=["posts.read", " posts.write ", "posts.read"],
    )
    row = await db.get("SELECT permissions FROM roles WHERE name = ?", ("editor",))
    assert row["permissions"] == "posts.read posts.write"


async def test_define_role_allows_empty_permission_list(rbac: RoleService) -> None:
    await rbac.define_role(name="pending", permissions=[])
    await rbac.grant_role(user_id="u1", role_name="pending")

    assert await rbac.roles_for(user_id="u1") == ["pending"]
    assert await rbac.permissions_for(user_id="u1") == frozenset()
    assert await rbac.has_permission(user_id="u1", permission="anything") is False


@pytest.mark.parametrize(
    "name",
    [
        "",
        "   ",
        "Admin",  # uppercase
        "has space",
        "a" * 65,  # too long
        "-admin",  # leading separator
        "admin-",  # trailing separator
        "ops--lead",  # doubled separator
        "rôle",  # non-ascii
    ],
)
async def test_define_role_rejects_invalid_names(
    rbac: RoleService, name: str
) -> None:
    with pytest.raises(ValueError):
        await rbac.define_role(name=name, permissions=["x"])


@pytest.mark.parametrize(
    "name", ["a", "admin", "billing-admin", "tier_2", "a" * 64]
)
async def test_define_role_accepts_slug_names(rbac: RoleService, name: str) -> None:
    await rbac.define_role(name=name, permissions=["x"])
    await rbac.grant_role(user_id="u1", role_name=name)
    assert await rbac.roles_for(user_id="u1") == [name]


@pytest.mark.parametrize(
    "permission",
    [
        "",
        "   ",
        "POSTS.READ",  # uppercase
        "a b",  # space
        "a" * 129,  # too long
        "a*",  # wildcard glued to a segment
        "*.read",  # leading wildcard
        "a.*.c",  # wildcard mid-pattern
        ".*",  # wildcard with empty prefix
        "*x",
    ],
)
async def test_define_role_rejects_invalid_permissions(
    rbac: RoleService, permission: str
) -> None:
    with pytest.raises(ValueError):
        await rbac.define_role(name="editor", permissions=[permission])


@pytest.mark.parametrize(
    "permission",
    ["*", "projects.*", "a.b.c", "reports:read", "a-b_c", "a" * 128],
)
async def test_define_role_accepts_valid_permissions(
    rbac: RoleService, permission: str
) -> None:
    await rbac.define_role(name="editor", permissions=[permission])


# ---------------------------------------------------------------------------
# grant / revoke


async def test_grant_is_idempotent(rbac: RoleService) -> None:
    await rbac.define_role(name="editor", permissions=["posts.read"])
    await rbac.grant_role(user_id="u1", role_name="editor")
    await rbac.grant_role(user_id="u1", role_name="editor")

    assert await rbac.roles_for(user_id="u1") == ["editor"]
    assert await rbac.users_with_role(role_name="editor") == ["u1"]


async def test_grant_unknown_role_raises(rbac: RoleService) -> None:
    with pytest.raises(RoleNotFound) as exc_info:
        await rbac.grant_role(user_id="u1", role_name="ghost")
    assert exc_info.value.name == "ghost"
    assert await rbac.roles_for(user_id="u1") == []


async def test_grant_validates_arguments(rbac: RoleService) -> None:
    await rbac.define_role(name="editor", permissions=["posts.read"])
    with pytest.raises(ValueError):
        await rbac.grant_role(user_id="", role_name="editor")
    with pytest.raises(ValueError):
        await rbac.grant_role(user_id="u1", role_name="  ")


async def test_revoke_role(rbac: RoleService) -> None:
    await rbac.define_role(name="editor", permissions=["posts.read"])
    await rbac.grant_role(user_id="u1", role_name="editor")

    assert await rbac.revoke_role(user_id="u1", role_name="editor") is True
    assert await rbac.roles_for(user_id="u1") == []
    assert await rbac.has_permission(user_id="u1", permission="posts.read") is False
    # Second revoke reports nothing happened.
    assert await rbac.revoke_role(user_id="u1", role_name="editor") is False


async def test_roles_for_and_users_with_role_are_sorted(rbac: RoleService) -> None:
    for name in ("zeta", "alpha", "mid"):
        await rbac.define_role(name=name, permissions=["x"])
        await rbac.grant_role(user_id="u1", role_name=name)
    await rbac.grant_role(user_id="u0", role_name="alpha")

    assert await rbac.roles_for(user_id="u1") == ["alpha", "mid", "zeta"]
    assert await rbac.users_with_role(role_name="alpha") == ["u0", "u1"]


# ---------------------------------------------------------------------------
# delete_role


async def test_delete_role_cascades_grants(rbac: RoleService) -> None:
    await rbac.define_role(name="editor", permissions=["posts.read"])
    await rbac.grant_role(user_id="u1", role_name="editor")
    await rbac.grant_role(user_id="u2", role_name="editor")

    assert await rbac.delete_role(name="editor") is True

    assert await rbac.roles_for(user_id="u1") == []
    assert await rbac.roles_for(user_id="u2") == []
    assert await rbac.users_with_role(role_name="editor") == []
    assert await rbac.has_permission(user_id="u1", permission="posts.read") is False
    # Idempotent: a second delete reports the role was already gone.
    assert await rbac.delete_role(name="editor") is False


async def test_redefining_a_deleted_role_does_not_resurrect_grants(
    rbac: RoleService,
) -> None:
    await rbac.define_role(name="editor", permissions=["posts.read"])
    await rbac.grant_role(user_id="u1", role_name="editor")
    await rbac.delete_role(name="editor")

    await rbac.define_role(name="editor", permissions=["posts.read"])

    assert await rbac.roles_for(user_id="u1") == []
    assert await rbac.has_permission(user_id="u1", permission="posts.read") is False


# ---------------------------------------------------------------------------
# wildcard semantics


async def test_trailing_wildcard_matches_dotted_prefix(rbac: RoleService) -> None:
    await rbac.define_role(name="pm", permissions=["projects.*"])
    await rbac.grant_role(user_id="u1", role_name="pm")

    assert await rbac.has_permission(user_id="u1", permission="projects.create")
    assert await rbac.has_permission(user_id="u1", permission="projects.a.b")
    # The granted wildcard string itself is an exact member.
    assert await rbac.has_permission(user_id="u1", permission="projects.*")


async def test_trailing_wildcard_is_prefix_not_substring(rbac: RoleService) -> None:
    await rbac.define_role(name="scoped", permissions=["a.*"])
    await rbac.grant_role(user_id="u1", role_name="scoped")

    # "ab.c" shares the leading "a" but not the dotted prefix "a.".
    assert await rbac.has_permission(user_id="u1", permission="ab.c") is False
    # Bare "a" is the namespace itself, not something under it.
    assert await rbac.has_permission(user_id="u1", permission="a") is False
    # An empty tail ("a." with nothing after the dot) is not a match.
    assert await rbac.has_permission(user_id="u1", permission="a.") is False
    assert await rbac.has_permission(user_id="u1", permission="a.b") is True


async def test_global_wildcard_grants_everything(rbac: RoleService) -> None:
    await rbac.define_role(name="root", permissions=["*"])
    await rbac.grant_role(user_id="u1", role_name="root")

    assert await rbac.has_permission(user_id="u1", permission="anything")
    assert await rbac.has_permission(user_id="u1", permission="deep.nested:thing")


async def test_permissions_union_across_roles(rbac: RoleService) -> None:
    await rbac.define_role(name="reader", permissions=["posts.read"])
    await rbac.define_role(name="media", permissions=["media.*"])
    await rbac.grant_role(user_id="u1", role_name="reader")
    await rbac.grant_role(user_id="u1", role_name="media")

    assert await rbac.has_permission(user_id="u1", permission="posts.read") is True
    assert await rbac.has_permission(user_id="u1", permission="media.upload") is True
    assert await rbac.has_permission(user_id="u1", permission="billing.view") is False
    # Wildcards are reported as-is, not expanded.
    assert await rbac.permissions_for(user_id="u1") == frozenset(
        {"posts.read", "media.*"}
    )


# ---------------------------------------------------------------------------
# has_permission edges


async def test_has_permission_requires_a_permission(rbac: RoleService) -> None:
    with pytest.raises(ValueError):
        await rbac.has_permission(user_id="u1", permission="")
    with pytest.raises(ValueError):
        await rbac.has_permission(user_id="u1", permission="   ")


async def test_unknown_user_has_no_permissions(rbac: RoleService) -> None:
    await rbac.define_role(name="root", permissions=["*"])
    assert await rbac.has_permission(user_id="nobody", permission="x") is False
    assert await rbac.permissions_for(user_id="nobody") == frozenset()
    assert await rbac.roles_for(user_id="nobody") == []


async def test_grants_are_isolated_per_user(rbac: RoleService) -> None:
    await rbac.define_role(name="editor", permissions=["posts.*"])
    await rbac.grant_role(user_id="u1", role_name="editor")

    assert await rbac.has_permission(user_id="u2", permission="posts.read") is False
    assert await rbac.roles_for(user_id="u2") == []

    # Revoking u1 never touches another user's grants.
    await rbac.grant_role(user_id="u2", role_name="editor")
    await rbac.revoke_role(user_id="u1", role_name="editor")
    assert await rbac.has_permission(user_id="u2", permission="posts.read") is True
