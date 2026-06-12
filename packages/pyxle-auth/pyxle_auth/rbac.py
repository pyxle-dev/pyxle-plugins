"""Pragmatic RBAC — named roles bundling permission strings.

Django's groups/permissions model, distilled: a **role** is a named set of
permission strings, users hold roles, and authorisation checks test
permission membership across the union of a user's roles. No permission
registry, no content types — apps invent permission strings
(``"posts.publish"``, ``"billing:read"``) and check them at the edge:

.. code-block:: python

    rbac = RoleService(db)
    await rbac.ensure_schema()

    await rbac.define_role(name="editor", permissions=["posts.*", "media.upload"])
    await rbac.grant_role(user_id=user.id, role_name="editor")

    await rbac.has_permission(user_id=user.id, permission="posts.publish")  # True

Wildcard grammar (the only two forms):

* ``*`` — the global wildcard; grants every permission.
* ``segment.*`` — a trailing wildcard segment; grants everything under the
  dotted prefix. ``projects.*`` matches ``projects.create`` and
  ``projects.a.b`` but **not** ``projectsx.create`` and **not** the bare
  ``projects``.

:class:`RoleService` satisfies the ``_PermissionChecker`` protocol in
:mod:`pyxle_auth.guards`; the plugin registers it as ``auth.rbac`` so
``require_permission_page`` / ``require_permission_action`` find it.

Schema (created by :meth:`ensure_schema`, or via the shipped migrations)::

    roles (
        name        TEXT PRIMARY KEY,
        permissions TEXT NOT NULL,          -- space-separated
        created_at  TIMESTAMP NOT NULL
    )

    user_roles (
        user_id    TEXT NOT NULL,
        role_name  TEXT NOT NULL,
        granted_at TIMESTAMP NOT NULL,
        PRIMARY KEY (user_id, role_name)
    )
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

from pyxle_db import DatabaseLike, IntegrityError

from pyxle_auth._ddl import ensure_index, timestamp_type
from pyxle_auth.errors import AuthError

__all__ = ["RoleNotFound", "RoleService"]


_MAX_NAME_LENGTH = 64
_MAX_PERMISSION_LENGTH = 128

# Role names are lowercase slugs: alphanumeric runs joined by single
# hyphens or underscores ("admin", "billing-admin", "tier_2").
_NAME_RE = re.compile(r"[a-z0-9]+(?:[-_][a-z0-9]+)*")

# The permission charset. Wildcards are layered on top: the global "*",
# or "<body>.*" where <body> matches this pattern.
_PERMISSION_RE = re.compile(r"[a-z0-9_.:-]+")

_SCHEMA_ROLES_TEMPLATE = """
CREATE TABLE IF NOT EXISTS roles (
    name        VARCHAR(64) PRIMARY KEY,
    permissions TEXT NOT NULL,
    created_at  {ts} NOT NULL
)
"""

_SCHEMA_USER_ROLES_TEMPLATE = """
CREATE TABLE IF NOT EXISTS user_roles (
    user_id    VARCHAR(64) NOT NULL,
    role_name  VARCHAR(64) NOT NULL,
    granted_at {ts} NOT NULL,
    PRIMARY KEY (user_id, role_name)
)
"""




def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class RoleNotFound(AuthError):
    """A role name was referenced that has never been defined."""

    def __init__(self, name: str) -> None:
        super().__init__(f"No role named {name!r}. Define it first.")
        self.name = name


def _validate_role_name(name: str) -> str:
    clean = (name or "").strip()
    if (
        not clean
        or len(clean) > _MAX_NAME_LENGTH
        or _NAME_RE.fullmatch(clean) is None
    ):
        raise ValueError(
            f"Invalid role name {name!r}: must be a 1-{_MAX_NAME_LENGTH} "
            "character lowercase slug (alphanumeric runs joined by single "
            "'-' or '_')"
        )
    return clean


def _validate_permissions(permissions: list[str]) -> tuple[str, ...]:
    """Strip, validate, and de-duplicate (order-preserving)."""
    cleaned: list[str] = []
    for permission in permissions:
        p = permission.strip()
        if not _is_valid_permission(p):
            raise ValueError(
                f"Invalid permission {permission!r}: must be "
                f"1-{_MAX_PERMISSION_LENGTH} characters of [a-z0-9_.:-], "
                "the global '*', or a trailing wildcard segment like "
                "'projects.*'"
            )
        if p not in cleaned:
            cleaned.append(p)
    return tuple(cleaned)


def _is_valid_permission(p: str) -> bool:
    if not p or len(p) > _MAX_PERMISSION_LENGTH:
        return False
    if p == "*":
        return True
    body = p[:-2] if p.endswith(".*") else p
    return bool(body) and _PERMISSION_RE.fullmatch(body) is not None


def _matches(granted: str, permission: str) -> bool:
    """Does one granted permission satisfy the requested ``permission``?

    Exact match, the global ``*``, or a trailing wildcard whose dotted
    prefix the request extends: ``a.*`` matches ``a.b`` and ``a.b.c``,
    never ``ab.c`` and never the bare ``a``.
    """
    if granted == "*" or granted == permission:
        return True
    if granted.endswith(".*"):
        prefix = granted[:-1]  # "a.*" -> "a." — keep the dot so "ab" can't match
        return permission.startswith(prefix) and len(permission) > len(prefix)
    return False


class RoleService:
    """Define roles, grant them to users, check permissions.

    One instance per app, sharing the app's :class:`pyxle_db.Database`.
    All SQL is portable canonical-qmark style and runs unchanged on
    SQLite, PostgreSQL, and MySQL.
    """

    def __init__(self, db: DatabaseLike) -> None:
        self._db = db

    async def ensure_schema(self) -> None:
        """Create our tables if they don't exist. Apps that own their
        migrations can apply the equivalent SQL there and skip this."""
        ts = timestamp_type(self._db.dialect.name)
        await self._db.execute(_SCHEMA_ROLES_TEMPLATE.format(ts=ts))
        await self._db.execute(_SCHEMA_USER_ROLES_TEMPLATE.format(ts=ts))
        await ensure_index(
            self._db, name="idx_user_roles_user", table="user_roles", columns="user_id"
        )

    # ---- role definitions ------------------------------------------------------

    async def define_role(self, *, name: str, permissions: list[str]) -> None:
        """Create or replace a role (upsert-by-replace, like Django's
        ``Group.permissions.set``): the stored permission list becomes
        exactly ``permissions`` — nothing is merged. ``created_at`` of an
        existing role is preserved. An empty list is allowed; such a role
        grants nothing but still names a user cohort.

        Raises :class:`ValueError` for an invalid name or permission.
        """
        clean_name = _validate_role_name(name)
        packed = " ".join(_validate_permissions(permissions))
        try:
            async with self._db.transaction() as tx:
                affected = await tx.execute(
                    "UPDATE roles SET permissions = ? WHERE name = ?",
                    (packed, clean_name),
                )
                if affected == 0:
                    await tx.execute(
                        "INSERT INTO roles (name, permissions, created_at) "
                        "VALUES (?, ?, ?)",
                        (clean_name, packed, _utcnow()),
                    )
        except IntegrityError:
            # The INSERT hit the primary key: either a concurrent
            # define_role won the race, or the backend reported the
            # UPDATE as zero rows because nothing changed (MySQL counts
            # changed rows, not matched rows). Either way the role row
            # exists now — settle the final state with a plain UPDATE.
            await self._db.execute(
                "UPDATE roles SET permissions = ? WHERE name = ?",
                (packed, clean_name),
            )

    async def delete_role(self, *, name: str) -> bool:
        """Delete a role and cascade every grant of it (one transaction).
        Returns ``True`` if the role existed. Idempotent."""
        clean_name = (name or "").strip()
        if not clean_name:
            raise ValueError("name must be a non-empty string")
        async with self._db.transaction() as tx:
            await tx.execute(
                "DELETE FROM user_roles WHERE role_name = ?", (clean_name,)
            )
            affected = await tx.execute(
                "DELETE FROM roles WHERE name = ?", (clean_name,)
            )
        return affected > 0

    # ---- grants ------------------------------------------------------------------

    async def grant_role(self, *, user_id: str, role_name: str) -> None:
        """Grant ``role_name`` to a user. Idempotent — granting an
        already-held role is a no-op, not an error.

        Raises :class:`RoleNotFound` for a role that was never defined
        (checked in the same transaction as the insert, so a concurrent
        :meth:`delete_role` cannot leave an orphan grant behind).
        """
        if not user_id or not user_id.strip():
            raise ValueError("user_id must be a non-empty string")
        clean_name = (role_name or "").strip()
        if not clean_name:
            raise ValueError("role_name must be a non-empty string")
        try:
            async with self._db.transaction() as tx:
                row = await tx.fetchone(
                    "SELECT name FROM roles WHERE name = ?", (clean_name,)
                )
                if row is None:
                    raise RoleNotFound(clean_name)
                await tx.execute(
                    "INSERT INTO user_roles (user_id, role_name, granted_at) "
                    "VALUES (?, ?, ?)",
                    (user_id, clean_name, _utcnow()),
                )
        except IntegrityError:
            # PRIMARY KEY (user_id, role_name) — the grant already
            # exists, which is exactly the requested end state.
            pass

    async def revoke_role(self, *, user_id: str, role_name: str) -> bool:
        """Remove one grant. Returns ``True`` if the user held the role."""
        affected = await self._db.execute(
            "DELETE FROM user_roles WHERE user_id = ? AND role_name = ?",
            (user_id, (role_name or "").strip()),
        )
        return affected > 0

    # ---- introspection -------------------------------------------------------------

    async def roles_for(self, *, user_id: str) -> list[str]:
        """The role names a user holds, sorted for determinism."""
        rows = await self._db.fetchall(
            "SELECT role_name FROM user_roles WHERE user_id = ? "
            "ORDER BY role_name",
            (user_id,),
        )
        return [row["role_name"] for row in rows]

    async def users_with_role(self, *, role_name: str) -> list[str]:
        """The user ids holding a role, sorted for determinism."""
        rows = await self._db.fetchall(
            "SELECT user_id FROM user_roles WHERE role_name = ? "
            "ORDER BY user_id",
            ((role_name or "").strip(),),
        )
        return [row["user_id"] for row in rows]

    async def permissions_for(self, *, user_id: str) -> frozenset[str]:
        """The union of permissions across the user's roles, wildcards
        left as-is (``projects.*`` stays ``projects.*``)."""
        rows = await self._db.fetchall(
            "SELECT r.permissions FROM roles r "
            "JOIN user_roles ur ON ur.role_name = r.name "
            "WHERE ur.user_id = ?",
            (user_id,),
        )
        union: set[str] = set()
        for row in rows:
            union.update(row["permissions"].split())
        return frozenset(union)

    # ---- checks --------------------------------------------------------------------

    async def has_permission(self, *, user_id: str, permission: str) -> bool:
        """Does any of the user's roles grant ``permission``?

        Exact membership or wildcard match (see module docstring). Users
        with no roles — and unknown user ids — simply get ``False``.
        """
        requested = (permission or "").strip()
        if not requested:
            raise ValueError("permission must be a non-empty string")
        granted = await self.permissions_for(user_id=user_id)
        return any(_matches(g, requested) for g in granted)
