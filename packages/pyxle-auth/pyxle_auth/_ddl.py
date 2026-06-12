"""Dialect-aware DDL fragments shared by the services' ``ensure_schema()``.

The bundled migration files handle dialect differences with per-backend
overrides (``0001-pyxle-auth-core.mysql.sql``); the services' idempotent
``ensure_schema()`` fallbacks build their DDL from these helpers so both
paths create identical schemas on every engine.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pyxle_db import DatabaseLike

__all__ = ["ensure_index", "timestamp_type"]


def timestamp_type(dialect_name: str) -> str:
    """The portable "datetime column" type for ``dialect_name``.

    ``TIMESTAMP`` works everywhere except MySQL, where it is capped at
    2038 (configurable session/token expiries can exceed it), rounds to
    whole seconds without an explicit precision, and is converted through
    the session time zone. ``DATETIME(6)`` stores the UTC wall time
    pyxle-db binds, byte for byte.
    """
    return "DATETIME(6)" if dialect_name == "mysql" else "TIMESTAMP"


async def ensure_index(db: DatabaseLike, *, name: str, table: str, columns: str) -> None:
    """Create a secondary index if it doesn't exist, on any engine.

    SQLite and PostgreSQL support ``CREATE INDEX IF NOT EXISTS``; MySQL
    does not (error 1064), so there we probe ``information_schema`` for
    the index first. ``name``/``table``/``columns`` are package-internal
    constants, never user input.
    """
    if db.dialect.name == "mysql":
        row = await db.fetchone(
            "SELECT 1 FROM information_schema.statistics"
            " WHERE table_schema = DATABASE() AND table_name = ?"
            " AND index_name = ? LIMIT 1",
            (table, name),
        )
        if row is None:
            await db.execute(f"CREATE INDEX {name} ON {table} ({columns})")
        return
    await db.execute(f"CREATE INDEX IF NOT EXISTS {name} ON {table} ({columns})")
