"""The structural contract a database layer satisfies to back Pyxle plugins.

:class:`pyxle_db.Database` is the reference implementation, but consumers
like ``pyxle-auth`` bind to the *shape*, not the class: anything registered
as the ``db.database`` plugin service that satisfies :class:`DatabaseLike`
can back them — a community SQLAlchemy plugin, a bespoke driver wrapper,
a test fake. The full contract such a replacement must honour:

1. **Surface.** The members of :class:`DatabaseLike` (and
   :class:`TransactionLike` for the object its ``transaction()`` yields).
   SQL arrives in canonical qmark style (``?`` placeholders, ``??``
   escape); rows come back as :class:`pyxle_db.Row`.
2. **Errors.** Unique-constraint violations must raise
   :class:`pyxle_db.IntegrityError` — consumers convert it into domain
   behaviour (e.g. pyxle-auth's "account already exists"). Other failures
   should map onto the matching :mod:`pyxle_db.errors` types.
3. **Dialect.** ``dialect`` is a :class:`pyxle_db.Dialect` whose ``name``
   consumers may branch on for DDL (``sqlite`` | ``postgresql`` |
   ``mysql`` have tested paths; other names fall back to the
   SQLite/PostgreSQL-flavoured DDL).
4. **Datetimes.** Reads return timezone-aware UTC datetimes; binds accept
   naive (assumed UTC) or aware (converted to UTC) datetimes.

Both protocols are ``runtime_checkable``: ``isinstance(obj, DatabaseLike)``
verifies member *presence* (signatures are checked statically only).
"""

from __future__ import annotations

from typing import Any, AsyncContextManager, Protocol, Sequence, runtime_checkable

from pyxle_db.backends.base import Dialect
from pyxle_db.rows import Row

__all__ = ["DatabaseLike", "TransactionLike"]

Params = Sequence[Any]


@runtime_checkable
class TransactionLike(Protocol):
    """What ``DatabaseLike.transaction()`` must yield: the same query
    surface, executed inside one transaction that commits on clean exit
    and rolls back when the block raises."""

    async def execute(self, sql: str, params: Params | None = None) -> int: ...

    async def fetchone(self, sql: str, params: Params | None = None) -> Row | None: ...

    async def fetchall(self, sql: str, params: Params | None = None) -> list[Row]: ...


@runtime_checkable
class DatabaseLike(Protocol):
    """The five-member surface Pyxle plugins require of a database layer."""

    @property
    def dialect(self) -> Dialect: ...

    async def execute(self, sql: str, params: Params | None = None) -> int: ...

    async def fetchone(self, sql: str, params: Params | None = None) -> Row | None: ...

    async def fetchall(self, sql: str, params: Params | None = None) -> list[Row]: ...

    def transaction(self) -> AsyncContextManager[TransactionLike]: ...
