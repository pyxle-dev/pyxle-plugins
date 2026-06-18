"""SQLAlchemy ORM path for pyxle-db (optional ``[sqlalchemy]`` extra).

Importing this subpackage requires the extra; without it, the import raises a
clear :class:`~pyxle_db.errors.ConfigurationError` with the install command. The
base ``import pyxle_db`` never reaches here, so the core library stays
SQLAlchemy-free.

Typical app usage::

    from pyxle_db.orm import Base
    from sqlalchemy.orm import Mapped, mapped_column

    class Note(Base):
        __tablename__ = "notes"
        id: Mapped[int] = mapped_column(primary_key=True)
        body: Mapped[str]

    # In a loader/action, the request-scoped session is injected:
    async def load(request):
        notes = (await request.state.session.scalars(select(Note))).all()
"""

from __future__ import annotations

from pyxle_db.orm._imports import require_sqlalchemy

# Fail fast (and clearly) if the extra is missing — before any SQLAlchemy import.
require_sqlalchemy()

from sqlalchemy.orm import DeclarativeBase  # noqa: E402 - must follow the guard

from pyxle_db.orm.engine import Engine, PoolStats  # noqa: E402
from pyxle_db.orm.pool import PoolConfig  # noqa: E402
from pyxle_db.orm.session import get_session  # noqa: E402


class Base(DeclarativeBase):
    """Declarative base class for application ORM models.

    Its ``metadata`` is what Alembic autogenerate compares against; keep all
    models importing this single ``Base`` so migrations see the full schema.
    """


__all__ = ["Base", "Engine", "PoolConfig", "PoolStats", "get_session"]
