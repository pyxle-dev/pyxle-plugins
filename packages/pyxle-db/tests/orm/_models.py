"""A shared ORM model for the orm tests (defined once on pyxle_db.orm.Base)."""
from __future__ import annotations

from sqlalchemy.orm import Mapped, mapped_column

from pyxle_db.orm import Base


class Widget(Base):
    __tablename__ = "widgets"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(unique=True)
