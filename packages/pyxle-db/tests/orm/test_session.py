"""Tests for the request-independent get_session() helper + error translation."""

from __future__ import annotations

import pytest
from sqlalchemy import select

from pyxle_db.errors import IntegrityError
from pyxle_db.orm import Engine, get_session

from tests.orm._models import Widget


async def test_get_session_commits(engine: Engine) -> None:
    async with get_session(engine) as session:
        session.add(Widget(name="alpha"))

    # A fresh session sees the committed row.
    async with get_session(engine) as session:
        names = (await session.scalars(select(Widget.name))).all()
    assert list(names) == ["alpha"]


async def test_get_session_rolls_back_on_error(engine: Engine) -> None:
    with pytest.raises(RuntimeError):
        async with get_session(engine) as session:
            session.add(Widget(name="beta"))
            await session.flush()
            raise RuntimeError("boom")

    async with get_session(engine) as session:
        names = (await session.scalars(select(Widget.name))).all()
    assert list(names) == []  # rolled back


async def test_get_session_translates_integrity_error(engine: Engine) -> None:
    async with get_session(engine) as session:
        session.add(Widget(name="dup"))

    # A second insert of the unique name must surface as pyxle_db.IntegrityError,
    # not a raw SQLAlchemy error.
    with pytest.raises(IntegrityError):
        async with get_session(engine) as session:
            session.add(Widget(name="dup"))

    async with get_session(engine) as session:
        count = len((await session.scalars(select(Widget))).all())
    assert count == 1  # the duplicate was rolled back
