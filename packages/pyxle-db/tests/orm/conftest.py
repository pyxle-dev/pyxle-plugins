"""Fixtures for the ORM tests — an in-memory engine with the schema created."""
from __future__ import annotations

from typing import AsyncIterator

import pytest

from pyxle_db.orm import Base, Engine
from pyxle_db.url import parse_database_url

from tests.orm import _models  # noqa: F401 - registers Widget on Base.metadata


@pytest.fixture
async def engine() -> AsyncIterator[Engine]:
    eng = Engine.from_config(parse_database_url(":memory:"))
    async with eng.sqlalchemy_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    try:
        yield eng
    finally:
        await eng.aclose()
