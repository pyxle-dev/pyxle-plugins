from __future__ import annotations

from pathlib import Path

import pytest

from pyxle_db import Database, connect


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    return tmp_path / "test.db"


@pytest.fixture
def sync_db(db_path: Path) -> Database:
    db = Database(db_path)
    yield db
    db.close()


@pytest.fixture
async def async_db(db_path: Path) -> Database:
    db = await connect(db_path)
    try:
        yield db
    finally:
        db.close()
