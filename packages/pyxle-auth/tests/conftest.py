from __future__ import annotations

from pathlib import Path

import pytest

from pyxle_auth import AuthService, AuthSettings
from pyxle_db import Database, connect


@pytest.fixture
async def db(tmp_path: Path) -> Database:
    db = await connect(tmp_path / "auth.db")
    try:
        yield db
    finally:
        db.close()


@pytest.fixture
def settings() -> AuthSettings:
    # for_tests() drops argon cost and cookie_secure.
    return AuthSettings(strict=False).for_tests()


@pytest.fixture
async def auth(db: Database, settings: AuthSettings) -> AuthService:
    service = AuthService(db, settings)
    await service.ensure_schema()
    return service
