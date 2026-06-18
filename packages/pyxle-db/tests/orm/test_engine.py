"""Tests for the ORM Engine facade + pool config + sqlalchemy_url()."""

from __future__ import annotations


from pyxle_db.orm import Engine, PoolConfig, PoolStats
from pyxle_db.url import parse_database_url


def test_sqlalchemy_url_sqlite_file() -> None:
    url = parse_database_url("./data/app.db").sqlalchemy_url()
    assert url.drivername == "sqlite+aiosqlite"
    assert url.database == "./data/app.db"


def test_sqlalchemy_url_sqlite_memory() -> None:
    url = parse_database_url(":memory:").sqlalchemy_url()
    assert url.drivername == "sqlite+aiosqlite"
    assert url.database is None  # in-memory


def test_sqlalchemy_url_postgresql() -> None:
    url = parse_database_url("postgresql://u:p@host:5432/appdb").sqlalchemy_url()
    assert url.drivername == "postgresql+asyncpg"
    assert (url.username, url.host, url.port, url.database) == ("u", "host", 5432, "appdb")


def test_sqlalchemy_url_mysql() -> None:
    url = parse_database_url("mysql://u:p@host:3306/appdb").sqlalchemy_url()
    assert url.drivername == "mysql+asyncmy"
    assert url.database == "appdb"


def test_pool_config_from_settings() -> None:
    pool = PoolConfig.from_settings({"poolSize": 20, "poolPrePing": False})
    assert pool.pool_size == 20
    assert pool.pool_pre_ping is False
    # Defaults stay for unset keys.
    assert pool.max_overflow == 10


def test_pool_config_defaults_pre_ping_on() -> None:
    assert PoolConfig().pool_pre_ping is True


async def test_engine_connect_and_close(engine: Engine) -> None:
    # The fixture already created the schema; a no-op round-trip must succeed.
    await engine.connect()
    stats = engine.pool_stats()
    assert isinstance(stats, PoolStats)
    # aclose is idempotent (the fixture closes too).
    await engine.aclose()


async def test_engine_file_backend(tmp_path) -> None:
    db_file = tmp_path / "orm.db"
    eng = Engine.from_config(parse_database_url(str(db_file)))
    try:
        await eng.connect()
        assert eng.config.backend == "sqlite"
    finally:
        await eng.aclose()
