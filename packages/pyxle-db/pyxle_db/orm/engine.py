"""Async engine + session-factory facade for the ORM path.

One :class:`Engine` per process owns a single SQLAlchemy ``AsyncEngine`` and a
single ``async_sessionmaker``. Individual ``AsyncSession`` objects are always
request-scoped (created and closed by the middleware, or by
:func:`pyxle_db.orm.session.get_session` for work outside a request) — sessions
are never shared across requests, which an ``AsyncSession`` does not support.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from pyxle_db.orm._imports import require_sqlalchemy
from pyxle_db.orm.pool import PoolConfig
from pyxle_db.url import DatabaseConfig

_logger = logging.getLogger("pyxle_db.orm")


@dataclass(frozen=True, slots=True)
class PoolStats:
    """A snapshot of the async engine's connection-pool usage (for metrics)."""

    size: int
    checked_in: int
    checked_out: int
    overflow: int


class Engine:
    """Process-wide async engine + session factory for the ORM path."""

    __slots__ = ("_engine", "_session_factory", "_config")

    def __init__(self, async_engine: Any, session_factory: Any, config: DatabaseConfig) -> None:
        self._engine = async_engine
        self._session_factory = session_factory
        self._config = config

    @classmethod
    def from_config(
        cls, config: DatabaseConfig, *, pool: PoolConfig | None = None
    ) -> "Engine":
        """Create an async engine + ``async_sessionmaker`` for *config*.

        SQLite is special-cased (a server-style pool does not apply): an
        in-memory database uses a shared ``StaticPool`` so every session sees the
        same data, and a file database uses the default pool with the
        server-pool knobs ignored.
        """
        require_sqlalchemy()
        from sqlalchemy.ext.asyncio import (  # noqa: PLC0415 - optional extra
            async_sessionmaker,
            create_async_engine,
        )
        from sqlalchemy.pool import StaticPool  # noqa: PLC0415

        pool = pool or PoolConfig()
        url = config.sqlalchemy_url()
        kwargs: dict[str, Any] = {}

        if config.backend == "sqlite":
            if config.path == ":memory:":
                # Without a shared connection each session would get its own
                # private in-memory database.
                kwargs["poolclass"] = StaticPool
                kwargs["connect_args"] = {"check_same_thread": False}
            if pool != PoolConfig():
                _logger.debug(
                    "pyxle-db ORM: pool settings are ignored for the SQLite backend"
                )
        else:
            kwargs.update(
                pool_size=pool.pool_size,
                max_overflow=pool.max_overflow,
                pool_timeout=pool.pool_timeout,
                pool_recycle=pool.pool_recycle,
                pool_pre_ping=pool.pool_pre_ping,
            )

        engine = create_async_engine(url, **kwargs)
        # expire_on_commit=False keeps loaded objects usable after the auto-commit
        # the middleware performs at request end.
        factory = async_sessionmaker(engine, expire_on_commit=False)
        return cls(engine, factory, config)

    @property
    def session_factory(self) -> Any:
        """The process-wide ``async_sessionmaker``."""
        return self._session_factory

    @property
    def sqlalchemy_engine(self) -> Any:
        """The underlying ``AsyncEngine`` (e.g. for Alembic or event listeners)."""
        return self._engine

    @property
    def config(self) -> DatabaseConfig:
        return self._config

    async def connect(self) -> None:
        """Verify connectivity with a no-op round-trip (idempotent)."""
        from sqlalchemy import text  # noqa: PLC0415

        async with self._engine.connect() as conn:
            await conn.execute(text("SELECT 1"))

    async def aclose(self) -> None:
        """Dispose the engine and its pool."""
        await self._engine.dispose()

    def pool_stats(self) -> PoolStats:
        """Current pool usage. SQLite pools may report zeros for some fields."""
        pool = self._engine.pool

        def _read(name: str) -> int:
            fn = getattr(pool, name, None)
            if not callable(fn):
                return 0
            try:
                return int(fn())
            except Exception:  # noqa: BLE001 - pool implementations vary
                return 0

        return PoolStats(
            size=_read("size"),
            checked_in=_read("checkedin"),
            checked_out=_read("checkedout"),
            overflow=_read("overflow"),
        )


__all__ = ["Engine", "PoolStats"]
