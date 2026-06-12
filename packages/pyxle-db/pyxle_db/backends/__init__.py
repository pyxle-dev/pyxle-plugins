"""Backend registry — maps a parsed config to a driver adapter.

Driver imports happen lazily so the base install stays dependency-free:
SQLite always works; PostgreSQL needs ``pyxle-db[postgres]``; MySQL needs
``pyxle-db[mysql]``. A missing driver surfaces as a clear
:class:`pyxle_db.errors.ConfigurationError`, not an ImportError five
frames deep.
"""

from __future__ import annotations

from pyxle_db.backends.base import (
    MYSQL_DIALECT,
    POSTGRESQL_DIALECT,
    SQLITE_DIALECT,
    Backend,
    BackendTransaction,
    Dialect,
)
from pyxle_db.errors import ConfigurationError
from pyxle_db.url import DatabaseConfig

__all__ = [
    "Backend",
    "BackendTransaction",
    "Dialect",
    "SQLITE_DIALECT",
    "POSTGRESQL_DIALECT",
    "MYSQL_DIALECT",
    "create_backend",
]


def create_backend(config: DatabaseConfig) -> Backend:
    if config.backend == "sqlite":
        from pyxle_db.backends.sqlite import SqliteBackend

        return SqliteBackend(config)
    if config.backend == "postgresql":
        try:
            from pyxle_db.backends.postgresql import PostgresBackend
        except ImportError as exc:  # asyncpg not installed
            raise ConfigurationError(
                "PostgreSQL support requires the asyncpg driver — "
                "install with: pip install 'pyxle-db[postgres]'"
            ) from exc
        return PostgresBackend(config)
    if config.backend == "mysql":
        try:
            from pyxle_db.backends.mysql import MysqlBackend
        except ImportError as exc:  # asyncmy not installed
            raise ConfigurationError(
                "MySQL support requires the asyncmy driver — "
                "install with: pip install 'pyxle-db[mysql]'"
            ) from exc
        return MysqlBackend(config)
    raise ConfigurationError(f"Unknown backend: {config.backend!r}")
