"""Connection-pool configuration for the ORM async engine."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping


@dataclass(frozen=True, slots=True)
class PoolConfig:
    """Async-engine connection-pool settings.

    These apply to the server backends (PostgreSQL/MySQL). SQLite does not pool
    like a networked server, so the engine ignores the size knobs there.

    ``pool_pre_ping`` defaults on: SQLAlchemy checks a connection is alive before
    handing it out, so a database restart or an idle-killed connection surfaces
    as a transparent reconnect rather than a failed request — the enterprise
    default.
    """

    pool_size: int = 5
    max_overflow: int = 10
    pool_timeout: float = 30.0
    pool_recycle: int = 1800  # seconds; recycle connections older than 30 min
    pool_pre_ping: bool = True

    @classmethod
    def from_settings(cls, settings: Mapping[str, Any] | None) -> "PoolConfig":
        """Build from the plugin's ``pool`` settings sub-mapping (all optional)."""
        pool = dict(settings or {})
        # ``slots=True`` turns class-level field access into slot descriptors, so
        # read the defaults from a default instance.
        d = cls()
        return cls(
            pool_size=int(pool.get("poolSize", d.pool_size)),
            max_overflow=int(pool.get("maxOverflow", d.max_overflow)),
            pool_timeout=float(pool.get("poolTimeout", d.pool_timeout)),
            pool_recycle=int(pool.get("poolRecycle", d.pool_recycle)),
            pool_pre_ping=bool(pool.get("poolPrePing", d.pool_pre_ping)),
        )


__all__ = ["PoolConfig"]
