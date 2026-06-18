"""Single guard for the optional SQLAlchemy dependency.

The base ``pyxle_db`` library never imports SQLAlchemy. Anything under
``pyxle_db.orm`` does, and calls :func:`require_sqlalchemy` first so a missing
extra surfaces as a clear, actionable :class:`~pyxle_db.errors.ConfigurationError`
instead of a raw ``ImportError``.
"""

from __future__ import annotations

from pyxle_db.errors import ConfigurationError

INSTALL_HINT = (
    "pyxle-db ORM features require SQLAlchemy and aiosqlite. "
    "Install them with: pip install 'pyxle-db[sqlalchemy]'"
)


def require_sqlalchemy() -> None:
    """Raise :class:`ConfigurationError` with an install hint if the
    ``[sqlalchemy]`` extra is not installed."""
    try:
        import sqlalchemy.ext.asyncio  # noqa: F401
    except ImportError as exc:  # pragma: no cover - exercised with the extra absent
        raise ConfigurationError(INSTALL_HINT) from exc


__all__ = ["require_sqlalchemy", "INSTALL_HINT"]
