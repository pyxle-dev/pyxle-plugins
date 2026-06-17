"""Resolve the database URL + target metadata for Alembic from the pyxle-db config.

Both the scaffolded ``env.py`` and the ``pyxle-db`` Alembic commands call
:func:`resolve_alembic_runtime`, so Alembic always targets the same database the
running app does, and autogenerate compares against the app's own models.
"""

from __future__ import annotations

import importlib
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from pyxle_db.errors import ConfigurationError

#: The CLI exports the project root here before invoking Alembic, so the
#: scaffolded ``env.py`` (which runs in Alembic's process) finds the right config.
PROJECT_ROOT_ENV = "PYXLE_DB_PROJECT_ROOT"


@dataclass(frozen=True, slots=True)
class AlembicRuntime:
    """What ``env.py`` needs: the async URL, the target metadata, dialect flags."""

    url: Any  # sqlalchemy.engine.URL
    metadata: Any  # sqlalchemy MetaData | None (None disables autogenerate)
    is_sqlite: bool


def resolve_alembic_runtime(project_root: Path | None = None) -> AlembicRuntime:
    """Build the Alembic runtime from ``pyxle.config.json`` + ``.env``."""
    from pyxle_db.cli._context import resolve_target_and_settings  # noqa: PLC0415
    from pyxle_db.url import parse_database_url  # noqa: PLC0415

    if project_root is None:
        env_root = os.environ.get(PROJECT_ROOT_ENV)
        project_root = Path(env_root) if env_root else Path.cwd()
    project_root = Path(project_root).expanduser().resolve()

    # The ORM/Alembic path uses Alembic's own versions/ dir, not the checksum
    # migrator's migrations/ — so it must not require that directory.
    target, settings = resolve_target_and_settings(project_root)
    config = parse_database_url(str(target))
    metadata = _load_metadata(settings, project_root)
    return AlembicRuntime(
        url=config.sqlalchemy_url(),
        metadata=metadata,
        is_sqlite=config.backend == "sqlite",
    )


def _load_metadata(settings: Mapping[str, Any], project_root: Path) -> Any:
    """Import the ``orm.metadata`` target (``"app.models:Base"``) and return its
    ``MetaData``. Returns ``None`` when not configured — manual revisions still
    work, only autogenerate needs the metadata."""
    orm = settings.get("orm")
    ref = orm.get("metadata") if isinstance(orm, Mapping) else None
    if not ref:
        return None

    module_name, sep, attr = str(ref).partition(":")
    if not sep or not attr:
        raise ConfigurationError(
            f"pyxle-db: orm.metadata {ref!r} must be 'module.path:Attribute' "
            '(e.g. "app.models:Base").'
        )

    # The app's modules live under the project root, which isn't necessarily on
    # sys.path when Alembic runs.
    root = str(project_root)
    if root not in sys.path:
        sys.path.insert(0, root)

    try:
        module = importlib.import_module(module_name)
    except ImportError as exc:
        raise ConfigurationError(
            f"pyxle-db: could not import orm.metadata module {module_name!r}: {exc}"
        ) from exc

    obj: Any = module
    for part in attr.split("."):
        obj = getattr(obj, part, None)
        if obj is None:
            raise ConfigurationError(
                f"pyxle-db: orm.metadata {ref!r} does not resolve — {attr!r} "
                f"not found in {module_name!r}."
            )
    # A DeclarativeBase exposes .metadata; a MetaData is already what we want.
    return getattr(obj, "metadata", obj)


__all__ = ["AlembicRuntime", "resolve_alembic_runtime", "PROJECT_ROOT_ENV"]
