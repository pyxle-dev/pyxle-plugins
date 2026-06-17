"""Resolve the database target + migrations directory for the ``pyxle-db`` CLI.

The CLI reads the **same** ``pyxle.config.json`` plugin settings and ``.env``
(``DATABASE_URL``) the running app uses, via Pyxle's public ``load_config`` and
``load_env_files`` — so ``pyxle-db migrate`` always targets the identical
database the server would open.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from pyxle_db.errors import ConfigurationError

_PLUGIN_NAMES = frozenset({"pyxle-db", "pyxle_db"})


@dataclass(frozen=True, slots=True)
class MigrationContext:
    """What the CLI needs to open the database and run migrations."""

    target: str | Path
    migrations_dir: Path
    settings: Mapping[str, Any]


def resolve_target_and_settings(
    project_root: Path, *, config_path: Path | None = None
) -> tuple[str | Path, Mapping[str, Any]]:
    """Load config + env and resolve the pyxle-db database target and settings.

    Shared by the checksum migrator (which also needs a migrations directory)
    and the ORM/Alembic path (which does not). Raises :class:`ConfigurationError`
    when ``pyxle-db`` isn't configured.
    """
    # Local imports: the CLI depends on pyxle core, but importing it lazily keeps
    # ``import pyxle_db`` (the library surface) free of the framework.
    from pyxle.config import load_config
    from pyxle.env import load_env_files

    from pyxle_db.plugin import _database_target

    project_root = project_root.expanduser().resolve()
    load_env_files(project_root, mode="production")
    config = load_config(project_root, config_path=config_path)

    settings = _find_plugin_settings(config.plugins, source=project_root)
    if settings is None:
        raise ConfigurationError(
            "pyxle-db is not listed in pyxle.config.json::plugins. Add it (or "
            "pass --config to point at the right config file) before running "
            "this command."
        )

    target = _database_target(dict(settings), project_root)
    return target, settings


def resolve_context(
    project_root: Path, *, config_path: Path | None = None
) -> MigrationContext:
    """Resolve the target, settings, AND checksum-migrations directory.

    Used by ``pyxle-db migrate``/``status``. Raises :class:`ConfigurationError`
    when the migrations directory is missing.
    """
    project_root = project_root.expanduser().resolve()
    target, settings = resolve_target_and_settings(project_root, config_path=config_path)
    migrations_dir = _resolve_migrations_dir(settings, project_root)
    return MigrationContext(
        target=target, migrations_dir=migrations_dir, settings=settings
    )


def _find_plugin_settings(
    plugins: Any, *, source: Path
) -> Mapping[str, Any] | None:
    from pyxle.plugins import PluginSpec

    for entry in plugins or ():
        try:
            spec = PluginSpec.from_config_entry(entry, source=source)
        except Exception:  # noqa: BLE001 - a malformed entry just isn't ours
            continue
        if spec.name in _PLUGIN_NAMES:
            return spec.settings
    return None


def _resolve_migrations_dir(
    settings: Mapping[str, Any], project_root: Path
) -> Path:
    raw = settings.get("migrationsDir", "migrations") or "migrations"
    candidate = Path(raw).expanduser()
    if not candidate.is_absolute():
        candidate = (project_root / candidate).resolve()
    if not candidate.is_dir():
        raise ConfigurationError(
            f"Migrations directory {str(candidate)!r} does not exist. Create it "
            "and add migration files (e.g. 0001-init.sql), or set "
            '"migrationsDir" in the pyxle-db plugin settings.'
        )
    return candidate
