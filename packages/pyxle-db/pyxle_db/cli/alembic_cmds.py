"""``pyxle-db`` Alembic commands (require the ``[sqlalchemy]`` extra).

Thin wrappers over Alembic's Python API: each builds an Alembic ``Config`` from
the scaffolded ``alembic.ini`` and exports the project root so the generated
``env.py`` resolves the same database the app uses.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import Any

from pyxle_db.errors import ConfigurationError
from pyxle_db.orm.alembic.runtime import PROJECT_ROOT_ENV


def _templates_dir() -> Path:
    from pyxle_db.orm import alembic as pkg  # noqa: PLC0415

    return Path(pkg.__file__).resolve().parent


def _require_alembic() -> None:
    try:
        import alembic.command  # noqa: F401, PLC0415
        import alembic.config  # noqa: F401, PLC0415
    except ImportError as exc:  # pragma: no cover - exercised with the extra absent
        raise ConfigurationError(
            "pyxle-db Alembic commands require the ORM extra. Install it with: "
            "pip install 'pyxle-db[sqlalchemy]'"
        ) from exc


def init(project_root: Path, *, logger: Any) -> None:
    """Scaffold ``alembic.ini`` + ``alembic/`` (env.py, script.py.mako, versions/)."""
    _require_alembic()
    templates = _templates_dir()
    ini = project_root / "alembic.ini"
    alembic_dir = project_root / "alembic"
    versions = alembic_dir / "versions"

    if ini.exists() or alembic_dir.exists():
        raise ConfigurationError(
            f"Alembic already initialised ({ini.name} / {alembic_dir.name}/ exist). "
            "Remove them to re-scaffold."
        )

    alembic_dir.mkdir(parents=True)
    versions.mkdir()
    shutil.copyfile(templates / "alembic.ini.tmpl", ini)
    shutil.copyfile(templates / "env.py.tmpl", alembic_dir / "env.py")
    shutil.copyfile(templates / "script.py.mako", alembic_dir / "script.py.mako")
    (versions / ".gitkeep").write_text("", encoding="utf-8")

    logger.success(f"Scaffolded Alembic: {ini.name} and {alembic_dir.name}/")
    logger.info(
        'Point autogenerate at your models in pyxle.config.json: '
        '"orm": {"metadata": "app.models:Base"}'
    )


def _config(project_root: Path) -> Any:
    _require_alembic()
    from alembic.config import Config  # noqa: PLC0415

    ini = project_root / "alembic.ini"
    if not ini.exists():
        raise ConfigurationError(
            "No alembic.ini found — run 'pyxle-db alembic-init' first."
        )
    # env.py (run inside Alembic) reads this to resolve the project's config.
    os.environ[PROJECT_ROOT_ENV] = str(project_root)
    cfg = Config(str(ini))
    cfg.set_main_option("script_location", str(project_root / "alembic"))
    return cfg


def revision(project_root: Path, *, message: str, autogenerate: bool, logger: Any) -> None:
    from alembic import command  # noqa: PLC0415

    command.revision(_config(project_root), message=message, autogenerate=autogenerate)


def upgrade(project_root: Path, *, revision: str, logger: Any) -> None:
    from alembic import command  # noqa: PLC0415

    command.upgrade(_config(project_root), revision)


def downgrade(project_root: Path, *, revision: str, logger: Any) -> None:
    from alembic import command  # noqa: PLC0415

    command.downgrade(_config(project_root), revision)


def current(project_root: Path, *, logger: Any) -> None:
    from alembic import command  # noqa: PLC0415

    command.current(_config(project_root))


def history(project_root: Path, *, logger: Any) -> None:
    from alembic import command  # noqa: PLC0415

    command.history(_config(project_root))


__all__ = ["init", "revision", "upgrade", "downgrade", "current", "history"]
