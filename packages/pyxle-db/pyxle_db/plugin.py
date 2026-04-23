"""Pyxle plugin entry point for ``pyxle-db``.

When the host app lists ``"pyxle-db"`` (or an equivalent object form)
in its :mod:`pyxle.config` ``plugins`` array, Pyxle imports this
module at startup, instantiates :class:`PyxleDbPlugin`, and runs its
:meth:`on_startup` hook inside the ASGI lifespan.

What the plugin does:

1. Opens a :class:`pyxle_db.Database` at the configured path.
2. Optionally runs migrations from a directory the host app configures.
3. Registers three services on the :class:`PluginContext`:

   * ``db.database`` — the open :class:`Database` (use this for queries)
   * ``db.path`` — the resolved filesystem path for logging/diagnostics
   * ``db.migrations_applied`` — the list of migration IDs applied

4. On shutdown, closes the database connection pool.

Config shape (both sugar forms accepted)::

    {
      "plugins": [
        "pyxle-db",
        {
          "name": "pyxle-db",
          "settings": {
            "path": "./data/app.db",
            "migrationsDir": "migrations",
            "waitForFileMs": 0
          }
        }
      ]
    }

Settings keys (all optional):

* ``path`` — relative or absolute database path. Default ``./data/app.db``.
  Relative paths are resolved against the host project root.
* ``migrationsDir`` — directory of ordered migration files. Default
  ``"migrations"`` if the folder exists at the project root; otherwise
  migrations are skipped.
* ``waitForFileMs`` — tolerate a transient "file doesn't exist yet"
  race by polling for this many milliseconds before opening. Default 0.

Host apps that want finer control (separate DBs per environment,
custom migration sources) can continue instantiating :class:`Database`
directly — the plugin is a convenience, not a replacement.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from pyxle.plugins import PluginContext, PyxlePlugin

from pyxle_db import Database, connect


_logger = logging.getLogger("pyxle_db.plugin")


class PyxleDbPlugin(PyxlePlugin):
    name = "pyxle-db"
    version = "0.1.0"

    async def on_startup(self, ctx: PluginContext) -> None:
        settings = dict(self.settings or {})
        project_root = _project_root_from_ctx(ctx)

        raw_path = settings.get("path", "./data/app.db")
        db_path = Path(raw_path).expanduser()
        if not db_path.is_absolute():
            db_path = (project_root / db_path).resolve()
        db_path.parent.mkdir(parents=True, exist_ok=True)

        migrations_dir: Path | None = None
        raw_migrations = settings.get("migrationsDir", "migrations")
        if raw_migrations:
            candidate = Path(raw_migrations).expanduser()
            if not candidate.is_absolute():
                candidate = (project_root / candidate).resolve()
            if candidate.is_dir():
                migrations_dir = candidate

        wait_ms = int(settings.get("waitForFileMs", 0) or 0)

        database: Database = await connect(
            db_path,
            migrations_dir=migrations_dir,
            wait_for_file_ms=wait_ms,
        )

        ctx.register("db.database", database)
        ctx.register("db.path", db_path)

        _logger.info(
            "pyxle-db: database open at %s%s",
            db_path,
            f" (migrations from {migrations_dir})" if migrations_dir else "",
        )

    async def on_shutdown(self, ctx: PluginContext) -> None:
        database = ctx.get("db.database")
        if database is None:
            return
        try:
            database.close()
        except Exception:  # pragma: no cover - best-effort
            _logger.exception("pyxle-db: close() failed during shutdown")


def _project_root_from_ctx(ctx: PluginContext) -> Path:
    """Pull the project root off the host's devserver settings.

    Kept in a helper so future changes to the settings layout (e.g. a
    renamed field) have exactly one edit point. Falls back to ``.``
    if the ctx wasn't constructed with a DevServerSettings — mostly a
    convenience for unit tests that new up a plain ``PluginContext()``.
    """
    settings = ctx.settings
    if settings is None:
        return Path.cwd()
    root = getattr(settings, "project_root", None)
    if root is None:
        return Path.cwd()
    return Path(root)


# Convention: Pyxle's loader looks for ``plugin`` on the module.
# Exporting the class (not an instance) lets Pyxle instantiate once per
# app, and each instance gets its own ``self.settings`` populated from
# the entry's ``settings`` dict.
plugin = PyxleDbPlugin
