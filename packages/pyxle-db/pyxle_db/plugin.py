"""Pyxle plugin entry point for ``pyxle-db``.

When the host app lists ``"pyxle-db"`` (or an equivalent object form)
in its :mod:`pyxle.config` ``plugins`` array, Pyxle imports this
module at startup, instantiates :class:`PyxleDbPlugin`, and runs its
:meth:`on_startup` hook inside the ASGI lifespan.

What the plugin does:

1. Opens a :class:`pyxle_db.Database` at the configured URL or path.
2. Optionally runs migrations from a directory the host app configures.
3. Registers services on the :class:`PluginContext`:

   * ``db.database`` — the open :class:`Database` (use this for queries)
   * ``db.url`` — password-redacted connection string for logging
   * ``db.path`` — resolved filesystem path (SQLite only, 0.1 back-compat)

4. On shutdown, closes the database via ``await aclose()``.

Config shape (both sugar forms accepted)::

    {
      "plugins": [
        "pyxle-db",
        {
          "name": "pyxle-db",
          "settings": {
            "url": "env:DATABASE_URL",
            "path": "./data/app.db",
            "migrationsDir": "migrations",
            "waitForFileMs": 0
          }
        }
      ]
    }

Settings keys (all optional):

* ``url`` — database URL (``sqlite:///...``, ``postgresql://...``,
  ``mysql://...``). Takes precedence over ``path`` when both are set.
  Because ``pyxle.config.json`` is committed to source control, never put
  credentials in this value directly — use the ``env:`` indirection:
  ``"url": "env:DATABASE_URL"`` resolves the ``DATABASE_URL`` environment
  variable at startup and raises :class:`pyxle_db.ConfigurationError`
  when it is unset.
* ``path`` — relative or absolute SQLite path. Default ``./data/app.db``.
  Relative paths are resolved against the host project root.
* ``migrationsDir`` — directory of ordered migration files. Default
  ``"migrations"`` if the folder exists at the project root; otherwise
  migrations are skipped.
* ``waitForFileMs`` — tolerate a transient "SQLite file doesn't exist
  yet" race by polling for this many milliseconds before opening.
  Default 0. Ignored by server backends.

Host apps that want finer control (separate DBs per environment,
custom migration sources) can continue instantiating :class:`Database`
directly — the plugin is a convenience, not a replacement.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any, Mapping, Sequence

from pyxle.plugins import PluginContext, PyxlePlugin

from pyxle_db import Database, connect
from pyxle_db.errors import ConfigurationError
from pyxle_db.url import parse_database_url


_logger = logging.getLogger("pyxle_db.plugin")

_ENV_PREFIX = "env:"


class PyxleDbPlugin(PyxlePlugin):
    name = "pyxle-db"
    version = "0.3.0"

    def middleware(self) -> Sequence[tuple[str, Mapping[str, Any]]]:
        """Inject ``request.state.db`` and manage per-request transactions.

        Runs for every request before loaders and actions. See
        :class:`pyxle_db.middleware.PyxleDbMiddleware`.
        """
        return [("pyxle_db.middleware:PyxleDbMiddleware", {})]

    async def on_startup(self, ctx: PluginContext) -> None:
        settings = dict(self.settings or {})
        project_root = _project_root_from_ctx(ctx)

        target = _database_target(settings, project_root)

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
            target,
            migrations_dir=migrations_dir,
            wait_for_file_ms=wait_ms,
        )

        redacted_url = database.config.redacted()
        ctx.register("db.database", database)
        ctx.register("db.url", redacted_url)
        # Whether the request middleware auto-commits a transaction for unsafe
        # methods. Default on; set "autoTransactions": false to manage every
        # transaction by hand.
        ctx.register(
            "db.auto_transactions",
            bool(settings.get("autoTransactions", True)),
        )

        # Optional SQLAlchemy ORM path: when "orm" is configured, build a
        # process-wide async engine + session factory against the same database
        # and register them. The middleware then injects request.state.session.
        orm_settings = settings.get("orm")
        if orm_settings is not None:
            await self._start_orm(ctx, database, orm_settings)
        if database.config.backend == "sqlite":
            # 0.1 back-compat: SQLite consumers (backup scripts, the
            # devserver's diagnostics page) read the file path directly.
            ctx.register("db.path", Path(database.config.path))

        _logger.info(
            "pyxle-db: database open at %s%s",
            redacted_url,
            f" (migrations from {migrations_dir})" if migrations_dir else "",
        )

    async def _start_orm(
        self, ctx: PluginContext, database: Database, orm_settings: Any
    ) -> None:
        """Build and register the SQLAlchemy async engine + session factory.

        Reuses the database's parsed config so the ORM connects to the same
        place the explicit-SQL handle does. Requires the ``[sqlalchemy]`` extra
        — a missing extra raises a clear ``ConfigurationError`` from the import.
        """
        from pyxle_db.orm import Engine, PoolConfig  # noqa: PLC0415 - optional extra

        pool_settings = (
            orm_settings.get("pool") if isinstance(orm_settings, Mapping) else None
        )
        engine = Engine.from_config(
            database.config, pool=PoolConfig.from_settings(pool_settings)
        )
        await engine.connect()  # verify connectivity at startup, not first request
        ctx.register("db.orm.engine", engine)
        ctx.register("db.orm.session_factory", engine.session_factory)
        _logger.info("pyxle-db: SQLAlchemy ORM engine ready")

    async def on_shutdown(self, ctx: PluginContext) -> None:
        engine = ctx.get("db.orm.engine")
        if engine is not None:
            try:
                await engine.aclose()
            except Exception:  # pragma: no cover - best-effort
                _logger.exception("pyxle-db: ORM engine aclose() failed during shutdown")

        database = ctx.get("db.database")
        if database is None:
            return
        try:
            await database.aclose()
        except Exception:  # pragma: no cover - best-effort
            _logger.exception("pyxle-db: aclose() failed during shutdown")


def _database_target(
    settings: Mapping[str, Any], project_root: Path
) -> str | Path:
    """Resolve the plugin settings to what :func:`pyxle_db.connect` opens.

    ``url`` wins over ``path``. SQLite targets (bare path, or a
    ``sqlite://`` URL with a file path) are resolved against the project
    root and their parent directory is created, matching 0.1 behaviour;
    server URLs pass through untouched.
    """
    raw_url = settings.get("url")
    if raw_url:
        url = _resolve_env_indirection(str(raw_url))
        config = parse_database_url(url)
        if config.backend == "sqlite" and config.path != ":memory:":
            return _resolved_sqlite_path(config.path, project_root)
        return url
    return _resolved_sqlite_path(
        str(settings.get("path", "./data/app.db")), project_root
    )


def _resolve_env_indirection(value: str) -> str:
    """Expand ``env:VAR_NAME`` to the variable's value, or pass through.

    Keeps credentials out of ``pyxle.config.json``: the committed config
    names the variable, the deploy environment supplies the secret.
    """
    if not value.startswith(_ENV_PREFIX):
        return value
    var_name = value[len(_ENV_PREFIX) :].strip()
    if not var_name:
        raise ConfigurationError(
            "pyxle-db: the 'url' setting uses env: indirection but names "
            'no variable — write e.g. "url": "env:DATABASE_URL"'
        )
    resolved = os.environ.get(var_name)
    if not resolved:
        raise ConfigurationError(
            f"pyxle-db: the 'url' setting points at environment variable "
            f"{var_name!r}, which is unset or empty. Export it in the "
            f"deploy environment (e.g. {var_name}=postgresql://...) "
            "before starting the app."
        )
    return resolved


def _resolved_sqlite_path(raw: str, project_root: Path) -> Path:
    """Resolve a SQLite path against the project root; ensure its folder."""
    path = Path(raw).expanduser()
    if not path.is_absolute():
        path = (project_root / path).resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


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
