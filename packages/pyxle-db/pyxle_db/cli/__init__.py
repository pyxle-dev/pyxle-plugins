"""``pyxle-db`` command-line interface.

The checksum-tracked migrator is exposed here:

* ``pyxle-db migrate``            — apply every pending migration
* ``pyxle-db migrate --dry-run``  — show what would be applied, change nothing
* ``pyxle-db status``             — list applied vs pending migrations

All commands resolve the same database the app uses (``pyxle.config.json`` +
``.env``); pass ``--project DIR`` to run from elsewhere and ``--config FILE`` to
point at a non-default config.

ORM/Alembic commands (``revision``, ``upgrade``, ...) are added when
``pyxle-db[sqlalchemy]`` is installed; see :mod:`pyxle_db.cli.alembic_cmds`.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from pyxle.cli.logger import ConsoleLogger

from pyxle_db import connect
from pyxle_db.cli._context import MigrationContext, resolve_context
from pyxle_db.errors import DatabaseError
from pyxle_db.migrator import Migrator


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pyxle-db",
        description="Database migrations and tooling for a Pyxle app.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    def _common(sub: argparse.ArgumentParser) -> None:
        sub.add_argument(
            "--project",
            type=Path,
            default=Path.cwd(),
            help="Project root containing pyxle.config.json (default: cwd).",
        )
        sub.add_argument(
            "--config",
            type=Path,
            default=None,
            help="Path to a non-default pyxle.config.json.",
        )

    migrate = subparsers.add_parser(
        "migrate", help="Apply pending migrations (checksum-tracked)."
    )
    _common(migrate)
    migrate.add_argument(
        "--dry-run",
        action="store_true",
        help="Show which migrations would be applied without applying them.",
    )

    status = subparsers.add_parser(
        "status", help="Show applied vs pending migrations."
    )
    _common(status)

    def _project_only(sub: argparse.ArgumentParser) -> None:
        sub.add_argument(
            "--project",
            type=Path,
            default=Path.cwd(),
            help="Project root containing pyxle.config.json (default: cwd).",
        )

    # --- ORM / Alembic commands (require the [sqlalchemy] extra) ---
    alembic_init = subparsers.add_parser(
        "alembic-init", help="Scaffold Alembic (ORM migrations) for this project."
    )
    _project_only(alembic_init)

    revision = subparsers.add_parser(
        "revision", help="Create a new Alembic revision (ORM)."
    )
    _project_only(revision)
    revision.add_argument("-m", "--message", required=True, help="Revision message.")
    revision.add_argument(
        "--autogenerate",
        action="store_true",
        help="Diff the models against the database to fill the revision.",
    )

    upgrade = subparsers.add_parser("upgrade", help="Run Alembic upgrade (ORM).")
    _project_only(upgrade)
    upgrade.add_argument("revision", nargs="?", default="head", help="Target (default: head).")

    downgrade = subparsers.add_parser("downgrade", help="Run Alembic downgrade (ORM).")
    _project_only(downgrade)
    downgrade.add_argument("revision", nargs="?", default="-1", help="Target (default: -1).")

    current = subparsers.add_parser("current", help="Show the current Alembic revision.")
    _project_only(current)

    history = subparsers.add_parser("history", help="Show the Alembic revision history.")
    _project_only(history)

    return parser


async def _run_migrate(ctx: MigrationContext, *, dry_run: bool, logger: ConsoleLogger) -> None:
    db = await connect(ctx.target)
    try:
        migrator = Migrator(db, ctx.migrations_dir)
        if dry_run:
            snapshot = await migrator.status()
            if not snapshot.pending:
                logger.success("Up to date — no pending migrations.")
                return
            logger.info(f"{len(snapshot.pending)} migration(s) would be applied:")
            for migration in snapshot.pending:
                logger.info(f"  • {migration.id}")
            return
        applied = await migrator.apply_all()
        if not applied:
            logger.success("Up to date — no pending migrations.")
            return
        logger.success(f"Applied {len(applied)} migration(s):")
        for migration in applied:
            logger.info(f"  • {migration.id}")
    finally:
        await db.aclose()


async def _run_status(ctx: MigrationContext, *, logger: ConsoleLogger) -> None:
    db = await connect(ctx.target)
    try:
        snapshot = await Migrator(db, ctx.migrations_dir).status()
        logger.info(
            f"{len(snapshot.applied)} applied, {len(snapshot.pending)} pending."
        )
        for migration in snapshot.applied:
            logger.success(f"  ✓ {migration.id}")
        for migration in snapshot.pending:
            logger.warning(f"  ○ {migration.id} (pending)")
    finally:
        await db.aclose()


def main(argv: list[str] | None = None) -> int:
    """CLI entry point. Returns a process exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)
    logger = ConsoleLogger()

    try:
        if args.command == "migrate":
            ctx = resolve_context(args.project, config_path=args.config)
            asyncio.run(_run_migrate(ctx, dry_run=args.dry_run, logger=logger))
        elif args.command == "status":
            ctx = resolve_context(args.project, config_path=args.config)
            asyncio.run(_run_status(ctx, logger=logger))
        else:
            # Alembic commands manage their own event loop (inside env.py), so
            # they are called synchronously.
            _run_alembic_command(args, logger)
    except DatabaseError as exc:
        # Configuration, migration drift, connection failures — surface the
        # message, not a traceback.
        logger.error(str(exc))
        return 1
    return 0


def _run_alembic_command(args: argparse.Namespace, logger: ConsoleLogger) -> None:
    from pyxle_db.cli import alembic_cmds  # noqa: PLC0415

    project = args.project
    if args.command == "alembic-init":
        alembic_cmds.init(project, logger=logger)
    elif args.command == "revision":
        alembic_cmds.revision(
            project, message=args.message, autogenerate=args.autogenerate, logger=logger
        )
    elif args.command == "upgrade":
        alembic_cmds.upgrade(project, revision=args.revision, logger=logger)
    elif args.command == "downgrade":
        alembic_cmds.downgrade(project, revision=args.revision, logger=logger)
    elif args.command == "current":
        alembic_cmds.current(project, logger=logger)
    elif args.command == "history":
        alembic_cmds.history(project, logger=logger)


def app() -> None:
    """Console-script shim: run :func:`main` and exit with its code."""
    sys.exit(main())


__all__ = ["main", "app", "build_parser"]
