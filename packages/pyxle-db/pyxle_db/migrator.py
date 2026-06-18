"""Filesystem-driven migrations for pyxle-db.

Conventions:

* Each migration is a ``.sql`` file in the migrations directory.
* Filenames start with a zero-padded numeric prefix (``0001``, ``0002``,
  ...) followed by a separator and a slug: ``0001-initial-schema.sql``.
  The numeric prefix is the canonical ordering; the slug is freeform and
  recorded for humans.
* A migration may ship a per-backend override named
  ``<NNN>-<slug>.<dialect>.sql`` (e.g. ``0002-indexes.postgresql.sql``).
  On that dialect the override is the effective file; every other dialect
  uses the base file. An override without a base file is a backend-only
  migration — the other dialects skip that id entirely.
* The migration id is ``<NNN>-<slug>``, dialect-independent, so the same
  logical migration is recorded under one id on every backend. Two files
  that resolve to the same id for the same effective dialect are rejected
  at :meth:`Migrator.discover`.
* A migration is applied exactly once per database. Every applied
  migration is recorded in a ``schema_migrations`` table with the SHA-256
  of the *effective* file's content — so a PostgreSQL and a SQLite
  database may legitimately record different checksums for the same id.
  Editing a migration after it was applied (including adding an override
  for an already-applied id) is detected per database and rejected.
* Each migration runs in its own transaction: statements execute
  sequentially and the ``schema_migrations`` insert rides the same
  transaction, so a failure rolls back that migration completely and
  leaves previously-applied migrations untouched.
* Migration SQL passes through the :class:`pyxle_db.Database` facade like
  any other SQL, so the canonical placeholder rules apply: write ``??``
  for a literal question mark (PostgreSQL JSON operators). There is no
  templating or variable substitution.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from pyxle_db.backends import MYSQL_DIALECT, POSTGRESQL_DIALECT, SQLITE_DIALECT
from pyxle_db.database import Database
from pyxle_db.errors import MigrationChecksumMismatch, MigrationError
from pyxle_db.sql import split_statements

_IDENTIFIER_RE = re.compile(r"^[a-z_][a-z0-9_]*$")

_DIALECT_NAMES = frozenset(
    dialect.name for dialect in (SQLITE_DIALECT, POSTGRESQL_DIALECT, MYSQL_DIALECT)
)

_FILENAME_RE = re.compile(
    r"^(?P<prefix>\d{3,})[-_](?P<slug>[A-Za-z0-9_\-]+)"
    rf"(?:\.(?P<dialect>{'|'.join(sorted(_DIALECT_NAMES))}))?\.sql$"
)


@dataclass(frozen=True, slots=True)
class Migration:
    """A single migration, resolved for one dialect and ready to apply.

    Attributes:
        id: ``<NNN>-<slug>`` — dialect-independent; the primary key in
            ``schema_migrations``.
        prefix: The numeric prefix, parsed for ordering.
        slug: The human-readable description.
        source_path: The effective file on disk — the per-dialect override
            when one exists, the base file otherwise.
        sql: The contents of the effective file.
        checksum: SHA-256 of the effective file's content, hex-encoded.
            Because overrides differ per backend, databases of different
            dialects may record different checksums for the same id —
            that is expected and correct.
    """

    id: str
    prefix: int
    slug: str
    source_path: Path
    sql: str
    checksum: str


@dataclass(frozen=True, slots=True)
class MigrationStatus:
    """A snapshot of which migrations are applied vs still pending.

    Returned by :meth:`Migrator.status` for the ``pyxle-db status`` /
    ``--dry-run`` CLI. ``applied`` and ``pending`` are ordered by prefix, and
    together cover every discovered migration.
    """

    applied: tuple[Migration, ...]
    pending: tuple[Migration, ...]


@dataclass(frozen=True, slots=True)
class _MigrationFile:
    """A parsed migration filename; contents are not read at this stage."""

    path: Path
    id: str
    prefix: int
    slug: str
    dialect: str | None


def _parse_filename(path: Path) -> _MigrationFile:
    match = _FILENAME_RE.match(path.name)
    if match is None:
        raise MigrationError(
            f"Migration filename {path.name!r} does not match "
            "<NNN>-<slug>[.<dialect>].sql (e.g. 0001-initial-schema.sql "
            "or 0002-indexes.postgresql.sql)"
        )
    prefix = match.group("prefix")
    slug = match.group("slug")
    return _MigrationFile(
        path=path,
        id=f"{prefix}-{slug}",
        prefix=int(prefix),
        slug=slug,
        dialect=match.group("dialect"),
    )


def select_migration_files(files: Iterable[Path], dialect_name: str) -> list[Path]:
    """Pick the effective migration file per id for ``dialect_name``.

    Pure function over filenames — no I/O — so override resolution is
    testable without a database server. Rules:

    * ``<NNN>-<slug>.<dialect>.sql`` beats ``<NNN>-<slug>.sql`` when
      ``dialect`` equals ``dialect_name``.
    * Overrides for other dialects are ignored.
    * An override with no base file is a backend-only migration: selected
      on its dialect, silently skipped everywhere else.

    Returns the effective paths sorted by numeric prefix. Raises
    :class:`MigrationError` for a malformed filename, two files resolving
    to the same id for the same dialect, an unknown ``dialect_name``, or
    two distinct migration ids sharing a numeric prefix.
    """
    if dialect_name not in _DIALECT_NAMES:
        raise MigrationError(
            f"Unknown dialect {dialect_name!r}; expected one of "
            f"{sorted(_DIALECT_NAMES)}"
        )

    parsed = sorted(
        (_parse_filename(path) for path in files), key=lambda f: f.path.name
    )

    seen: dict[tuple[str, str | None], _MigrationFile] = {}
    for file in parsed:
        clash = seen.get((file.id, file.dialect))
        if clash is not None:
            scope = f"dialect {file.dialect!r}" if file.dialect else "every dialect"
            raise MigrationError(
                f"{clash.path.name} and {file.path.name} both resolve to the "
                f"same migration id {file.id!r} for {scope}"
            )
        seen[(file.id, file.dialect)] = file

    prefix_owners: dict[int, str] = {}
    for file in parsed:
        owner = prefix_owners.setdefault(file.prefix, file.id)
        if owner != file.id:
            raise MigrationError(
                f"Two migrations share prefix {file.prefix}: "
                f"{owner!r} and {file.id!r}"
            )

    effective: dict[str, _MigrationFile] = {}
    for file in parsed:
        if file.dialect is None:
            effective.setdefault(file.id, file)
    for file in parsed:
        if file.dialect == dialect_name:
            effective[file.id] = file

    return [f.path for f in sorted(effective.values(), key=lambda f: f.prefix)]


class Migrator:
    """Applies ordered migrations to a :class:`Database` of any backend.

    All database access goes through the facade's async API, so the same
    migrator works on SQLite, PostgreSQL, and MySQL.

    .. code-block:: python

        migrator = Migrator(db, Path("migrations"))
        await migrator.apply_all()
    """

    def __init__(
        self,
        db: Database,
        directory: Path,
        *,
        tracking_table: str = "schema_migrations",
    ) -> None:
        if not directory.is_dir():
            raise MigrationError(
                f"Migrations directory does not exist: {directory}"
            )
        # The tracking table name is interpolated into DDL/DML, so it must be
        # a plain identifier — never attacker-controlled, but validated so a
        # typo fails loudly instead of producing malformed SQL. Distinct
        # tables let independent migration sources (e.g. a host app and the
        # pyxle-auth plugin) share ONE database without each seeing the
        # other's migrations as drift.
        if not _IDENTIFIER_RE.match(tracking_table):
            raise MigrationError(
                f"Invalid tracking_table name: {tracking_table!r} "
                "(use lowercase letters, digits, and underscores)"
            )
        self._db = db
        self._directory = directory
        self._table = tracking_table

    # ---- discovery -------------------------------------------------------------

    def discover(self) -> list[Migration]:
        """Read every effective migration for this database's dialect.

        Returns migrations sorted by numeric prefix. Per-dialect override
        files are resolved against :attr:`Database.dialect`; see
        :func:`select_migration_files` for the rules and the errors raised
        for malformed or conflicting filenames.
        """
        files = [
            entry
            for entry in self._directory.iterdir()
            if entry.is_file() and entry.suffix == ".sql"
        ]
        migrations: list[Migration] = []
        for path in select_migration_files(files, self._db.dialect.name):
            parsed = _parse_filename(path)
            sql = path.read_text(encoding="utf-8")
            migrations.append(
                Migration(
                    id=parsed.id,
                    prefix=parsed.prefix,
                    slug=parsed.slug,
                    source_path=path,
                    sql=sql,
                    checksum=hashlib.sha256(sql.encode("utf-8")).hexdigest(),
                )
            )
        return migrations

    # ---- application -----------------------------------------------------------

    async def apply_all(self) -> list[Migration]:
        """Apply every un-applied migration. Returns the list applied now.

        Safe to call on every app startup: a migration is applied exactly
        once and subsequent calls become a no-op for anything already
        recorded.

        Raises :class:`MigrationChecksumMismatch` if a previously-applied
        migration's effective content on disk no longer matches what was
        recorded, and :class:`MigrationError` if an applied migration has
        disappeared from the directory or a pending migration fails.
        """
        discovered = self.discover()
        applied = await self._load_applied(discovered)

        applied_now: list[Migration] = []
        for migration in discovered:
            if migration.id in applied:
                continue
            await self._apply_one(migration)
            applied_now.append(migration)
        return applied_now

    async def status(self) -> MigrationStatus:
        """Return the applied vs pending migrations without changing anything.

        Validates checksum drift (same as :meth:`apply_all`) so a drifted or
        deleted migration surfaces in ``pyxle-db status`` / ``--dry-run`` rather
        than only at apply time.
        """
        discovered = self.discover()
        applied = await self._load_applied(discovered)
        return MigrationStatus(
            applied=tuple(m for m in discovered if m.id in applied),
            pending=tuple(m for m in discovered if m.id not in applied),
        )

    # ---- internals -------------------------------------------------------------

    async def _load_applied(self, discovered: list[Migration]) -> dict[str, str]:
        """Ensure the tracking table exists, return ``{id: checksum}`` for every
        applied migration, and validate that none have drifted or vanished."""
        # The dialect DDL targets the default name; rebind it to ours.
        ddl = self._db.dialect.migrations_table_ddl.replace(
            "schema_migrations", self._table
        )
        await self._db.execute(ddl)
        rows = await self._db.fetchall(f"SELECT id, checksum FROM {self._table}")
        applied = {row["id"]: row["checksum"] for row in rows}

        # Checksum drift: every recorded migration must still exist on
        # disk (for this dialect) with a matching hash.
        by_id = {migration.id: migration for migration in discovered}
        for migration_id, recorded_hash in applied.items():
            on_disk = by_id.get(migration_id)
            if on_disk is None:
                raise MigrationError(
                    f"Migration {migration_id!r} was applied to this "
                    "database but is no longer present in the migrations "
                    "directory. Never delete applied migrations."
                )
            if on_disk.checksum != recorded_hash:
                raise MigrationChecksumMismatch(
                    migration_id=migration_id,
                    recorded_hash=recorded_hash,
                    actual_hash=on_disk.checksum,
                )
        return applied

    async def _apply_one(self, migration: Migration) -> None:
        # One transaction per migration: the script's statements and the
        # schema_migrations insert commit together or not at all.
        statements = split_statements(
            migration.sql, dialect_name=self._db.dialect.name
        )
        try:
            async with self._db.transaction() as tx:
                for statement in statements:
                    await tx.execute(statement)
                await tx.execute(
                    f"INSERT INTO {self._table} (id, checksum) VALUES (?, ?)",
                    (migration.id, migration.checksum),
                )
        except Exception as exc:
            raise MigrationError(
                f"Migration {migration.id!r} failed: {exc}"
            ) from exc
