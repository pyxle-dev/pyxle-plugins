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
* Exactly once holds under concurrency too: several processes — e.g.
  every worker of ``pyxle serve --workers N`` running the plugin's
  startup — may call :meth:`Migrator.apply_all` against one database at
  the same time. Appliers serialize on a per-backend lock (SQLite
  ``BEGIN IMMEDIATE``, PostgreSQL ``pg_advisory_xact_lock``, MySQL
  ``GET_LOCK``); one process runs a given migration's SQL, and the rest
  observe it as applied, verify the recorded checksum matches their
  effective file, and continue. A checksum difference still fails
  loudly.
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

import asyncio
import hashlib
import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from pyxle_db.backends import MYSQL_DIALECT, POSTGRESQL_DIALECT, SQLITE_DIALECT
from pyxle_db.database import Database, Transaction
from pyxle_db.errors import (
    DatabaseError,
    IntegrityError,
    MigrationChecksumMismatch,
    MigrationError,
    OperationalError,
)
from pyxle_db.sql import split_statements

_logger = logging.getLogger("pyxle_db.migrator")

_IDENTIFIER_RE = re.compile(r"^[a-z_][a-z0-9_]*$")

# How long a SQLite applier sleeps before re-entering once another process
# has held the write lock past the connection's ``busy_timeout``, and how
# long each MySQL ``GET_LOCK`` attempt waits before looping. Neither is a
# deadline — a waiter blocks until the lock frees, matching the
# block-until-released semantics of PostgreSQL's advisory lock; a dead
# holder's lock is always released by its process exit / connection drop.
_SQLITE_LOCKED_RETRY_SECONDS = 0.1
_MYSQL_LOCK_WAIT_SECONDS = 5

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


def _lock_digest(tracking_table: str) -> bytes:
    """A stable cross-process identity for one migration history.

    Derived with :mod:`hashlib` (never ``hash()``, which is per-process)
    and keyed on the tracking table so independent migration sources on
    one database — the host app's ``schema_migrations`` and pyxle-auth's
    ``schema_migrations_pyxle_auth`` — never serialize against each
    other, and neither do two apps sharing a server.
    """
    return hashlib.sha256(
        b"pyxle_db.migrations:" + tracking_table.encode("ascii")
    ).digest()


def _postgres_lock_keys(tracking_table: str) -> tuple[int, int]:
    """The two signed int32 keys for ``pg_advisory_xact_lock(int, int)``."""
    digest = _lock_digest(tracking_table)
    return (
        int.from_bytes(digest[:4], "big", signed=True),
        int.from_bytes(digest[4:8], "big", signed=True),
    )


def _mysql_lock_name(tracking_table: str) -> str:
    """The ``GET_LOCK`` name — 52 chars, under MySQL's 64-char limit."""
    return "pyxle_db_migrations_" + _lock_digest(tracking_table).hex()[:32]


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
        recorded. That holds across processes too — when several server
        workers race the same pending migration, they serialize on a
        database lock, exactly one applies it, and the others verify the
        recorded checksum and skip it. Only migrations applied by *this*
        call are returned.

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
            if await self._apply_one(migration):
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
        try:
            await self._db.execute(ddl)
        except IntegrityError:
            # Concurrent processes can race the CREATE TABLE IF NOT EXISTS
            # itself — PostgreSQL surfaces the loser's DDL as a duplicate-key
            # violation on the system catalogs. The winner created the
            # table; the SELECT below fails loudly if it truly is missing.
            pass
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

    async def _apply_one(self, migration: Migration) -> bool:
        """Apply one migration; return True iff *this* process applied it.

        Concurrent appliers serialize on a per-backend lock (see
        :meth:`_apply_in_transaction` and :meth:`_apply_under_mysql_lock`),
        and the first statement inside the lock re-checks the tracking
        table — so a process whose pending scan went stale finds the
        winner's row, verifies its checksum, and returns False instead of
        re-running the SQL. A checksum difference raises
        :class:`MigrationChecksumMismatch`; any other failure is wrapped
        in :class:`MigrationError` exactly as before.
        """
        statements = split_statements(
            migration.sql, dialect_name=self._db.dialect.name
        )
        logged_waiting = False
        while True:
            try:
                if self._db.dialect.name == "mysql":
                    return await self._apply_under_mysql_lock(
                        migration, statements
                    )
                return await self._apply_in_transaction(migration, statements)
            except MigrationError:
                # Raised by the migrator itself (checksum mismatch, lock
                # failure) — already precise; never re-wrap it.
                raise
            except IntegrityError as exc:
                return await self._resolve_tracking_conflict(migration, exc)
            except OperationalError as exc:
                if (
                    self._db.dialect.name == "sqlite"
                    and "database is locked" in str(exc)
                ):
                    # Another process has held BEGIN IMMEDIATE past this
                    # connection's busy_timeout — it is applying migrations
                    # right now. Wait it out and re-enter; the
                    # in-transaction re-check resolves what remains.
                    if not logged_waiting:
                        _logger.info(
                            "Migration %r: database locked by another "
                            "process applying migrations; waiting",
                            migration.id,
                        )
                        logged_waiting = True
                    await asyncio.sleep(_SQLITE_LOCKED_RETRY_SECONDS)
                    continue
                raise MigrationError(
                    f"Migration {migration.id!r} failed: {exc}"
                ) from exc
            except Exception as exc:
                raise MigrationError(
                    f"Migration {migration.id!r} failed: {exc}"
                ) from exc

    async def _apply_in_transaction(
        self, migration: Migration, statements: list[str]
    ) -> bool:
        """Run one migration inside one serialized transaction.

        One transaction per migration: the script's statements and the
        tracking insert commit together or not at all. Serialization:

        * SQLite — :meth:`Database.transaction` opens with
          ``BEGIN IMMEDIATE``, so the write lock itself is the mutex; the
          re-check below reads after the lock is granted and therefore
          sees a winner's committed row.
        * PostgreSQL — a transaction-scoped advisory lock keyed on the
          tracking table; it blocks until free and releases atomically at
          commit, exactly when the tracking row becomes visible to the
          next waiter's re-check.
        * MySQL — no transaction-scoped lock can cover DDL (which commits
          implicitly), so :meth:`_apply_under_mysql_lock` wraps this same
          body in a session lock and this transaction is the inner one;
          its REPEATABLE READ snapshot starts at the re-check, after the
          lock was acquired.
        """
        async with self._db.transaction() as tx:
            if self._db.dialect.name == "postgresql":
                # READ COMMITTED gives every statement its own snapshot, so
                # the re-check sees the winner's commit even where the
                # server's default isolation is stricter (REPEATABLE READ
                # would pin the snapshot before the lock wait finished and
                # hide the winner's row).
                await tx.execute(
                    "SET TRANSACTION ISOLATION LEVEL READ COMMITTED"
                )
                key_high, key_low = _postgres_lock_keys(self._table)
                await tx.fetchone(
                    "SELECT pg_advisory_xact_lock(?, ?)", (key_high, key_low)
                )
            row = await tx.fetchone(
                f"SELECT checksum FROM {self._table} WHERE id = ?",
                (migration.id,),
            )
            if row is not None:
                self._verify_lost_race(migration, row["checksum"])
                return False
            for statement in statements:
                await tx.execute(statement)
            await tx.execute(
                f"INSERT INTO {self._table} (id, checksum) VALUES (?, ?)",
                (migration.id, migration.checksum),
            )
        return True

    async def _apply_under_mysql_lock(
        self, migration: Migration, statements: list[str]
    ) -> bool:
        """Serialize one migration on a MySQL named session lock.

        The outer transaction scope exists only to pin one pooled
        connection for ``GET_LOCK``/``RELEASE_LOCK`` — a session lock must
        be released on the connection that took it, and the pool would
        otherwise hand the two statements different connections. The
        migration itself runs through :meth:`_apply_in_transaction` on a
        second pooled connection, and the lock is released strictly
        *after* that inner commit: released any earlier, the next
        waiter's REPEATABLE READ snapshot could predate the tracking
        insert and the race would be back. Startup migrations on MySQL
        therefore need ``pool_max`` >= 2 (the default is 10). A lock
        holder that dies is cleaned up by the server when its connection
        drops.
        """
        lock_name = _mysql_lock_name(self._table)
        async with self._db.transaction() as guard:
            await self._acquire_mysql_lock(guard, lock_name, migration)
            try:
                return await self._apply_in_transaction(migration, statements)
            finally:
                await self._release_mysql_lock(guard, lock_name)

    async def _acquire_mysql_lock(
        self, guard: Transaction, lock_name: str, migration: Migration
    ) -> None:
        logged_waiting = False
        while True:
            row = await guard.fetchone(
                "SELECT GET_LOCK(?, ?)", (lock_name, _MYSQL_LOCK_WAIT_SECONDS)
            )
            status = None if row is None else row[0]
            if status == 1:
                return
            if status == 0:
                # Timed out while another process applies migrations —
                # keep waiting, exactly like the other backends do.
                if not logged_waiting:
                    _logger.info(
                        "Migration %r: waiting for another process "
                        "applying migrations",
                        migration.id,
                    )
                    logged_waiting = True
                continue
            raise MigrationError(
                f"Migration {migration.id!r} failed: could not acquire "
                f"MySQL lock {lock_name!r} (GET_LOCK returned {status!r})"
            )

    async def _release_mysql_lock(
        self, guard: Transaction, lock_name: str
    ) -> None:
        try:
            await guard.fetchone("SELECT RELEASE_LOCK(?)", (lock_name,))
        except DatabaseError:
            # Never mask the migration's own outcome. A failed release
            # means the guard connection is gone — and the server frees
            # the lock with it.
            _logger.warning(
                "Could not release MySQL migration lock %r; the server "
                "frees it when the holding connection closes",
                lock_name,
            )

    async def _resolve_tracking_conflict(
        self, migration: Migration, exc: IntegrityError
    ) -> bool:
        """Decide what an ``IntegrityError`` during application meant.

        Belt-and-braces behind the per-backend locks, for any
        interleaving they cannot see (e.g. exotic isolation settings).
        The failed transaction has rolled back; re-read the tracking
        table on a fresh autocommit connection. A row recorded by
        another process means this was a lost race — verify its checksum
        and skip. No row means the error came from the migration's own
        SQL: a real failure, wrapped exactly as before.
        """
        row = await self._db.fetchone(
            f"SELECT checksum FROM {self._table} WHERE id = ?",
            (migration.id,),
        )
        if row is None:
            raise MigrationError(
                f"Migration {migration.id!r} failed: {exc}"
            ) from exc
        self._verify_lost_race(migration, row["checksum"])
        return False

    def _verify_lost_race(self, migration: Migration, recorded: str) -> None:
        """Another process applied ``migration`` first — was it the same file?

        Matching checksum: a clean skip. Different checksum: the same id
        was applied from different content somewhere — the drift
        protection must fail as loudly here as it does on a plain
        re-run.
        """
        if recorded != migration.checksum:
            raise MigrationChecksumMismatch(
                migration_id=migration.id,
                recorded_hash=recorded,
                actual_hash=migration.checksum,
            )
        _logger.info(
            "Migration %r was already applied by another process; skipping",
            migration.id,
        )
