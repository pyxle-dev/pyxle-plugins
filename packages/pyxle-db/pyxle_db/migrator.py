"""Filesystem-driven migrations for pyxle-db.

Conventions:

* Each migration is a ``.sql`` file in the migrations directory.
* Filenames must start with a zero-padded numeric prefix (``0001``,
  ``0002``, ...) followed by a hyphen and a description:
  ``0001-initial-schema.sql``. The numeric prefix is the canonical
  ordering; the description is freeform and recorded for humans.
* A migration is applied exactly once per database. We record every
  applied migration in a ``schema_migrations`` table with its SHA-256
  so edits to committed migrations are detected and rejected.
* Each migration runs in its own transaction. A failure rolls back
  that migration only; previously-applied migrations are untouched.
* Migrations execute SQL as-is — this includes multi-statement
  scripts. No templating, no variable substitution.
"""

from __future__ import annotations

import asyncio
import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from pyxle_db.database import Database
from pyxle_db.errors import MigrationChecksumMismatch, MigrationError


_FILENAME_RE = re.compile(r"^(?P<prefix>\d{3,})[-_](?P<slug>[A-Za-z0-9_\-]+)\.sql$")


@dataclass(frozen=True, slots=True)
class Migration:
    """A single migration file, ready to apply.

    Attributes:
        id: The filename minus the ``.sql`` suffix. Used as the
            primary key in ``schema_migrations``.
        prefix: The numeric prefix, parsed for ordering.
        slug: The human-readable description.
        source_path: Absolute path on disk.
        sql: The SQL to execute.
        checksum: SHA-256 of the SQL text, hex-encoded.
    """

    id: str
    prefix: int
    slug: str
    source_path: Path
    sql: str
    checksum: str


class Migrator:
    """Applies ordered migrations to a :class:`Database`.

    .. code-block:: python

        migrator = Migrator(db, Path("migrations"))
        await migrator.apply_all()
    """

    def __init__(self, db: Database, directory: Path) -> None:
        if not directory.is_dir():
            raise MigrationError(
                f"Migrations directory does not exist: {directory}"
            )
        self._db = db
        self._directory = directory

    # ---- discovery -------------------------------------------------------------

    def discover(self) -> list[Migration]:
        """Read every migration file from disk, sorted by prefix.

        Raises :class:`MigrationError` if two files share the same prefix
        or if any filename is malformed.
        """
        found: dict[int, Migration] = {}
        for entry in sorted(self._directory.iterdir()):
            if not entry.is_file() or entry.suffix != ".sql":
                continue
            match = _FILENAME_RE.match(entry.name)
            if not match:
                raise MigrationError(
                    f"Migration filename {entry.name!r} does not match "
                    "<NNN>-<slug>.sql (e.g. 0001-initial-schema.sql)"
                )
            prefix = int(match.group("prefix"))
            if prefix in found:
                raise MigrationError(
                    f"Two migrations share prefix {prefix}: "
                    f"{found[prefix].source_path.name} and {entry.name}"
                )
            sql = entry.read_text(encoding="utf-8")
            checksum = hashlib.sha256(sql.encode("utf-8")).hexdigest()
            found[prefix] = Migration(
                id=entry.stem,
                prefix=prefix,
                slug=match.group("slug"),
                source_path=entry,
                sql=sql,
                checksum=checksum,
            )
        return [found[prefix] for prefix in sorted(found)]

    # ---- application -----------------------------------------------------------

    async def apply_all(self) -> list[Migration]:
        """Apply every un-applied migration. Returns the list applied.

        Safe to call on every app startup: a migration is applied
        exactly once and subsequent calls become a no-op for anything
        already recorded.

        Raises :class:`MigrationChecksumMismatch` if a previously-applied
        migration's content on disk no longer matches what was recorded.
        """
        return await asyncio.to_thread(self._apply_all_sync)

    def _apply_all_sync(self) -> list[Migration]:
        self._ensure_tracking_table()
        applied_rows = self._load_applied()

        pending: list[Migration] = []
        discovered = self.discover()
        by_id = {m.id: m for m in discovered}

        # Checksum drift: every recorded migration must either exist on
        # disk with a matching hash or be flagged as missing.
        for migration_id, recorded_hash in applied_rows.items():
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

        for migration in discovered:
            if migration.id in applied_rows:
                continue
            pending.append(migration)

        applied_now: list[Migration] = []
        for migration in pending:
            self._apply_one(migration)
            applied_now.append(migration)
        return applied_now

    # ---- internals -------------------------------------------------------------

    def _ensure_tracking_table(self) -> None:
        with self._db.sync_transaction() as tx:
            tx.execute(
                """
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    id          TEXT PRIMARY KEY,
                    checksum    TEXT NOT NULL,
                    applied_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )

    def _load_applied(self) -> dict[str, str]:
        with self._db.sync_transaction() as tx:
            rows = tx.fetchall("SELECT id, checksum FROM schema_migrations")
        return {row["id"]: row["checksum"] for row in rows}

    def _apply_one(self, migration: Migration) -> None:
        # Each migration gets its own transaction. SQLite's ``executescript``
        # commits and re-opens a transaction implicitly; we side-step that by
        # running statements individually within our BEGIN IMMEDIATE.
        statements = _split_sql(migration.sql)
        try:
            with self._db.sync_transaction() as tx:
                for stmt in statements:
                    if stmt.strip():
                        tx.execute(stmt)
                tx.execute(
                    "INSERT INTO schema_migrations (id, checksum) VALUES (?, ?)",
                    (migration.id, migration.checksum),
                )
        except Exception as exc:
            raise MigrationError(
                f"Migration {migration.id!r} failed: {exc}"
            ) from exc


# ---------------------------------------------------------------------------
# SQL splitter
#
# SQLite's ``execute`` runs one statement at a time. We split on semicolons
# outside of strings and comments. This is deliberately simple — if a
# migration needs triggers or procedures with embedded semicolons it can
# wrap the body in ``BEGIN`` / ``END`` and we'll detect that.


def _split_sql(script: str) -> Iterable[str]:
    out: list[str] = []
    buf: list[str] = []
    i = 0
    n = len(script)
    in_single = False
    in_double = False
    in_line_comment = False
    in_block_comment = False
    begin_depth = 0

    while i < n:
        ch = script[i]
        nxt = script[i + 1] if i + 1 < n else ""
        if in_line_comment:
            buf.append(ch)
            if ch == "\n":
                in_line_comment = False
            i += 1
            continue
        if in_block_comment:
            buf.append(ch)
            if ch == "*" and nxt == "/":
                buf.append(nxt)
                i += 2
                in_block_comment = False
                continue
            i += 1
            continue
        if in_single:
            buf.append(ch)
            if ch == "'" and nxt == "'":
                buf.append(nxt)
                i += 2
                continue
            if ch == "'":
                in_single = False
            i += 1
            continue
        if in_double:
            buf.append(ch)
            if ch == '"' and nxt == '"':
                buf.append(nxt)
                i += 2
                continue
            if ch == '"':
                in_double = False
            i += 1
            continue
        # not inside any quoted/comment region
        if ch == "-" and nxt == "-":
            in_line_comment = True
            buf.append(ch)
            i += 1
            continue
        if ch == "/" and nxt == "*":
            in_block_comment = True
            buf.append(ch)
            buf.append(nxt)
            i += 2
            continue
        if ch == "'":
            in_single = True
            buf.append(ch)
            i += 1
            continue
        if ch == '"':
            in_double = True
            buf.append(ch)
            i += 1
            continue
        # BEGIN/END blocks — simple keyword detection; SQLite doesn't have
        # nested BEGINs in migrations in practice so a depth counter is enough.
        lookahead = script[i : i + 6].upper()
        if lookahead.startswith("BEGIN") and _is_word_boundary(script, i, 5):
            begin_depth += 1
        elif lookahead.startswith("END") and _is_word_boundary(script, i, 3):
            if begin_depth > 0:
                begin_depth -= 1
        if ch == ";" and begin_depth == 0:
            out.append("".join(buf))
            buf = []
            i += 1
            continue
        buf.append(ch)
        i += 1
    tail = "".join(buf).strip()
    if tail:
        out.append(tail)
    return out


def _is_word_boundary(s: str, start: int, length: int) -> bool:
    """True if ``s[start:start+length]`` is a standalone word.

    Used so ``ENDING`` doesn't get counted as ``END``.
    """
    end = start + length
    before = s[start - 1] if start > 0 else " "
    after = s[end] if end < len(s) else " "
    return not (before.isalnum() or before == "_") and not (
        after.isalnum() or after == "_"
    )
