"""Structured error types for pyxle-db.

Every failure mode a caller might branch on gets its own class so
``except`` clauses stay specific and error responses can return
meaningful codes.
"""

from __future__ import annotations


class DatabaseError(Exception):
    """Base class for every pyxle-db error."""


class IntegrityError(DatabaseError):
    """A constraint was violated (UNIQUE, FOREIGN KEY, NOT NULL, CHECK).

    Raised in preference to the driver's own integrity error so callers
    never import sqlite3/asyncpg/asyncmy just to handle a violation.
    """


class OperationalError(DatabaseError):
    """The database is unreachable, busy, or the connection died.

    The retryable family: connection refused, pool timeout, server gone
    away, lock timeouts. Application code may retry these; anything else
    under :class:`DatabaseError` is a programming or data error.
    """


class ConfigurationError(DatabaseError):
    """Bad database URL/settings, or a backend's driver isn't installed."""


class UnsupportedOperationError(DatabaseError):
    """The operation isn't available on this backend.

    Example: ``Database.sync_transaction()`` and ``close()`` are
    SQLite-only; server backends are natively async — use
    ``async with db.transaction()`` and ``await db.aclose()``.
    """


class NotFoundError(DatabaseError):
    """A ``fetchone`` / ``get`` returned no row where one was required."""


class MigrationError(DatabaseError):
    """Something went wrong applying migrations."""


class MigrationChecksumMismatch(MigrationError):
    """A migration file's hash no longer matches the hash stored in the DB.

    Raised when somebody edited a migration that has already been applied
    to this database. Always a bug: once a migration is committed and
    applied in any environment, it must never be edited — write a new
    migration instead.
    """

    def __init__(self, migration_id: str, recorded_hash: str, actual_hash: str) -> None:
        super().__init__(
            f"Migration {migration_id!r} has checksum {actual_hash} on disk "
            f"but was recorded as {recorded_hash} when applied. "
            "Never edit an applied migration — write a follow-up migration instead."
        )
        self.migration_id = migration_id
        self.recorded_hash = recorded_hash
        self.actual_hash = actual_hash
