"""Translate SQLAlchemy exceptions into pyxle_db error types.

So application code (and other plugins such as pyxle-auth) catch the *same*
errors regardless of whether the app chose the explicit-SQL path or the ORM
path — the cross-backend error contract holds across both surfaces.
"""

from __future__ import annotations

from pyxle_db.errors import DatabaseError, IntegrityError, OperationalError


def translate(exc: BaseException) -> DatabaseError:
    """Map a SQLAlchemy exception onto the matching pyxle_db error.

    Integrity violations (unique/foreign-key/not-null) become
    :class:`~pyxle_db.errors.IntegrityError`; connection/operational failures
    become :class:`~pyxle_db.errors.OperationalError`; anything else (bad SQL,
    etc.) becomes the base :class:`~pyxle_db.errors.DatabaseError`.
    """
    from sqlalchemy import exc as sa_exc  # noqa: PLC0415 - optional extra

    detail = str(getattr(exc, "orig", None) or exc)
    if isinstance(exc, sa_exc.IntegrityError):
        return IntegrityError(detail)
    if isinstance(exc, (sa_exc.OperationalError, sa_exc.InterfaceError)):
        return OperationalError(detail)
    return DatabaseError(detail)


__all__ = ["translate"]
