"""Tests for the SQLAlchemy-exception → pyxle_db-error translation."""

from __future__ import annotations

from sqlalchemy import exc as sa_exc

from pyxle_db.errors import DatabaseError, IntegrityError, OperationalError
from pyxle_db.orm.errors import translate


def test_translate_integrity_error() -> None:
    err = sa_exc.IntegrityError("INSERT ...", {}, Exception("UNIQUE constraint failed"))
    out = translate(err)
    assert isinstance(out, IntegrityError)
    assert "UNIQUE" in str(out)


def test_translate_operational_error() -> None:
    err = sa_exc.OperationalError("SELECT 1", {}, Exception("connection refused"))
    assert isinstance(translate(err), OperationalError)


def test_translate_interface_error() -> None:
    err = sa_exc.InterfaceError("SELECT 1", {}, Exception("driver gone"))
    assert isinstance(translate(err), OperationalError)


def test_translate_other_error_is_base() -> None:
    err = sa_exc.ProgrammingError("SELECT bad", {}, Exception("no such column"))
    out = translate(err)
    assert isinstance(out, DatabaseError)
    assert not isinstance(out, (IntegrityError, OperationalError))
