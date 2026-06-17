"""Request-independent AsyncSession helper.

Inside a request the middleware provides ``request.state.session`` and manages
its transaction. :func:`get_session` is for everything *outside* a request — a
CLI command, a background task, a one-off script — where you want a session with
the same commit-on-success / rollback-on-error semantics.
"""

from __future__ import annotations

import contextlib
from typing import TYPE_CHECKING, Any, AsyncIterator

from pyxle_db.orm.errors import translate

if TYPE_CHECKING:  # pragma: no cover - typing only
    from pyxle_db.orm.engine import Engine


@contextlib.asynccontextmanager
async def get_session(engine: "Engine") -> AsyncIterator[Any]:
    """Yield an ``AsyncSession`` that commits on success and rolls back on error.

    A SQLAlchemy error is rolled back and re-raised as the matching ``pyxle_db``
    error type (so callers catch the same errors as on the explicit-SQL path);
    any other exception rolls back and propagates unchanged. The session is
    always closed.
    """
    from sqlalchemy import exc as sa_exc  # noqa: PLC0415 - optional extra

    session = engine.session_factory()
    try:
        yield session
        await session.commit()
    except sa_exc.SQLAlchemyError as exc:
        await session.rollback()
        raise translate(exc) from exc
    except BaseException:
        await session.rollback()
        raise
    finally:
        await session.close()


__all__ = ["get_session"]
