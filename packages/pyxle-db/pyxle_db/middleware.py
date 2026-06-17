"""Request-scoped database injection and automatic transactions.

``PyxleDbMiddleware`` is contributed by :class:`~pyxle_db.plugin.PyxleDbPlugin`
through Pyxle's public plugin-middleware seam (no core monkey-patching). Per
request it:

* attaches a lazy database handle as ``request.state.db`` so every loader and
  action can query without importing or wiring anything;
* on an **unsafe** method (POST/PUT/PATCH/DELETE), runs the request's writes
  inside one transaction and **commits or rolls back based on the response** —
  not on whether an exception escaped.

That last point is the load-bearing design decision. Pyxle's action dispatcher
catches ``ActionError`` and every other exception *inside* the handler and turns
it into a non-2xx ``{"ok": false}`` JSON response — the exception never reaches
this middleware. Deciding commit-vs-rollback by "did ``call_next`` raise" would
therefore **commit the partial writes of every failed action**. Instead we
commit only on a 2xx/3xx response and roll back on anything else, which is a
stable, public contract of the dispatcher.

Lazy is also load-bearing: a request that never touches the database opens no
connection and no transaction.
"""

from __future__ import annotations

import logging
from typing import Any, Iterable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp

from pyxle_db.autotx import MANUAL_FLAG
from pyxle_db.contract import DatabaseLike, TransactionLike
from pyxle_db.rows import Row

_logger = logging.getLogger("pyxle_db.middleware")

# Methods that may not mutate state get a read-mode handle (per-statement
# autocommit, never a held write transaction).
_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

# Service keys (see PyxleDbPlugin.on_startup).
_DATABASE_SERVICE = "db.database"
_AUTO_TX_SERVICE = "db.auto_transactions"
_SESSION_FACTORY_SERVICE = "db.orm.session_factory"


async def _finalize_session(session: Any, *, auto: bool, ok: bool) -> None:
    """Commit or roll back the request's ``AsyncSession``, then close it.

    Only an auto-managed session that actually opened a transaction is
    committed/rolled back here; a read-mode or manual session just closes
    (rolling back any uncommitted reads — harmless)."""
    try:
        if auto and session.in_transaction():
            if ok:
                await session.commit()
            else:
                await session.rollback()
    finally:
        await session.close()


async def _discard_session(session: Any) -> None:
    """Roll back and close a session on an ASGI-level escape."""
    try:
        await session.rollback()
    finally:
        await session.close()


class _SentinelRollback(Exception):
    """Internal sentinel passed to a transaction's ``__aexit__`` to roll back
    without raising into application code."""


class _RequestUnitOfWork:
    """One lazily-opened transaction (or read handle) for a single request.

    In auto-commit mode the first query opens a transaction that every
    subsequent query on this request shares; the middleware commits or rolls it
    back exactly once at the request boundary. In read mode (safe methods, the
    ``autoTransactions`` opt-out, or an action decorated ``@no_auto_transaction``)
    queries run directly against the database (per-statement autocommit) and the
    middleware never commits anything.
    """

    __slots__ = ("_request", "_db", "_auto_commit", "_tx_ctx", "_tx")

    def __init__(self, request: Request, database: DatabaseLike, *, auto_commit: bool) -> None:
        self._request = request
        self._db = database
        self._auto_commit = auto_commit
        self._tx_ctx: Any = None
        self._tx: TransactionLike | None = None

    async def _executor(self) -> Any:
        """Return the object queries should run against — a shared transaction in
        auto mode, or the database directly in read/manual mode."""
        manual = getattr(self._request.state, MANUAL_FLAG, False)
        if self._auto_commit and not manual:
            if self._tx is None:
                self._tx_ctx = self._db.transaction()
                self._tx = await self._tx_ctx.__aenter__()
            return self._tx
        return self._db

    @property
    def opened(self) -> bool:
        """True once the auto-commit transaction has actually been opened."""
        return self._tx is not None

    async def commit(self) -> None:
        if self._tx_ctx is None:
            return
        ctx, self._tx_ctx, self._tx = self._tx_ctx, None, None
        await ctx.__aexit__(None, None, None)

    async def rollback(self) -> None:
        if self._tx_ctx is None:
            return
        ctx, self._tx_ctx, self._tx = self._tx_ctx, None, None
        # A non-None exc_type makes the transaction's __aexit__ roll back; the
        # sentinel is never raised into application code (we call __aexit__
        # directly rather than leaving an ``async with`` block).
        await ctx.__aexit__(_SentinelRollback, _SentinelRollback(), None)


class _SqlHandleProxy:
    """The ``request.state.db`` handle. Forwards the explicit-SQL query surface
    to the request's unit-of-work, materialising the connection/transaction only
    on first use."""

    __slots__ = ("_uow",)

    def __init__(self, uow: _RequestUnitOfWork) -> None:
        self._uow = uow

    async def execute(self, sql: str, params: Any | None = None) -> int:
        return await (await self._uow._executor()).execute(sql, params)

    async def executemany(self, sql: str, seq_params: Iterable[Any]) -> None:
        await (await self._uow._executor()).executemany(sql, seq_params)

    async def fetchone(self, sql: str, params: Any | None = None) -> Row | None:
        return await (await self._uow._executor()).fetchone(sql, params)

    async def fetchall(self, sql: str, params: Any | None = None) -> list[Row]:
        return await (await self._uow._executor()).fetchall(sql, params)

    async def get(self, sql: str, params: Any | None = None) -> Row:
        return await (await self._uow._executor()).get(sql, params)

    def transaction(self) -> Any:
        """Open an explicit transaction independent of the request unit-of-work.

        Use this (with ``@no_auto_transaction``) when an action needs to control
        commit boundaries itself.
        """
        return self._uow._db.transaction()

    @property
    def dialect(self) -> Any:
        return self._uow._db.dialect


class PyxleDbMiddleware(BaseHTTPMiddleware):
    """Inject ``request.state.db`` and manage the per-request transaction."""

    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)

    async def dispatch(self, request: Request, call_next: Any) -> Response:
        ctx = getattr(request.app.state, "pyxle_plugins", None)
        database = ctx.get(_DATABASE_SERVICE) if ctx is not None else None
        session_factory = ctx.get(_SESSION_FACTORY_SERVICE) if ctx is not None else None
        if database is None and session_factory is None:
            # Plugin registered middleware but nothing to inject — pass through.
            return await call_next(request)

        auto_commit = self._auto_commit_enabled(request, ctx)

        uow: _RequestUnitOfWork | None = None
        if database is not None:
            uow = _RequestUnitOfWork(request, database, auto_commit=auto_commit)
            request.state.db = _SqlHandleProxy(uow)

        # The AsyncSession object is cheap; its connection is opened lazily on
        # first query, so a request that never touches the ORM pays nothing.
        session = session_factory() if session_factory is not None else None
        if session is not None:
            request.state.session = session

        try:
            response = await call_next(request)
        except BaseException:
            # A genuine ASGI-level escape (rare — loaders are caught by the
            # error boundary). Discard any open work before re-raising.
            if uow is not None:
                await uow.rollback()
            if session is not None:
                await _discard_session(session)
            raise

        manual = getattr(request.state, MANUAL_FLAG, False)
        ok = 200 <= response.status_code < 400

        if uow is not None and uow.opened:
            # Commit on success; a failed action (ok:false ⇒ 4xx/5xx) discards
            # its partial writes.
            if ok:
                await uow.commit()
            else:
                await uow.rollback()
        if session is not None:
            await _finalize_session(session, auto=(auto_commit and not manual), ok=ok)
        return response

    @staticmethod
    def _auto_commit_enabled(request: Request, ctx: Any) -> bool:
        """Auto-commit applies only to unsafe methods, and only when the app has
        not globally disabled it via ``"autoTransactions": false``."""
        if request.method in _SAFE_METHODS:
            return False
        return bool(ctx.get(_AUTO_TX_SERVICE, True))


__all__ = ["PyxleDbMiddleware"]
