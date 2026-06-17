"""Tests for PyxleDbMiddleware — request-scoped DI + auto-transactions.

The middleware is driven directly (``await mw.dispatch(request, call_next)``)
rather than through a TestClient, so the async SQLite connection and the
handler run on the *same* event loop — TestClient spins its own loop, which
aiosqlite/asyncpg connections are bound to.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from pyxle.plugins import PluginContext
from pyxle_db import Database, connect
from pyxle_db.autotx import MANUAL_FLAG
from pyxle_db.middleware import PyxleDbMiddleware


async def _dummy_asgi(scope, receive, send):  # pragma: no cover - never called
    raise AssertionError("dispatch is invoked directly in tests")


def _request(ctx: PluginContext, *, method: str = "POST") -> Request:
    app = SimpleNamespace(state=SimpleNamespace(pyxle_plugins=ctx))
    scope = {
        "type": "http",
        "method": method,
        "path": "/x",
        "headers": [],
        "query_string": b"",
        "app": app,
        "state": {},
    }
    return Request(scope)


async def _open_notes_db(db_path: Path) -> Database:
    db = await connect(db_path)
    await db.execute("CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT)")
    return db


def _ctx(db: Database, *, auto: bool = True) -> PluginContext:
    ctx = PluginContext()
    ctx.register("db.database", db)
    ctx.register("db.auto_transactions", auto)
    return ctx


async def _count(db: Database) -> int:
    row = await db.get("SELECT COUNT(*) AS n FROM notes")
    return int(row["n"])


@pytest.fixture
def middleware() -> PyxleDbMiddleware:
    return PyxleDbMiddleware(_dummy_asgi)


async def test_successful_action_commits(db_path: Path, middleware: PyxleDbMiddleware) -> None:
    db = await _open_notes_db(db_path)
    try:
        ctx = _ctx(db)

        async def action(request: Request) -> Response:
            await request.state.db.execute("INSERT INTO notes (body) VALUES (?)", ("ok",))
            return JSONResponse({"ok": True})

        resp = await middleware.dispatch(_request(ctx), action)
        assert resp.status_code == 200
        assert await _count(db) == 1  # committed
    finally:
        await db.aclose()


async def test_failed_action_rolls_back(db_path: Path, middleware: PyxleDbMiddleware) -> None:
    """THE regression test. Pyxle's dispatcher catches the action's exception
    and returns a non-2xx response — no exception escapes the handler. The
    middleware must still roll back the partial write."""
    db = await _open_notes_db(db_path)
    try:
        ctx = _ctx(db)

        async def failing_action(request: Request) -> Response:
            # Wrote, then "failed": the dispatcher would catch the error and
            # return {"ok": false} / 400. The write must NOT persist.
            await request.state.db.execute("INSERT INTO notes (body) VALUES (?)", ("bad",))
            return JSONResponse({"ok": False, "error": "boom"}, status_code=400)

        resp = await middleware.dispatch(_request(ctx), failing_action)
        assert resp.status_code == 400
        assert await _count(db) == 0  # ← rolled back, not committed

        async def ok_action(request: Request) -> Response:
            await request.state.db.execute("INSERT INTO notes (body) VALUES (?)", ("good",))
            return JSONResponse({"ok": True})

        await middleware.dispatch(_request(ctx), ok_action)
        assert await _count(db) == 1  # a later success still commits
    finally:
        await db.aclose()


async def test_raised_exception_rolls_back(db_path: Path, middleware: PyxleDbMiddleware) -> None:
    """A genuine ASGI-level escape (not swallowed) also rolls back."""
    db = await _open_notes_db(db_path)
    try:
        ctx = _ctx(db)

        async def boom(request: Request) -> Response:
            await request.state.db.execute("INSERT INTO notes (body) VALUES (?)", ("x",))
            raise RuntimeError("escape")

        with pytest.raises(RuntimeError):
            await middleware.dispatch(_request(ctx), boom)
        assert await _count(db) == 0  # rolled back before re-raising
    finally:
        await db.aclose()


async def test_safe_method_does_not_open_write_transaction(
    db_path: Path, middleware: PyxleDbMiddleware
) -> None:
    db = await _open_notes_db(db_path)
    try:
        ctx = _ctx(db)
        opened: dict = {}

        async def reader(request: Request) -> Response:
            n = await request.state.db.get("SELECT COUNT(*) AS n FROM notes")
            # On a GET the handle is read-mode: no unit-of-work transaction.
            opened["uow"] = request.state.db._uow.opened
            return JSONResponse({"n": n["n"]})

        resp = await middleware.dispatch(_request(ctx, method="GET"), reader)
        assert resp.status_code == 200
        assert opened["uow"] is False  # never opened a write transaction
    finally:
        await db.aclose()


async def test_request_without_db_access_opens_nothing(
    db_path: Path, middleware: PyxleDbMiddleware
) -> None:
    db = await _open_notes_db(db_path)
    try:
        ctx = _ctx(db)
        captured: dict = {}

        async def no_db(request: Request) -> Response:
            captured["uow"] = request.state.db._uow
            return JSONResponse({"ok": True})

        await middleware.dispatch(_request(ctx), no_db)
        assert captured["uow"].opened is False  # lazy: nothing touched the DB
    finally:
        await db.aclose()


async def test_no_database_service_passes_through(middleware: PyxleDbMiddleware) -> None:
    ctx = PluginContext()  # no db.database registered

    async def handler(request: Request) -> Response:
        assert not hasattr(request.state, "db")
        return JSONResponse({"ok": True})

    resp = await middleware.dispatch(_request(ctx), handler)
    assert resp.status_code == 200


async def test_auto_transactions_disabled_does_not_roll_back(
    db_path: Path, middleware: PyxleDbMiddleware
) -> None:
    """With autoTransactions off, a write autocommits per statement and a failed
    response does NOT roll it back — the app opted into managing its own txns."""
    db = await _open_notes_db(db_path)
    try:
        ctx = _ctx(db, auto=False)

        async def failing_action(request: Request) -> Response:
            await request.state.db.execute("INSERT INTO notes (body) VALUES (?)", ("kept",))
            return JSONResponse({"ok": False}, status_code=400)

        await middleware.dispatch(_request(ctx), failing_action)
        assert await _count(db) == 1  # not rolled back (opt-out)
    finally:
        await db.aclose()


async def test_no_auto_transaction_flag_skips_rollback(
    db_path: Path, middleware: PyxleDbMiddleware
) -> None:
    """An action that sets the manual flag (as @no_auto_transaction does) keeps
    its autocommitted write even on a failed response."""
    db = await _open_notes_db(db_path)
    try:
        ctx = _ctx(db)

        async def manual_action(request: Request) -> Response:
            setattr(request.state, MANUAL_FLAG, True)
            await request.state.db.execute("INSERT INTO notes (body) VALUES (?)", ("manual",))
            return JSONResponse({"ok": False}, status_code=400)

        await middleware.dispatch(_request(ctx), manual_action)
        assert await _count(db) == 1  # manual mode: autocommitted, not rolled back
    finally:
        await db.aclose()


# --- ORM session injection + auto-transactions ----------------------------


async def _orm_engine():
    from pyxle_db.orm import Base, Engine
    from pyxle_db.url import parse_database_url

    from tests.orm import _models  # noqa: F401 - registers Widget

    eng = Engine.from_config(parse_database_url(":memory:"))
    async with eng.sqlalchemy_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    return eng


def _orm_ctx(engine) -> PluginContext:
    ctx = PluginContext()
    ctx.register("db.orm.session_factory", engine.session_factory)
    ctx.register("db.auto_transactions", True)
    return ctx


async def _widget_names(engine) -> list[str]:
    from sqlalchemy import select

    from tests.orm._models import Widget

    async with engine.session_factory() as session:
        return list((await session.scalars(select(Widget.name))).all())


async def test_orm_session_commits_on_success(middleware: PyxleDbMiddleware) -> None:
    from tests.orm._models import Widget

    engine = await _orm_engine()
    try:
        ctx = _orm_ctx(engine)

        async def action(request: Request) -> Response:
            request.state.session.add(Widget(name="orm-ok"))
            return JSONResponse({"ok": True})

        await middleware.dispatch(_request(ctx), action)
        assert await _widget_names(engine) == ["orm-ok"]
    finally:
        await engine.aclose()


async def test_orm_session_rolls_back_on_failed_action(
    middleware: PyxleDbMiddleware,
) -> None:
    """The ORM equivalent of the data-integrity regression: a failed action's
    session write must not persist."""
    from tests.orm._models import Widget

    engine = await _orm_engine()
    try:
        ctx = _orm_ctx(engine)

        async def failing(request: Request) -> Response:
            request.state.session.add(Widget(name="orm-bad"))
            await request.state.session.flush()
            return JSONResponse({"ok": False}, status_code=400)

        await middleware.dispatch(_request(ctx), failing)
        assert await _widget_names(engine) == []  # rolled back
    finally:
        await engine.aclose()


async def test_orm_session_unused_request_is_cheap(
    middleware: PyxleDbMiddleware,
) -> None:
    engine = await _orm_engine()
    try:
        ctx = _orm_ctx(engine)
        captured: dict = {}

        async def no_db(request: Request) -> Response:
            captured["in_tx"] = request.state.session.in_transaction()
            return JSONResponse({"ok": True})

        await middleware.dispatch(_request(ctx), no_db)
        assert captured["in_tx"] is False  # never opened a transaction
    finally:
        await engine.aclose()
