"""Tests for PyxleDbMiddleware — request-scoped DI + auto-transactions.

The middleware is a pure-ASGI app, driven here through a tiny in-process ASGI
harness (``_drive``) rather than a TestClient, so the async SQLite connection and
the handler run on the *same* event loop — TestClient spins its own loop, which
aiosqlite/asyncpg connections are bound to. The harness wraps a
``(request) -> Response`` handler as the inner ASGI app and returns the response
status, so the assertions below read like the dispatcher's real behaviour.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Awaitable, Callable

import pytest
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from pyxle.plugins import PluginContext
from pyxle_db import Database, connect
from pyxle_db.autotx import MANUAL_FLAG
from pyxle_db.middleware import PyxleDbMiddleware

Handler = Callable[[Request], Awaitable[Response]]


async def _drive(ctx: PluginContext, handler: Handler, *, method: str = "POST") -> int:
    """Run ``handler`` behind the middleware as a pure-ASGI request.

    Returns the response status code. The inner ASGI app builds its own
    scope-bound Request (sharing ``scope["state"]`` with the middleware's), calls
    the handler, and emits its Response — exactly as the real app would.
    """
    app = SimpleNamespace(state=SimpleNamespace(pyxle_plugins=ctx))
    scope: dict[str, Any] = {
        "type": "http",
        "method": method,
        "path": "/x",
        "headers": [],
        "query_string": b"",
        "app": app,
        "state": {},
    }

    async def inner(scope: dict, receive: Any, send: Any) -> None:
        request = Request(scope, receive)
        response = await handler(request)
        await response(scope, receive, send)

    # Deliver the request body once, then report the client disconnected. A
    # plain Response never polls receive(), but a StreamingResponse spawns a
    # disconnect-listener that loops on receive() until it sees
    # ``http.disconnect`` — returning a bare ``http.request`` forever would make
    # that poller busy-loop at 100% CPU. Yielding ``http.disconnect`` lets it
    # exit cleanly. Robust for both response kinds.
    delivered = {"body": False}

    async def receive() -> dict:
        if delivered["body"]:
            return {"type": "http.disconnect"}
        delivered["body"] = True
        return {"type": "http.request", "body": b"", "more_body": False}

    captured: dict[str, int] = {"status": 0}

    async def send(message: dict) -> None:
        if message["type"] == "http.response.start":
            captured["status"] = message["status"]

    await PyxleDbMiddleware(inner)(scope, receive, send)
    return captured["status"]


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


async def test_successful_action_commits(db_path: Path) -> None:
    db = await _open_notes_db(db_path)
    try:
        ctx = _ctx(db)

        async def action(request: Request) -> Response:
            await request.state.db.execute("INSERT INTO notes (body) VALUES (?)", ("ok",))
            return JSONResponse({"ok": True})

        status = await _drive(ctx, action)
        assert status == 200
        assert await _count(db) == 1  # committed
    finally:
        await db.aclose()


async def test_failed_action_rolls_back(db_path: Path) -> None:
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

        status = await _drive(ctx, failing_action)
        assert status == 400
        assert await _count(db) == 0  # ← rolled back, not committed

        async def ok_action(request: Request) -> Response:
            await request.state.db.execute("INSERT INTO notes (body) VALUES (?)", ("good",))
            return JSONResponse({"ok": True})

        await _drive(ctx, ok_action)
        assert await _count(db) == 1  # a later success still commits
    finally:
        await db.aclose()


async def test_raised_exception_rolls_back(db_path: Path) -> None:
    """A genuine ASGI-level escape (not swallowed) also rolls back."""
    db = await _open_notes_db(db_path)
    try:
        ctx = _ctx(db)

        async def boom(request: Request) -> Response:
            await request.state.db.execute("INSERT INTO notes (body) VALUES (?)", ("x",))
            raise RuntimeError("escape")

        with pytest.raises(RuntimeError):
            await _drive(ctx, boom)
        assert await _count(db) == 0  # rolled back before re-raising
    finally:
        await db.aclose()


async def test_safe_method_does_not_open_write_transaction(db_path: Path) -> None:
    db = await _open_notes_db(db_path)
    try:
        ctx = _ctx(db)
        opened: dict = {}

        async def reader(request: Request) -> Response:
            n = await request.state.db.get("SELECT COUNT(*) AS n FROM notes")
            # On a GET the handle is read-mode: no unit-of-work transaction.
            opened["uow"] = request.state.db._uow.opened
            return JSONResponse({"n": n["n"]})

        status = await _drive(ctx, reader, method="GET")
        assert status == 200
        assert opened["uow"] is False  # never opened a write transaction
    finally:
        await db.aclose()


async def test_request_without_db_access_opens_nothing(db_path: Path) -> None:
    db = await _open_notes_db(db_path)
    try:
        ctx = _ctx(db)
        captured: dict = {}

        async def no_db(request: Request) -> Response:
            captured["uow"] = request.state.db._uow
            return JSONResponse({"ok": True})

        await _drive(ctx, no_db)
        assert captured["uow"].opened is False  # lazy: nothing touched the DB
    finally:
        await db.aclose()


async def test_no_database_service_passes_through() -> None:
    ctx = PluginContext()  # no db.database registered

    async def handler(request: Request) -> Response:
        assert not hasattr(request.state, "db")
        return JSONResponse({"ok": True})

    status = await _drive(ctx, handler)
    assert status == 200


async def test_auto_transactions_disabled_does_not_roll_back(db_path: Path) -> None:
    """With autoTransactions off, a write autocommits per statement and a failed
    response does NOT roll it back — the app opted into managing its own txns."""
    db = await _open_notes_db(db_path)
    try:
        ctx = _ctx(db, auto=False)

        async def failing_action(request: Request) -> Response:
            await request.state.db.execute("INSERT INTO notes (body) VALUES (?)", ("kept",))
            return JSONResponse({"ok": False}, status_code=400)

        await _drive(ctx, failing_action)
        assert await _count(db) == 1  # not rolled back (opt-out)
    finally:
        await db.aclose()


async def test_no_auto_transaction_flag_skips_rollback(db_path: Path) -> None:
    """An action that sets the manual flag (as @no_auto_transaction does) keeps
    its autocommitted write even on a failed response."""
    db = await _open_notes_db(db_path)
    try:
        ctx = _ctx(db)

        async def manual_action(request: Request) -> Response:
            setattr(request.state, MANUAL_FLAG, True)
            await request.state.db.execute("INSERT INTO notes (body) VALUES (?)", ("manual",))
            return JSONResponse({"ok": False}, status_code=400)

        await _drive(ctx, manual_action)
        assert await _count(db) == 1  # manual mode: autocommitted, not rolled back
    finally:
        await db.aclose()


# --- streaming response (the bug this rewrite fixes) -----------------------


async def test_streaming_response_is_not_buffered(db_path: Path) -> None:
    """A streamed response passes through chunk-by-chunk and still commits on a
    2xx — the old BaseHTTPMiddleware buffered the whole body (breaking streaming
    SSR) and raised 'No response returned' on a mid-stream disconnect."""
    from starlette.responses import StreamingResponse

    db = await _open_notes_db(db_path)
    try:
        ctx = _ctx(db)

        async def streamer(request: Request) -> Response:
            await request.state.db.execute("INSERT INTO notes (body) VALUES (?)", ("stream",))

            async def body():
                yield b"shell "
                yield b"then-more"

            return StreamingResponse(body(), media_type="text/html")

        # Capture each body chunk in order to prove it streamed, not buffered.
        chunks: list[bytes] = []
        app = SimpleNamespace(state=SimpleNamespace(pyxle_plugins=ctx))
        scope = {"type": "http", "method": "POST", "path": "/x", "headers": [],
                 "query_string": b"", "app": app, "state": {}}

        async def inner(scope, receive, send):
            request = Request(scope, receive)
            response = await streamer(request)
            await response(scope, receive, send)

        # StreamingResponse spawns a disconnect-listener that polls receive() in
        # a loop until it sees ``http.disconnect``. Returning a bare
        # ``http.request`` forever makes that poller busy-loop at 100% CPU and
        # the test never returns. Deliver the request body once, then report the
        # client disconnected so the listener exits its loop cleanly.
        delivered = {"body": False}

        async def receive():
            if delivered["body"]:
                return {"type": "http.disconnect"}
            delivered["body"] = True
            return {"type": "http.request", "body": b"", "more_body": False}

        status = {"code": 0}

        async def send(message):
            if message["type"] == "http.response.start":
                status["code"] = message["status"]
            elif message["type"] == "http.response.body" and message.get("body"):
                chunks.append(message["body"])

        await PyxleDbMiddleware(inner)(scope, receive, send)
        assert status["code"] == 200
        assert b"".join(chunks) == b"shell then-more"
        assert len(chunks) >= 2  # delivered as multiple chunks, not one buffer
        assert await _count(db) == 1  # write committed after the stream finished
    finally:
        await db.aclose()


async def test_midstream_disconnect_rolls_back_partial_write(db_path: Path) -> None:
    """A streamed response cut short by a client disconnect must NOT commit. The
    body suspends after its first chunk; the client then disconnects, so Starlette
    cancels the stream and ``self.app`` returns normally with a 200 already sent —
    but the terminal body frame never arrives, so the partial write is rolled
    back (the page the client never fully received didn't 'succeed')."""
    from starlette.responses import StreamingResponse

    db = await _open_notes_db(db_path)
    try:
        ctx = _ctx(db)

        async def streamer(request: Request) -> Response:
            await request.state.db.execute("INSERT INTO notes (body) VALUES (?)", ("partial",))

            async def body():
                yield b"shell "
                await asyncio.sleep(30)  # suspend; the disconnect cancels us here
                yield b"never-sent"

            return StreamingResponse(body(), media_type="text/html")

        chunks: list[bytes] = []
        app = SimpleNamespace(state=SimpleNamespace(pyxle_plugins=ctx))
        scope = {"type": "http", "method": "POST", "path": "/x", "headers": [],
                 "query_string": b"", "app": app, "state": {}}

        async def inner(scope, receive, send):
            request = Request(scope, receive)
            response = await streamer(request)
            await response(scope, receive, send)

        # Deliver the request body, then report the client disconnected mid-stream.
        delivered = {"body": False}

        async def receive():
            if not delivered["body"]:
                delivered["body"] = True
                return {"type": "http.request", "body": b"", "more_body": False}
            return {"type": "http.disconnect"}

        async def send(message):
            if message["type"] == "http.response.body" and message.get("body"):
                chunks.append(message["body"])

        await PyxleDbMiddleware(inner)(scope, receive, send)
        assert b"".join(chunks) == b"shell "  # only the pre-disconnect chunk went out
        assert await _count(db) == 0  # truncated stream → rolled back, NOT committed
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


async def test_orm_session_commits_on_success() -> None:
    from tests.orm._models import Widget

    engine = await _orm_engine()
    try:
        ctx = _orm_ctx(engine)

        async def action(request: Request) -> Response:
            request.state.session.add(Widget(name="orm-ok"))
            return JSONResponse({"ok": True})

        await _drive(ctx, action)
        assert await _widget_names(engine) == ["orm-ok"]
    finally:
        await engine.aclose()


async def test_orm_session_rolls_back_on_failed_action() -> None:
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

        await _drive(ctx, failing)
        assert await _widget_names(engine) == []  # rolled back
    finally:
        await engine.aclose()


async def test_orm_session_unused_request_is_cheap() -> None:
    engine = await _orm_engine()
    try:
        ctx = _orm_ctx(engine)
        captured: dict = {}

        async def no_db(request: Request) -> Response:
            captured["in_tx"] = request.state.session.in_transaction()
            return JSONResponse({"ok": True})

        await _drive(ctx, no_db)
        assert captured["in_tx"] is False  # never opened a transaction
    finally:
        await engine.aclose()


async def test_a_bodyless_204_commits(db_path: Path) -> None:
    """`204 No Content` is the conventional answer to a successful DELETE.

    Pinned because the commit rule keys on having seen the terminal body frame,
    and it is not obvious from reading it that a status carrying no content
    still sends one. A future tightening of that rule must not start discarding
    the writes of every successful DELETE.
    """
    db = await _open_notes_db(db_path)
    try:
        ctx = _ctx(db)

        async def action(request: Request) -> Response:
            await request.state.db.execute("INSERT INTO notes (body) VALUES (?)", ("x",))
            return Response(status_code=204)

        status = await _drive(ctx, action, method="DELETE")
        assert status == 204
        assert await _count(db) == 1, "a successful 204 must commit its writes"
    finally:
        await db.aclose()


async def test_a_304_commits(db_path: Path) -> None:
    """The other status that carries no content."""
    db = await _open_notes_db(db_path)
    try:
        ctx = _ctx(db)

        async def action(request: Request) -> Response:
            await request.state.db.execute("INSERT INTO notes (body) VALUES (?)", ("x",))
            return Response(status_code=304)

        status = await _drive(ctx, action, method="POST")
        assert status == 304
        assert await _count(db) == 1
    finally:
        await db.aclose()


async def test_a_truncated_body_still_rolls_back(db_path: Path) -> None:
    """The behaviour the completeness check exists for must survive the fix: a
    200 whose body was cut short mid-stream discards its writes."""
    from starlette.responses import StreamingResponse

    db = await _open_notes_db(db_path)
    try:
        ctx = _ctx(db)

        async def action(request: Request) -> Response:
            await request.state.db.execute("INSERT INTO notes (body) VALUES (?)", ("x",))

            async def body():
                yield b"part"
                raise RuntimeError("connection lost mid-stream")

            return StreamingResponse(body())

        with pytest.raises(RuntimeError):
            await _drive(ctx, action)
        assert await _count(db) == 0, "a truncated response must not commit"
    finally:
        await db.aclose()
