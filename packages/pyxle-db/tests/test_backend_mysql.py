"""MysqlBackend tests.

Two layers:

* Unit tests against a fake asyncmy module (monkeypatched into
  ``pyxle_db.backends.mysql``) with real asyncmy error classes — verify
  commit/rollback discipline, error translation, Row building, datetime
  normalisation, parameter handling, and pool configuration without a server.
* Live conformance tests against a real MySQL, auto-skipped unless
  ``PYXLE_DB_TEST_MYSQL_URL`` is set, e.g.::

      PYXLE_DB_TEST_MYSQL_URL=mysql://root:secret@127.0.0.1:3306/pyxle_test
"""

from __future__ import annotations

import asyncio
import dataclasses
import os
import uuid
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from types import SimpleNamespace
from typing import Any, AsyncIterator, Callable

import pytest

pytest.importorskip("asyncmy")

import asyncmy.errors as mysql_errors

from pyxle_db.backends import mysql as mysql_module
from pyxle_db.backends.base import MYSQL_DIALECT
from pyxle_db.backends.mysql import MysqlBackend
from pyxle_db.errors import (
    ConfigurationError,
    DatabaseError,
    IntegrityError,
    OperationalError,
)
from pyxle_db.rows import Row
from pyxle_db.sql import translate
from pyxle_db.url import DatabaseConfig, parse_database_url

# ---------------------------------------------------------------------------
# Fake asyncmy


@dataclass(frozen=True)
class ResultSet:
    """One scripted result set a FakeCursor serves for an execute() call."""

    columns: tuple[str, ...]
    rows: tuple[tuple[Any, ...], ...]


class FakeCursor:
    def __init__(self, conn: "FakeConnection") -> None:
        self._conn = conn
        self._pending: list[tuple[Any, ...]] = []
        self.description: tuple[tuple[Any, ...], ...] | None = None
        self.rowcount = -1

    async def __aenter__(self) -> "FakeCursor":
        return self

    async def __aexit__(self, *exc_info: object) -> bool:
        return False

    async def execute(self, query: str, args: Any = None) -> None:
        self._conn.calls.append(("execute", query, args))
        if self._conn.execute_error is not None:
            raise self._conn.execute_error
        if self._conn.results:
            result = self._conn.results.pop(0)
            self.description = tuple(
                (name, None, None, None, None, None, None) for name in result.columns
            )
            self._pending = list(result.rows)
            self.rowcount = len(self._pending)
        else:
            self.rowcount = self._conn.rowcount

    async def executemany(self, query: str, args: Any) -> None:
        self._conn.calls.append(("executemany", query, list(args)))
        if self._conn.execute_error is not None:
            raise self._conn.execute_error
        self.rowcount = self._conn.rowcount

    async def fetchone(self) -> tuple[Any, ...] | None:
        return self._pending.pop(0) if self._pending else None

    async def fetchall(self) -> list[tuple[Any, ...]]:
        pending, self._pending = self._pending, []
        return pending


class FakeConnection:
    def __init__(
        self,
        *,
        results: tuple[ResultSet, ...] = (),
        rowcount: int = 1,
        execute_error: Exception | None = None,
        rollback_error: Exception | None = None,
    ) -> None:
        self.calls: list[tuple[Any, ...]] = []
        self.results = list(results)
        self.rowcount = rowcount
        self.execute_error = execute_error
        self.rollback_error = rollback_error

    def cursor(self) -> FakeCursor:
        return FakeCursor(self)

    async def begin(self) -> None:
        self.calls.append(("begin",))

    async def commit(self) -> None:
        self.calls.append(("commit",))

    async def rollback(self) -> None:
        self.calls.append(("rollback",))
        if self.rollback_error is not None:
            raise self.rollback_error

    def ops(self) -> list[str]:
        return [call[0] for call in self.calls]


class FakePool:
    def __init__(self, conn_factory: Callable[[], FakeConnection]) -> None:
        self._conn_factory = conn_factory
        self.acquired: list[FakeConnection] = []
        self.released: list[FakeConnection] = []
        self.closed = False
        self.wait_closed_calls = 0

    async def acquire(self) -> FakeConnection:
        conn = self._conn_factory()
        self.acquired.append(conn)
        return conn

    def release(self, conn: FakeConnection) -> None:
        self.released.append(conn)

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        self.wait_closed_calls += 1


def _config(options: dict[str, str] | None = None) -> DatabaseConfig:
    return DatabaseConfig(
        backend="mysql",
        host="db.internal",
        port=3306,
        user="app",
        password="s3cret",
        database="appdb",
        options=options or {},
    )


@pytest.fixture
def fake(monkeypatch: pytest.MonkeyPatch):
    """Install a fake asyncmy module and build a backend wired to it."""

    def install(
        *,
        conn_factory: Callable[[], FakeConnection] = FakeConnection,
        create_pool_error: Exception | None = None,
        options: dict[str, str] | None = None,
    ) -> tuple[MysqlBackend, FakePool, dict[str, Any]]:
        pool = FakePool(conn_factory)
        created: dict[str, Any] = {"count": 0, "kwargs": None}

        async def create_pool(**kwargs: Any) -> FakePool:
            await asyncio.sleep(0)  # yield control so the connect lock is exercised
            if create_pool_error is not None:
                raise create_pool_error
            created["count"] += 1
            created["kwargs"] = kwargs
            return pool

        module = SimpleNamespace(create_pool=create_pool, errors=mysql_errors)
        monkeypatch.setattr(mysql_module, "asyncmy", module)
        return MysqlBackend(_config(options)), pool, created

    return install


# ---------------------------------------------------------------------------
# Pool configuration and lifecycle


def test_dialect_is_mysql_format_style() -> None:
    assert MysqlBackend.dialect is MYSQL_DIALECT
    assert MysqlBackend.dialect.paramstyle == "format"
    assert MysqlBackend.dialect.supports_sync is False


def test_no_sync_escape_hatches() -> None:
    """The facade gates sync_transaction()/close() on these attributes."""
    assert not hasattr(MysqlBackend, "sync_transaction")
    assert not hasattr(MysqlBackend, "close_sync")


async def test_connect_is_lazy_idempotent_and_configures_pool(fake) -> None:
    backend, _pool, created = fake(options={"pool_min": "2", "pool_max": "7"})
    assert created["count"] == 0  # nothing happens at construction

    await asyncio.gather(backend.connect(), backend.connect())
    await backend.connect()

    assert created["count"] == 1
    assert created["kwargs"] == {
        "host": "db.internal",
        "port": 3306,
        "user": "app",
        "password": "s3cret",
        "database": "appdb",
        "charset": "utf8mb4",
        "autocommit": False,
        "minsize": 2,
        "maxsize": 7,
        "init_command": "SET time_zone = '+00:00'",
    }


async def test_pool_bounds_default(fake) -> None:
    backend, _pool, created = fake()
    await backend.connect()
    assert created["kwargs"]["minsize"] == 1
    assert created["kwargs"]["maxsize"] == 10


@pytest.mark.parametrize(
    "options",
    [
        {"pool_min": "two"},
        {"pool_max": "0"},
        {"pool_min": "-1"},
        {"pool_min": "5", "pool_max": "2"},
    ],
)
def test_bad_pool_bounds_rejected_at_construction(options: dict[str, str]) -> None:
    with pytest.raises(ConfigurationError):
        MysqlBackend(_config(options))


async def test_connect_failure_is_operational_error(fake) -> None:
    original = mysql_errors.OperationalError(2003, "Can't connect to MySQL server")
    backend, _pool, _created = fake(create_pool_error=original)
    with pytest.raises(OperationalError) as exc_info:
        await backend.connect()
    assert exc_info.value.__cause__ is original


async def test_aclose_is_idempotent_and_backend_is_reusable(fake) -> None:
    backend, pool, created = fake()
    await backend.connect()

    await backend.aclose()
    await backend.aclose()
    assert pool.closed is True
    assert pool.wait_closed_calls == 1

    await backend.connect()  # reusable after another connect()
    assert created["count"] == 2


# ---------------------------------------------------------------------------
# One-shot statements: commit/rollback discipline


async def test_execute_commits_and_releases(fake) -> None:
    backend, pool, _created = fake()
    affected = await backend.execute("INSERT INTO t (v) VALUES (%s)", ["hello"])

    assert affected == 1
    (conn,) = pool.acquired
    assert conn.ops() == ["execute", "commit"]
    assert conn.calls[0] == ("execute", "INSERT INTO t (v) VALUES (%s)", ("hello",))
    assert pool.released == [conn]


async def test_execute_rolls_back_translates_and_releases_on_error(fake) -> None:
    original = mysql_errors.IntegrityError(1062, "Duplicate entry 'x' for key 't.v'")
    backend, pool, _created = fake(
        conn_factory=lambda: FakeConnection(execute_error=original)
    )

    with pytest.raises(IntegrityError) as exc_info:
        await backend.execute("INSERT INTO t (v) VALUES (%s)", ("x",))

    assert exc_info.value.__cause__ is original
    (conn,) = pool.acquired
    assert conn.ops() == ["execute", "rollback"]
    assert pool.released == [conn]


async def test_empty_params_are_passed_as_tuple_not_none(fake) -> None:
    """asyncmy only collapses the translator's ``%%`` when args is not None."""
    backend, pool, _created = fake()
    await backend.execute("SELECT 5 %% 2")
    (conn,) = pool.acquired
    assert conn.calls[0] == ("execute", "SELECT 5 %% 2", ())


async def test_fetches_commit_to_release_the_read_snapshot(fake) -> None:
    result = ResultSet(columns=("id",), rows=((1,),))
    backend, pool, _created = fake(
        conn_factory=lambda: FakeConnection(results=(result,))
    )
    await backend.fetchall("SELECT id FROM t")
    (conn,) = pool.acquired
    assert conn.ops() == ["execute", "commit"]


async def test_executemany_is_one_call_one_commit(fake) -> None:
    backend, pool, _created = fake()
    await backend.executemany("INSERT INTO t (v) VALUES (%s)", [["a"], ("b",), ("c",)])

    (conn,) = pool.acquired
    assert conn.ops() == ["executemany", "commit"]
    assert conn.calls[0] == (
        "executemany",
        "INSERT INTO t (v) VALUES (%s)",
        [("a",), ("b",), ("c",)],
    )


async def test_executemany_with_no_rows_is_a_noop(fake) -> None:
    backend, pool, created = fake()
    await backend.executemany("INSERT INTO t (v) VALUES (%s)", [])
    assert created["count"] == 0  # no pool, no connection, no commit
    assert pool.acquired == []


async def test_rollback_failure_does_not_mask_original_error(fake) -> None:
    original = mysql_errors.IntegrityError(1062, "Duplicate entry")
    backend, pool, _created = fake(
        conn_factory=lambda: FakeConnection(
            execute_error=original,
            rollback_error=mysql_errors.OperationalError(2006, "server has gone away"),
        )
    )
    with pytest.raises(IntegrityError) as exc_info:
        await backend.execute("INSERT INTO t (v) VALUES (%s)", ("x",))
    assert exc_info.value.__cause__ is original
    assert pool.released == pool.acquired


# ---------------------------------------------------------------------------
# Error mapping (real asyncmy error classes)


@pytest.mark.parametrize(
    ("original", "expected"),
    [
        (mysql_errors.IntegrityError(1062, "Duplicate entry"), IntegrityError),
        (mysql_errors.IntegrityError(1452, "FK constraint fails"), IntegrityError),
        (mysql_errors.OperationalError(2002, "Can't connect through socket"), OperationalError),
        (mysql_errors.OperationalError(2003, "Can't connect to MySQL server"), OperationalError),
        (mysql_errors.OperationalError(2006, "MySQL server has gone away"), OperationalError),
        (mysql_errors.OperationalError(2013, "Lost connection during query"), OperationalError),
        (mysql_errors.OperationalError(1205, "Lock wait timeout exceeded"), OperationalError),
        (mysql_errors.InterfaceError(0, "Connection closed"), OperationalError),
        (mysql_errors.ProgrammingError(1064, "Syntax error"), DatabaseError),
        (mysql_errors.DataError(1264, "Out of range value"), DatabaseError),
        (mysql_errors.InternalError(1129, "Host is blocked"), DatabaseError),
    ],
)
async def test_driver_errors_never_leak(
    fake, original: Exception, expected: type[DatabaseError]
) -> None:
    backend, _pool, _created = fake(
        conn_factory=lambda: FakeConnection(execute_error=original)
    )
    with pytest.raises(expected) as exc_info:
        await backend.execute("SELECT 1")
    assert type(exc_info.value) is expected  # exact class, not a subclass
    assert exc_info.value.__cause__ is original


# ---------------------------------------------------------------------------
# Row building and datetime normalisation


async def test_fetchone_builds_row_and_normalises_datetimes(fake) -> None:
    naive = datetime(2026, 6, 11, 12, 30, 0)
    aware_ist = datetime(2026, 6, 11, 18, 0, 0, tzinfo=timezone(timedelta(hours=5, minutes=30)))
    result = ResultSet(
        columns=("id", "created_at", "updated_at", "due_on"),
        rows=((7, naive, aware_ist, date(2026, 6, 12)),),
    )
    backend, _pool, _created = fake(
        conn_factory=lambda: FakeConnection(results=(result,))
    )

    row = await backend.fetchone("SELECT * FROM t WHERE id = %s", (7,))

    assert isinstance(row, Row)
    assert row["id"] == 7
    assert row.keys() == ("id", "created_at", "updated_at", "due_on")
    # Naive values are assumed UTC and tagged.
    assert row["created_at"] == datetime(2026, 6, 11, 12, 30, 0, tzinfo=timezone.utc)
    # Aware values are converted to UTC.
    assert row["updated_at"] == datetime(2026, 6, 11, 12, 30, 0, tzinfo=timezone.utc)
    assert row["updated_at"].tzinfo == timezone.utc
    # Plain dates pass through untouched.
    assert row["due_on"] == date(2026, 6, 12)


async def test_fetchone_returns_none_when_no_row(fake) -> None:
    result = ResultSet(columns=("id",), rows=())
    backend, _pool, _created = fake(
        conn_factory=lambda: FakeConnection(results=(result,))
    )
    assert await backend.fetchone("SELECT id FROM t WHERE id = %s", (404,)) is None


async def test_fetchall_returns_rows_in_order(fake) -> None:
    result = ResultSet(columns=("id", "v"), rows=((1, "a"), (2, "b")))
    backend, _pool, _created = fake(
        conn_factory=lambda: FakeConnection(results=(result,))
    )
    rows = await backend.fetchall("SELECT id, v FROM t ORDER BY id")
    assert rows == [(1, "a"), (2, "b")]
    assert all(isinstance(row, Row) for row in rows)


# ---------------------------------------------------------------------------
# Transactions


async def test_transaction_begins_and_commits_once(fake) -> None:
    backend, pool, _created = fake()
    async with backend.transaction() as tx:
        await tx.execute("INSERT INTO t (v) VALUES (%s)", ("a",))
        await tx.execute("INSERT INTO t (v) VALUES (%s)", ("b",))

    (conn,) = pool.acquired
    assert conn.ops() == ["begin", "execute", "execute", "commit"]
    assert pool.released == [conn]


async def test_transaction_rolls_back_on_exception(fake) -> None:
    backend, pool, _created = fake()

    class Boom(Exception):
        pass

    with pytest.raises(Boom):
        async with backend.transaction() as tx:
            await tx.execute("INSERT INTO t (v) VALUES (%s)", ("a",))
            raise Boom()

    (conn,) = pool.acquired
    assert conn.ops() == ["begin", "execute", "rollback"]
    assert pool.released == [conn]


async def test_transaction_translates_statement_errors_and_rolls_back(fake) -> None:
    original = mysql_errors.IntegrityError(1062, "Duplicate entry")
    backend, pool, _created = fake(
        conn_factory=lambda: FakeConnection(execute_error=original)
    )

    with pytest.raises(IntegrityError) as exc_info:
        async with backend.transaction() as tx:
            await tx.execute("INSERT INTO t (v) VALUES (%s)", ("x",))

    assert exc_info.value.__cause__ is original
    (conn,) = pool.acquired
    assert conn.ops() == ["begin", "execute", "rollback"]


async def test_concurrent_transactions_use_distinct_connections(fake) -> None:
    """Contract rule 6: no statement interleaving across transactions."""
    backend, pool, _created = fake()

    async def run(value: str) -> None:
        async with backend.transaction() as tx:
            await tx.execute("INSERT INTO t (v) VALUES (%s)", (value,))
            await asyncio.sleep(0)  # force interleaved scheduling
            await tx.execute("UPDATE t SET v = %s", (value.upper(),))

    await asyncio.gather(run("a"), run("b"))

    assert len(pool.acquired) == 2
    first, second = pool.acquired
    assert first is not second
    for conn in (first, second):
        assert conn.ops() == ["begin", "execute", "execute", "commit"]
        params = {call[2] for call in conn.calls if call[0] == "execute"}
        values = {p[0].lower() for p in params}
        assert len(values) == 1  # each connection saw exactly one caller's statements


async def test_transaction_fetches_return_rows(fake) -> None:
    result = ResultSet(columns=("n",), rows=((41,), (42,)))
    backend, _pool, _created = fake(
        conn_factory=lambda: FakeConnection(results=(result, result))
    )
    async with backend.transaction() as tx:
        row = await tx.fetchone("SELECT n FROM t")
        assert row == (41,)
        assert isinstance(row, Row)


# ---------------------------------------------------------------------------
# Live conformance (requires a real MySQL; auto-skipped otherwise)

LIVE_URL = os.environ.get("PYXLE_DB_TEST_MYSQL_URL", "")

live = pytest.mark.skipif(
    not LIVE_URL, reason="PYXLE_DB_TEST_MYSQL_URL is not set"
)


def _q(sql: str) -> str:
    """Translate canonical qmark SQL to native %s style, as the facade does."""
    return translate(sql, MYSQL_DIALECT.paramstyle)


@live
class TestLiveMysqlConformance:
    @pytest.fixture
    async def backend(self) -> AsyncIterator[MysqlBackend]:
        backend = MysqlBackend(parse_database_url(LIVE_URL))
        await backend.connect()
        await backend.connect()  # idempotent
        yield backend
        await backend.aclose()
        await backend.aclose()  # idempotent

    @pytest.fixture
    async def table(self, backend: MysqlBackend) -> AsyncIterator[str]:
        name = f"pyxle_test_{uuid.uuid4().hex[:12]}"
        await backend.execute(
            f"CREATE TABLE {name} ("
            "  id BIGINT AUTO_INCREMENT PRIMARY KEY,"
            "  v VARCHAR(64) NOT NULL UNIQUE,"
            "  created_at DATETIME(6) NULL"
            ") ENGINE=InnoDB"
        )
        yield name
        await backend.execute(f"DROP TABLE IF EXISTS {name}")

    async def test_roundtrip_returns_rows(self, backend: MysqlBackend, table: str) -> None:
        affected = await backend.execute(
            _q(f"INSERT INTO {table} (v) VALUES (?)"), ("hello",)
        )
        assert affected == 1

        row = await backend.fetchone(
            _q(f"SELECT v FROM {table} WHERE v = ?"), ("hello",)
        )
        assert isinstance(row, Row)
        assert row["v"] == "hello"

        assert await backend.fetchone(
            _q(f"SELECT v FROM {table} WHERE v = ?"), ("absent",)
        ) is None

    async def test_aware_datetime_param_stores_utc_instant(
        self, backend: MysqlBackend, table: str
    ) -> None:
        """Write side of the datetime contract on a real server: an aware
        non-UTC datetime must be converted to UTC before binding (asyncmy
        would otherwise serialise the foreign wall clock, silently storing
        the wrong instant) and read back as the same instant, aware UTC."""
        ist = timezone(timedelta(hours=5, minutes=30))
        moment = datetime(2026, 6, 11, 9, 30, 15, 123456, tzinfo=ist)
        await backend.execute(
            _q(f"INSERT INTO {table} (v, created_at) VALUES (?, ?)"),
            ("aware", moment),
        )
        row = await backend.fetchone(
            _q(f"SELECT created_at FROM {table} WHERE v = ?"), ("aware",)
        )
        assert row is not None
        assert row["created_at"].tzinfo is not None
        assert row["created_at"] == moment  # same instant, normalised to UTC

    async def test_unique_violation_is_integrity_error(
        self, backend: MysqlBackend, table: str
    ) -> None:
        insert = _q(f"INSERT INTO {table} (v) VALUES (?)")
        await backend.execute(insert, ("dup",))
        with pytest.raises(IntegrityError) as exc_info:
            await backend.execute(insert, ("dup",))
        assert isinstance(exc_info.value.__cause__, mysql_errors.IntegrityError)

    async def test_transaction_commit_and_rollback(
        self, backend: MysqlBackend, table: str
    ) -> None:
        insert = _q(f"INSERT INTO {table} (v) VALUES (?)")
        async with backend.transaction() as tx:
            await tx.execute(insert, ("committed",))

        class Boom(Exception):
            pass

        with pytest.raises(Boom):
            async with backend.transaction() as tx:
                await tx.execute(insert, ("rolled-back",))
                raise Boom()

        rows = await backend.fetchall(_q(f"SELECT v FROM {table} ORDER BY id"))
        assert [row["v"] for row in rows] == ["committed"]

    async def test_executemany_is_atomic(self, backend: MysqlBackend, table: str) -> None:
        insert = _q(f"INSERT INTO {table} (v) VALUES (?)")
        with pytest.raises(IntegrityError):
            # The duplicate inside the batch must take the whole batch down.
            await backend.executemany(insert, [("a",), ("b",), ("a",)])
        count = await backend.fetchone(_q(f"SELECT COUNT(*) AS n FROM {table}"))
        assert count is not None and count["n"] == 0

        await backend.executemany(insert, [("a",), ("b",)])
        rows = await backend.fetchall(_q(f"SELECT v FROM {table} ORDER BY v"))
        assert [row["v"] for row in rows] == ["a", "b"]

    async def test_datetimes_come_back_utc_aware(
        self, backend: MysqlBackend, table: str
    ) -> None:
        # MySQL DATETIME stores naive values; the contract tags them as UTC.
        stored = datetime(2026, 6, 11, 12, 30, 0, 250000)
        await backend.execute(
            _q(f"INSERT INTO {table} (v, created_at) VALUES (?, ?)"),
            ("stamped", stored),
        )
        row = await backend.fetchone(
            _q(f"SELECT created_at FROM {table} WHERE v = ?"), ("stamped",)
        )
        assert row is not None
        assert row["created_at"] == stored.replace(tzinfo=timezone.utc)

    async def test_unreachable_server_is_operational_error(self) -> None:
        config = dataclasses.replace(parse_database_url(LIVE_URL), port=9)  # discard port
        backend = MysqlBackend(config)
        with pytest.raises(OperationalError):
            await backend.connect()
        await backend.aclose()
