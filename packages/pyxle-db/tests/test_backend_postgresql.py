"""PostgreSQL backend tests.

Two layers:

* Unit tests against a fake asyncpg layer — ``pyxle_db.backends.postgresql``
  reaches the driver through its module-level ``asyncpg`` reference, so a
  stub swapped in with ``monkeypatch`` captures every pool/connection call.
  Error translation is exercised with *real* asyncpg exception classes
  instantiated directly.
* Live conformance tests against a real server, auto-skipped unless the
  ``PYXLE_DB_TEST_POSTGRES_URL`` environment variable is set, e.g.::

      PYXLE_DB_TEST_POSTGRES_URL=postgresql://app:secret@localhost:5432/pyxle_test
"""

from __future__ import annotations

import os
import uuid
from datetime import date, datetime, timedelta, timezone
from typing import Any, Iterator

import pytest

pytest.importorskip("asyncpg")

from asyncpg import exceptions as apg_exc

import pyxle_db.backends.postgresql as pg_module
from pyxle_db.backends.postgresql import PostgresBackend
from pyxle_db.errors import (
    ConfigurationError,
    DatabaseError,
    IntegrityError,
    OperationalError,
)
from pyxle_db.rows import Row
from pyxle_db.url import DatabaseConfig, parse_database_url

# --------------------------------------------------------------------------
# Fake asyncpg layer
# --------------------------------------------------------------------------


class FakeRecord:
    """Duck-typed asyncpg.Record: ``keys()`` and ``values()``."""

    def __init__(self, mapping: dict[str, Any]) -> None:
        self._mapping = mapping

    def keys(self) -> Iterator[str]:
        return iter(self._mapping.keys())

    def values(self) -> Iterator[Any]:
        return iter(self._mapping.values())


class FakeTransactionHandle:
    """Stands in for the object ``Connection.transaction()`` returns."""

    def __init__(self, commit_error: Exception | None = None) -> None:
        self.commit_error = commit_error
        self.started = False
        self.committed = False
        self.rolled_back = False

    async def start(self) -> None:
        self.started = True

    async def commit(self) -> None:
        if self.commit_error is not None:
            raise self.commit_error
        self.committed = True

    async def rollback(self) -> None:
        self.rolled_back = True

    async def __aenter__(self) -> "FakeTransactionHandle":
        await self.start()
        return self

    async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> bool:
        if exc_type is None:
            await self.commit()
        else:
            await self.rollback()
        return False


class FakeConnection:
    """Records every statement; per-method results or exceptions to raise."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, tuple[Any, ...]]] = []
        self.results: dict[str, Any] = {}
        self.transactions: list[FakeTransactionHandle] = []
        self.tx_commit_error: Exception | None = None

    def _result(self, method: str, default: Any) -> Any:
        value = self.results.get(method, default)
        if isinstance(value, BaseException):
            raise value
        return value

    async def execute(self, sql: str, *args: Any) -> str:
        self.calls.append(("execute", sql, args))
        return self._result("execute", "OK")

    async def executemany(self, sql: str, args: Any) -> None:
        self.calls.append(("executemany", sql, tuple(tuple(a) for a in args)))
        self._result("executemany", None)

    async def fetchrow(self, sql: str, *args: Any) -> Any:
        self.calls.append(("fetchrow", sql, args))
        return self._result("fetchrow", None)

    async def fetch(self, sql: str, *args: Any) -> Any:
        self.calls.append(("fetch", sql, args))
        return self._result("fetch", [])

    def transaction(self) -> FakeTransactionHandle:
        handle = FakeTransactionHandle(commit_error=self.tx_commit_error)
        self.transactions.append(handle)
        return handle


class FakeAcquireContext:
    """Supports both ``await pool.acquire()`` and ``async with pool.acquire()``."""

    def __init__(self, pool: "FakePool") -> None:
        self._pool = pool
        self._conn: FakeConnection | None = None

    def __await__(self) -> Any:
        async def _acquire() -> FakeConnection:
            return self._pool.take()

        return _acquire().__await__()

    async def __aenter__(self) -> FakeConnection:
        self._conn = self._pool.take()
        return self._conn

    async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> bool:
        await self._pool.release(self._conn)
        return False


class FakePool:
    def __init__(self, conns: list[FakeConnection]) -> None:
        self._available = list(conns)
        self.released: list[FakeConnection] = []
        self.close_calls = 0
        self.acquire_error: Exception | None = None

    def take(self) -> FakeConnection:
        if self.acquire_error is not None:
            raise self.acquire_error
        return self._available.pop(0)

    def acquire(self) -> FakeAcquireContext:
        return FakeAcquireContext(self)

    async def release(self, conn: FakeConnection) -> None:
        self.released.append(conn)
        self._available.append(conn)

    async def close(self) -> None:
        self.close_calls += 1


class FakeAsyncpgModule:
    """Swap-in for the ``asyncpg`` reference inside the backend module."""

    def __init__(self, pool: FakePool) -> None:
        self.pool = pool
        self.create_pool_calls: list[dict[str, Any]] = []
        self.create_pool_error: Exception | None = None

    async def create_pool(self, **kwargs: Any) -> FakePool:
        self.create_pool_calls.append(kwargs)
        if self.create_pool_error is not None:
            raise self.create_pool_error
        return self.pool


# --------------------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------------------


def make_config(**options: str) -> DatabaseConfig:
    return DatabaseConfig(
        backend="postgresql",
        host="db.example",
        port=5432,
        user="app",
        password="s3c",
        database="appdb",
        options=options,
    )


@pytest.fixture
def fake_conn() -> FakeConnection:
    return FakeConnection()


@pytest.fixture
def fake_pool(fake_conn: FakeConnection) -> FakePool:
    return FakePool([fake_conn])


@pytest.fixture
def fake_asyncpg(
    fake_pool: FakePool, monkeypatch: pytest.MonkeyPatch
) -> FakeAsyncpgModule:
    stub = FakeAsyncpgModule(fake_pool)
    monkeypatch.setattr(pg_module, "asyncpg", stub)
    return stub


@pytest.fixture
def backend(fake_asyncpg: FakeAsyncpgModule) -> PostgresBackend:
    return PostgresBackend(make_config())


# --------------------------------------------------------------------------
# Pool configuration
# --------------------------------------------------------------------------


class TestPoolConfig:
    async def test_default_pool_kwargs(
        self, backend: PostgresBackend, fake_asyncpg: FakeAsyncpgModule
    ) -> None:
        await backend.connect()
        (kwargs,) = fake_asyncpg.create_pool_calls
        assert kwargs == {
            "host": "db.example",
            "port": 5432,
            "user": "app",
            "password": "s3c",
            "database": "appdb",
            "min_size": 1,
            "max_size": 10,
            "ssl": None,
            "server_settings": None,
        }

    async def test_custom_pool_sizes(
        self, fake_asyncpg: FakeAsyncpgModule
    ) -> None:
        backend = PostgresBackend(make_config(pool_min="2", pool_max="50"))
        await backend.connect()
        (kwargs,) = fake_asyncpg.create_pool_calls
        assert kwargs["min_size"] == 2
        assert kwargs["max_size"] == 50

    @pytest.mark.parametrize(
        "options",
        [
            {"pool_min": "0"},
            {"pool_max": "101"},
            {"pool_min": "abc"},
            {"pool_max": "2.5"},
            {"pool_min": "-1"},
        ],
    )
    def test_pool_size_out_of_bounds_or_unparsable(
        self, options: dict[str, str]
    ) -> None:
        with pytest.raises(ConfigurationError):
            PostgresBackend(make_config(**options))

    def test_pool_min_may_not_exceed_pool_max(self) -> None:
        with pytest.raises(ConfigurationError, match="pool_min"):
            PostgresBackend(make_config(pool_min="8", pool_max="2"))

    async def test_empty_user_and_password_become_none(
        self, fake_asyncpg: FakeAsyncpgModule
    ) -> None:
        config = DatabaseConfig(
            backend="postgresql", host="h", port=5432, database="d"
        )
        backend = PostgresBackend(config)
        await backend.connect()
        (kwargs,) = fake_asyncpg.create_pool_calls
        assert kwargs["user"] is None
        assert kwargs["password"] is None

    async def test_parsed_url_flows_through_to_create_pool(
        self, fake_asyncpg: FakeAsyncpgModule
    ) -> None:
        config = parse_database_url(
            "postgresql://app:pw@db.internal:6432/appdb"
            "?sslmode=verify-full&pool_min=2&pool_max=4"
        )
        backend = PostgresBackend(config)
        await backend.connect()
        (kwargs,) = fake_asyncpg.create_pool_calls
        assert kwargs["host"] == "db.internal"
        assert kwargs["port"] == 6432
        assert kwargs["ssl"] == "verify-full"
        assert kwargs["min_size"] == 2
        assert kwargs["max_size"] == 4


class TestSslMode:
    @pytest.mark.parametrize(
        ("sslmode", "expected"),
        [
            ("disable", False),
            ("allow", "allow"),
            ("prefer", "prefer"),
            ("require", "require"),
            ("verify-ca", "verify-ca"),
            ("verify-full", "verify-full"),
        ],
    )
    async def test_sslmode_maps_to_asyncpg_ssl(
        self, fake_asyncpg: FakeAsyncpgModule, sslmode: str, expected: Any
    ) -> None:
        backend = PostgresBackend(make_config(sslmode=sslmode))
        await backend.connect()
        (kwargs,) = fake_asyncpg.create_pool_calls
        assert kwargs["ssl"] == expected

    def test_unknown_sslmode_raises(self) -> None:
        with pytest.raises(ConfigurationError, match="sslmode"):
            PostgresBackend(make_config(sslmode="sideways"))


class TestServerSettings:
    async def test_leftover_options_forwarded_as_server_settings(
        self, fake_asyncpg: FakeAsyncpgModule
    ) -> None:
        backend = PostgresBackend(
            make_config(sslmode="require", pool_max="5", application_name="myapp")
        )
        await backend.connect()
        (kwargs,) = fake_asyncpg.create_pool_calls
        assert kwargs["server_settings"] == {"application_name": "myapp"}
        assert kwargs["ssl"] == "require"
        assert kwargs["max_size"] == 5


# --------------------------------------------------------------------------
# Lifecycle
# --------------------------------------------------------------------------


class TestLifecycle:
    async def test_connect_is_lazy_and_idempotent(
        self, backend: PostgresBackend, fake_asyncpg: FakeAsyncpgModule
    ) -> None:
        assert fake_asyncpg.create_pool_calls == []
        await backend.connect()
        await backend.connect()
        assert len(fake_asyncpg.create_pool_calls) == 1

    async def test_first_query_connects_implicitly(
        self, backend: PostgresBackend, fake_asyncpg: FakeAsyncpgModule
    ) -> None:
        await backend.execute("CREATE TABLE t (id INT)")
        assert len(fake_asyncpg.create_pool_calls) == 1

    async def test_aclose_is_idempotent(
        self, backend: PostgresBackend, fake_pool: FakePool
    ) -> None:
        await backend.connect()
        await backend.aclose()
        await backend.aclose()
        assert fake_pool.close_calls == 1

    async def test_reusable_after_close_via_another_connect(
        self, backend: PostgresBackend, fake_asyncpg: FakeAsyncpgModule
    ) -> None:
        await backend.connect()
        await backend.aclose()
        await backend.connect()
        assert len(fake_asyncpg.create_pool_calls) == 2

    async def test_create_pool_failure_translates_to_operational_error(
        self, backend: PostgresBackend, fake_asyncpg: FakeAsyncpgModule
    ) -> None:
        fake_asyncpg.create_pool_error = ConnectionRefusedError(61, "refused")
        with pytest.raises(OperationalError):
            await backend.connect()


# --------------------------------------------------------------------------
# One-shot statements
# --------------------------------------------------------------------------


class TestExecute:
    @pytest.mark.parametrize(
        ("tag", "expected"),
        [
            ("UPDATE 3", 3),
            ("DELETE 0", 0),
            ("INSERT 0 5", 5),
            ("SELECT 12", 12),
            ("COPY 7", 7),
            ("CREATE TABLE", -1),
            ("BEGIN", -1),
            ("", -1),
        ],
    )
    async def test_rowcount_parsed_from_command_tag(
        self,
        backend: PostgresBackend,
        fake_conn: FakeConnection,
        tag: str,
        expected: int,
    ) -> None:
        fake_conn.results["execute"] = tag
        assert await backend.execute("UPDATE t SET x = $1", (1,)) == expected

    async def test_params_passed_positionally(
        self, backend: PostgresBackend, fake_conn: FakeConnection
    ) -> None:
        await backend.execute("INSERT INTO t VALUES ($1, $2)", (1, "a"))
        assert fake_conn.calls == [
            ("execute", "INSERT INTO t VALUES ($1, $2)", (1, "a"))
        ]

    async def test_one_shot_executemany_runs_in_a_transaction(
        self, backend: PostgresBackend, fake_conn: FakeConnection
    ) -> None:
        await backend.executemany("INSERT INTO t VALUES ($1)", [(1,), (2,)])
        (handle,) = fake_conn.transactions
        assert handle.started and handle.committed
        assert fake_conn.calls == [
            ("executemany", "INSERT INTO t VALUES ($1)", ((1,), (2,)))
        ]

    async def test_connection_released_after_one_shot(
        self,
        backend: PostgresBackend,
        fake_conn: FakeConnection,
        fake_pool: FakePool,
    ) -> None:
        await backend.execute("DELETE FROM t")
        assert fake_pool.released == [fake_conn]


class TestFetch:
    async def test_fetchone_none_passes_through(
        self, backend: PostgresBackend
    ) -> None:
        assert await backend.fetchone("SELECT 1 WHERE FALSE") is None

    async def test_fetchone_builds_row(
        self, backend: PostgresBackend, fake_conn: FakeConnection
    ) -> None:
        fake_conn.results["fetchrow"] = FakeRecord({"id": 1, "email": "a@b.c"})
        row = await backend.fetchone("SELECT id, email FROM users")
        assert isinstance(row, Row)
        assert row.keys() == ("id", "email")
        assert row["email"] == "a@b.c"
        assert row == (1, "a@b.c")

    async def test_fetchall_builds_rows(
        self, backend: PostgresBackend, fake_conn: FakeConnection
    ) -> None:
        fake_conn.results["fetch"] = [
            FakeRecord({"id": 1}),
            FakeRecord({"id": 2}),
        ]
        rows = await backend.fetchall("SELECT id FROM users")
        assert [row["id"] for row in rows] == [1, 2]
        assert all(isinstance(row, Row) for row in rows)

    async def test_naive_datetime_tagged_utc(
        self, backend: PostgresBackend, fake_conn: FakeConnection
    ) -> None:
        naive = datetime(2026, 1, 2, 3, 4, 5)
        fake_conn.results["fetchrow"] = FakeRecord({"created_at": naive})
        row = await backend.fetchone("SELECT created_at FROM t")
        assert row is not None
        assert row["created_at"] == datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)

    async def test_aware_datetime_converted_to_utc(
        self, backend: PostgresBackend, fake_conn: FakeConnection
    ) -> None:
        ist = timezone(timedelta(hours=5, minutes=30))
        aware = datetime(2026, 1, 2, 9, 0, 0, tzinfo=ist)
        fake_conn.results["fetchrow"] = FakeRecord({"t": aware})
        row = await backend.fetchone("SELECT t FROM x")
        assert row is not None
        assert row["t"].utcoffset() == timedelta(0)
        assert row["t"] == aware  # same instant

    async def test_normalisation_is_top_level_only(
        self, backend: PostgresBackend, fake_conn: FakeConnection
    ) -> None:
        naive = datetime(2026, 1, 2, 3, 4, 5)
        fake_conn.results["fetchrow"] = FakeRecord(
            {"times": [naive], "d": date(2026, 1, 2)}
        )
        row = await backend.fetchone("SELECT times, d FROM t")
        assert row is not None
        assert row["times"][0].tzinfo is None  # nested values untouched
        assert row["d"] == date(2026, 1, 2)  # dates are not datetimes


# --------------------------------------------------------------------------
# Error translation
# --------------------------------------------------------------------------


class _WeirdClass23Error(apg_exc.PostgresError):
    """A server error in SQLSTATE class 23 asyncpg has no subclass for."""

    sqlstate = "23P99"


class TestErrorTranslation:
    @pytest.mark.parametrize(
        ("driver_exc", "expected"),
        [
            (apg_exc.UniqueViolationError("duplicate key"), IntegrityError),
            (apg_exc.ForeignKeyViolationError("fk violated"), IntegrityError),
            (apg_exc.NotNullViolationError("null in NOT NULL"), IntegrityError),
            (apg_exc.CheckViolationError("check failed"), IntegrityError),
            (_WeirdClass23Error("custom integrity"), IntegrityError),
            (apg_exc.CannotConnectNowError("starting up"), OperationalError),
            (apg_exc.ConnectionDoesNotExistError("conn gone"), OperationalError),
            (apg_exc.ConnectionFailureError("conn failed"), OperationalError),
            (apg_exc.AdminShutdownError("server shutting down"), OperationalError),
            (apg_exc.InterfaceError("connection is closed"), OperationalError),
            (ConnectionRefusedError(61, "refused"), OperationalError),
            (TimeoutError(), OperationalError),
            (apg_exc.PostgresSyntaxError("syntax error at or near"), DatabaseError),
            (apg_exc.DataError("invalid input syntax"), DatabaseError),
            (apg_exc.InternalClientError("protocol desync"), DatabaseError),
        ],
    )
    async def test_driver_exception_translates(
        self,
        backend: PostgresBackend,
        fake_conn: FakeConnection,
        driver_exc: Exception,
        expected: type[DatabaseError],
    ) -> None:
        fake_conn.results["execute"] = driver_exc
        with pytest.raises(expected) as excinfo:
            await backend.execute("INSERT INTO t VALUES ($1)", (1,))
        assert type(excinfo.value) is expected
        assert excinfo.value.__cause__ is driver_exc

    async def test_message_preserved_and_chained(
        self, backend: PostgresBackend, fake_conn: FakeConnection
    ) -> None:
        original = apg_exc.UniqueViolationError(
            'duplicate key value violates unique constraint "users_email_key"'
        )
        fake_conn.results["execute"] = original
        with pytest.raises(IntegrityError) as excinfo:
            await backend.execute("INSERT INTO users VALUES ($1)", ("a@b.c",))
        assert str(excinfo.value) == str(original)
        assert excinfo.value.__cause__ is original

    async def test_fetch_paths_translate_too(
        self, backend: PostgresBackend, fake_conn: FakeConnection
    ) -> None:
        fake_conn.results["fetchrow"] = apg_exc.ConnectionDoesNotExistError("gone")
        with pytest.raises(OperationalError):
            await backend.fetchone("SELECT 1")
        fake_conn.results["fetch"] = apg_exc.UniqueViolationError("dup")
        with pytest.raises(IntegrityError):
            await backend.fetchall("SELECT 1")

    async def test_pool_acquire_timeout_translates(
        self, backend: PostgresBackend, fake_pool: FakePool
    ) -> None:
        fake_pool.acquire_error = TimeoutError()
        with pytest.raises(OperationalError):
            await backend.fetchone("SELECT 1")


# --------------------------------------------------------------------------
# Transactions
# --------------------------------------------------------------------------


class TestTransaction:
    async def test_commit_on_success_and_release(
        self,
        backend: PostgresBackend,
        fake_conn: FakeConnection,
        fake_pool: FakePool,
    ) -> None:
        async with backend.transaction() as tx:
            rowcount = await tx.execute("UPDATE t SET x = $1", (1,))
        assert rowcount == -1  # fake's default "OK" tag has no count
        (handle,) = fake_conn.transactions
        assert handle.started and handle.committed and not handle.rolled_back
        assert fake_pool.released == [fake_conn]

    async def test_rollback_on_driver_error_and_release(
        self,
        backend: PostgresBackend,
        fake_conn: FakeConnection,
        fake_pool: FakePool,
    ) -> None:
        fake_conn.results["execute"] = apg_exc.UniqueViolationError("dup")
        with pytest.raises(IntegrityError):
            async with backend.transaction() as tx:
                await tx.execute("INSERT INTO t VALUES ($1)", (1,))
        (handle,) = fake_conn.transactions
        assert handle.rolled_back and not handle.committed
        assert fake_pool.released == [fake_conn]

    async def test_application_error_passes_through_untranslated(
        self,
        backend: PostgresBackend,
        fake_conn: FakeConnection,
        fake_pool: FakePool,
    ) -> None:
        with pytest.raises(ValueError, match="app bug"):
            async with backend.transaction():
                raise ValueError("app bug")
        (handle,) = fake_conn.transactions
        assert handle.rolled_back
        assert fake_pool.released == [fake_conn]

    async def test_statements_share_the_acquired_connection(
        self, backend: PostgresBackend, fake_conn: FakeConnection
    ) -> None:
        async with backend.transaction() as tx:
            await tx.execute("INSERT INTO t VALUES ($1)", (1,))
            await tx.executemany("INSERT INTO t VALUES ($1)", [(2,), (3,)])
            await tx.fetchone("SELECT 1")
            await tx.fetchall("SELECT 2")
        assert [call[0] for call in fake_conn.calls] == [
            "execute",
            "executemany",
            "fetchrow",
            "fetch",
        ]

    async def test_rowcount_parsed_inside_transaction(
        self, backend: PostgresBackend, fake_conn: FakeConnection
    ) -> None:
        fake_conn.results["execute"] = "UPDATE 4"
        async with backend.transaction() as tx:
            assert await tx.execute("UPDATE t SET x = 1") == 4

    async def test_commit_failure_translates_and_releases(
        self,
        backend: PostgresBackend,
        fake_conn: FakeConnection,
        fake_pool: FakePool,
    ) -> None:
        fake_conn.tx_commit_error = apg_exc.ConnectionDoesNotExistError("died")
        with pytest.raises(OperationalError):
            async with backend.transaction() as tx:
                await tx.execute("INSERT INTO t VALUES (1)")
        assert fake_pool.released == [fake_conn]

    async def test_acquire_failure_translates(
        self, backend: PostgresBackend, fake_pool: FakePool
    ) -> None:
        fake_pool.acquire_error = TimeoutError()
        with pytest.raises(OperationalError):
            async with backend.transaction():
                pass  # pragma: no cover - never entered

    async def test_concurrent_transactions_use_distinct_connections(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        conn_a, conn_b = FakeConnection(), FakeConnection()
        pool = FakePool([conn_a, conn_b])
        monkeypatch.setattr(pg_module, "asyncpg", FakeAsyncpgModule(pool))
        backend = PostgresBackend(make_config())
        async with backend.transaction() as tx_a:
            async with backend.transaction() as tx_b:
                await tx_a.execute("SELECT 'a'")
                await tx_b.execute("SELECT 'b'")
        assert [call[1] for call in conn_a.calls] == ["SELECT 'a'"]
        assert [call[1] for call in conn_b.calls] == ["SELECT 'b'"]


# --------------------------------------------------------------------------
# Live conformance tests (skipped unless PYXLE_DB_TEST_POSTGRES_URL is set)
# --------------------------------------------------------------------------

LIVE_URL = os.environ.get("PYXLE_DB_TEST_POSTGRES_URL", "")

live = pytest.mark.skipif(
    not LIVE_URL, reason="PYXLE_DB_TEST_POSTGRES_URL is not set"
)


@live
class TestLivePostgres:
    @pytest.fixture
    async def db(self):  # type: ignore[no-untyped-def]  # pyxle_db.Database
        from pyxle_db import Database

        database = Database.from_url(LIVE_URL)
        await database.connect()
        try:
            yield database
        finally:
            await database.aclose()

    @pytest.fixture
    async def users(self, db):  # type: ignore[no-untyped-def]
        table = f"pyxle_test_{uuid.uuid4().hex[:12]}"
        await db.execute(
            f"CREATE TABLE {table} ("
            "  id SERIAL PRIMARY KEY,"
            "  email TEXT UNIQUE NOT NULL,"
            "  data JSONB,"
            "  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),"
            "  local_ts TIMESTAMP"
            ")"
        )
        try:
            yield table
        finally:
            await db.execute(f"DROP TABLE IF EXISTS {table}")

    async def test_roundtrip(self, db, users: str) -> None:  # type: ignore[no-untyped-def]
        await db.execute(
            f"INSERT INTO {users} (email, local_ts) VALUES (?, ?)",
            ("ada@example.com", datetime(2026, 1, 2, 3, 4, 5)),
        )
        row = await db.fetchone(
            f"SELECT id, email, created_at, local_ts FROM {users} WHERE email = ?",
            ("ada@example.com",),
        )
        assert isinstance(row, Row)
        assert row["email"] == "ada@example.com"
        # Contract rule 4: every datetime is aware UTC — including the
        # naive TIMESTAMP column.
        assert row["created_at"].tzinfo is not None
        assert row["created_at"].utcoffset() == timedelta(0)
        assert row["local_ts"] == datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)

    async def test_aware_datetime_param_binds_to_naive_timestamp(self, db, users: str) -> None:  # type: ignore[no-untyped-def]
        """Write side of the datetime contract on a real server: an aware
        non-UTC datetime must bind into a naive TIMESTAMP column (asyncpg
        rejects that without the backend's normalisation) and read back as
        the same instant, aware UTC."""
        ist = timezone(timedelta(hours=5, minutes=30))
        moment = datetime(2026, 6, 11, 9, 30, 15, 123456, tzinfo=ist)
        await db.execute(
            f"INSERT INTO {users} (email, local_ts) VALUES (?, ?)",
            ("aware@example.com", moment),
        )
        row = await db.fetchone(
            f"SELECT local_ts FROM {users} WHERE email = ?", ("aware@example.com",)
        )
        assert row is not None
        assert row["local_ts"].tzinfo is not None
        assert row["local_ts"] == moment  # same instant, normalised to UTC

    async def test_transaction_commit_and_rowcount(self, db, users: str) -> None:  # type: ignore[no-untyped-def]
        async with db.transaction() as tx:
            await tx.execute(
                f"INSERT INTO {users} (email) VALUES (?)", ("grace@example.com",)
            )
            updated = await tx.execute(
                f"UPDATE {users} SET email = ? WHERE email = ?",
                ("grace@pyxle.dev", "grace@example.com"),
            )
            assert updated == 1
        row = await db.fetchone(
            f"SELECT email FROM {users} WHERE email = ?", ("grace@pyxle.dev",)
        )
        assert row is not None

    async def test_transaction_rolls_back_on_error(self, db, users: str) -> None:  # type: ignore[no-untyped-def]
        with pytest.raises(RuntimeError, match="abort"):
            async with db.transaction() as tx:
                await tx.execute(
                    f"INSERT INTO {users} (email) VALUES (?)",
                    ("rollback@example.com",),
                )
                raise RuntimeError("abort")
        row = await db.fetchone(
            f"SELECT 1 FROM {users} WHERE email = ?", ("rollback@example.com",)
        )
        assert row is None

    async def test_unique_violation_raises_integrity_error(self, db, users: str) -> None:  # type: ignore[no-untyped-def]
        await db.execute(
            f"INSERT INTO {users} (email) VALUES (?)", ("dup@example.com",)
        )
        with pytest.raises(IntegrityError):
            await db.execute(
                f"INSERT INTO {users} (email) VALUES (?)", ("dup@example.com",)
            )

    async def test_executemany_is_atomic(self, db, users: str) -> None:  # type: ignore[no-untyped-def]
        with pytest.raises(IntegrityError):
            await db.executemany(
                f"INSERT INTO {users} (email) VALUES (?)",
                [("one@example.com",), ("one@example.com",)],
            )
        rows = await db.fetchall(f"SELECT email FROM {users}")
        assert rows == []  # the non-violating row rolled back with the batch

    async def test_double_question_mark_json_operator(self, db, users: str) -> None:  # type: ignore[no-untyped-def]
        await db.execute(
            f"INSERT INTO {users} (email, data) VALUES (?, ?)",
            ("json@example.com", '{"plan": "pro"}'),
        )
        # `??` survives translation as the jsonb `?` (key exists) operator
        # while real placeholders become $1/$2.
        row = await db.fetchone(
            f"SELECT data ?? ? AS has_plan FROM {users} WHERE email = ?",
            ("plan", "json@example.com"),
        )
        assert row is not None
        assert row["has_plan"] is True
