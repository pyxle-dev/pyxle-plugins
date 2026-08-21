from __future__ import annotations

from pathlib import Path
from typing import AsyncIterator

import pytest

from pyxle_auth import AuthService, AuthSettings
from pyxle_db import Database, connect


@pytest.fixture
async def db(tmp_path: Path) -> AsyncIterator[Database]:
    db = await connect(tmp_path / "auth.db")
    try:
        yield db
    finally:
        await db.aclose()


@pytest.fixture
def settings() -> AuthSettings:
    # for_tests() drops argon cost and cookie_secure.
    return AuthSettings(strict=False).for_tests()


@pytest.fixture
async def auth(db: Database, settings: AuthSettings) -> AuthService:
    service = AuthService(db, settings)
    await service.ensure_schema()
    return service


# ---------------------------------------------------------------------------
# Coverage floor + skipped live suites (D-026)
#
# The coverage floor is measured with the live database engines running. Clone
# the repo, run `pytest` with no engines, and the live suites skip — taking
# their coverage with them — so the run lands *under* the floor and fails for a
# reason that has nothing to do with the change being made.
#
# Loosening the floor would hide a real signal. Instead the failure explains
# itself: what happened, why, and the two ways forward. The person most likely
# to meet this is a first-time contributor on day one, with the least context
# and the least patience for a gate that fails without saying why.
# ---------------------------------------------------------------------------


def _live_skip_count(terminalreporter) -> int:
    """How many tests skipped for a missing engine URL or driver.

    Counts only the two masks that remove live-backend coverage; an unrelated
    skip must not make this message appear and misexplain the failure.
    """
    markers = (
        "PYXLE_DB_TEST_POSTGRES_URL",
        "PYXLE_DB_TEST_MYSQL_URL",
        "asyncpg",
        "asyncmy",
    )
    count = 0
    for report in terminalreporter.stats.get("skipped", []):
        reason = ""
        if isinstance(getattr(report, "longrepr", None), tuple) and len(report.longrepr) == 3:
            reason = str(report.longrepr[2])
        if any(m in reason for m in markers):
            count += 1
    return count


# trylast: pytest-cov fills in the coverage total during its own terminal
# summary. Run before it and the total is still None, so this hook reads
# "nothing to explain" and stays silent exactly when it is needed.
@pytest.hookimpl(trylast=True)
def pytest_terminal_summary(terminalreporter, exitstatus, config) -> None:
    if exitstatus == 0:
        return
    # Real test failures own the summary — never talk over them.
    if terminalreporter.stats.get("failed") or terminalreporter.stats.get("error"):
        return

    skipped = _live_skip_count(terminalreporter)
    if not skipped:
        return

    cov = config.pluginmanager.getplugin("_cov")
    total = getattr(cov, "cov_total", None) if cov else None
    floor = getattr(getattr(cov, "options", None), "cov_fail_under", None) if cov else None
    if total is None or floor is None or total >= floor:
        return

    write = terminalreporter.write_line
    write("")
    write("=" * 72, yellow=True)
    write("Coverage is under the floor because the live suites did not run.", yellow=True, bold=True)
    write("")
    write(f"  {skipped} test(s) skipped: no live database engine was reachable.")
    write(f"  Their coverage is missing, which is why the total came in at")
    write(f"  {total:.2f}% against a floor of {floor:.1f}%.")
    write("")
    write("  Your change did not cause this.")
    write("")
    write("  Two ways forward:")
    write("")
    write("    1. Start the engines and re-run (what CI does):")
    write("         docker run -d -e POSTGRES_USER=pyxle -e POSTGRES_PASSWORD=pyxle \\")
    write("           -e POSTGRES_DB=pyxle_test -p 5432:5432 postgres:16")
    write("         docker run -d -e MYSQL_ROOT_PASSWORD=pyxle -e MYSQL_USER=pyxle \\")
    write("           -e MYSQL_PASSWORD=pyxle -e MYSQL_DATABASE=pyxle_test -p 3306:3306 mysql:8")
    write("         export PYXLE_DB_TEST_POSTGRES_URL=postgresql://pyxle:pyxle@127.0.0.1:5432/pyxle_test")
    write("         export PYXLE_DB_TEST_MYSQL_URL=mysql://pyxle:pyxle@127.0.0.1:3306/pyxle_test")
    write("       (the postgres/mysql extras must be installed too — see README)")
    write("")
    write("    2. Iterating on one test? Skip coverage for the loop:")
    write("         pytest --no-cov tests/test_something.py")
    write("")
    write("=" * 72, yellow=True)
