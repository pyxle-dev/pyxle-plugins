"""End-to-end Alembic integration: scaffold, autogenerate, upgrade, downgrade.

Exercises the generated async env.py against real SQLite — the metadata, the
URL resolution from pyxle config, and the upgrade/downgrade commands.
"""

from __future__ import annotations

import json
import sqlite3
import sys
import textwrap
from pathlib import Path

import pytest

from pyxle_db.cli import main

_MODELS = textwrap.dedent(
    """
    from sqlalchemy.orm import Mapped, mapped_column

    from pyxle_db.orm import Base


    class Gadget(Base):
        __tablename__ = "gadgets_alembic"

        id: Mapped[int] = mapped_column(primary_key=True)
        label: Mapped[str]
    """
)


def _make_orm_project(tmp_path: Path) -> Path:
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "pyxle.config.json").write_text(
        json.dumps(
            {
                "plugins": [
                    {
                        "name": "pyxle-db",
                        "settings": {
                            "path": "./data/app.db",
                            "orm": {"metadata": "alembic_test_models:Base"},
                        },
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    (proj / "alembic_test_models.py").write_text(_MODELS, encoding="utf-8")
    return proj


def _table_exists(db_file: Path, table: str) -> bool:
    con = sqlite3.connect(db_file)
    try:
        cur = con.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table,)
        )
        return cur.fetchone() is not None
    finally:
        con.close()


@pytest.fixture(autouse=True)
def _clean_models_module():
    # The generated env.py imports the project's models by name; clear any cached
    # copy so each test sees its own, and drop the table from Base.metadata after.
    sys.modules.pop("alembic_test_models", None)
    yield
    sys.modules.pop("alembic_test_models", None)


def test_alembic_init_scaffolds(tmp_path: Path) -> None:
    proj = _make_orm_project(tmp_path)
    assert main(["alembic-init", "--project", str(proj)]) == 0
    assert (proj / "alembic.ini").is_file()
    assert (proj / "alembic" / "env.py").is_file()
    assert (proj / "alembic" / "script.py.mako").is_file()
    assert (proj / "alembic" / "versions").is_dir()


def test_alembic_init_twice_errors(tmp_path: Path) -> None:
    proj = _make_orm_project(tmp_path)
    assert main(["alembic-init", "--project", str(proj)]) == 0
    assert main(["alembic-init", "--project", str(proj)]) == 1


def test_alembic_autogenerate_upgrade_downgrade(tmp_path: Path) -> None:
    proj = _make_orm_project(tmp_path)
    db_file = proj / "data" / "app.db"

    assert main(["alembic-init", "--project", str(proj)]) == 0
    assert main(["revision", "-m", "init", "--autogenerate", "--project", str(proj)]) == 0

    # A revision file was generated.
    versions = list((proj / "alembic" / "versions").glob("*.py"))
    assert versions, "autogenerate produced no revision"

    assert main(["upgrade", "head", "--project", str(proj)]) == 0
    assert _table_exists(db_file, "gadgets_alembic")

    assert main(["downgrade", "base", "--project", str(proj)]) == 0
    assert not _table_exists(db_file, "gadgets_alembic")


def test_revision_without_init_errors(tmp_path: Path) -> None:
    proj = _make_orm_project(tmp_path)
    assert main(["revision", "-m", "x", "--project", str(proj)]) == 1
