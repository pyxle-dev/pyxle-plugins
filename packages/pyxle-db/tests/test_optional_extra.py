"""Verify the base install never requires SQLAlchemy, and the ORM path guards
its absence with a clear error.

The "SQLAlchemy is absent" case is exercised in a subprocess that blocks the
import — the dev environment has the extra installed, and you can't reliably
un-import a C-extension-backed package in-process.
"""

from __future__ import annotations

import subprocess
import sys
import textwrap


def test_base_install_is_sqlalchemy_free_and_orm_is_guarded() -> None:
    script = textwrap.dedent(
        """
        import builtins, sys
        _real_import = builtins.__import__
        def _blocked(name, *args, **kwargs):
            if name == "sqlalchemy" or name.startswith("sqlalchemy."):
                raise ImportError("sqlalchemy blocked for this test")
            return _real_import(name, *args, **kwargs)
        builtins.__import__ = _blocked

        # The base library must import and work with no SQLAlchemy present.
        import pyxle_db
        from pyxle_db import connect, no_auto_transaction, Database  # noqa: F401

        # Touching the ORM subpackage must raise a clean ConfigurationError.
        from pyxle_db.errors import ConfigurationError
        try:
            import pyxle_db.orm  # noqa: F401
        except ConfigurationError:
            print("ORM_GUARDED")
        else:
            print("ORM_NOT_GUARDED")
            sys.exit(2)
        print("BASE_OK")
        """
    )
    result = subprocess.run(
        [sys.executable, "-c", script], capture_output=True, text=True
    )
    assert result.returncode == 0, result.stderr
    assert "BASE_OK" in result.stdout
    assert "ORM_GUARDED" in result.stdout


def test_sqlalchemy_url_uses_a_local_import() -> None:
    # url.py must not import sqlalchemy at module load — only inside the method.
    import pyxle_db.url as url_mod

    source = (url_mod.__file__ or "")
    assert source  # sanity
    text = open(source, encoding="utf-8").read()
    # The only sqlalchemy reference is the local import inside sqlalchemy_url().
    module_level = [
        line
        for line in text.splitlines()
        if line.startswith("import sqlalchemy") or line.startswith("from sqlalchemy")
    ]
    assert module_level == []
