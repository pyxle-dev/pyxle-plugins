"""Alembic integration for the pyxle-db ORM path.

Scaffolding templates (``env.py.tmpl``, ``alembic.ini.tmpl``, ``script.py.mako``)
live here; :mod:`pyxle_db.cli.alembic_cmds` copies them on ``pyxle-db alembic-init``
and drives Alembic's Python API. :func:`pyxle_db.orm.alembic.runtime.resolve_alembic_runtime`
gives the scaffolded ``env.py`` the same database URL + metadata the app uses.
"""

from __future__ import annotations

__all__: list[str] = []
