"""Dialect-aware SQL text utilities.

Two jobs, one literal-aware scanner:

* :func:`translate` — rewrite canonical qmark (``?``) placeholders into the
  target dialect's parameter style (``$1``/``$2`` for PostgreSQL, ``%s`` for
  MySQL). ``??`` escapes a literal question mark (needed for PostgreSQL's
  JSON operators, e.g. ``data ?? 'key'`` → ``data ? 'key'``).
* :func:`split_statements` — split a multi-statement script on ``;`` so
  migrations can run statement-at-a-time inside one transaction.

Both MUST ignore anything inside:

* single-quoted strings (with ``''`` escape),
* double-quoted identifiers (with ``""`` escape),
* MySQL backtick identifiers,
* line comments (``-- …`` to end of line, and MySQL ``# …``),
* block comments (``/* … */``, non-nesting per the SQL standard),
* PostgreSQL dollar-quoted strings (``$$ … $$`` and ``$tag$ … $tag$``).

A translator that misses one of these turns user data into SQL structure —
this module is security-sensitive and exhaustively tested with hostile
inputs in ``tests/test_sql.py``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Iterator


_DOLLAR_TAG = re.compile(r"\$([A-Za-z_][A-Za-z0-9_]*)?\$")


@dataclass(frozen=True)
class _Region:
    """A half-open [start, end) span of SQL that is literal text."""

    start: int
    end: int


def _scan_literal_regions(
    sql: str,
    *,
    dollar_quotes: bool,
    hash_comments: bool,
    backtick_identifiers: bool,
) -> list[_Region]:
    """Return every span the scanner must treat as opaque text."""
    regions: list[_Region] = []
    i = 0
    n = len(sql)
    while i < n:
        ch = sql[i]

        # -- line comment
        if ch == "-" and sql.startswith("--", i):
            end = sql.find("\n", i)
            end = n if end == -1 else end
            regions.append(_Region(i, end))
            i = end
            continue

        # # line comment (MySQL)
        if hash_comments and ch == "#":
            end = sql.find("\n", i)
            end = n if end == -1 else end
            regions.append(_Region(i, end))
            i = end
            continue

        # /* block comment */ — the standard says these do not nest.
        if ch == "/" and sql.startswith("/*", i):
            end = sql.find("*/", i + 2)
            end = n if end == -1 else end + 2
            regions.append(_Region(i, end))
            i = end
            continue

        # 'string' with '' escape
        if ch == "'":
            j = i + 1
            while j < n:
                j = sql.find("'", j)
                if j == -1:
                    j = n
                    break
                if sql.startswith("''", j):
                    j += 2
                    continue
                j += 1
                break
            regions.append(_Region(i, j))
            i = j
            continue

        # "identifier" with "" escape
        if ch == '"':
            j = i + 1
            while j < n:
                j = sql.find('"', j)
                if j == -1:
                    j = n
                    break
                if sql.startswith('""', j):
                    j += 2
                    continue
                j += 1
                break
            regions.append(_Region(i, j))
            i = j
            continue

        # `identifier` (MySQL); `` escapes a backtick inside.
        if backtick_identifiers and ch == "`":
            j = i + 1
            while j < n:
                j = sql.find("`", j)
                if j == -1:
                    j = n
                    break
                if sql.startswith("``", j):
                    j += 2
                    continue
                j += 1
                break
            regions.append(_Region(i, j))
            i = j
            continue

        # $tag$ … $tag$ (PostgreSQL). An unterminated opener swallows the
        # rest of the script — matching PostgreSQL's own behaviour.
        if dollar_quotes and ch == "$":
            m = _DOLLAR_TAG.match(sql, i)
            if m is not None:
                tag = m.group(0)
                close = sql.find(tag, m.end())
                end = n if close == -1 else close + len(tag)
                regions.append(_Region(i, end))
                i = end
                continue

        i += 1
    return regions


def _walk(
    sql: str,
    *,
    dollar_quotes: bool = False,
    hash_comments: bool = False,
    backtick_identifiers: bool = False,
) -> Iterator[tuple[int, str, bool]]:
    """Yield ``(index, char, in_literal)`` for every character."""
    regions = _scan_literal_regions(
        sql,
        dollar_quotes=dollar_quotes,
        hash_comments=hash_comments,
        backtick_identifiers=backtick_identifiers,
    )
    bounds = iter(regions)
    current = next(bounds, None)
    for i, ch in enumerate(sql):
        while current is not None and i >= current.end:
            current = next(bounds, None)
        in_literal = current is not None and current.start <= i < current.end
        yield i, ch, in_literal


def translate(sql: str, paramstyle: str) -> str:
    """Rewrite qmark placeholders for the target ``paramstyle``.

    Supported styles:

    * ``"qmark"`` — pass through, but still honour the ``??`` escape so SQL
      written portably behaves identically on every backend.
    * ``"numeric_dollar"`` — ``$1``, ``$2``, … (asyncpg).
    * ``"format"`` — ``%s`` (MySQL drivers). Every literal ``%`` is doubled,
      *including inside string literals and comments*: the pymysql/asyncmy
      driver family applies printf-style substitution across the whole SQL
      string, so a single ``%`` anywhere (e.g. ``LIKE 'a%'``) would be
      misread by the driver's formatter. Placeholder rewriting itself stays
      literal-aware — a ``?`` inside a string is data, never a parameter.
    """
    if paramstyle not in ("qmark", "numeric_dollar", "format"):
        raise ValueError(f"Unknown paramstyle: {paramstyle!r}")

    dollar = paramstyle == "numeric_dollar"
    hashc = paramstyle == "format"
    ticks = paramstyle == "format"

    out: list[str] = []
    counter = 0
    skip = 0
    chars = sql  # local alias

    for i, ch, in_literal in _walk(
        chars,
        dollar_quotes=dollar,
        hash_comments=hashc,
        backtick_identifiers=ticks,
    ):
        if skip:
            skip -= 1
            continue
        if not in_literal and ch == "?":
            if chars.startswith("??", i):
                out.append("?")
                skip = 1
                continue
            counter += 1
            if paramstyle == "qmark":
                out.append("?")
            elif paramstyle == "numeric_dollar":
                out.append(f"${counter}")
            else:
                out.append("%s")
            continue
        if ch == "%" and paramstyle == "format":
            # Doubled even inside literals/comments — see the docstring: the
            # MySQL driver family formats the ENTIRE string, literals included.
            out.append("%%")
            continue
        out.append(ch)
    return "".join(out)


def count_placeholders(sql: str) -> int:
    """Number of bind parameters the canonical (qmark) SQL expects."""
    count = 0
    skip = 0
    for i, ch, in_literal in _walk(sql, dollar_quotes=True, hash_comments=True, backtick_identifiers=True):
        if skip:
            skip -= 1
            continue
        if not in_literal and ch == "?":
            if sql.startswith("??", i):
                skip = 1
                continue
            count += 1
    return count


def split_statements(
    script: str,
    *,
    dialect_name: str = "sqlite",
) -> list[str]:
    """Split a migration script into individual statements.

    Splits on ``;`` outside literals/comments. Empty fragments (whitespace,
    pure comments) are dropped. PostgreSQL scripts honour dollar quoting so
    function bodies survive; MySQL scripts honour ``#`` comments and
    backticks.
    """
    dollar = dialect_name == "postgresql"
    hashc = dialect_name == "mysql"
    ticks = dialect_name == "mysql"

    statements: list[str] = []
    start = 0
    for i, ch, in_literal in _walk(
        script,
        dollar_quotes=dollar,
        hash_comments=hashc,
        backtick_identifiers=ticks,
    ):
        if not in_literal and ch == ";":
            fragment = script[start:i]
            if _has_content(fragment):
                statements.append(fragment.strip())
            start = i + 1
    tail = script[start:]
    if _has_content(tail):
        statements.append(tail.strip())
    return statements


def _has_content(fragment: str) -> bool:
    """True if the fragment contains anything beyond whitespace/comments."""
    for _, ch, in_literal in _walk(fragment, dollar_quotes=True, hash_comments=True, backtick_identifiers=True):
        if in_literal:
            continue
        if not ch.isspace():
            return True
    return False


TranslateFn = Callable[[str], str]


def translator_for(paramstyle: str) -> TranslateFn:
    """Return a single-arg translate function bound to ``paramstyle``."""
    if paramstyle not in ("qmark", "numeric_dollar", "format"):
        raise ValueError(f"Unknown paramstyle: {paramstyle!r}")
    return lambda sql: translate(sql, paramstyle)
