"""Backend-neutral result row.

Every backend returns :class:`Row` so application code behaves identically
on SQLite, PostgreSQL, and MySQL: index access (``row[0]``), name access
(``row["email"]``), ``keys()``, iteration, and equality against tuples.
Immutable by design — rows are snapshots, not live cursors.
"""

from __future__ import annotations

from typing import Any, Iterator, Sequence


class Row(Sequence[Any]):
    __slots__ = ("_columns", "_values", "_index")

    def __init__(self, columns: Sequence[str], values: Sequence[Any]) -> None:
        if len(columns) != len(values):
            raise ValueError(
                f"Row column/value mismatch: {len(columns)} columns, {len(values)} values"
            )
        object.__setattr__(self, "_columns", tuple(columns))
        object.__setattr__(self, "_values", tuple(values))
        # Last-one-wins for duplicate column names (matches sqlite3.Row).
        object.__setattr__(
            self, "_index", {name: i for i, name in enumerate(columns)}
        )

    # -- mapping-style access -------------------------------------------------

    def keys(self) -> tuple[str, ...]:
        return self._columns

    def get(self, key: str, default: Any = None) -> Any:
        i = self._index.get(key)
        return self._values[i] if i is not None else default

    # -- sequence protocol ----------------------------------------------------

    def __getitem__(self, key: int | str | slice) -> Any:
        if isinstance(key, str):
            try:
                return self._values[self._index[key]]
            except KeyError:
                raise KeyError(
                    f"No such column {key!r}; columns are {list(self._columns)}"
                ) from None
        return self._values[key]

    def __len__(self) -> int:
        return len(self._values)

    def __iter__(self) -> Iterator[Any]:
        return iter(self._values)

    def __contains__(self, item: object) -> bool:
        return item in self._values

    # -- niceties ---------------------------------------------------------------

    def asdict(self) -> dict[str, Any]:
        return {name: self._values[i] for name, i in self._index.items()}

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Row):
            return self._columns == other._columns and self._values == other._values
        if isinstance(other, tuple):
            return self._values == other
        return NotImplemented

    def __hash__(self) -> int:
        return hash((self._columns, self._values))

    def __setattr__(self, name: str, value: Any) -> None:
        raise AttributeError("Row is immutable")

    def __repr__(self) -> str:
        pairs = ", ".join(f"{k}={v!r}" for k, v in zip(self._columns, self._values))
        return f"Row({pairs})"
