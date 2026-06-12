"""Tests for :mod:`pyxle_db.rows` — the portable result row.

Row is the one object every backend hands to application code, so its
access semantics (index, name, slice), equality rules, and immutability
must be exact.
"""

from __future__ import annotations

from collections.abc import Sequence

import pytest

from pyxle_db.rows import Row


@pytest.fixture
def row() -> Row:
    return Row(["id", "email"], [7, "ada@example.com"])


class TestConstruction:
    def test_column_value_mismatch_raises(self) -> None:
        with pytest.raises(ValueError, match="2 columns, 3 values"):
            Row(["a", "b"], [1, 2, 3])

    def test_empty_row(self) -> None:
        empty = Row([], [])
        assert len(empty) == 0
        assert empty.keys() == ()
        assert empty.asdict() == {}
        assert empty == ()


class TestAccess:
    def test_index_access(self, row: Row) -> None:
        assert row[0] == 7
        assert row[1] == "ada@example.com"

    def test_negative_index(self, row: Row) -> None:
        assert row[-1] == "ada@example.com"

    def test_index_out_of_range(self, row: Row) -> None:
        with pytest.raises(IndexError):
            row[5]

    def test_name_access(self, row: Row) -> None:
        assert row["id"] == 7
        assert row["email"] == "ada@example.com"

    def test_slice_access_returns_value_tuple(self, row: Row) -> None:
        assert row[0:2] == (7, "ada@example.com")
        assert row[::-1] == ("ada@example.com", 7)
        assert isinstance(row[0:1], tuple)

    def test_missing_column_keyerror_lists_columns(self, row: Row) -> None:
        with pytest.raises(KeyError) as excinfo:
            row["nope"]
        assert excinfo.value.args[0] == (
            "No such column 'nope'; columns are ['id', 'email']"
        )

    def test_get_present(self, row: Row) -> None:
        assert row.get("email") == "ada@example.com"

    def test_get_value_at_index_zero_is_not_treated_as_missing(self) -> None:
        assert Row(["n"], [0]).get("n") == 0

    def test_get_missing_defaults_to_none(self, row: Row) -> None:
        assert row.get("nope") is None

    def test_get_missing_with_explicit_default(self, row: Row) -> None:
        assert row.get("nope", "fallback") == "fallback"

    def test_keys(self, row: Row) -> None:
        assert row.keys() == ("id", "email")


class TestDuplicateColumns:
    def test_name_access_last_wins(self) -> None:
        dup = Row(["a", "a"], [1, 2])
        assert dup["a"] == 2
        assert dup.get("a") == 2

    def test_index_access_still_sees_both(self) -> None:
        dup = Row(["a", "a"], [1, 2])
        assert dup[0] == 1 and dup[1] == 2
        assert dup.keys() == ("a", "a")

    def test_asdict_collapses_to_last(self) -> None:
        assert Row(["a", "a"], [1, 2]).asdict() == {"a": 2}


class TestEquality:
    def test_equal_to_matching_tuple_both_directions(self, row: Row) -> None:
        assert row == (7, "ada@example.com")
        assert (7, "ada@example.com") == row

    def test_not_equal_to_different_tuple(self, row: Row) -> None:
        assert row != (7, "other@example.com")

    def test_equal_to_identical_row(self, row: Row) -> None:
        assert row == Row(["id", "email"], [7, "ada@example.com"])

    def test_same_values_different_columns_not_equal(self) -> None:
        assert Row(["a", "b"], [1, 2]) != Row(["x", "y"], [1, 2])

    def test_list_comparison_is_false_not_an_error(self, row: Row) -> None:
        assert (row == [7, "ada@example.com"]) is False


class TestHashing:
    def test_equal_rows_hash_equal(self, row: Row) -> None:
        twin = Row(["id", "email"], [7, "ada@example.com"])
        assert hash(row) == hash(twin)
        assert len({row, twin}) == 1

    def test_usable_as_dict_key(self, row: Row) -> None:
        twin = Row(["id", "email"], [7, "ada@example.com"])
        assert {row: "hit"}[twin] == "hit"


class TestImmutability:
    def test_new_attribute_rejected(self, row: Row) -> None:
        with pytest.raises(AttributeError, match="immutable"):
            row.extra = 1  # type: ignore[attr-defined]

    def test_internal_attribute_rejected(self, row: Row) -> None:
        with pytest.raises(AttributeError, match="immutable"):
            row._values = ()  # type: ignore[misc]


class TestSequenceBehaviour:
    def test_len(self, row: Row) -> None:
        assert len(row) == 2

    def test_iteration_yields_values_in_order(self, row: Row) -> None:
        assert list(row) == [7, "ada@example.com"]

    def test_contains_checks_values_not_column_names(self, row: Row) -> None:
        assert 7 in row
        assert "ada@example.com" in row
        assert "id" not in row
        assert None not in row

    def test_is_a_sequence_with_working_mixins(self, row: Row) -> None:
        assert isinstance(row, Sequence)
        assert row.count(7) == 1
        assert row.index("ada@example.com") == 1


class TestConveniences:
    def test_asdict(self, row: Row) -> None:
        assert row.asdict() == {"id": 7, "email": "ada@example.com"}

    def test_repr(self) -> None:
        assert repr(Row(["id", "name"], [1, "ada"])) == "Row(id=1, name='ada')"
