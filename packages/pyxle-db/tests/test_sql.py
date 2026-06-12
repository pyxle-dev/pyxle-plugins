"""Hostile-input tests for :mod:`pyxle_db.sql`.

The translator/splitter is security-critical: one ``?`` rewritten inside a
string literal, or one ``;`` split inside a dollar-quoted function body,
silently corrupts SQL. Every test here feeds the scanner the constructs an
attacker (or an unlucky migration author) could produce: quote escapes,
comment markers inside literals, literals inside comments, placeholders
hugging closing quotes, and unterminated everything.
"""

from __future__ import annotations

import re

import pytest

from pyxle_db.sql import count_placeholders, split_statements, translate, translator_for

ALL_STYLES = ("qmark", "numeric_dollar", "format")


class TestTranslateQmark:
    """qmark is a passthrough — except the ``??`` escape must still apply."""

    def test_placeholders_pass_through_unchanged(self) -> None:
        sql = "SELECT * FROM users WHERE id = ? AND active = ?"
        assert translate(sql, "qmark") == sql

    def test_double_question_mark_collapses_to_one(self) -> None:
        assert (
            translate("SELECT data ?? 'key' FROM docs", "qmark")
            == "SELECT data ? 'key' FROM docs"
        )

    def test_escape_does_not_apply_inside_string_literal(self) -> None:
        # ``??`` inside a single-quoted string is data, not an escape.
        sql = "SELECT '??' , data ?? 'k'"
        assert translate(sql, "qmark") == "SELECT '??' , data ? 'k'"


class TestTranslateNumericDollar:
    def test_numbers_placeholders_in_order(self) -> None:
        assert (
            translate("INSERT INTO t (a, b, c) VALUES (?, ?, ?)", "numeric_dollar")
            == "INSERT INTO t (a, b, c) VALUES ($1, $2, $3)"
        )

    def test_escape_does_not_consume_a_number(self) -> None:
        assert (
            translate("WHERE data ?? 'key' AND id = ?", "numeric_dollar")
            == "WHERE data ? 'key' AND id = $1"
        )

    def test_question_mark_inside_single_quoted_string_kept(self) -> None:
        assert (
            translate("WHERE a = '?' AND b = ?", "numeric_dollar")
            == "WHERE a = '?' AND b = $1"
        )

    def test_doubled_quote_escape_keeps_string_open(self) -> None:
        # 'it''s ?' is ONE literal; the ? inside must not become $1.
        assert (
            translate("SELECT 'it''s ?' , ?", "numeric_dollar")
            == "SELECT 'it''s ?' , $1"
        )

    def test_double_quoted_identifier_not_rewritten(self) -> None:
        assert (
            translate('SELECT "a?b", ? FROM t', "numeric_dollar")
            == 'SELECT "a?b", $1 FROM t'
        )

    def test_doubled_double_quote_keeps_identifier_open(self) -> None:
        assert (
            translate('SELECT "we""ird?" , ?', "numeric_dollar")
            == 'SELECT "we""ird?" , $1'
        )

    def test_escape_sequence_inside_identifier_untouched(self) -> None:
        # ``??`` inside a quoted identifier stays doubled — it is not an escape.
        assert (
            translate('SELECT "a??b", ?', "numeric_dollar") == 'SELECT "a??b", $1'
        )

    def test_line_comment_not_rewritten(self) -> None:
        assert (
            translate("SELECT ? -- tail ? comment\nFROM t WHERE x = ?", "numeric_dollar")
            == "SELECT $1 -- tail ? comment\nFROM t WHERE x = $2"
        )

    def test_block_comment_not_rewritten(self) -> None:
        assert (
            translate("SELECT ? /* not ? this */ , ?", "numeric_dollar")
            == "SELECT $1 /* not ? this */ , $2"
        )

    def test_untagged_dollar_quote_not_rewritten(self) -> None:
        assert (
            translate("SELECT $$ ? $$, ?", "numeric_dollar") == "SELECT $$ ? $$, $1"
        )

    def test_tagged_dollar_quote_not_rewritten(self) -> None:
        assert (
            translate(
                "CREATE FUNCTION f() AS $body$ SELECT ?; $body$ WHERE x = ?",
                "numeric_dollar",
            )
            == "CREATE FUNCTION f() AS $body$ SELECT ?; $body$ WHERE x = $1"
        )

    def test_mismatched_inner_tag_swallowed_until_real_close(self) -> None:
        # $a$ … $a$ is one region; the $b$ inside it is just text.
        assert (
            translate("$a$ ? $b$ ? $a$ ?", "numeric_dollar") == "$a$ ? $b$ ? $a$ $1"
        )

    def test_hash_is_not_a_comment_for_postgresql(self) -> None:
        # ``#`` is the PostgreSQL XOR operator, never a comment — the ?
        # after it is a real placeholder and MUST be rewritten.
        assert translate("SELECT 5 # ?", "numeric_dollar") == "SELECT 5 # $1"


class TestTranslateFormat:
    def test_placeholders_become_percent_s(self) -> None:
        assert (
            translate("WHERE a = ? AND b = ?", "format") == "WHERE a = %s AND b = %s"
        )

    def test_escape_collapses(self) -> None:
        assert translate("data ?? 'key'", "format") == "data ? 'key'"

    def test_percent_doubled_everywhere_including_literals(self) -> None:
        # The pymysql/asyncmy driver family printf-formats the WHOLE SQL
        # string, string literals included — so the % inside 'a%b' must be
        # doubled too, or the driver's formatter chokes on it.
        assert (
            translate(
                "SELECT * FROM t WHERE name LIKE 'a%b' AND score % 10 = ?", "format"
            )
            == "SELECT * FROM t WHERE name LIKE 'a%%b' AND score %% 10 = %s"
        )

    def test_preexisting_percent_s_is_neutralised_everywhere(self) -> None:
        # A raw %s in the input — literal or not — must not become a phantom
        # placeholder once the driver formats the string.
        assert (
            translate("SELECT '%s', x % y FROM t WHERE id = ?", "format")
            == "SELECT '%%s', x %% y FROM t WHERE id = %s"
        )

    def test_percent_inside_comment_also_doubled(self) -> None:
        # Comments ride through the driver's formatter like everything else.
        assert (
            translate("SELECT ? -- 100% done", "format") == "SELECT %s -- 100%% done"
        )

    def test_backtick_identifier_not_rewritten(self) -> None:
        assert (
            translate("SELECT `a?b`, ? FROM t", "format") == "SELECT `a?b`, %s FROM t"
        )

    def test_doubled_backtick_keeps_identifier_open(self) -> None:
        assert (
            translate("SELECT `we``ird?` , ?", "format") == "SELECT `we``ird?` , %s"
        )

    def test_hash_comment_not_rewritten(self) -> None:
        assert (
            translate("SELECT ? # trailing ? here", "format")
            == "SELECT %s # trailing ? here"
        )

    def test_dollar_quotes_are_not_mysql_syntax(self) -> None:
        # MySQL has no dollar quoting, so the scanner must NOT honour it in
        # format mode — the ? between $$ markers is a real placeholder.
        assert translate("SELECT $$?$$", "format") == "SELECT $$%s$$"


class TestTranslateEdges:
    @pytest.mark.parametrize("style", ALL_STYLES)
    def test_empty_sql(self, style: str) -> None:
        assert translate("", style) == ""

    @pytest.mark.parametrize("style", ALL_STYLES)
    def test_sql_without_placeholders_unchanged(self, style: str) -> None:
        sql = "SELECT 1 FROM t WHERE a = 'x'"
        assert translate(sql, style) == sql

    @pytest.mark.parametrize("style", ALL_STYLES)
    def test_four_question_marks_are_two_literals(self, style: str) -> None:
        assert translate("SELECT ????", style) == "SELECT ??"

    def test_three_question_marks_are_literal_then_placeholder(self) -> None:
        assert translate("SELECT ???", "numeric_dollar") == "SELECT ?$1"

    @pytest.mark.parametrize(
        ("style", "placeholder"),
        [("qmark", "?"), ("numeric_dollar", "$1"), ("format", "%s")],
    )
    def test_placeholder_immediately_after_closing_single_quote(
        self, style: str, placeholder: str
    ) -> None:
        # Classic off-by-one: the region must end ON the closing quote, so
        # the very next character is scanned as live SQL.
        assert translate("'x'?", style) == f"'x'{placeholder}"

    def test_placeholder_immediately_after_closing_double_quote(self) -> None:
        assert translate('"c"?', "numeric_dollar") == '"c"$1'

    def test_placeholder_immediately_after_closing_backtick(self) -> None:
        assert translate("`c`?", "format") == "`c`%s"

    @pytest.mark.parametrize(
        ("style", "placeholder"),
        [("qmark", "?"), ("numeric_dollar", "$1"), ("format", "%s")],
    )
    def test_unterminated_string_swallows_rest(
        self, style: str, placeholder: str
    ) -> None:
        out = translate("SELECT ? FROM t WHERE s = 'oops ? ?", style)
        assert out == f"SELECT {placeholder} FROM t WHERE s = 'oops ? ?"

    @pytest.mark.parametrize(
        ("style", "placeholder"),
        [("qmark", "?"), ("numeric_dollar", "$1"), ("format", "%s")],
    )
    def test_unterminated_block_comment_swallows_rest(
        self, style: str, placeholder: str
    ) -> None:
        out = translate("SELECT ? /* dangling ?", style)
        assert out == f"SELECT {placeholder} /* dangling ?"

    @pytest.mark.parametrize(
        ("style", "placeholder"),
        [("qmark", "?"), ("numeric_dollar", "$1"), ("format", "%s")],
    )
    def test_unterminated_identifier_swallows_rest(
        self, style: str, placeholder: str
    ) -> None:
        out = translate('SELECT ? "dangling ?', style)
        assert out == f'SELECT {placeholder} "dangling ?'

    def test_unterminated_dollar_quote_swallows_rest(self) -> None:
        sql = "SELECT $tag$ ? ; never closed"
        assert translate(sql, "numeric_dollar") == sql

    def test_unterminated_untagged_dollar_quote_swallows_rest(self) -> None:
        sql = "SELECT $$ ? unclosed"
        assert translate(sql, "numeric_dollar") == sql

    def test_unterminated_backtick_swallows_rest(self) -> None:
        assert translate("SELECT ? `dangling ?", "format") == "SELECT %s `dangling ?"

    @pytest.mark.parametrize("style", ["pyformat", "numeric", "named", "", "QMARK"])
    def test_unknown_paramstyle_raises_value_error(self, style: str) -> None:
        with pytest.raises(ValueError, match="Unknown paramstyle"):
            translate("SELECT 1", style)


class TestTranslatorFor:
    def test_binds_paramstyle(self) -> None:
        to_pg = translator_for("numeric_dollar")
        assert to_pg("a = ? AND b = ?") == "a = $1 AND b = $2"

    def test_unknown_style_raises_eagerly(self) -> None:
        # Validation is eager: a typo'd paramstyle fails at bind time, not
        # on first use deep inside a request handler.
        with pytest.raises(ValueError, match="Unknown paramstyle"):
            translator_for("pyformat")


# SQL using only constructs every dialect scanner agrees on, so
# count_placeholders must mirror translate exactly on each of these.
PORTABLE_SQL = [
    "SELECT * FROM t WHERE a = ? AND b = ?",
    "INSERT INTO t (a, b) VALUES (?, ?)",
    "WHERE s = 'it''s ?' AND x = ?",
    'SELECT "a?b", ? FROM t',
    "SELECT ? -- tail ?\n, ?",
    "SELECT ? /* ? */ , ?",
    "data ?? 'key'",
    "SELECT ????",
    "SELECT ???",
    "'x'?",
    "SELECT ? FROM t WHERE s = 'oops ? ?",
    "SELECT ? /* dangling ?",
    "",
]


class TestCountPlaceholders:
    @pytest.mark.parametrize("sql", PORTABLE_SQL)
    def test_mirrors_translate_on_portable_sql(self, sql: str) -> None:
        # None of the portable samples contain a raw ``$``, so every $N in
        # the numeric_dollar rendering is a placeholder translate produced.
        rendered = translate(sql, "numeric_dollar")
        assert count_placeholders(sql) == len(re.findall(r"\$\d+", rendered))

    @pytest.mark.parametrize(
        ("sql", "expected"),
        [
            ("SELECT * FROM t WHERE a = ? AND b = ?", 2),
            ("WHERE data ?? 'key' AND id = ?", 1),
            ("SELECT ????", 0),
            ("SELECT ???", 1),
            ("'x'?", 1),
            ("", 0),
            # Dialect-specific constructs: the counter honours every
            # dialect's literal syntax at once (see module docstring).
            ("SELECT $$ ? $$, ?", 1),
            ("SELECT $body$ ? $body$, ?", 1),
            ("SELECT ? # ?", 1),
            ("SELECT `a?b`, ?", 1),
        ],
    )
    def test_expected_counts(self, sql: str, expected: int) -> None:
        assert count_placeholders(sql) == expected

    def test_unterminated_dollar_quote_does_not_crash(self) -> None:
        assert count_placeholders("SELECT $$ ? unclosed") == 0


class TestSplitStatements:
    def test_basic_split_with_trailing_semicolon(self) -> None:
        script = "CREATE TABLE a (x INT);\nCREATE TABLE b (y INT);\n"
        assert split_statements(script) == [
            "CREATE TABLE a (x INT)",
            "CREATE TABLE b (y INT)",
        ]

    def test_trailing_statement_without_semicolon_kept(self) -> None:
        assert split_statements("SELECT 1; SELECT 2") == ["SELECT 1", "SELECT 2"]

    def test_semicolon_inside_string_does_not_split(self) -> None:
        assert split_statements("INSERT INTO t VALUES ('a;b'); SELECT 1") == [
            "INSERT INTO t VALUES ('a;b')",
            "SELECT 1",
        ]

    def test_semicolon_inside_escaped_string_does_not_split(self) -> None:
        assert split_statements("INSERT INTO t VALUES ('it''s; ok'); SELECT 1") == [
            "INSERT INTO t VALUES ('it''s; ok')",
            "SELECT 1",
        ]

    def test_semicolon_inside_quoted_identifier_does_not_split(self) -> None:
        assert split_statements('CREATE TABLE "a;b" (x INT); SELECT 1') == [
            'CREATE TABLE "a;b" (x INT)',
            "SELECT 1",
        ]

    def test_semicolon_inside_line_comment_does_not_split(self) -> None:
        assert split_statements("SELECT 1 -- one; two\n; SELECT 2") == [
            "SELECT 1 -- one; two",
            "SELECT 2",
        ]

    def test_semicolon_inside_block_comment_does_not_split(self) -> None:
        assert split_statements("SELECT 1 /* a; b */; SELECT 2") == [
            "SELECT 1 /* a; b */",
            "SELECT 2",
        ]

    def test_comment_only_and_whitespace_fragments_dropped(self) -> None:
        script = "-- header comment\n;\n   \n; /* notes; here */ ;\nSELECT 1;"
        assert split_statements(script) == ["SELECT 1"]

    @pytest.mark.parametrize("script", ["", "   \n\t  ", ";;;", "-- just a comment"])
    def test_scripts_with_no_statements(self, script: str) -> None:
        assert split_statements(script) == []

    def test_hash_comments_respected_only_under_mysql(self) -> None:
        script = "SELECT 1 # not a comment; SELECT 2"
        # MySQL: ``#`` opens a comment, so the ; never splits.
        assert split_statements(script, dialect_name="mysql") == [script]
        # SQLite and PostgreSQL: ``#`` is just a character (PG: the XOR
        # operator), so the ; splits.
        expected = ["SELECT 1 # not a comment", "SELECT 2"]
        assert split_statements(script, dialect_name="sqlite") == expected
        assert split_statements(script, dialect_name="postgresql") == expected

    def test_backtick_identifier_protects_semicolon_under_mysql(self) -> None:
        script = "INSERT INTO `a;b` VALUES (1); SELECT 2"
        assert split_statements(script, dialect_name="mysql") == [
            "INSERT INTO `a;b` VALUES (1)",
            "SELECT 2",
        ]

    def test_untagged_dollar_quote_protects_semicolon_under_postgresql(self) -> None:
        script = "SELECT $$a;b$$; SELECT 1"
        assert split_statements(script, dialect_name="postgresql") == [
            "SELECT $$a;b$$",
            "SELECT 1",
        ]
        # Under SQLite ``$$`` is not quoting syntax, so the same text tears.
        assert split_statements(script, dialect_name="sqlite") == [
            "SELECT $$a",
            "b$$",
            "SELECT 1",
        ]

    def test_unterminated_string_swallows_rest_without_crashing(self) -> None:
        script = "SELECT 'unterminated; SELECT 2"
        assert split_statements(script) == [script]

    def test_create_function_body_survives_only_under_postgresql(self) -> None:
        # THE reason split_statements takes dialect_name: a plpgsql function
        # body is full of semicolons that are only protected by dollar
        # quoting, which exists solely in PostgreSQL.
        script = (
            "CREATE TABLE audit (note TEXT);\n"
            "CREATE FUNCTION touch() RETURNS trigger AS $fn$\n"
            "BEGIN\n"
            "    INSERT INTO audit (note) VALUES ('touched; twice');\n"
            "    RETURN NEW;\n"
            "END;\n"
            "$fn$ LANGUAGE plpgsql;\n"
            "CREATE TABLE t (x INT);"
        )

        pg = split_statements(script, dialect_name="postgresql")
        assert len(pg) == 3
        assert pg[0] == "CREATE TABLE audit (note TEXT)"
        # The function arrives whole: internal semicolons intact.
        assert pg[1].startswith("CREATE FUNCTION touch()")
        assert pg[1].endswith("$fn$ LANGUAGE plpgsql")
        assert "RETURN NEW;" in pg[1] and "END;" in pg[1]
        assert pg[2] == "CREATE TABLE t (x INT)"

        # The same script under sqlite tears the body apart at every
        # internal semicolon (only the single-quoted 'touched; twice'
        # survives, since single quotes are universal). Note also that the
        # "$fn$ LANGUAGE plpgsql" fragment vanishes: _has_content scans
        # dollar quotes for every dialect, sees an unterminated $fn$, and
        # judges the fragment empty.
        lite = split_statements(script, dialect_name="sqlite")
        assert lite == [
            "CREATE TABLE audit (note TEXT)",
            "CREATE FUNCTION touch() RETURNS trigger AS $fn$\n"
            "BEGIN\n"
            "    INSERT INTO audit (note) VALUES ('touched; twice')",
            "RETURN NEW",
            "END",
            "CREATE TABLE t (x INT)",
        ]
