"""Hostile-input tests for :mod:`pyxle_db.url`.

Covers every documented URL form, the scheme aliases, percent-decoding,
error paths for malformed URLs, and password redaction.
"""

from __future__ import annotations

import dataclasses

import pytest

from pyxle_db.errors import ConfigurationError
from pyxle_db.url import DatabaseConfig, parse_database_url


class TestBarePathPassthrough:
    @pytest.mark.parametrize(
        "path", ["./data/app.db", "data/app.db", "/abs/app.db", ":memory:"]
    )
    def test_non_url_is_sqlite_path_verbatim(self, path: str) -> None:
        cfg = parse_database_url(path)
        assert cfg.backend == "sqlite"
        assert cfg.path == path
        assert (cfg.host, cfg.port, cfg.user, cfg.password, cfg.database) == (
            "",
            0,
            "",
            "",
            "",
        )
        assert cfg.options == {}

    def test_surrounding_whitespace_stripped(self) -> None:
        assert parse_database_url("  ./app.db \n").path == "./app.db"


class TestSqliteUrls:
    def test_three_slashes_is_relative(self) -> None:
        cfg = parse_database_url("sqlite:///relative/path/app.db")
        assert cfg.backend == "sqlite"
        assert cfg.path == "relative/path/app.db"

    def test_four_slashes_is_absolute(self) -> None:
        cfg = parse_database_url("sqlite:////absolute/path/app.db")
        assert cfg.backend == "sqlite"
        assert cfg.path == "/absolute/path/app.db"

    def test_memory(self) -> None:
        assert parse_database_url("sqlite:///:memory:").path == ":memory:"

    def test_sqlite3_alias(self) -> None:
        cfg = parse_database_url("sqlite3:///app.db")
        assert cfg.backend == "sqlite"
        assert cfg.path == "app.db"

    def test_percent_encoded_path_decodes(self) -> None:
        assert parse_database_url("sqlite:///my%20app.db").path == "my app.db"

    def test_host_rejected(self) -> None:
        with pytest.raises(ConfigurationError, match="no host"):
            parse_database_url("sqlite://localhost/app.db")

    @pytest.mark.parametrize("url", ["sqlite://", "sqlite:///"])
    def test_missing_path_rejected(self, url: str) -> None:
        with pytest.raises(ConfigurationError, match="missing a database path"):
            parse_database_url(url)


class TestServerUrls:
    def test_postgresql_docstring_example(self) -> None:
        cfg = parse_database_url("postgresql://user:pass@host:5432/dbname?sslmode=require")
        assert cfg == DatabaseConfig(
            backend="postgresql",
            host="host",
            port=5432,
            user="user",
            password="pass",
            database="dbname",
            options={"sslmode": "require"},
        )

    def test_mysql_docstring_example(self) -> None:
        cfg = parse_database_url("mysql://user:pass@host:3306/dbname")
        assert cfg == DatabaseConfig(
            backend="mysql",
            host="host",
            port=3306,
            user="user",
            password="pass",
            database="dbname",
        )

    @pytest.mark.parametrize(
        ("scheme", "backend"),
        [
            ("postgres", "postgresql"),
            ("postgresql", "postgresql"),
            ("mysql", "mysql"),
            ("mariadb", "mysql"),
        ],
    )
    def test_scheme_aliases(self, scheme: str, backend: str) -> None:
        assert parse_database_url(f"{scheme}://u@h/db").backend == backend

    def test_scheme_is_case_insensitive(self) -> None:
        assert parse_database_url("POSTGRES://u@h/db").backend == "postgresql"

    @pytest.mark.parametrize(
        ("url", "port"),
        [
            ("postgresql://u@h/db", 5432),
            ("mysql://u@h/db", 3306),
            ("postgresql://u@h:6543/db", 6543),
        ],
    )
    def test_default_and_explicit_ports(self, url: str, port: int) -> None:
        assert parse_database_url(url).port == port

    def test_percent_encoded_credentials_decode(self) -> None:
        cfg = parse_database_url("postgresql://app%2Buser:p%40ss%2Fword@h/db")
        assert cfg.user == "app+user"
        assert cfg.password == "p@ss/word"

    def test_duplicate_options_last_wins(self) -> None:
        cfg = parse_database_url("mysql://u@h/db?a=1&b=2&a=3")
        assert cfg.options == {"a": "3", "b": "2"}

    def test_no_options_is_empty_dict(self) -> None:
        assert parse_database_url("postgresql://u@h/db").options == {}

    @pytest.mark.parametrize(
        "url", ["postgresql:///dbname", "postgresql://user:pw@/dbname"]
    )
    def test_missing_host_rejected(self, url: str) -> None:
        with pytest.raises(ConfigurationError, match="missing a host"):
            parse_database_url(url)

    @pytest.mark.parametrize("url", ["postgresql://host", "mysql://host/"])
    def test_missing_database_rejected(self, url: str) -> None:
        with pytest.raises(ConfigurationError, match="missing a database name"):
            parse_database_url(url)

    def test_database_name_with_slash_rejected(self) -> None:
        with pytest.raises(ConfigurationError, match="may not contain '/'"):
            parse_database_url("postgresql://host/a/b")

    def test_percent_encoded_slash_in_database_rejected(self) -> None:
        # %2F decodes to "/" — must be caught after decoding, not smuggled.
        with pytest.raises(ConfigurationError, match="may not contain '/'"):
            parse_database_url("postgresql://host/a%2Fb")

    def test_unknown_scheme_rejected_with_supported_list(self) -> None:
        with pytest.raises(ConfigurationError, match="sqlite") as excinfo:
            parse_database_url("oracle://h/db")
        assert "oracle" in str(excinfo.value)

    @pytest.mark.parametrize("bad", ["", "   ", None, 42])
    def test_non_string_or_blank_rejected(self, bad: object) -> None:
        with pytest.raises(ConfigurationError, match="non-empty string"):
            parse_database_url(bad)  # type: ignore[arg-type]

    def test_malformed_port_is_a_configuration_error(self) -> None:
        """KNOWN FAILURE — documents a real bug in pyxle_db/url.py.

        ``urlsplit(...).port`` raises a bare ``ValueError`` for a
        non-numeric or out-of-range port, and ``parse_database_url`` lets
        it escape instead of wrapping it:

            parse_database_url("postgresql://h:notaport/db")  -> ValueError
            parse_database_url("postgresql://h:99999/db")     -> ValueError
            parse_database_url("postgresql://[::1/db")        -> ValueError

        Every other malformed URL raises ConfigurationError ("Bad database
        URL/settings" per pyxle_db/errors.py), so callers branching on
        DatabaseError subclasses miss exactly these inputs. Do not edit the
        canon to make this pass without fixing url.py itself.
        """
        with pytest.raises(ConfigurationError):
            parse_database_url("postgresql://h:notaport/db")


class TestRedacted:
    def test_sqlite_relative_round_trips(self) -> None:
        cfg = parse_database_url("sqlite:///rel/app.db")
        assert cfg.redacted() == "sqlite:///rel/app.db"

    def test_sqlite_absolute_round_trips(self) -> None:
        cfg = parse_database_url("sqlite:////abs/app.db")
        assert cfg.redacted() == "sqlite:////abs/app.db"

    def test_password_masked_and_never_leaked(self) -> None:
        cfg = parse_database_url("postgresql://app:s3cr3t@db.internal:5432/appdb")
        redacted = cfg.redacted()
        assert redacted == "postgresql://app:***@db.internal:5432/appdb"
        assert "s3cr3t" not in redacted

    def test_no_mask_marker_without_password(self) -> None:
        cfg = parse_database_url("mysql://app@h/db")
        redacted = cfg.redacted()
        assert redacted == "mysql://app@h:3306/db"
        assert "***" not in redacted

    def test_no_userinfo_at_all(self) -> None:
        cfg = parse_database_url("postgresql://h/db")
        redacted = cfg.redacted()
        assert redacted == "postgresql://h:5432/db"
        assert "@" not in redacted and "***" not in redacted

    def test_password_without_user_still_masked(self) -> None:
        cfg = parse_database_url("postgresql://:pw@h/db")
        redacted = cfg.redacted()
        assert redacted == "postgresql://:***@h:5432/db"
        assert "pw@" not in redacted

    def test_alias_redacts_under_canonical_backend_name(self) -> None:
        assert parse_database_url("mariadb://u:p@h/db").redacted().startswith("mysql://")


class TestDatabaseConfigImmutability:
    def test_frozen(self) -> None:
        cfg = parse_database_url("postgresql://u:p@h/db")
        with pytest.raises(dataclasses.FrozenInstanceError):
            cfg.password = "other"  # type: ignore[misc]
