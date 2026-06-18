"""``sanitize_next`` — the open-redirect guard."""

from __future__ import annotations

import pytest

from pyxle_auth.oauth.util import sanitize_next


@pytest.mark.parametrize(
    "value",
    [
        "/dashboard",
        "/",
        "/a/b/c?x=1#frag",
        "/settings?tab=security",
    ],
)
def test_same_origin_paths_pass(value: str) -> None:
    assert sanitize_next(value) == value


@pytest.mark.parametrize(
    "value",
    [
        "https://evil.com",
        "http://evil.com/path",
        "//evil.com",              # protocol-relative
        "//evil.com/path",
        "/\\evil.com",             # backslash trick
        "/path\\with\\backslash",
        "javascript:alert(1)",
        "relative/path",           # not absolute
        "",
        "  /leading-space",
        "/has space",
        "/has\ttab",
        "/has\nnewline",
        "/has\r\nsmuggle",
    ],
)
def test_off_origin_or_dangerous_falls_back(value: str) -> None:
    assert sanitize_next(value) == "/"


def test_non_string_falls_back() -> None:
    assert sanitize_next(None) == "/"
    assert sanitize_next(123) == "/"
    assert sanitize_next(["/x"]) == "/"


def test_custom_default() -> None:
    assert sanitize_next("https://evil.com", default="/login") == "/login"
