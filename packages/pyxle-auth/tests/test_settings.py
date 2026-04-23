from __future__ import annotations

import os

import pytest

from pyxle_auth import AuthSettings


def test_strict_requires_secure_cookie() -> None:
    with pytest.raises(ValueError, match="strict mode"):
        AuthSettings(cookie_secure=False, strict=True)


def test_samesite_none_requires_secure() -> None:
    with pytest.raises(ValueError, match="SameSite=None"):
        AuthSettings(cookie_samesite="None", cookie_secure=False, strict=False)


def test_absolute_max_must_be_ge_lifetime() -> None:
    with pytest.raises(ValueError, match="absolute_max"):
        AuthSettings(
            session_lifetime_seconds=100,
            session_absolute_max_seconds=10,
        )


def test_from_env_reads_overrides(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PYXLE_AUTH_COOKIE_NAME", "x_session")
    monkeypatch.setenv("PYXLE_AUTH_COOKIE_SECURE", "false")
    monkeypatch.setenv("PYXLE_AUTH_SESSION_TTL", "600")
    monkeypatch.setenv("PYXLE_AUTH_RL_SIGN_IN_PER_HOUR", "5")
    s = AuthSettings.from_env(strict=False)
    assert s.cookie_name == "x_session"
    assert s.cookie_secure is False
    assert s.session_lifetime_seconds == 600
    assert s.rate_limit_sign_in_per_hour == 5


def test_for_tests_relaxes_cost() -> None:
    s = AuthSettings().for_tests()
    assert s.argon_time_cost == 1
    assert s.cookie_secure is False
    assert s.strict is False
