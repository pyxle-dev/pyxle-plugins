from __future__ import annotations

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


def test_token_ttl_defaults() -> None:
    s = AuthSettings()
    assert s.password_reset_ttl_seconds == 1800
    assert s.email_verify_ttl_seconds == 86400
    assert s.rate_limit_password_reset_per_hour == 3


@pytest.mark.parametrize(
    "field",
    [
        "password_reset_ttl_seconds",
        "email_verify_ttl_seconds",
        "rate_limit_password_reset_per_hour",
    ],
)
@pytest.mark.parametrize("value", [0, -1])
def test_token_fields_must_be_positive(field: str, value: int) -> None:
    with pytest.raises(ValueError, match=field):
        AuthSettings(**{field: value})


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


def test_from_env_reads_token_overrides(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PYXLE_AUTH_PASSWORD_RESET_TTL_SECONDS", "900")
    monkeypatch.setenv("PYXLE_AUTH_EMAIL_VERIFY_TTL_SECONDS", "3600")
    monkeypatch.setenv("PYXLE_AUTH_RATE_LIMIT_PASSWORD_RESET_PER_HOUR", "7")
    s = AuthSettings.from_env(strict=False)
    assert s.password_reset_ttl_seconds == 900
    assert s.email_verify_ttl_seconds == 3600
    assert s.rate_limit_password_reset_per_hour == 7


def test_from_env_token_defaults_when_unset() -> None:
    s = AuthSettings.from_env(strict=False)
    assert s.password_reset_ttl_seconds == 1800
    assert s.email_verify_ttl_seconds == 86400
    assert s.rate_limit_password_reset_per_hour == 3


def test_from_env_explicit_overrides_beat_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The plugin routes pyxle.config.json settings through ``overrides`` —
    config must win over the environment, and env values not overridden
    must still apply."""
    monkeypatch.setenv("PYXLE_AUTH_PASSWORD_RESET_TTL_SECONDS", "900")
    monkeypatch.setenv("PYXLE_AUTH_EMAIL_VERIFY_TTL_SECONDS", "3600")
    s = AuthSettings.from_env(
        strict=False,
        overrides={"password_reset_ttl_seconds": 1234},
    )
    assert s.password_reset_ttl_seconds == 1234  # override beats env
    assert s.email_verify_ttl_seconds == 3600  # env applies when not overridden


def test_from_env_overrides_are_validated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PYXLE_AUTH_PASSWORD_RESET_TTL_SECONDS", "900")
    with pytest.raises(ValueError, match="password_reset_ttl_seconds"):
        AuthSettings.from_env(
            strict=False, overrides={"password_reset_ttl_seconds": 0}
        )


def test_for_tests_relaxes_cost() -> None:
    s = AuthSettings().for_tests()
    assert s.argon_time_cost == 1
    assert s.cookie_secure is False
    assert s.strict is False


def test_for_tests_shrinks_token_ttls() -> None:
    s = AuthSettings().for_tests()
    assert s.password_reset_ttl_seconds == 60
    assert s.email_verify_ttl_seconds == 60
    # Rate limits are a behaviour under test, not a cost — unchanged.
    assert s.rate_limit_password_reset_per_hour == 3
