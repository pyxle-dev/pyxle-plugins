"""Provider templates, env credential loading, and secret redaction."""

from __future__ import annotations

import pytest

from pyxle_auth.oauth.errors import OAuthConfigError
from pyxle_auth.oauth.providers import BUILTIN_PROVIDERS, OAuthProvider


def test_builtins_present() -> None:
    assert set(BUILTIN_PROVIDERS) == {"google", "github", "discord"}


def test_from_env_reads_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PYXLE_AUTH_OAUTH_GOOGLE_CLIENT_ID", "gid")
    monkeypatch.setenv("PYXLE_AUTH_OAUTH_GOOGLE_CLIENT_SECRET", "gsecret")
    p = OAuthProvider.from_env("google")
    assert p.client_id == "gid"
    assert p.client_secret == "gsecret"
    assert p.name == "google"


def test_from_env_explicit_overrides_win() -> None:
    p = OAuthProvider.from_env("github", client_id="x", client_secret="y")
    assert p.client_id == "x"
    assert p.name == "github"
    assert p.emails_url == "https://api.github.com/user/emails"


def test_from_env_unknown_provider_raises() -> None:
    with pytest.raises(OAuthConfigError, match="Unknown OAuth provider"):
        OAuthProvider.from_env("myspace", client_id="a", client_secret="b")


def test_from_env_missing_credentials_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("PYXLE_AUTH_OAUTH_DISCORD_CLIENT_ID", raising=False)
    monkeypatch.delenv("PYXLE_AUTH_OAUTH_DISCORD_CLIENT_SECRET", raising=False)
    with pytest.raises(OAuthConfigError, match="missing credentials"):
        OAuthProvider.from_env("discord")


def test_repr_redacts_secret() -> None:
    p = OAuthProvider.from_env("google", client_id="gid", client_secret="TOP-SECRET")
    text = repr(p)
    assert "TOP-SECRET" not in text
    assert "***" in text
    assert "gid" in text  # the id is not a secret


def test_authorization_url_includes_pkce_and_state() -> None:
    p = OAuthProvider.from_env("google", client_id="gid", client_secret="s")
    url = p.authorization_url(
        redirect_uri="https://app.example.com/auth/oauth/google/callback",
        state="the-nonce",
        code_challenge="the-challenge",
    )
    assert url.startswith("https://accounts.google.com/o/oauth2/v2/auth?")
    assert "state=the-nonce" in url
    assert "code_challenge=the-challenge" in url
    assert "code_challenge_method=S256" in url
    assert "response_type=code" in url
    # redirect_uri is URL-encoded into the query.
    assert "redirect_uri=https%3A%2F%2Fapp.example.com" in url


def test_authorization_url_omits_pkce_when_disabled() -> None:
    p = OAuthProvider.from_env("google", client_id="gid", client_secret="s")
    from dataclasses import replace

    no_pkce = replace(p, use_pkce=False)
    url = no_pkce.authorization_url(
        redirect_uri="https://app/cb", state="n", code_challenge="c"
    )
    assert "code_challenge" not in url


def test_github_uses_emails_endpoint_not_userinfo_email() -> None:
    p = OAuthProvider.from_env("github", client_id="a", client_secret="b")
    # GitHub's /user.email is unreliable; email always comes from /user/emails.
    assert p.email_key is None
    assert p.email_verified_key is None
    assert p.emails_url == "https://api.github.com/user/emails"
