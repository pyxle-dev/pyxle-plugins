"""OAuthService — code exchange, identity fetch, and account-linking matrix.

The linking rules are the security core:

* a returning identity signs in directly (no email re-check);
* a *new* identity links/creates only on a provider-**verified** email
  (account-takeover guard);
* GitHub's email comes from ``/user/emails``, not the profile.
"""

from __future__ import annotations

import pytest

from pyxle_auth import AuthService
from pyxle_auth.oauth.errors import OAuthEmailUnverified, OAuthExchangeError
from pyxle_auth.oauth.providers import OAuthProvider
from pyxle_auth.oauth.service import OAuthService

from tests.oauth._fakes import FakeClient, FakeResponse, factory_for

GOOGLE_TOKEN = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO = "https://openidconnect.googleapis.com/v1/userinfo"
GITHUB_TOKEN = "https://github.com/login/oauth/access_token"
GITHUB_USERINFO = "https://api.github.com/user"
GITHUB_EMAILS = "https://api.github.com/user/emails"


def _google() -> OAuthProvider:
    return OAuthProvider.from_env("google", client_id="gid", client_secret="gsecret")


def _github() -> OAuthProvider:
    return OAuthProvider.from_env("github", client_id="hid", client_secret="hsecret")


async def _make_service(auth: AuthService, provider: OAuthProvider, client: FakeClient):
    svc = OAuthService(
        auth._db,  # the same Database the AuthService uses
        auth,
        {provider.name: provider},
        http_client_factory=factory_for(client),
    )
    await svc.ensure_schema()
    return svc


def _google_client(*, sub: str, email: str, verified: bool) -> FakeClient:
    return FakeClient(
        post={GOOGLE_TOKEN: FakeResponse(200, {"access_token": "at-123"})},
        get={
            GOOGLE_USERINFO: FakeResponse(
                200, {"sub": sub, "email": email, "email_verified": verified}
            )
        },
    )


async def _complete(svc: OAuthService, provider_name: str = "google"):
    return await svc.complete(
        provider_name,
        code="auth-code",
        redirect_uri="https://app.example.com/auth/oauth/google/callback",
        code_verifier="the-verifier",
        ip="203.0.113.5",
        user_agent="pytest",
    )


async def test_new_user_is_created_and_linked(auth: AuthService) -> None:
    client = _google_client(sub="g-1", email="alice@example.com", verified=True)
    svc = await _make_service(auth, _google(), client)

    user, cookie = await _complete(svc)
    assert user.email == "alice@example.com"
    assert user.email_verified_at is not None  # provider vouched for it
    assert cookie.value  # a session was issued

    row = await auth._db.fetchone(
        "SELECT user_id FROM oauth_identities WHERE provider = ? AND subject = ?",
        ("google", "g-1"),
    )
    assert row is not None and row["user_id"] == user.id


async def test_pkce_verifier_is_sent_in_exchange(auth: AuthService) -> None:
    client = _google_client(sub="g-1", email="a@b.c", verified=True)
    svc = await _make_service(auth, _google(), client)
    await _complete(svc)
    (_url, data, _headers) = client.posts[0]
    assert data["code_verifier"] == "the-verifier"
    assert data["grant_type"] == "authorization_code"
    assert data["client_secret"] == "gsecret"


async def test_returning_identity_signs_in_same_user(auth: AuthService) -> None:
    svc = await _make_service(
        auth, _google(), _google_client(sub="g-9", email="bob@example.com", verified=True)
    )
    user1, _ = await _complete(svc)

    # Second sign-in, same provider subject → same account, no duplicate.
    svc2 = await _make_service(
        auth, _google(), _google_client(sub="g-9", email="bob@example.com", verified=True)
    )
    user2, _ = await _complete(svc2)
    assert user2.id == user1.id

    rows = await auth._db.fetchall("SELECT id FROM users WHERE email = ?", ("bob@example.com",))
    assert len(rows) == 1


async def test_links_to_existing_account_on_verified_email(auth: AuthService) -> None:
    # A local password account already exists for this email.
    existing, _ = await auth.sign_up(email="carol@example.com", password="correct horse staple")

    svc = await _make_service(
        auth, _google(), _google_client(sub="g-77", email="carol@example.com", verified=True)
    )
    user, _ = await _complete(svc)
    assert user.id == existing.id  # linked, not duplicated

    row = await auth._db.fetchone(
        "SELECT user_id FROM oauth_identities WHERE provider = ? AND subject = ?",
        ("google", "g-77"),
    )
    assert row is not None and row["user_id"] == existing.id


async def test_refuses_to_link_on_unverified_email(auth: AuthService) -> None:
    # The takeover guard: a new identity with an UNVERIFIED email must not link.
    auth_existing, _ = await auth.sign_up(email="victim@example.com", password="correct horse staple")
    svc = await _make_service(
        auth, _google(), _google_client(sub="attacker-sub", email="victim@example.com", verified=False)
    )
    with pytest.raises(OAuthEmailUnverified):
        await _complete(svc)

    # No link was created.
    row = await auth._db.fetchone(
        "SELECT 1 FROM oauth_identities WHERE provider = ? AND subject = ?",
        ("google", "attacker-sub"),
    )
    assert row is None


async def test_returning_identity_signs_in_even_if_now_unverified(auth: AuthService) -> None:
    # Establish the link while verified.
    svc = await _make_service(
        auth, _google(), _google_client(sub="g-5", email="dana@example.com", verified=True)
    )
    user1, _ = await _complete(svc)

    # Later, the provider reports the email as unverified — the existing link
    # still signs the user in (the email check only gates NEW links).
    svc2 = await _make_service(
        auth, _google(), _google_client(sub="g-5", email="dana@example.com", verified=False)
    )
    user2, _ = await _complete(svc2)
    assert user2.id == user1.id


async def test_token_exchange_rejection_raises(auth: AuthService) -> None:
    client = FakeClient(post={GOOGLE_TOKEN: FakeResponse(400, {"error": "invalid_grant"})})
    svc = await _make_service(auth, _google(), client)
    with pytest.raises(OAuthExchangeError):
        await _complete(svc)


async def test_token_200_without_access_token_raises(auth: AuthService) -> None:
    # GitHub returns 200 + {"error": ...} on a bad code.
    client = FakeClient(post={GOOGLE_TOKEN: FakeResponse(200, {"error": "bad_verification_code"})})
    svc = await _make_service(auth, _google(), client)
    with pytest.raises(OAuthExchangeError):
        await _complete(svc)


async def test_github_email_comes_from_emails_endpoint(auth: AuthService) -> None:
    client = FakeClient(
        post={GITHUB_TOKEN: FakeResponse(200, {"access_token": "gh-at"})},
        get={
            GITHUB_USERINFO: FakeResponse(200, {"id": 4242, "login": "octocat"}),
            GITHUB_EMAILS: FakeResponse(
                200,
                [
                    {"email": "secondary@example.com", "primary": False, "verified": True},
                    {"email": "octocat@example.com", "primary": True, "verified": True},
                ],
            ),
        },
    )
    svc = await _make_service(auth, _github(), client)
    user, _ = await svc.complete(
        "github",
        code="c",
        redirect_uri="https://app/auth/oauth/github/callback",
        code_verifier="v",
    )
    assert user.email == "octocat@example.com"


async def test_github_unverified_primary_email_refuses(auth: AuthService) -> None:
    client = FakeClient(
        post={GITHUB_TOKEN: FakeResponse(200, {"access_token": "gh-at"})},
        get={
            GITHUB_USERINFO: FakeResponse(200, {"id": 99}),
            GITHUB_EMAILS: FakeResponse(
                200, [{"email": "x@example.com", "primary": True, "verified": False}]
            ),
        },
    )
    svc = await _make_service(auth, _github(), client)
    with pytest.raises(OAuthEmailUnverified):
        await svc.complete(
            "github", code="c", redirect_uri="https://app/cb", code_verifier="v"
        )


async def test_unknown_provider_raises(auth: AuthService) -> None:
    from pyxle_auth.oauth.errors import OAuthConfigError

    svc = await _make_service(auth, _google(), _google_client(sub="x", email="a@b.c", verified=True))
    with pytest.raises(OAuthConfigError):
        await svc.complete("github", code="c", redirect_uri="x", code_verifier="v")
