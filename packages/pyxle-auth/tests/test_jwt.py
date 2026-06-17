"""JWTService — access verification + refresh rotation with reuse detection."""

from __future__ import annotations

from datetime import timedelta

import pytest

from pyxle_auth import AuthService
from pyxle_auth.errors import InvalidToken
from pyxle_auth.jwt_tokens import JWTService
from pyxle_auth.models import User, _now_utc


@pytest.fixture
async def jwt_service(auth: AuthService) -> JWTService:
    svc = JWTService(
        auth._db, secret="test-signing-secret", access_ttl_seconds=900, refresh_ttl_seconds=3600
    )
    await svc.ensure_schema()
    return svc


@pytest.fixture
async def user(auth: AuthService) -> User:
    u, _ = await auth.sign_up(email="jwt@example.com", password="correct horse staple")
    return u


# ---------------------------------------------------------------------------
# access tokens


async def test_issue_and_verify_access(jwt_service: JWTService, user: User) -> None:
    pair = await jwt_service.issue_pair(user_id=user.id)
    claims = jwt_service.verify_access(pair.access_token)
    assert claims is not None
    assert claims["sub"] == user.id
    assert claims["type"] == "access"
    assert pair.token_type == "Bearer"
    assert pair.access_expires_in == 900


def test_verify_rejects_garbage(jwt_service: JWTService) -> None:
    assert jwt_service.verify_access("not-a-jwt") is None
    assert jwt_service.verify_access("") is None


async def test_verify_rejects_tampered(jwt_service: JWTService, user: User) -> None:
    pair = await jwt_service.issue_pair(user_id=user.id)
    assert jwt_service.verify_access(pair.access_token[:-3] + "xyz") is None


async def test_verify_rejects_wrong_secret(auth: AuthService, user: User) -> None:
    signer = JWTService(auth._db, secret="secret-A")
    await signer.ensure_schema()
    pair = await signer.issue_pair(user_id=user.id)
    other = JWTService(auth._db, secret="secret-B")
    assert other.verify_access(pair.access_token) is None


async def test_verify_rejects_expired_access(auth: AuthService, user: User) -> None:
    # A negative TTL stamps an already-expired token.
    expired_signer = JWTService(auth._db, secret="s", access_ttl_seconds=-10)
    await expired_signer.ensure_schema()
    pair = await expired_signer.issue_pair(user_id=user.id)
    assert expired_signer.verify_access(pair.access_token) is None


async def test_refresh_token_is_not_a_valid_access_token(
    jwt_service: JWTService, user: User
) -> None:
    # The opaque refresh token must never pass as an access JWT.
    pair = await jwt_service.issue_pair(user_id=user.id)
    assert jwt_service.verify_access(pair.refresh_token) is None


async def test_issuer_is_enforced(auth: AuthService, user: User) -> None:
    signer = JWTService(auth._db, secret="s", issuer="pyxle")
    await signer.ensure_schema()
    pair = await signer.issue_pair(user_id=user.id)
    assert signer.verify_access(pair.access_token) is not None
    # A verifier expecting a different issuer rejects it.
    other = JWTService(auth._db, secret="s", issuer="someone-else")
    assert other.verify_access(pair.access_token) is None


# ---------------------------------------------------------------------------
# refresh rotation


async def test_refresh_rotates(jwt_service: JWTService, user: User) -> None:
    pair = await jwt_service.issue_pair(user_id=user.id)
    new_pair = await jwt_service.refresh(pair.refresh_token)
    assert new_pair.refresh_token != pair.refresh_token
    assert jwt_service.verify_access(new_pair.access_token) is not None
    # The new refresh token works once...
    assert await jwt_service.refresh(new_pair.refresh_token) is not None


async def test_unknown_refresh_token_raises(jwt_service: JWTService) -> None:
    with pytest.raises(InvalidToken):
        await jwt_service.refresh("nonexistent-token")


async def test_reuse_of_rotated_token_revokes_family(
    jwt_service: JWTService, user: User
) -> None:
    pair = await jwt_service.issue_pair(user_id=user.id)
    new_pair = await jwt_service.refresh(pair.refresh_token)  # rotate once

    # Replaying the OLD (now used) token is reuse → InvalidToken.
    with pytest.raises(InvalidToken):
        await jwt_service.refresh(pair.refresh_token)

    # And the whole family is dead: the legitimate NEW token no longer works.
    with pytest.raises(InvalidToken):
        await jwt_service.refresh(new_pair.refresh_token)


async def test_refresh_expired_token_raises(jwt_service: JWTService, user: User) -> None:
    pair = await jwt_service.issue_pair(user_id=user.id)
    past = _now_utc() - timedelta(hours=1)
    await jwt_service._db.execute(
        "UPDATE jwt_refresh_tokens SET expires_at = ? WHERE 1=1", (past,)
    )
    with pytest.raises(InvalidToken):
        await jwt_service.refresh(pair.refresh_token)


async def test_revoke_family_blocks_refresh(jwt_service: JWTService, user: User) -> None:
    pair = await jwt_service.issue_pair(user_id=user.id)
    row = await jwt_service._db.fetchone(
        "SELECT family_id FROM jwt_refresh_tokens LIMIT 1"
    )
    revoked = await jwt_service.revoke_family(family_id=row["family_id"])
    assert revoked == 1
    with pytest.raises(InvalidToken):
        await jwt_service.refresh(pair.refresh_token)


async def test_revoke_all_for_user(jwt_service: JWTService, user: User) -> None:
    p1 = await jwt_service.issue_pair(user_id=user.id)
    p2 = await jwt_service.issue_pair(user_id=user.id)  # separate family
    count = await jwt_service.revoke_all_for_user(user_id=user.id)
    assert count == 2
    for token in (p1.refresh_token, p2.refresh_token):
        with pytest.raises(InvalidToken):
            await jwt_service.refresh(token)


def test_empty_secret_rejected(auth: AuthService) -> None:
    with pytest.raises(ValueError, match="signing secret"):
        JWTService(auth._db, secret="")
