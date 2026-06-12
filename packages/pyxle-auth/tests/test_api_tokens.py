"""Hostile tests for :mod:`pyxle_auth.api_tokens`.

Personal access tokens are bearer credentials with no second factor — a
single soft spot here is full account takeover for API surfaces. These
tests attack storage (is the raw value really never persisted?), scope
checks, revocation ownership, expiry edges, the per-user cap's atomic
counting, and the last-used throttle.

Time is controlled by monkeypatching the module's ``_utcnow`` — the single
clock used by ``create``, ``resolve``, ``_touch``, and ``ApiToken.active``.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from typing import AsyncIterator

import pytest

import pyxle_auth.api_tokens as api_tokens_module
from pyxle_auth.api_tokens import TOKEN_PREFIX, ApiTokenService, TokenLimitReached
from pyxle_db import Database

T0 = datetime(2026, 6, 11, 12, 0, 0, tzinfo=timezone.utc)


@pytest.fixture
async def db() -> AsyncIterator[Database]:
    database = Database(":memory:")
    try:
        yield database
    finally:
        await database.aclose()


@pytest.fixture
async def service(db: Database) -> ApiTokenService:
    svc = ApiTokenService(db)
    await svc.ensure_schema()
    return svc


def _freeze(monkeypatch: pytest.MonkeyPatch, at: datetime) -> None:
    monkeypatch.setattr(api_tokens_module, "_utcnow", lambda: at)


def _sha256(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Creation and at-rest storage


async def test_create_returns_prefixed_raw_and_metadata(
    service: ApiTokenService,
) -> None:
    token, raw = await service.create(
        user_id="u1", name="  ci deploy  ", scopes=["deploy"]
    )
    assert raw.startswith(TOKEN_PREFIX)
    assert len(raw) == len(TOKEN_PREFIX) + 43  # 256 bits of urlsafe base64
    assert token.user_id == "u1"
    assert token.name == "ci deploy"  # whitespace normalised
    assert token.scopes == ("deploy",)
    assert token.expires_at is None
    assert token.last_used_at is None
    assert token.revoked_at is None
    assert token.active


async def test_create_mints_distinct_secrets(service: ApiTokenService) -> None:
    raws = {
        (await service.create(user_id="u1", name=f"t{i}", scopes=["read"]))[1]
        for i in range(10)
    }
    assert len(raws) == 10


async def test_raw_token_never_stored_only_sha256(
    db: Database, service: ApiTokenService
) -> None:
    token, raw = await service.create(user_id="u1", name="ci", scopes=["deploy"])
    secret_part = raw[len(TOKEN_PREFIX) :]
    row = await db.fetchone("SELECT * FROM api_tokens WHERE id = ?", (token.id,))
    assert row is not None
    for value in row:
        if isinstance(value, str):
            # Neither the full raw token nor its secret tail may be at rest.
            assert raw not in value
            assert secret_part not in value
    assert row["token_sha256"] == _sha256(raw)


@pytest.mark.parametrize("user_id", ["", None])
async def test_create_rejects_bad_user_id(
    service: ApiTokenService, user_id: object
) -> None:
    with pytest.raises(ValueError):
        await service.create(user_id=user_id, name="ci", scopes=["read"])  # type: ignore[arg-type]


@pytest.mark.parametrize("name", ["", "   ", None, "x" * 101])
async def test_create_rejects_bad_name(service: ApiTokenService, name: object) -> None:
    with pytest.raises(ValueError):
        await service.create(user_id="u1", name=name, scopes=["read"])  # type: ignore[arg-type]


async def test_create_accepts_max_length_name(service: ApiTokenService) -> None:
    token, _ = await service.create(user_id="u1", name="x" * 100, scopes=["read"])
    assert token.name == "x" * 100


@pytest.mark.parametrize("days", [0, -1])
async def test_create_rejects_non_positive_expiry(
    service: ApiTokenService, days: int
) -> None:
    with pytest.raises(ValueError):
        await service.create(
            user_id="u1", name="ci", scopes=["read"], expires_in_days=days
        )


# ---------------------------------------------------------------------------
# Scope validation


@pytest.mark.parametrize(
    "scopes",
    [[], [""], ["   "], ["a b"], ["x" * 65], [f"s{i}" for i in range(33)]],
    ids=["empty-list", "empty-scope", "blank-scope", "space", "too-long", "too-many"],
)
async def test_create_rejects_invalid_scopes(
    service: ApiTokenService, scopes: list[str]
) -> None:
    with pytest.raises(ValueError):
        await service.create(user_id="u1", name="ci", scopes=scopes)


async def test_duplicate_scopes_collapse_preserving_order(
    service: ApiTokenService,
) -> None:
    token, _ = await service.create(
        user_id="u1", name="ci", scopes=["read", " write ", "read", "write"]
    )
    assert token.scopes == ("read", "write")


async def test_scope_at_length_limit_is_accepted(service: ApiTokenService) -> None:
    token, _ = await service.create(user_id="u1", name="ci", scopes=["x" * 64])
    assert token.scopes == ("x" * 64,)


# ---------------------------------------------------------------------------
# Resolution


async def test_resolve_happy_path(service: ApiTokenService) -> None:
    token, raw = await service.create(
        user_id="u1", name="ci", scopes=["deploy", "projects:read"]
    )
    resolved = await service.resolve(raw_token=raw)
    assert resolved is not None
    assert resolved.id == token.id
    assert resolved.user_id == "u1"
    assert resolved.scopes == ("deploy", "projects:read")


async def test_resolve_enforces_required_scope(service: ApiTokenService) -> None:
    _, raw = await service.create(user_id="u1", name="ci", scopes=["deploy"])
    assert await service.resolve(raw_token=raw, required_scope="deploy") is not None
    # A deploy token must not authorise admin actions.
    assert await service.resolve(raw_token=raw, required_scope="admin") is None
    # Scope names are exact-match — no prefix or hierarchy tricks.
    assert await service.resolve(raw_token=raw, required_scope="deploy:prod") is None


async def test_resolve_revoked_token_returns_none(service: ApiTokenService) -> None:
    token, raw = await service.create(user_id="u1", name="ci", scopes=["deploy"])
    assert await service.revoke(user_id="u1", token_id=token.id) is True
    assert await service.resolve(raw_token=raw) is None


async def test_resolve_expired_token_returns_none(
    service: ApiTokenService, monkeypatch: pytest.MonkeyPatch
) -> None:
    _freeze(monkeypatch, T0)
    _, raw = await service.create(
        user_id="u1", name="ci", scopes=["deploy"], expires_in_days=1
    )
    _freeze(monkeypatch, T0 + timedelta(days=1) - timedelta(seconds=1))
    assert await service.resolve(raw_token=raw) is not None
    # Exactly at expires_at the token is dead (expires_at <= now).
    _freeze(monkeypatch, T0 + timedelta(days=1))
    assert await service.resolve(raw_token=raw) is None


async def test_resolve_rejects_malformed_inputs(service: ApiTokenService) -> None:
    _, raw = await service.create(user_id="u1", name="ci", scopes=["deploy"])

    # Prefix stripped — the secret alone must not resolve.
    assert await service.resolve(raw_token=raw[len(TOKEN_PREFIX) :]) is None
    # Tampered last character.
    flipped = raw[:-1] + ("A" if raw[-1] != "A" else "B")
    assert await service.resolve(raw_token=flipped) is None
    # Garbage shapes — None for all, never an exception.
    assert await service.resolve(raw_token="") is None
    assert await service.resolve(raw_token=None) is None  # type: ignore[arg-type]
    assert await service.resolve(raw_token=5) is None  # type: ignore[arg-type]
    assert await service.resolve(raw_token=TOKEN_PREFIX) is None
    assert await service.resolve(raw_token="Bearer " + raw) is None
    assert await service.resolve(raw_token=TOKEN_PREFIX + "a" * 300) is None


# ---------------------------------------------------------------------------
# last_used_at throttle


async def _last_used(db: Database, token_id: str) -> datetime | None:
    row = await db.fetchone(
        "SELECT last_used_at FROM api_tokens WHERE id = ?", (token_id,)
    )
    assert row is not None
    return row["last_used_at"]


async def test_last_used_updates_then_throttles_within_a_minute(
    db: Database, service: ApiTokenService, monkeypatch: pytest.MonkeyPatch
) -> None:
    _freeze(monkeypatch, T0)
    token, raw = await service.create(user_id="u1", name="ci", scopes=["deploy"])

    assert await service.resolve(raw_token=raw) is not None
    assert await _last_used(db, token.id) == T0

    # 59 seconds later: inside the throttle window, no write.
    _freeze(monkeypatch, T0 + timedelta(seconds=59))
    assert await service.resolve(raw_token=raw) is not None
    assert await _last_used(db, token.id) == T0

    # Exactly one minute later: the throttle opens.
    _freeze(monkeypatch, T0 + timedelta(seconds=60))
    assert await service.resolve(raw_token=raw) is not None
    assert await _last_used(db, token.id) == T0 + timedelta(seconds=60)


# ---------------------------------------------------------------------------
# Listing


async def test_list_for_user_excludes_revoked_and_orders_newest_first(
    service: ApiTokenService, monkeypatch: pytest.MonkeyPatch
) -> None:
    _freeze(monkeypatch, T0)
    oldest, _ = await service.create(user_id="alice", name="t1", scopes=["read"])
    _freeze(monkeypatch, T0 + timedelta(minutes=1))
    middle, _ = await service.create(user_id="alice", name="t2", scopes=["read"])
    _freeze(monkeypatch, T0 + timedelta(minutes=2))
    newest, _ = await service.create(user_id="alice", name="t3", scopes=["read"])
    await service.create(user_id="bob", name="not-alices", scopes=["read"])

    assert await service.revoke(user_id="alice", token_id=middle.id) is True

    listed = await service.list_for_user(user_id="alice")
    assert [t.id for t in listed] == [newest.id, oldest.id]
    assert all(t.user_id == "alice" for t in listed)


async def test_list_for_unknown_user_is_empty(service: ApiTokenService) -> None:
    assert await service.list_for_user(user_id="ghost") == []


# ---------------------------------------------------------------------------
# Revocation — ownership scoping


async def test_revoke_is_scoped_to_the_owner(service: ApiTokenService) -> None:
    token, raw = await service.create(user_id="alice", name="ci", scopes=["deploy"])

    # Bob holding a leaked token id must not be able to revoke it...
    assert await service.revoke(user_id="bob", token_id=token.id) is False
    # ...and the token stays fully alive.
    assert await service.resolve(raw_token=raw) is not None
    assert len(await service.list_for_user(user_id="alice")) == 1

    # The owner can revoke; a second revoke is a no-op, not an error.
    assert await service.revoke(user_id="alice", token_id=token.id) is True
    assert await service.revoke(user_id="alice", token_id=token.id) is False
    assert await service.resolve(raw_token=raw) is None


async def test_revoke_unknown_id_returns_false(service: ApiTokenService) -> None:
    assert await service.revoke(user_id="alice", token_id="no-such-id") is False


async def test_revoke_all_hits_only_that_users_active_tokens(
    service: ApiTokenService,
) -> None:
    a1, raw_a1 = await service.create(user_id="alice", name="t1", scopes=["read"])
    _, raw_a2 = await service.create(user_id="alice", name="t2", scopes=["read"])
    _, raw_a3 = await service.create(user_id="alice", name="t3", scopes=["read"])
    _, raw_b = await service.create(user_id="bob", name="t1", scopes=["read"])
    assert await service.revoke(user_id="alice", token_id=a1.id) is True

    # Only the two still-active tokens count.
    assert await service.revoke_all(user_id="alice") == 2
    assert await service.list_for_user(user_id="alice") == []
    for raw in (raw_a1, raw_a2, raw_a3):
        assert await service.resolve(raw_token=raw) is None
    # Bob is untouched.
    assert await service.resolve(raw_token=raw_b) is not None

    assert await service.revoke_all(user_id="alice") == 0


# ---------------------------------------------------------------------------
# Per-user cap


async def test_cap_raises_at_limit_and_excludes_revoked(
    service: ApiTokenService,
) -> None:
    first, _ = await service.create(
        user_id="u1", name="t1", scopes=["read"], max_tokens_per_user=2
    )
    await service.create(
        user_id="u1", name="t2", scopes=["read"], max_tokens_per_user=2
    )

    with pytest.raises(TokenLimitReached) as exc_info:
        await service.create(
            user_id="u1", name="t3", scopes=["read"], max_tokens_per_user=2
        )
    assert exc_info.value.limit == 2
    assert "2" in str(exc_info.value)
    # The failed create must not have inserted anything.
    assert len(await service.list_for_user(user_id="u1")) == 2

    # Revoked tokens do not count toward the cap.
    assert await service.revoke(user_id="u1", token_id=first.id) is True
    token, _ = await service.create(
        user_id="u1", name="t3", scopes=["read"], max_tokens_per_user=2
    )
    assert token.name == "t3"


async def test_cap_is_per_user(service: ApiTokenService) -> None:
    await service.create(
        user_id="u1", name="t1", scopes=["read"], max_tokens_per_user=1
    )
    # Another user's tokens never count against u1's cap, and vice versa.
    token, _ = await service.create(
        user_id="u2", name="t1", scopes=["read"], max_tokens_per_user=1
    )
    assert token.user_id == "u2"
