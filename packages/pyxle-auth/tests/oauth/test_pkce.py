"""PKCE primitives — verifier entropy and the S256 challenge."""

from __future__ import annotations

import base64
import hashlib

from pyxle_auth.oauth import pkce


def test_verifier_is_in_rfc_length_range() -> None:
    # RFC 7636 §4.1: 43–128 characters.
    for _ in range(20):
        v = pkce.generate_verifier()
        assert 43 <= len(v) <= 128


def test_verifier_is_url_safe_and_unique() -> None:
    seen = {pkce.generate_verifier() for _ in range(200)}
    assert len(seen) == 200  # no collisions → high entropy
    allowed = set(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    )
    for v in seen:
        assert set(v) <= allowed


def test_challenge_matches_rfc_s256() -> None:
    verifier = pkce.generate_verifier()
    expected = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest())
        .rstrip(b"=")
        .decode("ascii")
    )
    assert pkce.challenge_for(verifier) == expected


def test_challenge_is_deterministic_and_unpadded() -> None:
    challenge = pkce.challenge_for("a-fixed-verifier-value-for-the-test")
    assert "=" not in challenge
    assert challenge == pkce.challenge_for("a-fixed-verifier-value-for-the-test")


def test_method_is_s256() -> None:
    assert pkce.CHALLENGE_METHOD == "S256"
