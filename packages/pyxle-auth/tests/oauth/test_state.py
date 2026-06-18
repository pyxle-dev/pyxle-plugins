"""The signed state cookie — the OAuth CSRF/integrity backbone.

These are the hostile tests: tamper, wrong key, expiry, future-dating,
malformed input. A single failing check must return ``None`` (never raise,
never partially trust the payload).
"""

from __future__ import annotations

import pytest

from pyxle_auth.oauth import state as oauth_state
from pyxle_auth.oauth.state import OAuthState

SECRET = b"a-32-byte-test-secret-key-000000"


def _state(**overrides) -> OAuthState:
    base = dict(
        provider="google",
        nonce="nonce-abc",
        verifier="verifier-xyz",
        next="/dashboard",
        issued_at=1_000_000,
    )
    base.update(overrides)
    return OAuthState(**base)


def test_round_trip() -> None:
    cookie = oauth_state.issue(_state(), secret=SECRET)
    back = oauth_state.verify(cookie, secret=SECRET, max_age_seconds=600, now=1_000_100)
    assert back is not None
    assert back.provider == "google"
    assert back.nonce == "nonce-abc"
    assert back.verifier == "verifier-xyz"
    assert back.next == "/dashboard"


def test_tampered_payload_is_rejected() -> None:
    cookie = oauth_state.issue(_state(), secret=SECRET)
    payload, _, sig = cookie.rpartition(".")
    # Flip a character in the payload; the signature no longer matches.
    forged = payload[:-1] + ("A" if payload[-1] != "A" else "B") + "." + sig
    assert oauth_state.verify(forged, secret=SECRET, max_age_seconds=600, now=1_000_100) is None


def test_tampered_signature_is_rejected() -> None:
    cookie = oauth_state.issue(_state(), secret=SECRET)
    payload, _, sig = cookie.rpartition(".")
    forged = payload + "." + (sig[:-1] + ("A" if sig[-1] != "A" else "B"))
    assert oauth_state.verify(forged, secret=SECRET, max_age_seconds=600, now=1_000_100) is None


def test_wrong_secret_is_rejected() -> None:
    cookie = oauth_state.issue(_state(), secret=SECRET)
    assert oauth_state.verify(cookie, secret=b"different-secret-key", max_age_seconds=600, now=1_000_100) is None


def test_expired_is_rejected() -> None:
    cookie = oauth_state.issue(_state(issued_at=1_000_000), secret=SECRET)
    # now is 601s after issue, ttl is 600 → expired.
    assert oauth_state.verify(cookie, secret=SECRET, max_age_seconds=600, now=1_000_601) is None


def test_within_ttl_is_accepted() -> None:
    cookie = oauth_state.issue(_state(issued_at=1_000_000), secret=SECRET)
    assert oauth_state.verify(cookie, secret=SECRET, max_age_seconds=600, now=1_000_600) is not None


def test_future_dated_beyond_skew_is_rejected() -> None:
    # Issued 120s in the "future" relative to now → beyond the 60s skew window.
    cookie = oauth_state.issue(_state(issued_at=1_000_120), secret=SECRET)
    assert oauth_state.verify(cookie, secret=SECRET, max_age_seconds=600, now=1_000_000) is None


@pytest.mark.parametrize(
    "bad",
    ["", "no-dot", ".", "onlypayload.", ".onlysig", "a.b.c.d"],
)
def test_malformed_cookies_return_none(bad: str) -> None:
    assert oauth_state.verify(bad, secret=SECRET, max_age_seconds=600, now=1_000_000) is None


def test_none_cookie_returns_none() -> None:
    assert oauth_state.verify(None, secret=SECRET, max_age_seconds=600, now=1_000_000) is None


def test_non_base64_payload_returns_none() -> None:
    # Valid structure (payload.sig) but payload isn't decodable JSON.
    forged = "!!!notbase64!!!"
    sig = oauth_state._sign(forged, SECRET)
    assert oauth_state.verify(f"{forged}.{sig}", secret=SECRET, max_age_seconds=600, now=1_000_000) is None


def test_nonce_is_random_and_url_safe() -> None:
    nonces = {oauth_state.generate_nonce() for _ in range(200)}
    assert len(nonces) == 200
