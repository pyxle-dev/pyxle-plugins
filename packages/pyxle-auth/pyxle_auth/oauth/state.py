"""The signed, single-use OAuth ``state`` cookie.

This cookie is the CSRF and integrity backbone of the OAuth flow. Because the
callback is a ``GET`` carrying an attacker-influenceable ``?code&state``, the
cookie is what proves *this browser* started *this* flow:

* It is **HMAC-signed** with a server secret, so its contents (provider, the
  PKCE ``code_verifier``, the post-login ``next`` path, and a random nonce)
  cannot be forged or tampered with — verified with :func:`hmac.compare_digest`.
* It is **HttpOnly** and short-lived (the middleware sets those attributes),
  so script on the page can't read the PKCE verifier and a stale cookie can't
  be replayed.
* The random ``nonce`` is echoed to the provider as the OAuth ``state``
  parameter; on callback the value the provider returns must equal the nonce in
  the cookie. An attacker who starts their own flow gets their own
  cookie+nonce and cannot make the victim's browser present it.

The PKCE ``code_verifier`` lives **only** in this cookie, never in the URL, so
it stays secret end to end.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class OAuthState:
    """The bound parameters of one in-flight OAuth authorization."""

    provider: str
    nonce: str
    verifier: str
    next: str
    issued_at: int


def generate_nonce() -> str:
    """A random, opaque value for the OAuth ``state`` query parameter."""
    return secrets.token_urlsafe(32)


def _b64u_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64u_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def _sign(payload_b64: str, secret: bytes) -> str:
    digest = hmac.new(secret, payload_b64.encode("ascii"), hashlib.sha256).digest()
    return _b64u_encode(digest)


def issue(state: OAuthState, *, secret: bytes) -> str:
    """Serialize and sign ``state`` into the cookie value."""
    payload = {
        "p": state.provider,
        "n": state.nonce,
        "v": state.verifier,
        "x": state.next,
        "t": int(state.issued_at),
    }
    payload_b64 = _b64u_encode(
        json.dumps(payload, separators=(",", ":")).encode("utf-8")
    )
    return f"{payload_b64}.{_sign(payload_b64, secret)}"


def verify(
    cookie_value: str | None,
    *,
    secret: bytes,
    max_age_seconds: int,
    now: int | None = None,
) -> OAuthState | None:
    """Validate a state cookie and return its :class:`OAuthState`, or ``None``.

    Returns ``None`` — never raises — for a missing, malformed, badly-signed,
    expired, or future-dated cookie. The signature is checked in constant time
    before anything in the payload is trusted.
    """
    if not cookie_value or "." not in cookie_value:
        return None
    payload_b64, _, signature = cookie_value.rpartition(".")
    if not payload_b64 or not signature:
        return None
    if not hmac.compare_digest(signature, _sign(payload_b64, secret)):
        return None
    try:
        data = json.loads(_b64u_decode(payload_b64))
    except (ValueError, binascii.Error, UnicodeDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    try:
        provider = str(data["p"])
        nonce = str(data["n"])
        verifier = str(data["v"])
        next_path = str(data["x"])
        issued_at = int(data["t"])
    except (KeyError, TypeError, ValueError):
        return None

    now_ts = int(time.time()) if now is None else now
    # Expired, or issued implausibly in the future (60s clock-skew tolerance).
    if now_ts - issued_at > max_age_seconds or issued_at - now_ts > 60:
        return None

    return OAuthState(
        provider=provider,
        nonce=nonce,
        verifier=verifier,
        next=next_path,
        issued_at=issued_at,
    )


__all__ = ["OAuthState", "generate_nonce", "issue", "verify"]
