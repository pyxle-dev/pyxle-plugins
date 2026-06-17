"""PKCE (RFC 7636) — Proof Key for Code Exchange.

PKCE binds the authorization code to the client that started the flow: the
``code_verifier`` is a high-entropy secret kept server-side (in our signed,
HttpOnly state cookie), and only its SHA-256 hash (the ``code_challenge``) ever
travels in the authorization URL. An attacker who intercepts the redirected
code cannot redeem it without the verifier.

We always use the ``S256`` method — ``plain`` is forbidden, since it would put
the verifier itself in the URL and defeat the point.
"""

from __future__ import annotations

import base64
import hashlib
import secrets

# RFC 7636 §4.1 — the verifier is 43–128 chars from the unreserved set. 48
# random bytes encodes to 64 url-safe chars, comfortably inside the range and
# well above the 256-bit entropy floor.
_VERIFIER_BYTES = 48

#: The only PKCE method we use. ``plain`` is intentionally unsupported.
CHALLENGE_METHOD = "S256"


def generate_verifier() -> str:
    """Return a fresh, high-entropy ``code_verifier`` (URL-safe, unpadded)."""
    return secrets.token_urlsafe(_VERIFIER_BYTES)


def challenge_for(verifier: str) -> str:
    """Return the ``S256`` ``code_challenge`` for ``verifier``.

    ``BASE64URL(SHA256(ASCII(verifier)))`` with padding stripped, exactly as
    RFC 7636 §4.2 specifies.
    """
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


__all__ = ["CHALLENGE_METHOD", "generate_verifier", "challenge_for"]
