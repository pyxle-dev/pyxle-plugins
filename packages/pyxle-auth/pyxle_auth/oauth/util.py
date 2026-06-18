"""Small shared helpers for the OAuth flow."""

from __future__ import annotations


def sanitize_next(raw: object, *, default: str = "/") -> str:
    """Return a safe same-origin redirect target, or ``default``.

    The post-login ``next`` parameter is attacker-controllable (it rides in the
    start URL), so it must never be allowed to redirect off-origin. We accept
    only an absolute path on this origin and reject everything that could point
    elsewhere:

    * not a string, or empty → default
    * protocol-relative (``//evil.com``) or scheme-bearing
      (``https://evil.com``) → default
    * a backslash anywhere (``/\\evil.com`` — some browsers treat ``\\`` as
      ``/``) → default
    * control characters or whitespace (header/redirect smuggling) → default
    """
    if not isinstance(raw, str) or not raw:
        return default
    if not raw.startswith("/"):
        return default
    if raw.startswith("//"):
        return default
    if "\\" in raw:
        return default
    if any(ch in raw for ch in "\r\n\t ") or any(ord(ch) < 0x20 for ch in raw):
        return default
    return raw


__all__ = ["sanitize_next"]
