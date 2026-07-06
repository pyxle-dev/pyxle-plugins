"""Username normalisation and validation.

Kept dependency-light (only :mod:`pyxle_auth.errors`) and pure — every
function takes its policy as arguments rather than reaching for settings —
so the rules are trivial to unit-test and reuse from both the service and
the plugin's HTTP endpoints.

Usernames are **lowercase-normalised**: ``"Ada"`` and ``"ada"`` are the same
account. This keeps uniqueness case-insensitive on every backend without a
functional index (which MySQL can't express portably).
"""

from __future__ import annotations

import re
from typing import Iterable

from .errors import AuthError


# A conservative default block-list. It guards two things every multi-user
# app cares about: impersonation of system/staff identities, and collisions
# with the routes apps commonly mount (``/login``, ``/settings``, ``/api`` …).
# Apps tune this via ``AuthSettings.username_reserved`` — pass an empty set to
# allow everything, or extend it with your own product's routes.
DEFAULT_RESERVED_USERNAMES: frozenset[str] = frozenset(
    {
        # system / staff identities
        "admin", "administrator", "root", "superuser", "sysadmin", "system",
        "support", "help", "helpdesk", "staff", "team", "moderator", "mod",
        "owner", "official", "security", "abuse", "postmaster", "webmaster",
        "noreply", "no-reply", "donotreply",
        # auth / account routes
        "login", "logout", "signin", "sign-in", "signout", "sign-out",
        "signup", "sign-up", "register", "auth", "oauth", "sso", "session",
        "account", "accounts", "settings", "profile", "password", "verify",
        "me", "user", "users",
        # infra / common app routes
        "api", "app", "www", "mail", "email", "ftp", "smtp", "static",
        "assets", "public", "cdn", "media", "files", "download", "downloads",
        "dashboard", "home", "index", "search", "explore", "billing",
        "payment", "payments", "checkout", "status", "health", "metrics",
        "about", "contact", "terms", "privacy", "legal", "docs", "blog",
        "favicon", "robots", "sitemap",
        # placeholders that signal a bug, not a real handle
        "null", "undefined", "none", "nan", "anonymous", "guest", "test",
    }
)


def normalise_username(
    raw: str,
    *,
    min_length: int,
    max_length: int,
    pattern: str,
    reserved: Iterable[str] = DEFAULT_RESERVED_USERNAMES,
) -> str:
    """Normalise and validate *raw*, returning the canonical username.

    Trims surrounding whitespace and lowercases, then enforces length, the
    allowed-character ``pattern`` (matched against the lowercased value), and
    the ``reserved`` block-list. Raises :class:`AuthError` with a
    user-facing message on any violation — the same exception type the email
    path uses, so callers handle both identifiers uniformly.
    """
    username = raw.strip().lower()
    if not username:
        raise AuthError("Please choose a username.")
    if len(username) < min_length:
        raise AuthError(
            f"Username must be at least {min_length} characters."
        )
    if len(username) > max_length:
        raise AuthError(
            f"Username must be at most {max_length} characters."
        )
    if not re.match(pattern, username):
        raise AuthError(
            "Username may only contain lowercase letters, numbers, "
            "hyphens, and underscores."
        )
    if username in {r.strip().lower() for r in reserved}:
        raise AuthError("That username is reserved. Please choose another.")
    return username
