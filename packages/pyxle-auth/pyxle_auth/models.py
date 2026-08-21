"""Domain objects returned from :class:`pyxle_auth.AuthService`.

Everything is a ``frozen=True`` dataclass — the auth service never
mutates what it returns. Handlers can pass these into other layers
without worrying about someone silently editing the email address.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone
from typing import Any


@dataclass(frozen=True, slots=True)
class User:
    """A user account.

    The ``password_hash`` field is populated only on the version held
    internally by the service — the version handed to request handlers
    via :meth:`AuthService.with_user` never includes it.
    """

    id: str
    # Exactly one of ``email`` / ``username`` is the login identifier (see
    # ``AuthSettings.identifier``); the other may be ``None``. Email-mode apps
    # always have an email and a ``None`` username — unchanged from before.
    email: str | None
    username: str | None
    email_verified_at: datetime | None
    created_at: datetime
    plan: str


@dataclass(frozen=True, slots=True)
class Session:
    """An active session row.

    ``token_sha256`` is the hash stored in the DB; the raw token that
    the browser holds lives in a :class:`SessionCookie`.
    """

    token_sha256: str
    user_id: str
    created_at: datetime
    expires_at: datetime
    user_agent: str | None
    ip: str | None


@dataclass(frozen=True, slots=True)
class SessionInfo:
    """One row in a user's "active sessions" (devices) screen.

    ``id`` is the session's ``token_sha256`` — safe to expose because it
    is a one-way hash of the cookie value: possession of the hash cannot
    resurrect the session, but it uniquely names the row for
    :meth:`AuthService.revoke_session`.

    ``current`` is ``True`` for the session belonging to the cookie the
    caller passed to :meth:`AuthService.list_sessions`, so the UI can
    render "this device".
    """

    id: str
    created_at: datetime
    expires_at: datetime
    user_agent: str | None
    ip: str | None
    current: bool = False


@dataclass(frozen=True, slots=True)
class SessionCookie:
    """Cookie attributes for a session.

    Pass the result of :meth:`kwargs` straight into Starlette's
    ``response.set_cookie(**cookie.kwargs())``.
    """

    name: str
    value: str
    max_age: int
    secure: bool
    http_only: bool = True
    samesite: str = "Lax"
    path: str = "/"
    domain: str | None = None

    def for_request(self, request: Any) -> "SessionCookie":
        """This cookie, with ``Secure`` dropped when the connection is not TLS.

        A browser **discards** a ``Secure`` cookie that arrives over plain
        HTTP. Sending one there does not degrade security — there is no
        confidentiality on the connection to protect — it simply means no
        session cookie is stored, so the user is silently returned to the sign
        in page with no error to read. Self-hosted deployments hit this
        constantly: a LAN address, a homelab, a private network behind
        WireGuard, or any proxy that terminates TLS and forgets
        ``X-Forwarded-Proto``.

        Over HTTPS — directly or per that header — the flag is untouched.
        """
        if not self.secure or _is_https(request):
            return self
        return replace(self, secure=False)

    def kwargs(self) -> dict[str, Any]:
        """Return a dict shaped for ``Starlette response.set_cookie``."""
        out: dict[str, Any] = {
            "key": self.name,
            "value": self.value,
            "max_age": self.max_age,
            "httponly": self.http_only,
            "secure": self.secure,
            "samesite": self.samesite.lower(),
            "path": self.path,
        }
        if self.domain is not None:
            out["domain"] = self.domain
        return out

    @classmethod
    def delete(cls, name: str, *, domain: str | None = None, path: str = "/") -> "SessionCookie":
        """Produce a cookie that instructs the browser to drop ours."""
        return cls(
            name=name,
            value="",
            max_age=0,
            secure=False,
            http_only=True,
            samesite="Lax",
            path=path,
            domain=domain,
        )


def _is_https(request: Any) -> bool:
    """Whether *request* reached the app over TLS.

    ``X-Forwarded-Proto`` first, because the overwhelmingly common production
    shape is a proxy terminating TLS and speaking plain HTTP to the app — where
    the request's own scheme says ``http`` and the browser's connection was
    HTTPS throughout.
    """
    headers = getattr(request, "headers", None)
    if headers is not None:
        forwarded = headers.get("x-forwarded-proto") or ""
        if forwarded:
            return forwarded.split(",")[0].strip().lower() == "https"
    url = getattr(request, "url", None)
    return str(getattr(url, "scheme", "")).lower() in ("https", "wss")


# ---------------------------------------------------------------------------
# Helpers used by the service


def _now_utc() -> datetime:
    """Wrap ``datetime.now`` so tests can monkeypatch a single call site."""
    return datetime.now(tz=timezone.utc)
