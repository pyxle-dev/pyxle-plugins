"""OAuthService — code exchange, identity fetch, and account linking.

The flow, once the middleware has validated the signed state cookie:

1. **Exchange** the authorization ``code`` (+ PKCE verifier) for an access
   token at the provider's token endpoint.
2. **Fetch identity** — the provider-unique account id plus the email and its
   verified flag.
3. **Resolve the local user**:
   * a returning identity (``oauth_identities`` row) signs in directly;
   * a *new* identity links to an existing local account **only when the
     provider says the email is verified** — linking on an unverified email
     would let an attacker pre-register an account at the provider with the
     victim's address and hijack the local account;
   * otherwise a fresh passwordless account is created.
4. **Issue a session** via :meth:`AuthService.start_session`.

Network calls go through an injected ``httpx.AsyncClient`` factory so tests run
fully offline. ``httpx`` is the ``[oauth]`` extra — imported lazily so the rest
of pyxle-auth never needs it.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Callable, Mapping

from pyxle_db import DatabaseLike, IntegrityError

from pyxle_auth._ddl import ensure_index, timestamp_type
from pyxle_auth.models import SessionCookie, User, _now_utc
from pyxle_auth.oauth.errors import (
    OAuthConfigError,
    OAuthEmailUnverified,
    OAuthExchangeError,
)
from pyxle_auth.oauth.providers import OAuthProvider

_logger = logging.getLogger("pyxle_auth.oauth")

# A conservative per-request network timeout for the provider round-trips.
_HTTP_TIMEOUT_SECONDS = 10.0


@dataclass(frozen=True, slots=True)
class OAuthIdentity:
    """What we learned about the user from the provider."""

    subject: str
    email: str | None
    email_verified: bool


def _default_client_factory() -> Any:
    """Build a fresh ``httpx.AsyncClient`` (lazy import — the ``[oauth]`` extra)."""
    try:
        import httpx
    except ImportError as exc:  # pragma: no cover - exercised via OAuthConfigError
        raise OAuthConfigError(
            "OAuth needs the optional 'httpx' dependency. Install the extra: "
            "pip install 'pyxle-auth[oauth]'."
        ) from exc
    # follow_redirects stays off: token/userinfo endpoints never legitimately
    # redirect, and following one could exfiltrate the bearer token.
    return httpx.AsyncClient(timeout=httpx.Timeout(_HTTP_TIMEOUT_SECONDS), follow_redirects=False)


class OAuthService:
    """Owns the ``oauth_identities`` table and the sign-in-via-provider flow."""

    def __init__(
        self,
        db: DatabaseLike,
        auth_service: Any,
        providers: Mapping[str, OAuthProvider],
        *,
        http_client_factory: Callable[[], Any] | None = None,
    ) -> None:
        self._db = db
        self._auth = auth_service
        self._providers = dict(providers)
        self._client_factory = http_client_factory or _default_client_factory

    @property
    def providers(self) -> Mapping[str, OAuthProvider]:
        return self._providers

    def provider(self, name: str) -> OAuthProvider:
        """Return a configured provider, or raise :class:`OAuthConfigError`."""
        provider = self._providers.get(name.lower())
        if provider is None:
            raise OAuthConfigError(
                f"OAuth provider {name!r} is not configured. Configured: "
                f"{', '.join(sorted(self._providers)) or '(none)'}."
            )
        return provider

    # ---- schema ----------------------------------------------------------------

    async def ensure_schema(self) -> None:
        """Create ``oauth_identities`` if it doesn't exist (idempotent)."""
        ts = timestamp_type(self._db.dialect.name)
        await self._db.execute(
            """
            CREATE TABLE IF NOT EXISTS oauth_identities (
                provider   VARCHAR(64)  NOT NULL,
                subject    VARCHAR(255) NOT NULL,
                user_id    VARCHAR(64)  NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                email      TEXT,
                created_at {ts} NOT NULL,
                PRIMARY KEY (provider, subject)
            )
            """.format(ts=ts)
        )
        await ensure_index(
            self._db,
            name="oauth_identities_user",
            table="oauth_identities",
            columns="user_id",
        )

    # ---- the flow --------------------------------------------------------------

    async def complete(
        self,
        provider_name: str,
        *,
        code: str,
        redirect_uri: str,
        code_verifier: str | None,
        ip: str | None = None,
        user_agent: str | None = None,
    ) -> tuple[User, SessionCookie]:
        """Run the whole post-callback flow and return ``(user, session)``."""
        provider = self.provider(provider_name)
        async with self._client_factory() as client:
            access_token = await self._exchange_code(
                client,
                provider,
                code=code,
                redirect_uri=redirect_uri,
                code_verifier=code_verifier,
            )
            identity = await self._fetch_identity(client, provider, access_token)
        user = await self._resolve_or_create_user(provider, identity)
        cookie = await self._auth.start_session(
            user_id=user.id, ip=ip, user_agent=user_agent
        )
        return user, cookie

    async def _exchange_code(
        self,
        client: Any,
        provider: OAuthProvider,
        *,
        code: str,
        redirect_uri: str,
        code_verifier: str | None,
    ) -> str:
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": provider.client_id,
            "client_secret": provider.client_secret,
        }
        if provider.use_pkce and code_verifier:
            data["code_verifier"] = code_verifier
        try:
            response = await client.post(
                provider.token_url,
                data=data,
                headers={"Accept": "application/json"},
            )
        except Exception as exc:  # network error — never expose details
            _logger.warning("oauth: token exchange request failed: %s", exc)
            raise OAuthExchangeError("Could not reach the identity provider.") from exc
        if response.status_code != 200:
            _logger.warning(
                "oauth: token endpoint returned %s for provider %s",
                response.status_code,
                provider.name,
            )
            raise OAuthExchangeError("The identity provider rejected the sign-in.")
        try:
            payload = response.json()
        except ValueError as exc:
            raise OAuthExchangeError("Malformed token response.") from exc
        token = payload.get("access_token") if isinstance(payload, dict) else None
        if not isinstance(token, str) or not token:
            # GitHub returns 200 with {"error": ...} on a bad code.
            _logger.warning("oauth: token response had no access_token (%s)", provider.name)
            raise OAuthExchangeError("The identity provider rejected the sign-in.")
        return token

    async def _fetch_identity(
        self, client: Any, provider: OAuthProvider, access_token: str
    ) -> OAuthIdentity:
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json",
        }
        data = await self._get_json(client, provider.userinfo_url, headers, provider)
        subject = data.get(provider.subject_key)
        if subject is None or str(subject) == "":
            raise OAuthExchangeError("Provider profile is missing an account id.")

        email: str | None = None
        verified = False
        if provider.email_key:
            raw_email = data.get(provider.email_key)
            if isinstance(raw_email, str) and raw_email:
                email = raw_email
                if provider.email_verified_key:
                    verified = bool(data.get(provider.email_verified_key))

        if provider.emails_url and not email:
            email, verified = await self._fetch_primary_email(
                client, provider, headers
            )

        return OAuthIdentity(
            subject=str(subject),
            email=email,
            email_verified=bool(verified and email),
        )

    async def _fetch_primary_email(
        self, client: Any, provider: OAuthProvider, headers: Mapping[str, str]
    ) -> tuple[str | None, bool]:
        """GitHub path: read the primary, verified email from ``/user/emails``."""
        try:
            response = await client.get(provider.emails_url, headers=headers)
        except Exception as exc:
            _logger.warning("oauth: emails request failed: %s", exc)
            return None, False
        if response.status_code != 200:
            return None, False
        try:
            entries = response.json()
        except ValueError:
            return None, False
        if not isinstance(entries, list):
            return None, False
        for entry in entries:
            if (
                isinstance(entry, dict)
                and entry.get("primary")
                and entry.get("verified")
                and isinstance(entry.get("email"), str)
            ):
                return entry["email"], True
        return None, False

    async def _get_json(
        self,
        client: Any,
        url: str,
        headers: Mapping[str, str],
        provider: OAuthProvider,
    ) -> dict[str, Any]:
        try:
            response = await client.get(url, headers=headers)
        except Exception as exc:
            _logger.warning("oauth: userinfo request failed: %s", exc)
            raise OAuthExchangeError("Could not reach the identity provider.") from exc
        if response.status_code != 200:
            _logger.warning(
                "oauth: userinfo returned %s for provider %s",
                response.status_code,
                provider.name,
            )
            raise OAuthExchangeError("Could not read your profile from the provider.")
        try:
            payload = response.json()
        except ValueError as exc:
            raise OAuthExchangeError("Malformed profile response.") from exc
        if not isinstance(payload, dict):
            raise OAuthExchangeError("Unexpected profile response.")
        return payload

    # ---- account resolution ----------------------------------------------------

    async def _resolve_or_create_user(
        self, provider: OAuthProvider, identity: OAuthIdentity
    ) -> User:
        # 1. A returning identity signs in directly — no email re-check (the
        #    link was established when the email was verified).
        row = await self._db.fetchone(
            "SELECT user_id FROM oauth_identities WHERE provider = ? AND subject = ?",
            (provider.name, identity.subject),
        )
        if row is not None:
            user = await self._auth.get_user(user_id=row["user_id"])
            if user is not None:
                return user
            # Dangling link (user row deleted) — drop it and fall through.
            await self._db.execute(
                "DELETE FROM oauth_identities WHERE provider = ? AND subject = ?",
                (provider.name, identity.subject),
            )

        # 2. A new identity must carry a provider-verified email to link or
        #    create — the takeover guard.
        if not identity.email or not identity.email_verified:
            raise OAuthEmailUnverified()

        # 3. Link to an existing local account with this (verified) email.
        existing = await self._auth.get_user_by_email(email=identity.email)
        if existing is not None:
            await self._link(provider, identity, existing.id)
            if existing.email_verified_at is None:
                await self._auth.mark_email_verified(user_id=existing.id)
            return existing

        # 4. Brand-new passwordless account.
        user = await self._auth.create_external_user(
            email=identity.email, email_verified=True
        )
        await self._link(provider, identity, user.id)
        return user

    async def _link(
        self, provider: OAuthProvider, identity: OAuthIdentity, user_id: str
    ) -> None:
        try:
            await self._db.execute(
                """
                INSERT INTO oauth_identities (provider, subject, user_id, email, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (provider.name, identity.subject, user_id, identity.email, _now_utc()),
            )
        except IntegrityError:
            # A concurrent callback linked the same (provider, subject) first —
            # the existing link wins; nothing to do.
            pass


__all__ = ["OAuthService", "OAuthIdentity"]
