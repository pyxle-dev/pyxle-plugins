"""OAuth provider definitions and env-only credential loading.

A :class:`OAuthProvider` is the *static* description of a provider — its
endpoints, scopes, and how to read the account id / email / verified flag out
of its userinfo response — plus the app's client credentials. Built-in
templates ship for Google, GitHub, and Discord; :func:`OAuthProvider.from_env`
fills the credentials from the environment.

**Secrets never live in config.** ``pyxle.config.json`` is committed, so the
client id and secret are read only from
``PYXLE_AUTH_OAUTH_<PROVIDER>_CLIENT_ID`` / ``…_CLIENT_SECRET``. The secret is
redacted in ``repr`` so it can't leak into logs or tracebacks.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field, replace
from urllib.parse import urlencode

from pyxle_auth.oauth.errors import OAuthConfigError


@dataclass(frozen=True, slots=True)
class OAuthProvider:
    """A configured OAuth 2.0 / OIDC provider.

    Attributes:
        name: Stable lowercase key (``"google"``) used in URLs and the DB.
        client_id: The app's OAuth client id.
        client_secret: The app's OAuth client secret (redacted in ``repr``).
        authorize_url: Where the user is sent to grant consent.
        token_url: Where the authorization code is exchanged for tokens.
        userinfo_url: Where the access token reads the user's profile.
        scopes: Requested scopes.
        subject_key: JSON key in the userinfo response holding the stable,
            provider-unique account id.
        email_key: JSON key holding the email, or ``None`` when the provider
            only exposes it via :attr:`emails_url` (GitHub).
        email_verified_key: JSON key holding the verified flag, or ``None``.
        emails_url: Optional endpoint returning a list of the user's emails
            with ``primary`` / ``verified`` flags (GitHub's ``/user/emails``).
        use_pkce: Send a PKCE ``S256`` challenge (always ``True`` for the
            built-ins).
    """

    name: str
    client_id: str
    client_secret: str = field(repr=False)
    authorize_url: str
    token_url: str
    userinfo_url: str
    scopes: tuple[str, ...]
    subject_key: str
    email_key: str | None
    email_verified_key: str | None
    emails_url: str | None = None
    use_pkce: bool = True

    def __repr__(self) -> str:  # redact the secret; never log it
        secret = "***" if self.client_secret else ""
        return (
            f"OAuthProvider(name={self.name!r}, client_id={self.client_id!r}, "
            f"client_secret={secret!r}, scopes={self.scopes!r})"
        )

    def authorization_url(
        self, *, redirect_uri: str, state: str, code_challenge: str | None = None
    ) -> str:
        """Build the URL the browser is redirected to for consent."""
        params = {
            "client_id": self.client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": " ".join(self.scopes),
            "state": state,
        }
        if self.use_pkce and code_challenge:
            params["code_challenge"] = code_challenge
            params["code_challenge_method"] = "S256"
        return f"{self.authorize_url}?{urlencode(params)}"

    @classmethod
    def from_env(
        cls,
        name: str,
        *,
        client_id: str | None = None,
        client_secret: str | None = None,
        scopes: tuple[str, ...] | None = None,
    ) -> "OAuthProvider":
        """Build a built-in provider, reading credentials from the environment.

        ``client_id`` / ``client_secret`` override the env lookup (used in
        tests). Raises :class:`OAuthConfigError` for an unknown provider or
        missing credentials.
        """
        template = _BUILTINS.get(name.lower())
        if template is None:
            raise OAuthConfigError(
                f"Unknown OAuth provider {name!r}. Built-ins: "
                f"{', '.join(sorted(_BUILTINS))}."
            )
        env = name.upper()
        cid = client_id or os.environ.get(f"PYXLE_AUTH_OAUTH_{env}_CLIENT_ID")
        secret = client_secret or os.environ.get(
            f"PYXLE_AUTH_OAUTH_{env}_CLIENT_SECRET"
        )
        if not cid or not secret:
            raise OAuthConfigError(
                f"OAuth provider {name!r} is missing credentials. Set "
                f"PYXLE_AUTH_OAUTH_{env}_CLIENT_ID and "
                f"PYXLE_AUTH_OAUTH_{env}_CLIENT_SECRET in the environment "
                "(never in pyxle.config.json)."
            )
        return replace(
            template,
            client_id=cid,
            client_secret=secret,
            scopes=scopes or template.scopes,
        )


# --- Built-in templates (credentials filled by from_env) -------------------

_GOOGLE = OAuthProvider(
    name="google",
    client_id="",
    client_secret="",
    authorize_url="https://accounts.google.com/o/oauth2/v2/auth",
    token_url="https://oauth2.googleapis.com/token",
    userinfo_url="https://openidconnect.googleapis.com/v1/userinfo",
    scopes=("openid", "email", "profile"),
    subject_key="sub",
    email_key="email",
    email_verified_key="email_verified",
)

_GITHUB = OAuthProvider(
    name="github",
    client_id="",
    client_secret="",
    authorize_url="https://github.com/login/oauth/authorize",
    token_url="https://github.com/login/oauth/access_token",
    userinfo_url="https://api.github.com/user",
    scopes=("read:user", "user:email"),
    subject_key="id",
    # GitHub's /user.email is often null and carries no verified flag, so the
    # email always comes from /user/emails (primary + verified).
    email_key=None,
    email_verified_key=None,
    emails_url="https://api.github.com/user/emails",
)

_DISCORD = OAuthProvider(
    name="discord",
    client_id="",
    client_secret="",
    authorize_url="https://discord.com/oauth2/authorize",
    token_url="https://discord.com/api/oauth2/token",
    userinfo_url="https://discord.com/api/users/@me",
    scopes=("identify", "email"),
    subject_key="id",
    email_key="email",
    email_verified_key="verified",
)

_BUILTINS: dict[str, OAuthProvider] = {
    "google": _GOOGLE,
    "github": _GITHUB,
    "discord": _DISCORD,
}

#: Provider names with a built-in template.
BUILTIN_PROVIDERS: tuple[str, ...] = tuple(sorted(_BUILTINS))


__all__ = ["OAuthProvider", "BUILTIN_PROVIDERS"]
