"""Database URL parsing.

One configuration grammar across backends, Django-``DATABASES``-equivalent
but in the URL form modern deploys expect::

    sqlite:///relative/path/app.db
    sqlite:////absolute/path/app.db
    sqlite:///:memory:
    postgresql://user:pass@host:5432/dbname?sslmode=require
    mysql://user:pass@host:3306/dbname

Anything that is not a URL (no ``://``) is treated as a bare SQLite path —
preserving the 0.1 ``Database("./data/app.db")`` behaviour exactly.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import parse_qsl, unquote, urlsplit

from pyxle_db.errors import ConfigurationError

_SCHEME_ALIASES = {
    "sqlite": "sqlite",
    "sqlite3": "sqlite",
    "postgres": "postgresql",
    "postgresql": "postgresql",
    "mysql": "mysql",
    "mariadb": "mysql",
}

_DEFAULT_PORTS = {"postgresql": 5432, "mysql": 3306}


@dataclass(frozen=True)
class DatabaseConfig:
    """Parsed, backend-neutral connection configuration."""

    backend: str
    """``"sqlite"`` | ``"postgresql"`` | ``"mysql"``."""

    path: str = ""
    """SQLite file path (or ``:memory:``). Empty for server backends."""

    host: str = ""
    port: int = 0
    user: str = ""
    password: str = ""
    database: str = ""
    options: dict[str, str] = field(default_factory=dict)
    """Query-string options, passed through to the driver (e.g. sslmode)."""

    def redacted(self) -> str:
        """Loggable description with the password stripped."""
        if self.backend == "sqlite":
            return f"sqlite:///{self.path}"
        auth = self.user or ""
        if self.password:
            auth += ":***"
        if auth:
            auth += "@"
        return f"{self.backend}://{auth}{self.host}:{self.port}/{self.database}"


def parse_database_url(url_or_path: str) -> DatabaseConfig:
    """Parse a database URL (or bare SQLite path) into a config."""
    if not isinstance(url_or_path, str) or not url_or_path.strip():
        raise ConfigurationError("Database URL/path must be a non-empty string")

    raw = url_or_path.strip()
    if "://" not in raw:
        # Bare path → SQLite, the 0.1 behaviour.
        return DatabaseConfig(backend="sqlite", path=raw)

    parts = urlsplit(raw)
    scheme = parts.scheme.lower()
    backend = _SCHEME_ALIASES.get(scheme)
    if backend is None:
        supported = ", ".join(sorted(set(_SCHEME_ALIASES)))
        raise ConfigurationError(
            f"Unsupported database scheme {scheme!r}; supported: {supported}"
        )

    if backend == "sqlite":
        # urlsplit puts "/rel/path" or "//abs/path" in .path; netloc must be
        # empty (sqlite has no host). `sqlite:///x.db` → path "/x.db" (rel),
        # `sqlite:////x.db` → "//x.db" (abs), `sqlite:///:memory:`.
        if parts.netloc not in ("", None):
            raise ConfigurationError(
                "SQLite URLs take no host — use sqlite:///relative/path.db "
                "or sqlite:////absolute/path.db"
            )
        path = unquote(parts.path or "")
        if path.startswith("//"):
            path = path[1:]  # absolute: keep one leading slash
        elif path.startswith("/"):
            path = path[1:]  # relative
        if not path:
            raise ConfigurationError("SQLite URL is missing a database path")
        return DatabaseConfig(backend="sqlite", path=path)

    if not parts.hostname:
        raise ConfigurationError(f"{backend} URL is missing a host")
    try:
        port = parts.port  # urlsplit raises lazily on non-numeric ports
    except ValueError as exc:
        raise ConfigurationError(f"Invalid port in {backend} URL") from exc
    database = unquote(parts.path.lstrip("/"))
    if not database:
        raise ConfigurationError(f"{backend} URL is missing a database name")
    if "/" in database:
        raise ConfigurationError(
            f"{backend} database name may not contain '/': {database!r}"
        )

    return DatabaseConfig(
        backend=backend,
        host=parts.hostname,
        port=port or _DEFAULT_PORTS[backend],
        user=unquote(parts.username or ""),
        password=unquote(parts.password or ""),
        database=database,
        options={k: v for k, v in parse_qsl(parts.query)},
    )
