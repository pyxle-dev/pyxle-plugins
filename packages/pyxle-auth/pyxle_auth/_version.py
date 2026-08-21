"""Single source of truth for the package version.

Read from the installed distribution rather than restated in source. A literal
here drifts from ``pyproject.toml`` the moment a release bumps one and not the
other — which is exactly what happened between 0.3.0 and 0.4.0, leaving the
plugin reporting a version it had not been for two releases.
"""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("pyxle-auth")
except PackageNotFoundError:  # pragma: no cover - source tree, not installed
    __version__ = "unknown"

__all__ = ["__version__"]
