"""Single source of truth for the package version.

Read from the installed distribution rather than restated in source, so the
version this package reports can never drift from ``pyproject.toml``.
"""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("pyxle-mail")
except PackageNotFoundError:  # pragma: no cover - source tree, not installed
    __version__ = "unknown"

__all__ = ["__version__"]
