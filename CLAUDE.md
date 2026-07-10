# CLAUDE.md — Pyxle Official Plugins

Official plugins for the Pyxle framework. Each plugin is an independent Python package.

---

## Structure

Each plugin is an independent Python package under `packages/`:

```
packages/
|-- pyxle-auth/            # Authentication plugin
|   |-- pyproject.toml
|   |-- pyxle_auth/
|   |   +-- __init__.py
|   +-- tests/
|-- pyxle-db/              # Database plugin
|-- pyxle-mail/            # Email plugin
+-- ...
```

## Creating a New Plugin

1. Create a directory under `packages/` named `pyxle-<name>`
2. Add a `pyproject.toml` with `pyxle` as a dependency
3. Create the Python package at `pyxle_<name>/`
4. Add `tests/` mirroring the source structure
5. Add a README.md describing the plugin's purpose and API

### Plugin pyproject.toml Template

```toml
[build-system]
requires = ["hatchling>=1.25,<2.0"]
build-backend = "hatchling.build"

[project]
name = "pyxle-<name>"
version = "0.1.0"
description = "<Plugin description>"
requires-python = ">=3.10"
dependencies = [
  "pyxle>=0.1.0",
]
```

## Rules

- Each plugin must be independently installable (`pip install pyxle-<name>`)
- Plugins depend on `pyxle` core but never on each other (unless explicitly documented)
- Follow the same coding standards as `pyxle` core (frozen dataclasses, type hints, async I/O)
- Each plugin must have its own test suite
- Plugins must not monkey-patch or modify pyxle core internals -- use public APIs only
- **Always ask for explicit user confirmation before committing or deploying**
