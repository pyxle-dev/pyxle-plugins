# Pyxle Plugins

Official plugins for the [Pyxle](https://pyxle.dev) framework — one repo, independently versioned packages.

[![CI](https://github.com/pyxle-dev/pyxle-plugins/actions/workflows/ci.yml/badge.svg)](https://github.com/pyxle-dev/pyxle-plugins/actions/workflows/ci.yml)
[![pyxle-db on PyPI](https://img.shields.io/pypi/v/pyxle-db?label=pyxle-db)](https://pypi.org/project/pyxle-db/)
[![pyxle-auth on PyPI](https://img.shields.io/pypi/v/pyxle-auth?label=pyxle-auth)](https://pypi.org/project/pyxle-auth/)

## Packages

| Package | What it is | Docs |
|---|---|---|
| [`pyxle-db`](packages/pyxle-db) | One explicit-SQL API over SQLite, PostgreSQL, and MySQL: portable `?` placeholders, a uniform `Row`, checksum-tracked migrations, and the `DatabaseLike` contract other plugins build on. Not an ORM, on purpose. | [pyxle.dev/docs/plugins/pyxle-db](https://pyxle.dev/docs/plugins/pyxle-db) |
| [`pyxle-auth`](packages/pyxle-auth) | Email + password accounts with argon2id, sliding sessions, password-reset / email-verification flows, RBAC with wildcards, scoped API tokens, and request guards. Brings no UI and sends no email — hardened primitives only. | [pyxle.dev/docs/plugins/pyxle-auth](https://pyxle.dev/docs/plugins/pyxle-auth) |

```bash
pip install pyxle-db                # SQLite needs nothing else
pip install "pyxle-db[postgres]"    # + asyncpg
pip install "pyxle-db[mysql]"       # + asyncmy, cryptography
pip install pyxle-auth              # pulls in pyxle-db
```

Wire them up in `pyxle.config.json` and they handle their own lifecycle at
app startup — see each package's README for the two-line config.

## One repo, independent releases

This is a monorepo by design, because official plugins change together:
when `pyxle-db` grew its `DatabaseLike` protocol, `pyxle-auth`'s
annotations and contract tests landed in the same commit, with one CI run
proving both sides. What stays **independent** is everything release-shaped:

- **Versions** — each package owns its `pyproject.toml` version and its
  own `CHANGELOG.md`. They drift apart as they should.
- **Releases** — tags are per-package: `pyxle-db-v0.3.0` releases
  `pyxle-db` and nothing else. Publishing a GitHub release with that tag
  triggers [`publish.yml`](.github/workflows/publish.yml), which checks
  the tag against the package's declared version, builds just that
  package, and publishes it via PyPI trusted publishing through the
  package's own `pypi-<package>` environment (PyPI pending publishers
  are unique per repo + workflow + environment, so per-package
  environments let every plugin register its own). Upgrading one plugin
  never touches another's PyPI history.
- **Issues** — label with the package name.

CI ([`ci.yml`](.github/workflows/ci.yml)) runs every package's suite on
Python 3.10–3.14 against **real PostgreSQL 16 and MySQL 8 servers** — the
multi-database claims in these packages are enforced, not aspirational. A
job fails if the live suites are ever silently skipped.

## Layout

```
packages/
├── pyxle-db/          # each package is independently installable
│   ├── pyproject.toml #   own version, deps, extras
│   ├── CHANGELOG.md   #   own release history
│   ├── pyxle_db/      #   source (py.typed)
│   └── tests/         #   own suite, incl. live-server conformance tests
└── pyxle-auth/
    └── …same shape
```

## Development

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e "packages/pyxle-db[postgres,mysql,dev]" -e "packages/pyxle-auth[dev]"

# unit + SQLite suites
(cd packages/pyxle-db && pytest)
(cd packages/pyxle-auth && pytest)

# the live-server suites run when these are set (CI always sets them):
export PYXLE_DB_TEST_POSTGRES_URL=postgresql://user:pass@127.0.0.1:5432/pyxle_test
export PYXLE_DB_TEST_MYSQL_URL=mysql://user:pass@127.0.0.1:3306/pyxle_test

ruff check packages/pyxle-db/pyxle_db packages/pyxle-auth/pyxle_auth
```

## Adding a plugin

A new plugin is a new directory under `packages/` — the release machinery
is generic and never needs editing:

1. `packages/pyxle-<name>/` with its own `pyproject.toml` (version `0.1.0`),
   `pyxle_<name>/` source (ship a `py.typed` marker), `tests/`, `README.md`,
   `CHANGELOG.md`, and a copy of `LICENSE`.
2. Depend on `pyxle-framework`, not on sibling plugins — unless the
   dependency is the point and documented (as `pyxle-auth` → `pyxle-db` is).
   If your plugin needs a database, build against the
   `pyxle_db.DatabaseLike` contract rather than a concrete class.
3. Wire your suite into `ci.yml`.
4. Register a PyPI [pending publisher](https://docs.pypi.org/trusted-publishers/)
   for the project: repo `pyxle-dev/pyxle-plugins`, workflow `publish.yml`,
   environment **`pypi-pyxle-<name>`** (per-package environments keep the
   publisher tuples unique — PyPI requires that for pending publishers).
   Then release with a `pyxle-<name>-v0.1.0` tag.

## Security

Vulnerability reports: **security@pyxle.dev** — see [SECURITY.md](SECURITY.md)
for scope and response expectations. Please don't open public issues for
security problems.

## License

[MIT](LICENSE), all packages.
