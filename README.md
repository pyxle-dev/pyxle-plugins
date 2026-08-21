# Pyxle Plugins

Official plugins for the [Pyxle](https://pyxle.dev) framework — one repo, independently versioned packages.

[![CI](https://github.com/pyxle-dev/pyxle-plugins/actions/workflows/ci.yml/badge.svg)](https://github.com/pyxle-dev/pyxle-plugins/actions/workflows/ci.yml)
[![pyxle-db on PyPI](https://img.shields.io/pypi/v/pyxle-db?label=pyxle-db)](https://pypi.org/project/pyxle-db/)
[![pyxle-auth on PyPI](https://img.shields.io/pypi/v/pyxle-auth?label=pyxle-auth)](https://pypi.org/project/pyxle-auth/)
[![pyxle-mail on PyPI](https://img.shields.io/pypi/v/pyxle-mail?label=pyxle-mail)](https://pypi.org/project/pyxle-mail/)

## Packages

| Package | What it is | Docs |
|---|---|---|
| [`pyxle-db`](packages/pyxle-db) | One explicit-SQL API over SQLite, PostgreSQL, and MySQL: portable `?` placeholders, a uniform `Row`, checksum-tracked migrations, and the `DatabaseLike` contract other plugins build on. Not an ORM, on purpose. | [pyxle.dev/docs/plugins/pyxle-db](https://pyxle.dev/docs/plugins/pyxle-db) |
| [`pyxle-auth`](packages/pyxle-auth) | Email + password accounts with argon2id, sliding sessions, password-reset / email-verification flows, RBAC with wildcards, scoped API tokens, and request guards. Brings no UI and sends no email — hardened primitives only. | [pyxle.dev/docs/plugins/pyxle-auth](https://pyxle.dev/docs/plugins/pyxle-auth) |
| [`pyxle-mail`](packages/pyxle-mail) | Email through one `mail.service` over SMTP, Resend, or any `MailProvider` contract — swap providers by config, not code. With no configuration it logs instead of sending, so local dev needs zero setup. | [pyxle.dev/docs/plugins/pyxle-mail](https://pyxle.dev/docs/plugins/pyxle-mail) |

```bash
pip install pyxle-db                # SQLite needs nothing else
pip install "pyxle-db[postgres]"    # + asyncpg
pip install "pyxle-db[mysql]"       # + asyncmy, cryptography
pip install pyxle-auth              # pulls in pyxle-db
pip install pyxle-mail              # SMTP + dev "log instead of send"
pip install "pyxle-mail[resend]"    # + Resend HTTP API
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

It runs those suites against **two different framework builds**, because they
answer different questions:

| Job | Framework | Question it answers |
|-----|-----------|---------------------|
| `framework=released` | `pyxle-framework` from PyPI | Do the plugins work against the framework people actually have installed? |
| `framework=source` | `pyxle-dev/pyxle@main`, installed from source | Would the framework release we are about to cut break a plugin? |

Only the first existed until 2026-08. The framework arrived as a transitive
dependency resolved from PyPI, so a fully green plugin CI said nothing about the
framework release being cut that same week — CI that resolves its most important
dependency from a registry is testing yesterday's integration. **If `source` is
red while `released` is green, the framework changed underneath us**: look in
`pyxle-dev/pyxle`, not here.

`framework=source` **blocks on pushes to `main` and on the nightly run**, and is
**advisory on pull requests** — it runs and shows red, but does not fail your
check suite. If you open a pull request and only that job is red, it is not your
change: the framework moved. Pushes and the nightly run already gate the
release, so nothing is missed by letting your PR through.

**A skipped suite is not a passing suite.** The live-backend tests hide behind
*two* masks, and checking for one reports the other as fine:

- **no engine URL** — `PYXLE_DB_TEST_POSTGRES_URL` / `PYXLE_DB_TEST_MYSQL_URL` unset
- **no driver** — `asyncpg` / `asyncmy` not installed (i.e. the `postgres` / `mysql` extras were not installed)

Either one produces a green run with the live suites silently absent. That is
why the "No skipped live suites" job exists and why it fails the build rather
than warning: on 2026-08-18 the driver mask alone was hiding **116 tests** on
`pyxle-db`, while the note we had recorded described only the URL mask.

## Layout

```
packages/
├── pyxle-db/          # each package is independently installable
│   ├── pyproject.toml #   own version, deps, extras
│   ├── CHANGELOG.md   #   own release history
│   ├── pyxle_db/      #   source (py.typed)
│   └── tests/         #   own suite, incl. live-server conformance tests
├── pyxle-auth/
│   └── …same shape
└── pyxle-mail/
    └── …same shape
```

## Development

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e "packages/pyxle-db[sqlalchemy,postgres,mysql,dev]" -e "packages/pyxle-auth[dev]" -e "packages/pyxle-mail[resend,dev]"

# unit + SQLite suites
(cd packages/pyxle-db && pytest)
(cd packages/pyxle-auth && pytest)
(cd packages/pyxle-mail && pytest)

# the live-server suites run when these are set (CI always sets them):
export PYXLE_DB_TEST_POSTGRES_URL=postgresql://user:pass@127.0.0.1:5432/pyxle_test
export PYXLE_DB_TEST_MYSQL_URL=mysql://user:pass@127.0.0.1:3306/pyxle_test

ruff check packages/pyxle-db/pyxle_db packages/pyxle-auth/pyxle_auth
```

### Coverage floors

`pytest` measures branch coverage and **fails below each package's floor**. The
floor lives in that package's `pyproject.toml` under `[tool.coverage.report]`,
next to the reasoning — not in a workflow file, so `pytest` behaves the same on
a laptop as on a runner.

| Package | Floor | Measured when it was set |
|---------|-------|--------------------------|
| `pyxle-db` | 92.0% | 92.0575% |
| `pyxle-auth` | 92.3% | 92.3956% |
| `pyxle-mail` | 95.8% | 95.8435% |

**The floor only moves up.** Raising it — improve coverage, read the new
`TOTAL`, put it in the same change — needs no explanation. Lowering it needs a
reason stated in the pull request; it is not a knob for turning a red build
green.

These sit below the project-wide 95% target on purpose, and **the gap closes in
the first post-launch release**. The 95% figure had been written down for months
without ever being implemented or measured; the numbers above are what is true
and enforced from today. Wiring the fiction in during launch week would only
have bought hurried coverage-chasing tests, which is a worse artifact than an
honest low number with a date on it.

Run without the live database engines and you will land *below* the floor: the
live suites skip and their coverage goes with them (116 tests on `pyxle-db`).
That is the gate telling you the truth — start the engines, or pass `--no-cov`
for a quick single-test loop.

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
