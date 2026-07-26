# Security Policy

## Supported versions

Only the latest released version of each package receives security fixes.
All packages are pre-1.0: we fix forward rather than backporting.

| Package      | Supported          |
| ------------ | ------------------ |
| `pyxle-db`   | latest release     |
| `pyxle-auth` | latest release     |
| `pyxle-mail` | latest release     |

## Reporting a vulnerability

**Please do not open a public issue for security reports.**

Report privately through either channel:

- **GitHub private advisory (preferred):** [Report a vulnerability](https://github.com/pyxle-dev/pyxle-plugins/security/advisories/new) — this opens a private thread with the maintainers.
- **Email:** **security@pyxle.dev**

Please include:

- The affected package and version.
- A description of the issue and its impact.
- Steps to reproduce (a minimal proof of concept helps a lot).

You will get an acknowledgement within 72 hours. We aim to ship a fix and
publish an advisory within 14 days for confirmed issues; we will keep you
updated and credit you in the advisory unless you ask otherwise.

## Scope notes

- `pyxle-auth` stores argon2id password hashes, sha256-hashed session and
  API tokens, and enforces strict-mode floors on argon2 parameters. Reports
  about weakening of any of those defaults are in scope.
- `pyxle-db` executes caller-supplied SQL by design. SQL injection in
  *application* code that interpolates strings instead of using `?`
  placeholders is out of scope; placeholder-translation bugs that *break*
  parameterization are very much in scope.
- Timing side channels on authentication paths (sign-in, password reset,
  token resolution) are in scope — these paths are written to be
  timing-neutral.
