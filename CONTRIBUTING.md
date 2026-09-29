# Contributing to SpatiumDDI

Thank you for your interest in contributing! SpatiumDDI is an open project and we welcome contributions of all kinds — code, documentation, bug reports, and feature ideas.

## Before You Start

- Read the [CLAUDE.md](CLAUDE.md) file — it is the canonical spec for the project and defines all architectural decisions
- Check [open issues](https://github.com/spatiumnorth/spatiumddi/issues) to avoid duplicate work
- For significant changes, open a discussion or issue first so we can align before you invest time coding

## Development Setup

```bash
git clone https://github.com/spatiumnorth/spatiumddi.git
cd spatiumddi
cp .env.example .env
# The api refuses to boot on the placeholder SECRET_KEY (#1222):
# (-i.bak, not -i: BSD sed on macOS takes the next argument as the suffix.)
sed -i.bak "s|^SECRET_KEY=.*|SECRET_KEY=$(openssl rand -hex 32)|" .env && rm .env.bak
docker compose up -d
```

## Code Standards

- Python: `ruff`, `black`, `mypy` — all enforced in CI
- TypeScript: `eslint`, `prettier` — all enforced in CI
- All new API endpoints need tests: success, unauthorized, and validation error cases
- All mutations must write to the audit log before returning a response

## Pull Request Process

1. Fork the repo and create a branch from `main`
2. Make your changes, including tests
3. Run `make ci` locally before pushing — it executes the exact three
   lint jobs GitHub Actions runs (`backend-lint`: ruff + black + mypy;
   `frontend-lint`: eslint + prettier + tsc; `frontend-build`) so you
   catch the same failures locally that would otherwise show up on your
   PR. For the full test run, use `make test` separately (needs a
   dedicated `spatiumddi_test` database).
4. Open a PR using the repository's PR template — it asks for area, test
   plan, and migration notes. Fill those in, don't leave them blank.
5. Link any related issues (`Closes #123`, `Refs #456`).

> **Note for maintainers:** the Contributors table at the bottom of
> [README.md](README.md) is maintained by hand. Add a first-time
> contributor to it as part of merging their PR — nobody's first
> contribution should land unacknowledged.

### A note on forks

Fork PRs currently **cannot** satisfy this repo's required `code_quality`
check: GitHub does not create CodeQL `dynamic` runs for pull requests from
forks, so the gate stays pending indefinitely and the PR is unmergeable
through no fault of the contribution. That is a limitation of the setup,
not a signal about your work — a maintainer will re-push the branch
in-repo and credit you via `Co-Authored-By`. Open the fork PR as normal;
it is still the right way to contribute.

## Reporting Bugs

Use the [GitHub Issues](https://github.com/spatiumnorth/spatiumddi/issues)
tracker — the "Bug report" issue template will prompt you for everything
that's needed (version, deployment method, area, repro steps, logs,
environment details). The "Feature request" template has separate fields
for the problem, the proposed solution, and alternatives considered.

Security vulnerabilities should **not** be filed as issues — please use
[GitHub Security Advisories](https://github.com/spatiumnorth/spatiumddi/security/advisories/new)
for private disclosure.

## License

By contributing, you agree that your contributions will be licensed under the Apache 2.0 License.
