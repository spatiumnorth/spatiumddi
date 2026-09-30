# Contributing to SpatiumDDI

Thank you for your interest in contributing! SpatiumDDI is an open project and we welcome contributions of all kinds — code, documentation, bug reports, and feature ideas.

## Before You Start

Please read this page before opening a pull request. We would rather tell you
up front how contributions work than have a check surprise you afterwards.
The PR template asks you to confirm you have read it.

- **Sign off your commits.** We use the [Developer Certificate of Origin](#developer-certificate-of-origin-dco):
  add `-s` to `git commit` to certify you have the right to contribute the
  change. No CLA, no account. A required check verifies it on every PR.
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
6. Sign off every commit (`git commit -s`). See
   [Developer Certificate of Origin](#developer-certificate-of-origin-dco)
   below. A required `DCO` check fails the PR if a commit is missing
   its sign-off.

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

## Developer Certificate of Origin (DCO)

This project uses the [Developer Certificate of Origin](https://developercertificate.org/)
(DCO) instead of a CLA. There is nothing to sign and no account to create.
You certify, commit by commit, that you wrote the change or otherwise have the
right to submit it under the project's license, by adding a `Signed-off-by:`
line to each commit message:

```
Signed-off-by: Jane Doe <jane@example.com>
```

`git commit -s` adds it for you from your `user.name` and `user.email`. The
name and email must match the commit's author, since that is what the check
compares. Commits made in the GitHub web UI (including accepted review
suggestions) are signed off automatically.

**Forgot to sign off?** Add it to every commit on your branch and force-push:

```bash
git rebase --signoff main      # or: git commit --amend -s --no-edit (last commit only)
git push --force-with-lease
```

Sign-offs survive the squash merge, because the squash message is built from
your commit messages. The DCO applies from its adoption onward; nothing
already in `main` is rewritten.

> **Note for maintainers:** when re-pushing a fork PR in-repo (see
> [A note on forks](#a-note-on-forks)), keep the contributor's own
> signed-off commits. If you re-author them, add your own sign-off as
> well. DCO clauses (b) and (c) cover passing on work you received.

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

By contributing, you agree that your contributions will be licensed under the Apache 2.0 License. The `Signed-off-by:` line on each commit is how you certify that (see [Developer Certificate of Origin](#developer-certificate-of-origin-dco)).
