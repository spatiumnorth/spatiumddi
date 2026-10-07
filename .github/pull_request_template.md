<!--
Thanks for contributing to SpatiumDDI!

Title format: `<type>(<scope>): <short summary>`
  types: feat, fix, docs, refactor, perf, test, build, ci, chore
  scope: ipam, dns, dhcp, auth, rbac, audit, alerts, backup, ui, api, ops,
         logging, k8s, charts, compose, appliance,
         agent-dns, agent-dhcp, agent-supervisor

PRs are squash-merged and the squash message is built from your commit
messages, so write those for the permanent history.

See CLAUDE.md + docs/DEVELOPMENT.md for conventions.
-->

## Before you open this PR

Thanks for taking the time to contribute. So that nothing comes as a
surprise, we ask everyone to read [CONTRIBUTING.md](https://github.com/spatiumnorth/spatiumddi/blob/main/CONTRIBUTING.md) first. It is
short, and it explains how we review and merge.

- [ ] I have read [CONTRIBUTING.md](https://github.com/spatiumnorth/spatiumddi/blob/main/CONTRIBUTING.md)
- [ ] Every commit is signed off (`git commit -s`) under the [Developer Certificate of Origin](https://github.com/spatiumnorth/spatiumddi/blob/main/CONTRIBUTING.md#developer-certificate-of-origin-dco)

## Summary

<!-- What does this PR change and why? -->

## Area

<!-- Check all that apply -->

- [ ] IPAM
- [ ] DNS
- [ ] DHCP
- [ ] Discovery
- [ ] Auth / Providers
- [ ] Permissions / RBAC
- [ ] Alerts / notifications / audit forwarding
- [ ] Audit log / observability
- [ ] Backup / restore
- [ ] Reporting / dashboards
- [ ] Integrations
- [ ] Operator Copilot / MCP
- [ ] Appliance (OS, install, upgrade, Fleet)
- [ ] Deployment (Compose / Helm / manifests)
- [ ] Frontend / UI
- [ ] API
- [ ] Docs

## Screenshots / API examples

<!-- UI changes: before/after screenshots. API changes: example request + response. -->

## Test plan

<!--
What did you run to verify this works? CI runs the full backend suite, so
locally run the tests for the code you touched rather than everything. The
full local suite starts one worker per CPU and can exhaust memory on a small
machine, and the failures then look like unrelated fixture errors.
-->

- [ ] `make ci` passes (lint, type check, frontend build, chart render)
- [ ] Ran the relevant tests, e.g. `make test-one T=tests/test_foo.py` (list them below)
- [ ] Manually verified in the UI / via curl (describe below)
- [ ] New/changed behavior is covered by a test

## Security

- [ ] This touches authentication, permissions, secrets / crypto, or an unauthenticated route (it gets a closer security review)

## Project checklist

<!-- Tick what applies; leave the rest. Most of these also fail CI when missed. -->

- [ ] `CHANGELOG.md` entry under `## Unreleased`
- [ ] Alembic migration included (DB models changed). Its `down_revision` is the current head; re-point it if another migration merges first
- [ ] `charts/` and `k8s/` (+ `k8s/README.md`) updated (services, env or ports changed)
- [ ] `NOTICE` + `docs/THIRD_PARTY.md` updated (new shipped third-party component)
- [ ] `versions.json` updated (new or changed version pin)
- [ ] `docs/PRIVACY.md` updated (new outbound network connection)
- [ ] MCP tools added for the new REST surface, with an explicit default-enabled decision
- [ ] Feature-module gating considered (new top-level surface)
- [ ] Breaking change — users must take action to upgrade (describe it below)

## AI assistance

<!-- Optional. If an AI tool wrote a meaningful part of this PR, say which and what you checked yourself. -->

## Related issues

<!-- One keyword per issue, or only the first one closes: "Closes #123, Closes #124". Use "Refs #456" for related work. -->
