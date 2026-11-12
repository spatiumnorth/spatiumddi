# SpatiumDDI Roadmap

The live roadmap is the public
[SpatiumDDI project board](https://github.com/orgs/spatiumnorth/projects/2).
Release scope is set with GitHub milestones. Everything planned or under
discussion is an issue labelled `roadmap` (planned) or `idea` (not yet
committed). This page summarises the board; the board is authoritative.

## Current release line

- **1.0.0.** Release candidates are being tested. The ship criteria are in
  [#1181](https://github.com/spatiumnorth/spatiumddi/issues/1181).
  Release-blocking fixes go on the current `1.0.0-rc.N` milestone.
- **1.0.1.** The first patch release, for P2 and P3 fixes found during the
  release candidates.

## Next: 1.1.0

[Milestone 1.1.0](https://github.com/spatiumnorth/spatiumddi/milestone/2).
Highlights include:

- OpenShift / OKD support for the Helm chart
  ([#3852](https://github.com/spatiumnorth/spatiumddi/issues/3852));
- DNS-over-QUIC on BIND9 and PowerDNS
  ([#2886](https://github.com/spatiumnorth/spatiumddi/issues/2886)).

## Longer term

Open `roadmap` issues, by area, include multi-tenancy, Terraform and
Ansible providers, more integrations (pfSense, MikroTik, load balancers),
capacity forecasting, approval workflows for bulk operations, config
snapshots with rollback, and a `spddi` CLI. See
[all open roadmap issues](https://github.com/spatiumnorth/spatiumddi/issues?q=is%3Aopen+label%3Aroadmap).

## Proposing something

Open a feature request with the issue template. Maintainers decide release
scope as described in [`GOVERNANCE.md`](GOVERNANCE.md).

What has already shipped is recorded per release in
[`CHANGELOG.md`](CHANGELOG.md).
