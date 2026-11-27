# SpatiumDDI Roadmap

The live roadmap is the public
[SpatiumDDI project board](https://github.com/orgs/spatiumnorth/projects/2).
Release scope is set with GitHub milestones. Everything planned or under
discussion is an issue labelled `roadmap` (planned) or `idea` (not yet
committed). This page summarises the board; the board is authoritative.

## Current release line

- **1.0.0.** Shipped on 20 November 2026, built from `1.0.0-rc.3`: the
  first stable SemVer release.
- **1.0.1.** In soak (`1.0.1-soak.1` was released on 21 November 2026) and
  shipping next, with the fixes found in 1.0.0, including three PowerDNS
  fixes ([#4564](https://github.com/spatiumnorth/spatiumddi/issues/4564),
  [#4565](https://github.com/spatiumnorth/spatiumddi/issues/4565),
  [#4562](https://github.com/spatiumnorth/spatiumddi/issues/4562)).
  [Milestone 1.0.1](https://github.com/spatiumnorth/spatiumddi/milestone/3).

## Next: 1.1.0

[Milestone 1.1.0](https://github.com/spatiumnorth/spatiumddi/milestone/2).
Highlights include:

- BIND9 feature parity: the settings the audit found missing
  ([#3567](https://github.com/spatiumnorth/spatiumddi/issues/3567)),
  per-primary TSIG and TLS for secondary zones
  ([#3568](https://github.com/spatiumnorth/spatiumddi/issues/3568)),
  per-view recursion and validation options
  ([#3569](https://github.com/spatiumnorth/spatiumddi/issues/3569)),
  notify and query-cache options in the UI
  ([#3572](https://github.com/spatiumnorth/spatiumddi/issues/3572)),
  response rate limiting on by default for public-facing groups
  ([#3577](https://github.com/spatiumnorth/spatiumddi/issues/3577)) and
  catalog-zone hardening
  ([#3578](https://github.com/spatiumnorth/spatiumddi/issues/3578));
- DNS query logs: a View filter
  ([#4170](https://github.com/spatiumnorth/spatiumddi/issues/4170)),
  CSV / JSON export
  ([#4171](https://github.com/spatiumnorth/spatiumddi/issues/4171)),
  clients resolved to host names
  ([#4249](https://github.com/spatiumnorth/spatiumddi/issues/4249)),
  more actions in the query details
  ([#4250](https://github.com/spatiumnorth/spatiumddi/issues/4250)) and
  how each query was answered
  ([#4251](https://github.com/spatiumnorth/spatiumddi/issues/4251));
- DHCPv6 high availability
  ([#1258](https://github.com/spatiumnorth/spatiumddi/issues/1258));
- appliance installer polish: the serial console
  ([#4549](https://github.com/spatiumnorth/spatiumddi/issues/4549)),
  FQDN, search domain and outbound proxy
  ([#4550](https://github.com/spatiumnorth/spatiumddi/issues/4550)) and
  first-install fixes
  ([#4551](https://github.com/spatiumnorth/spatiumddi/issues/4551));
- pool-extension suggestions
  ([#4489](https://github.com/spatiumnorth/spatiumddi/issues/4489)),
  option-43 vendor presets
  ([#4490](https://github.com/spatiumnorth/spatiumddi/issues/4490)),
  API-token usage analytics
  ([#4491](https://github.com/spatiumnorth/spatiumddi/issues/4491)) and
  CIDR holds
  ([#4492](https://github.com/spatiumnorth/spatiumddi/issues/4492)).

## Longer term: 1.2.0

[Milestone 1.2.0](https://github.com/spatiumnorth/spatiumddi/milestone/10).
Highlights include:

- multi-tenancy, phase 1
  ([#4263](https://github.com/spatiumnorth/spatiumddi/issues/4263));
- remote sites: a cloud or remote control plane with on-prem workers
  ([#4256](https://github.com/spatiumnorth/spatiumddi/issues/4256));
- staged changes with an explicit commit
  ([#3550](https://github.com/spatiumnorth/spatiumddi/issues/3550));
- approval workflows for bulk operations, factory reset and imports
  ([#717](https://github.com/spatiumnorth/spatiumddi/issues/717));
- content filtering
  ([#3298](https://github.com/spatiumnorth/spatiumddi/issues/3298));
- Copilot Watch
  ([#4405](https://github.com/spatiumnorth/spatiumddi/issues/4405));
- DNS-over-QUIC on BIND9 and PowerDNS
  ([#2886](https://github.com/spatiumnorth/spatiumddi/issues/2886));
- an optional ClickHouse backend for the query and activity logs
  ([#2186](https://github.com/spatiumnorth/spatiumddi/issues/2186));
- a Home Assistant integration
  ([#2148](https://github.com/spatiumnorth/spatiumddi/issues/2148));
- the rest of the BIND9 parity work: forwarding and serve-stale options
  ([#3570](https://github.com/spatiumnorth/spatiumddi/issues/3570)),
  per-server source and listen addresses
  ([#3571](https://github.com/spatiumnorth/spatiumddi/issues/3571)),
  more DNSSEC policy options
  ([#3573](https://github.com/spatiumnorth/spatiumddi/issues/3573),
  [#3574](https://github.com/spatiumnorth/spatiumddi/issues/3574)),
  per-list RPZ options
  ([#3575](https://github.com/spatiumnorth/spatiumddi/issues/3575)) and
  zone transfer and journal options
  ([#3576](https://github.com/spatiumnorth/spatiumddi/issues/3576));
- a "Decommission host" action
  ([#4493](https://github.com/spatiumnorth/spatiumddi/issues/4493)),
  scheduled emailed reports
  ([#4494](https://github.com/spatiumnorth/spatiumddi/issues/4494)) and
  zone-transfer alerting
  ([#4495](https://github.com/spatiumnorth/spatiumddi/issues/4495)).

Also planned, not yet on a milestone: an official Terraform provider and
Ansible collection
([#693](https://github.com/spatiumnorth/spatiumddi/issues/693)). See
[all open roadmap issues](https://github.com/spatiumnorth/spatiumddi/issues?q=is%3Aopen+label%3Aroadmap).

## Proposing something

Open a feature request with the issue template. Maintainers decide release
scope as described in [`GOVERNANCE.md`](GOVERNANCE.md).

What has already shipped is recorded per release in
[`CHANGELOG.md`](CHANGELOG.md).
