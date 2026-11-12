# SpatiumDDI Governance

This document describes how SpatiumDDI is run: who makes decisions, how
they are made, and how people move into project roles.

## Values

- **Open by default.** Design discussion, issues, roadmap and review happen
  in public on GitHub. The exception is security reports, which follow
  [`SECURITY.md`](SECURITY.md).
- **Operators first.** SpatiumDDI runs the DNS, DHCP and IPAM that whole
  networks depend on, so correctness, upgrade safety and privacy
  ([`docs/PRIVACY.md`](docs/PRIVACY.md): no telemetry, ever) come before
  new features.
- **Vendor neutral.** The project is open to contributions and maintainers
  from any organisation. No single company's interests override the
  project's.

## Roles

### Users

Anyone who runs SpatiumDDI. Users shape the project by filing issues, taking
part in discussions and adding themselves to [`ADOPTERS.md`](ADOPTERS.md).

### Contributors

Anyone who contributes code, documentation, tests, translations, reviews,
triage or testing. Contributions follow [`CONTRIBUTING.md`](CONTRIBUTING.md),
and every commit carries a DCO sign-off.

### Maintainers

Maintainers are listed in [`MAINTAINERS.md`](MAINTAINERS.md). They:

- review and merge pull requests;
- triage issues and set release scope (milestones and priority);
- cut releases;
- handle security reports under [`SECURITY.md`](SECURITY.md);
- enforce the [Code of Conduct](CODE_OF_CONDUCT.md).

A maintainer may hold an area (for example DNS, DHCP, the appliance, or the
Helm chart). That area is recorded in `MAINTAINERS.md`.

### Becoming a maintainer

A contributor can be nominated by any maintainer after sustained,
high-quality contribution. That usually means several months of merged
work, reviews or triage, and showing judgement on correctness, upgrade
safety and the project's non-negotiables. The nomination is a pull request
to `MAINTAINERS.md`. It is accepted with the approval of a majority of the
current maintainers and no objection from any of them in the following
seven days.

### Stepping down and emeritus status

A maintainer may step down at any time by opening a pull request against
`MAINTAINERS.md`. A maintainer with no project activity for six months may
be moved to emeritus status by a majority of the other maintainers, after
being asked first. Emeritus maintainers keep their recognition and can
return through the normal nomination process.

A maintainer can be removed for a Code of Conduct violation, or other
conduct harmful to the project, by a two-thirds vote of the other
maintainers.

## Decision making

Most decisions are made by **lazy consensus** on the relevant issue or pull
request. A proposal stands unless a maintainer objects, and an objection
must give its reasons and, where possible, an alternative.

When consensus cannot be reached, any maintainer may call a vote on the
issue. A vote passes with a simple majority of all maintainers, except
where this document asks for more. Votes stay open for at least seven days,
or until every maintainer has voted.

These decisions require a vote by a two-thirds majority of maintainers:

- changes to this document;
- adding or removing a maintainer for cause;
- changing the license or the project's non-negotiables (no telemetry,
  API-first, server-side permissions, the audit log);
- donating, transferring or renaming the project.

## Conflicts of interest

Maintainers act in the interest of the project, not their employer. A
maintainer with a conflict on a decision (for example a change that mainly
benefits their employer's product) discloses it and may abstain.

The project wants maintainers from more than one organisation. Once
maintainers from other organisations join, no single organisation may hold
more than half of the maintainer seats. If a departure leaves one
organisation over that limit, its maintainers vote as a single bloc until
the balance is restored.

## Releases and roadmap

The release process is in [`CONTRIBUTING.md`](CONTRIBUTING.md) and
`.github/workflows/release.yml`. Release scope is set by maintainers on the
public [project board](https://github.com/orgs/spatiumnorth/projects/2), and
the roadmap is summarised in [`ROADMAP.md`](ROADMAP.md).

## Code of Conduct

SpatiumDDI follows the [CNCF Code of Conduct](CODE_OF_CONDUCT.md).

## Changes to this document

Changes are proposed as a pull request, and need the two-thirds maintainer
vote described above.
