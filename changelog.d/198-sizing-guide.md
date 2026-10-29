### Added

- **A measured sizing guide, `docs/deployment/SIZING.md` (#198).** Memory,
  CPU and disk measured on running appliances: one node and a three-node
  control plane, at rest, under light and realistic load, through
  upgrades and the HA drills, and over a 3-day soak of 1.0.0-beta.1. It
  gives the Minimum and Recommended per deployment shape with the rule
  behind each, says what is not measured yet (Docker Compose, Kubernetes,
  the Appliance role on its own, per-pod CPU, disk I/O), and shows how to
  measure your own install. The README's Requirements gain a Memory / CPU
  table.
  - A three-node control plane is now advised 48 GiB disks per node: a
    slot upgrade followed by a rolling upgrade took `/var` on 40 GiB disks
    to the 80% disk warning.
  - Docker Compose's stated minimum rises from 2 GB to 4 GiB (8 GiB
    recommended), derived from the same containers on the appliance and
    marked as not yet measured on Compose.
  - Kubernetes: the api process held 0.4 to 0.85 GiB on the appliance,
    above the chart's default 512Mi limit, so the docs advise `1Gi` or
    more.
