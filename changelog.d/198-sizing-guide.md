### Added

- **A measured sizing guide, `docs/deployment/SIZING.md` (#198).** Memory,
  CPU and disk measured on running appliances: one node and a three-node
  control plane, at rest, under light and realistic load, through
  upgrades and the HA drills, and over a 3-day soak of 1.0.0-beta.1. It
  gives the Minimum and Recommended per deployment shape with the rule
  behind each, adds Docker Compose and Kubernetes measured at rest and under
  light load (arm64), says what is not measured yet (the Appliance role on
  its own, per-pod CPU on the appliance, disk I/O, amd64 Compose and
  Kubernetes), and shows how to measure your own install. The README's
  Requirements gain a Memory / CPU table.
  - A three-node control plane is now advised 48 GiB disks per node: a
    slot upgrade followed by a rolling upgrade took `/var` on 40 GiB disks
    to the 80% disk warning.
  - Docker Compose's stated minimum rises from 2 GB to 4 GiB (8 GiB
    recommended): its containers held 1.6 GiB at rest and at most 1.9 GiB
    under light load, and the worker kept growing.
  - Kubernetes: with the chart's defaults the api autoscaler runs 10
    replicas at rest (one api process, about 300 MiB, is above 80% of its
    256Mi request), and the worker sits at its 1Gi limit. The docs advise a
    `512Mi` request and `1Gi` limit for the api and `2Gi` for the worker.
