### Added

- **A measured sizing guide, `docs/deployment/SIZING.md` (#198).** Memory,
  CPU and disk measured on running appliances: one node and a three-node
  control plane, at rest, under light and realistic load, through
  upgrades and the HA drills, and over a 3-day soak of 1.0.0-beta.1. It
  gives the Minimum and Recommended per deployment shape with the rule
  behind each, adds Docker Compose and Kubernetes measured at rest and under
  light load (amd64, with arm64 beside it), says what is not measured yet
  (the Appliance role on its own, per-pod CPU on the appliance, disk I/O,
  Compose and Kubernetes under realistic load), and shows how to measure
  your own install. The README's Requirements gain a Memory / CPU table.
  - A three-node control plane is now advised 48 GiB disks per node: a
    slot upgrade followed by a rolling upgrade took `/var` on 40 GiB disks
    to the 80% disk warning.
  - Docker Compose's stated minimum rises from 2 GB to 4 GiB (8 GiB
    recommended): on amd64 its containers held 1.3 GiB at rest and at most
    1.65 GiB under light load, and the host with its OS at most 2.2 GiB
    (arm64: 1.6 and 1.9 GiB for the containers).
  - Kubernetes: with the chart's defaults the api autoscaler runs 10
    replicas at rest (one api process, about 300 MiB, is above 80% of its
    256Mi request), which on an 8 GiB node leaves less than 1 GiB free, and
    the worker levels off at or near its 1Gi limit. The docs advise a
    `512Mi` request and `1Gi` limit for the api and `2Gi` for the worker.
