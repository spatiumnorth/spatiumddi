# spatiumddi-appliance

Helm chart that reconciles the SpatiumDDI **appliance's local k3s
cluster** to the operator's role assignment.

Issued in [issue #183](https://github.com/spatiumnorth/spatiumddi/issues/183)
Phase 2. Phase 1 baked k3s into the slot image; Phase 2 ships this
chart; Phase 3 wires the supervisor as the CRD reconciler that
turns operator role assignments on the control plane into Helm
releases.

## Status

**Phase 2 scaffold — not yet wired to the supervisor.**

The chart structure is stable + lint-clean. Templates render but
the supervisor still runs via docker-compose on the appliance host;
flipping `<role>.enabled: true` does nothing useful until Phase 3
lands.

## Architecture

This chart is **not** a control-plane install — that's
[`charts/spatiumddi/`](../spatiumddi/). This chart targets the
appliance's *local* k3s, deploying the per-role service workloads:

- `dnsBind9` — Deployment + Service. BIND9 authoritative DNS.
- `dnsPowerdns` — Deployment + Service. PowerDNS alternative.
- `dnsTechnitium` — Deployment + Service. Technitium alternative.
- `dhcpKea` — DaemonSet with `hostNetwork: true`. Kea DHCPv4/v6.
- `lookingGlass` — DaemonSet with `hostNetwork: true`. Receive-only
  BGP collector (GoBGP, issue #566) — see
  `docs/features/LOOKING_GLASS.md`.
- `supervisor` — DaemonSet, privileged. The reconciler itself.

Each role is gated on a `<role>.enabled` flag. Mutual exclusion
across the three DNS engines (bind9 / powerdns / technitium) is
enforced upstream by the supervisor's CRD reconciler — at the chart
level all three blocks can render side-by-side if values.yaml says so.

## Air-gap defaults

- `global.imagePullPolicy: Never` everywhere. All container images
  are imported by k3s from `/var/lib/rancher/k3s/agent/images/*.tar.zst`
  into containerd when it starts. No registry lookups at runtime.
- `global.imageTag` defaults to the slot's `SPATIUMDDI_VERSION`
  stamp; the supervisor rewrites it on apply.

## Resource requests

Every workload here carries a CPU + memory **request** and no CPU
limit. The requests are QoS floors rather than measurements: without
one a pod is BestEffort, which is the lowest CFS weight on the node,
and on a 3 vCPU appliance under a device rush the api starved Kea
down to 7.5 % of a CPU — only 37 % of the DISCOVERs on the wire were
answered, while Kea answered 100 % of what reached it. With
`dhcpKea.resources.requests.cpu` in place the same cell measured
95.6 % handshake success. A CPU *limit* would throttle exactly the
bursts the data plane exists to serve, so none is set.

| Values key | Default request |
|---|---|
| `dhcpKea.resources` | `500m` CPU / `128Mi` |
| `dnsBind9.resources` / `dnsTechnitium.resources` | `250m` CPU / `256Mi` (BIND's memory limit + request come from `dnsBind9.memory`, which the supervisor sizes from node RAM: a quarter of the smallest DNS node, 2Gi to 8Gi, request an eighth of it, #1725 / #2223; a memory value in `dnsBind9.resources` overrides it) |
| `dnsPowerdns.resources` | `250m` CPU / `128Mi` |
| `supervisor.resources` | `50m` CPU / `128Mi` |
| `lookingGlass.resources` | `50m` CPU / `128Mi` |
| `agentLanding.resources` | `10m` CPU / `16Mi` |

The supervisor's values map does not touch these keys, so the chart
defaults apply on the appliance; BYO installs can tune or clear them.

## Local linting

```bash
make charts-lint
```

Runs the same gate CI's **Charts — Lint & Template** job runs, in a
helm container: `helm lint` + `helm template` over every value set
(including the CloudNativePG + Redis Sentinel HA shape),
`kubeconform -strict`, a no-BestEffort check on every render, and a
toggle-coverage check that fails when a template is gated on a values
key no render flips. Renders land in `.charts-render/`.

For a single ad-hoc render:

```bash
helm template demo charts/spatiumddi-appliance/ \
     --set dnsBind9.enabled=true \
     --set dhcpKea.enabled=true
```
