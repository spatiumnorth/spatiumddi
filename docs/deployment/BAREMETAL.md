# Bare-Metal Deployment

> **There are no Ansible playbooks and no systemd-native / `.deb` / `.rpm`
> package install path in this repo today.** A "Bare metal / VM (Ansible)"
> option appears as **📋 Planned** in the [README deployment table](https://github.com/spatiumnorth/spatiumddi/blob/main/README.md#deployment-options),
> but it is not implemented — do not expect playbooks under `ansible/` or
> `playbooks/` (there are none). The single `GET /api/v1/ansible/inventory`
> endpoint in the codebase is an Ansible **dynamic-inventory** source for
> consuming SpatiumDDI data, not an installer.

If you want SpatiumDDI running on a physical machine or a plain VM, you have
two real, supported paths today. Pick by how much of the OS you want to own:

| Path | What you manage | Start here |
|---|---|---|
| **Docker Compose on a host/VM** | Your own OS + Docker; SpatiumDDI runs in containers | [`DOCKER.md`](DOCKER.md) |
| **OS appliance image (true bare-metal-OS install)** | Nothing — boot the image, configure via web UI | [`APPLIANCE.md`](APPLIANCE.md) |

The **OS appliance is the supported bare-metal-OS path**: a bootable Debian 13
image with k3s and the full SpatiumDDI stack pre-baked, installed straight onto
the disk with no prior OS or container-runtime setup.

---

## 1. Docker Compose on a bare-metal host or VM

This is the canonical way to run SpatiumDDI on a machine you already own. Install
Docker Engine + Compose v2 on your host (any Linux distro Docker supports), then
follow the standard Compose guide:

- **[`DOCKER.md`](DOCKER.md)** — prerequisites, port reference, first-time setup
  (`cp .env.example .env`, `docker compose pull`, `docker compose run --rm migrate`,
  `docker compose up -d`), TLS, and password reset.

Everything in that guide applies unchanged on bare metal — the only difference
from a cloud host is that you provide the box. The DNS and DHCP service containers
are opt-in via Compose profiles (`COMPOSE_PROFILES=dns,dhcp docker compose up -d`),
which is useful on bare metal where you may want the host's real NIC bound to a
DHCP server.

---

## 2. HA PostgreSQL (Patroni) under Docker Compose

**Not supported in 1.0.** The repo ships
[`k8s/ha/postgres-docker-compose.yaml`](https://github.com/spatiumnorth/spatiumddi/blob/main/k8s/ha/postgres-docker-compose.yaml),
a Patroni overlay (3 Postgres nodes, 3 etcd nodes and HAProxy) meant to replace the
single `postgres` service. It does not work, and following it on an existing
install is harmful:

- `pg1`–`pg3` have no `command:`, so they run the Postgres image's own entrypoint
  and **Patroni never starts**: three independent standalone databases.
- Its top-level `name: spatiumddi-ha` overrides the project name, so an existing
  install comes up as a **new project on empty volumes**.
- It declares the `spatiumddi` network `external`, but the base stack creates
  `spatiumddi_spatiumddi`, so `up` fails.
- `docker-compose.yml` hardcodes `DATABASE_URL` under `environment:`, which
  overrides `.env`, so pointing `.env` at HAProxy changes nothing.
- It mounts `./haproxy.cfg`, which is not in the repo.

The file carries the same warning in its header and is kept only as a starting
point for [#137](https://github.com/spatiumnorth/spatiumddi/issues/137), which
tracks making Compose HA real. For a highly available database today, use the OS
appliance's multi-node control plane (below) or Kubernetes with CloudNativePG.

**Topology 4 — HA control plane** in [`TOPOLOGIES.md`](TOPOLOGIES.md) describes
the hand-rolled HA shape (HA Postgres + Redis Sentinel + API hosts behind a load
balancer) if you build your own. On the OS appliance, HA PostgreSQL is provided
automatically via CloudNativePG when you promote control-plane members, and you do
not run Patroni there.

---

## 3. OS appliance — the supported bare-metal-OS install

If you want SpatiumDDI to **own the whole machine** (no host OS to maintain, no
Docker to install), use the OS appliance image. It is a bootable Debian 13 image
that installs straight onto bare-metal disk and runs the full stack on embedded
k3s, configured entirely from the web UI and the dedicated `/appliance`
management hub.

- **[`APPLIANCE.md`](APPLIANCE.md)** — image layout, the installer wizard, install
  roles (control plane / appliance agent), atomic A/B slot upgrades, and the
  in-UI management surface (TLS, releases, pods, logs, diagnostics).

Build a local ISO with `make appliance-dev-iso`.

---

## Where to go next

- **[`DOCKER.md`](DOCKER.md)** — the canonical container guide; use it for any
  bare-metal-host-with-Docker deployment.
- **[`APPLIANCE.md`](APPLIANCE.md)** — the supported bare-metal-OS install.
- **[`TOPOLOGIES.md`](TOPOLOGIES.md)** — seven reference production topologies,
  including the hand-rolled HA control plane (Topology 4).
- **[`KUBERNETES.md`](KUBERNETES.md)** — the umbrella Helm chart walkthrough for
  Kubernetes / Helm deployments, backed by [`k8s/README.md`](https://github.com/spatiumnorth/spatiumddi/blob/main/k8s/README.md)
  and the chart's own [`charts/spatiumddi/README.md`](https://github.com/spatiumnorth/spatiumddi/blob/main/charts/spatiumddi/README.md).
