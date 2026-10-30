# Sizing

How much memory, CPU and disk SpatiumDDI needs, measured on running
appliances (amd64), and on Docker Compose and Kubernetes (arm64): the numbers
per deployment shape and load, the Minimum and Recommended they give, what is
not measured yet, and how to measure your own install. The README carries the short table
([Requirements, Memory / CPU](https://github.com/spatiumnorth/spatiumddi#memory--cpu)).

## Minimum and Recommended

| Deployment | Minimum | Recommended | Measured |
|---|---|---|---|
| **Appliance, one node**: control plane with DNS and DHCP | 4 vCPU, 6 GiB RAM, 40 GiB disk | 4 vCPU, 8 GiB RAM, 40 GiB SSD | Yes |
| **Appliance, one node**: control plane only | 4 vCPU, 6 GiB RAM, 40 GiB disk | 4 vCPU, 8 GiB RAM, 40 GiB SSD | Derived from the row above: at this data size the DNS and DHCP pods (BIND, Kea and their agents) held about 0.2 GiB |
| **Appliance, three-node control plane** | first node 4 vCPU / 8 GiB, two more 2 vCPU / 6 GiB, 40 GiB disks | every node 4 vCPU, 8 GiB RAM, 48 GiB SSD | Yes |
| **Appliance role** (a DNS and / or DHCP agent box) | 3 GiB RAM: its pods do not schedule below that | 2 vCPU, 4 GiB RAM, 32 GiB SSD | No |
| **Docker Compose**, one host | 2 vCPU, 4 GiB RAM | 4 vCPU, 8 GiB RAM | Minimum measured (arm64, Docker Desktop): the containers held at most 1.9 GiB, at rest and under light load. Recommended derived: no realistic load or agent profiles on Compose |
| **Kubernetes**, the umbrella chart | one node: 4 vCPU, 6 GiB RAM with the overrides in [Kubernetes](#kubernetes), 8 GiB on the chart's defaults | 4 vCPU, 8 GiB RAM per node, with those overrides | Measured (arm64, Docker Desktop) on one k3s node, at rest and under light load; per pod in [Kubernetes](#kubernetes) |

Give every control-plane node 64 GiB of disk or more for about 1M devices,
and plan for more memory with very large DNS groups (250k records and up).
Both were measured separately; see "Measured floors" and "Data disk for large
installs" in [`APPLIANCE.md`](APPLIANCE.md).

Three things the measurements show:

- **Memory is mostly the stack itself, not the load.** One node at rest used
  3.3 GiB. The busiest suite took it to 4.1 GiB. The same node given 8 GiB
  used the same 4.0 to 4.1 GiB.
- **Disk is set by upgrades.** Each upgrade imports a full set of container
  images onto `/var`, and the appliance keeps the previous release's images
  so a rollback works.
- **The CPU figures are upper bounds.** The appliances ran as nested VMs on
  shared hosts.

## How it was measured

- **What:** SpatiumDDI OS appliances, amd64, as VMs: the nightly builds of 24
  to 28 October 2026, the same builds reached by an upgrade from the previous
  release, three-node clusters installed fresh from each build's ISO,
  development builds of 27 to 29 October, and 1.0.0-beta.1 soaking for 3.3
  days.
- **Sizes:** one node with 4 vCPU and 6 GiB, and the same node with 8 GiB.
  Three-node clusters: a first node with 4 vCPU and 8 GiB, two more with
  2 vCPU and 6 GiB. 40 GiB disks. Every node of the three-node clusters
  served DNS (BIND 9) and DHCP (Kea), except on the soaking 1.0.0-beta.1,
  where the first node alone did.
- **Data:** 14 subnets, 3 forward zones with 21 records plus their reverse
  zones, 5 DHCP scopes with 4 reservations, 16 feature modules on, 2 alert
  rules, and 8 integrations configured but not polling. The realistic load
  adds its own (below).
- **Sampled:** every 15 seconds on every node, from inside the guest:
  `/proc/meminfo`, the resident memory (RSS) of every process summed by
  component, CPU, memory and I/O pressure (`/proc/pressure`, avg10), the
  1-minute load average, and `df` of `/` and `/var`. Once a minute: pod
  restarts, OOM kills and evictions.
- **How much:** 143 time windows. Each run shape on five builds, the steady
  state on five single nodes and three three-node clusters, the soak in 14
  windows. Percentiles are taken over every sample of a shape.

**Used memory** is `MemTotal - MemAvailable`: what the machine cannot hand
back. It is the number to size from. The per-component figures are RSS,
which counts a shared page once in every process that maps it: PostgreSQL's
shared buffers appear once per backend, and the forked worker processes
share most of their pages. Read them for proportion, not as limits.

### Load shapes

| Shape | What ran | Notes |
|---|---|---|
| Steady | Settled stretches with nothing driving the nodes: at least 20 minutes after the last test and 30 minutes after any restart, 22 minutes to 2.6 hours each (7.3 hours on single nodes, 4.3 hours on clusters) | |
| Light: API | Create, read, update and delete of every object type through the REST API, 25 to 63 minutes | Busier than one operator |
| Light: web UI | A browser walking every page and its flows, 44 to 74 minutes | Busier than one operator |
| Protocol and DHCP burst (one node) | DNS on the wire, DHCP leases and dynamic DNS, then 600 devices at 10 DORA a second for 60 seconds, DNS up to 20 queries a second (50 in bursts) | Short and bursty |
| Realistic (three nodes) | 12 more /22 subnets, 8,000 records in one zone, 4,000 devices with 3,000 active leases at a 30-minute lease time, DNS up to 600 queries a second (3,000 in bursts), DHCP up to 6 DORA a second, operator changes at 2 a second (20 in bursts), about 25 minutes | Heavier rates than a typical site, fewer zones, integrations not polling |
| Spikes | A slot upgrade from the previous release, a rolling upgrade of the cluster, and the HA drills: kill the leader, cut a member off, demote, replace a dead node, reboot every node | Harsher than an operator's spike |
| Soak (three nodes) | 1.0.0-beta.1 for 3.3 days: a steady HTTP trickle (63 requests a second on average) with the realistic load for 25 minutes every 6 hours | |

## One node: control plane with DNS and DHCP, 4 vCPU and 6 GiB

MemTotal 5.79 GiB. Each run shape on five builds, the steady state on five
nodes.

| Shape | Used GiB, p50 / p95 / max | Lowest MemAvailable, GiB | Load average, p50 / p95 | CPU pressure %, p50 / p95 |
|---|---|---|---|---|
| Steady | 3.33 / 3.45 / 3.76 | 2.03 | 2.7 / 5.0 | 15 / 21 |
| Light: API | 3.34 / 3.77 / 3.99 | 1.80 | 4.3 / 7.8 | 22 / 31 |
| Light: web UI | 3.73 / 3.87 / 3.98 | 1.81 | 5.9 / 9.7 | 28 / 40 |
| Protocol and DHCP burst | 3.77 / 3.92 / 4.07 | 1.72 | 3.7 / 7.5 | 19 / 32 |
| Slot upgrade from the previous release | 2.62 / 3.02 / 3.40 | 2.40 | 6.0 / 13.5 | 25 / 58 |
| Whole run, upgrade included | 3.47 / 3.85 / 4.13 | 1.67 | 4.6 / 9.7 | 22 / 43 |

No OOM kill, no eviction and no swap to speak of (5 MiB at most), and no pod
restart in the steady, light and protocol shapes. With 8 GiB (MemTotal 7.76
GiB) the same node used at most 4.00 to 4.09 GiB in the light and protocol
shapes.

## Three-node control plane

First node 4 vCPU and 8 GiB (MemTotal 7.76 GiB), two more with 2 vCPU and
6 GiB (MemTotal 5.79 GiB). Each run shape on five builds, the steady state on
three clusters.

| Shape | First node: used GiB, p50 / p95 / max | Other nodes: used GiB, p50 / p95 / max | Lowest MemAvailable, GiB: first / others | CPU pressure % p50: first / others |
|---|---|---|---|---|
| Steady | 3.53 / 4.21 / 4.34 | 3.07 / 3.60 / 3.99 | 3.42 / 1.80 | 36 / 52 |
| Realistic load | 4.07 / 4.24 / 4.40 | 2.90 / 3.22 / 3.33 | 3.36 / 2.47 | 47 / 58 |
| HA drills | 3.20 / 3.94 / 4.44 | 2.99 / 3.47 / 3.77 | 3.32 / 2.03 | 49 / 62 |
| Rolling upgrade | 3.08 / 3.86 / 4.22 | 2.79 / 3.54 / 3.96 | 3.54 / 1.84 | 53 / 73 |
| Installed fresh from the ISO, whole run | 3.20 / 3.98 / 4.24 | 2.26 / 3.26 / 3.54 | 3.52 / 2.25 | 37 / 52 |
| Soak, 3.3 days (DNS and DHCP on the first node only) | 3.09 / 3.31 / 3.50 | 3.30 / 3.65 / 3.87 | 4.26 / 1.92 | 75 / 82 |

No OOM kill and no eviction on any node in any shape. The CPU pressure on
these clusters is mostly the test host's: the three appliances shared six
host cores with the load generator. It is not a product figure.

## Where the memory goes

RSS per component, MiB, p50 / p95. Each column is one node's processes; the
components overlap (see "Used memory" above), so they add up to more than
the node used.

| Component | One node, web UI suite | Three nodes, realistic load: first node | Three nodes, realistic load: another node |
|---|---|---|---|
| api (one uvicorn process) | 652 / 670 | 522 / 854 | 439 / 770 |
| worker and beat (two worker processes) | 981 / 1017 | 934 / 1011 | 739 / 930 |
| PostgreSQL (overcounted) | 1114 / 1409 | 3021 / 3926 | 276 / 300 |
| Redis | 24 / 31 | 36 / 39 | 32 / 39 |
| BIND | 22 / 22 | 32 / 32 | 26 / 27 |
| Kea | 30 / 30 | 35 / 37 | 31 / 31 |
| supervisor with the DNS and DHCP agents | 315 / 331 | 366 / 380 | 330 / 379 |
| k3s | 803 / 820 | 833 / 858 | 635 / 674 |
| containerd and the pods' shims | 524 / 536 | 508 / 549 | 445 / 496 |
| CoreDNS | 67 / 68 | 65 / 66 | 66 / 68 |
| everything else (nginx, the PostgreSQL operator's instance manager, the OS) | 750 / 1357 | 887 / 1508 | 675 / 1328 |

## Disk

`/var` holds what grows: the container images, PostgreSQL, etcd and the
logs. It is what the disk leaves after about 17 GiB of fixed partitions: a
40 GiB disk gives about 23 GiB of `/var`, 48 GiB about 31 GiB, 64 GiB about
47 GiB.

`/var` use as `df` shows it, on 40 GiB disks:

| Shape | `/var` used |
|---|---|
| One node, a whole run without an upgrade | 41 to 53 % |
| One node, slot upgrade from the previous release | 45 % before, 64 to 71 % at the peak, 51 to 63 % after |
| Three nodes installed fresh, whole run | 38 to 64 % |
| Three nodes, a slot upgrade and then a rolling upgrade | 46 to 85 % at the peak, staying near it afterwards. On 3 of 5 runs some node reached 78 % or more |
| Soak, 3.3 days | rose 4 to 8 points per node (about 1 to 2 GiB), not yet level |

The slot upgrade added 4 to 6 GiB to `/var` on one node. The default-on
`appliance_disk_usage` alert warns at 80 % and is critical at 87 %. It
counts the 5 % that ext4 keeps for root as free, so `df` reads a few points
higher: 85 % in `df` is about 81 % to the alert. That is why the three-node
recommendation is 48 GiB. The same 19 GiB is about 63 % of a 48 GiB disk's
`/var`.

## How Minimum and Recommended are set

- **Memory, Minimum:** the smallest VM measured on which every shape ran to
  the end with no OOM kill, no eviction, no swap, and at least 1 GiB of
  MemAvailable at the worst sample (twice the 512 MiB at which the kubelet
  starts evicting pods). Never below the product's own floor: a control
  plane's pods do not schedule below 4 GiB (see
  [`APPLIANCE.md`](APPLIANCE.md)).
- **Memory, Recommended:** the worst used sample times 1.5, plus the growth
  the 3.3-day soak showed (0.64 GiB on its busiest node), rounded up to an
  even number of GiB. One node: 4.13 x 1.5 + 0.64 = 6.8, so 8 GiB. Three
  nodes: 4.44 x 1.5 + 0.64 = 7.3, so 8 GiB on every node. Any node can take
  over the leader and the PostgreSQL primary, and the pod limits are sized
  for the whole control plane from one node's RAM.
- **CPU:** the Minimum is what every shape ran to the end on. The
  Recommended is 4 vCPU per control-plane node: the floor tests of 2026-09
  put the CPU floor at 3 vCPU under 20k active DHCP devices (see
  [`APPLIANCE.md`](APPLIANCE.md)), and the 2 vCPU nodes here waited for CPU
  most of the time (on a shared host, so partly the host's doing).
- **Disk:** the Minimum is the smallest disk measured (40 GiB); every shape
  ran to the end on it. The Recommended is the smallest of 40, 48 and 64 GiB
  on which the worst `/var` sample stays at least 10 points under the 80 %
  warning, as the alert counts.

The installer recommends 8 GiB and 40 GiB for a control plane and warns
below them. The 6 GiB Minimum is below that warning on purpose: it is the
measured floor, not the comfortable size.

## Not measured yet

- **Docker Compose and Kubernetes beyond light load, and on amd64.** Both were
  measured on arm64, at rest and under the light load only (see [Docker
  Compose](#docker-compose) and [Kubernetes](#kubernetes)): no realistic load,
  no DNS or DHCP agents, one Kubernetes node. Each ran for 29 to 47 minutes,
  and the worker was still growing at the end.
- **The Appliance role on its own.** No run installed a DNS-only or
  DHCP-only agent box. On the measured nodes BIND held 15 to 41 MiB and Kea
  30 to 45 MiB at this data size. The rest of such a box is k3s (0.6 to 0.9
  GiB), containerd (0.4 to 0.6 GiB), CoreDNS and the supervisor with its
  agents (0.3 to 0.4 GiB). Its pods need 3 GiB to schedule. The 2 vCPU,
  4 GiB, 32 GiB recommendation stands until it is measured.
- **One node under sustained realistic load** on these builds. The realistic
  load ran on the three-node clusters only. The single-node floor tests of
  2026-09 were heavier (250k records, 20k active devices) and passed at 6 GiB
  and 3 vCPU (see "Measured floors" in [`APPLIANCE.md`](APPLIANCE.md)).
- **CPU per pod on the appliance, and disk I/O rates.** The appliance samples
  carry no per-pod CPU and no disk throughput; their CPU figures are for the
  whole node. Docker Compose and Kubernetes have CPU per container below
  (arm64).
- **Growth past 3.3 days.** On the soak, used memory rose 0.4 to 0.6 GiB per
  node and `/var` 1 to 2 GiB, still rising at the end.
- **Smaller sizes** than the Minimums (5 GiB or 2 vCPU on one node, a
  three-node cluster of 6 GiB nodes only), and **arm64 appliances**.

## Docker Compose and Kubernetes: how they were measured

- **What:** the 2026-10-28 nightly build's published images, arm64, on Docker
  Desktop (Apple silicon, 10 CPUs, 11.7 GiB for its VM). The two shapes ran
  one after the other, never side by side.
- **Light load,** the same for both: the demo seed (`scripts/seed_demo.py`),
  then four clients looping over 29 list pages of the API through the
  frontend (IPAM, DNS, DHCP, VRFs, ASNs, devices, sites, customers, alerts,
  audit, users, dashboards, settings, search), pausing half a second after
  each answer. About 6 requests a second for 10 minutes, every answer a 200.
- **Sampled:** every 15 seconds, at rest after the start, under the light
  load, and at rest again after it. Memory is what `docker stats` and
  `kubectl top` report: the container's memory less its inactive page cache
  (the working set). It counts a page shared by forked processes once, unlike
  RSS. CPU is each container's average over the stretch.
- **arm64:** memory should carry to amd64 within a small margin (the same
  Python, the same libraries, 64-bit on both). CPU does not: these cores are
  faster than the VMs the appliance rows ran on, so read the CPU figures as
  lower bounds.

## Docker Compose

The shipped `docker-compose.yml` with its default services (PostgreSQL,
Redis, the api, one worker with four processes, beat, the frontend; no agent
profiles) and a `.env` made from `.env.example`.

| Container | At rest, MiB p50 | Light load, MiB p50 / max | CPU at rest / light load, millicores |
|---|---|---|---|
| api (one uvicorn process) | 352 | 431 / 435 | 6 / 101 |
| worker (four processes) | 782, rising | 884 / 980 | 28 / 31 |
| beat | 269 | 269 / 270 | 3 / 3 |
| PostgreSQL | 103 | 163 / 164 | 8 / 14 |
| Redis | 77 | 77 / 78 | 5 / 4 |
| frontend (nginx) | 18 | 19 / 20 | 1 / 3 |
| All containers | 1600 | 1843 / 1944 | 50 / 156 |

At rest again after the load the containers held 1960 MiB (1989 at most).
The worker was still growing: 641 MiB a minute after the start, 1021 MiB 28
minutes later, its cgroup at 1084 MiB at the peak. The host's own OS and the
Docker engine come on top. Hence the 4 GiB Minimum: it leaves about 2 GiB for
them and for that growth. The 8 GiB Recommended stays derived: the realistic
load, the DNS and DHCP agent profiles and long runs were not measured on
Compose.

## Kubernetes

The appliance runs the same umbrella chart on k3s, but its supervisor sizes
the api, worker and PostgreSQL limits from the node's RAM (see
[`APPLIANCE.md`](APPLIANCE.md)). On another cluster the chart's defaults in
`values.yaml` apply.

**With the chart's defaults,** measured on one k3s 1.36 node with
metrics-server, installed with `helm install` and only the image tag set.
Working set per pod, as `kubectl top` reports it and as the autoscaler reads
it:

| Pod | Chart default, request / limit | At rest, MiB | Light load, MiB p50 / max | CPU at rest / light load, millicores per pod |
|---|---|---|---|---|
| api (one uvicorn process) | 256Mi / 512Mi | 295 to 305 | 344 / 355 (363 / 366 on 2 replicas) | 4 / 16 (3 / 53 on 2 replicas) |
| worker (four processes) | 256Mi / 1Gi | 774, rising to 966 | 834 / 879 | 31 / 32 |
| beat | 128Mi / 256Mi | 173 | 173 / 177 | 5 / 4 |
| PostgreSQL | 256Mi / 1Gi | 73 | 324 / 387 | 16 / 23 |
| Redis | 64Mi / 512Mi | 16 | 16 / 17 | 6 / 5 |
| frontend (nginx), each of 2 | 64Mi / 128Mi | 9 | 10 / 11 | 0 / 2 |
| CoreDNS, metrics-server, the local-path provisioner | | 59 | 69 | 8 / 7 |

The node (pods, k3s and containerd) used 6.5 GiB at rest after the load with
the defaults, and 3.7 GiB with two api replicas. Three things the defaults
do:

- **The api autoscaler runs 10 replicas at rest.** Its memory target is 80 %
  of a 256Mi request, about 205 MiB, and one api process holds about 300 MiB
  as soon as it has started. It went from 2 to 10 replicas within two
  minutes of the install, with no traffic, and stayed there: memory does not
  fall when replicas are added. The eight extra replicas cost about 2.8 GiB
  and served the light load no faster than two did (#3110). Each holds its
  own database pool: PostgreSQL saw 46 connections under the light load,
  against the measured build's `max_connections` of 100; the chart now sizes
  `max_connections` from the pools and the autoscaler's maximum (#2955).
- **The worker sits at its 1Gi limit.** Its four processes reached the limit
  about 40 minutes after the install, half of them under the light load, and
  the kernel kept it under by reclaiming page cache (no OOM kill in 47
  minutes). On Compose, with no limit, the same worker reached 1084 MiB.
- **The api's 512Mi limit leaves little room.** One api process taking all of
  the light load (on Compose) peaked at 469 MiB. On the appliance it held 0.4
  to 0.85 GiB under the API suite.

Until the chart's defaults change, set:

```yaml
api:
  resources:
    requests: { memory: 512Mi }
    limits:   { memory: 1Gi }
worker:
  resources:
    limits: { memory: 2Gi }
```

With a 512Mi request the autoscaler's memory target is about 410 MiB, above
what each api pod held here at rest and under the light load (366 MiB at
most, on two replicas). Or set
`api.autoscaling.enabled: false` and `api.replicas` to the count you want.
Once the autoscaler has scaled the api, `helm upgrade` with Helm 4 stops on a
conflict over the Deployment's `replicas` until you add `--force-conflicts`
(#3111).

**Measured on the appliance,** RSS in MiB across every shape:

| Pod | Chart default, request / limit | Measured on the appliance |
|---|---|---|
| api (one uvicorn process) | 256Mi / 512Mi | 380 to 710 at p50, up to 854 at p95, 1276 in one sample |
| worker | 256Mi / 1Gi, four processes | worker and beat together: 600 to 1017 at p50, up to 1106 at p95, with two worker processes |
| beat | 128Mi / 256Mi | (with the worker above) |
| PostgreSQL | 256Mi / 1Gi | not readable from RSS (shared buffers count once per backend). The appliance gives it 1.3 GiB or more |
| Redis | 64Mi / 512Mi | 23 to 70 at p50 |

The api's resident memory there was above the default 512Mi limit in nearly
every shape, hence the `1Gi` above. Instead of a `2Gi` worker you can run two
worker processes (`worker.concurrency: 2`), as the appliance does on nodes of
12 GiB or less. Per node, plan as for the appliance: its figures include k3s
itself (0.6 to 0.9 GiB; 0.55 GiB for the k3s server on the arm64 node).

## Measure your own install

Sample every 15 seconds or so through each kind of use you have (a quiet
night, a working day, your busiest hour, an upgrade) and keep the maximum.

**On the appliance** the web UI shows it live: **Appliance → Cluster →
Overview** has memory and CPU per node and the top pods by use, from the
kubelet's own stats. From a shell on a node:

```bash
grep -E '^(MemTotal|MemAvailable):' /proc/meminfo   # used = MemTotal - MemAvailable
cat /proc/pressure/cpu /proc/pressure/memory         # "some avg10": % of the last 10 s something waited
cat /proc/loadavg
df -h /var
ps -eo rss,comm --sort=-rss | head -20               # the largest processes, RSS in KiB
kubectl get nodes                                    # then, per node:
kubectl get --raw "/api/v1/nodes/<node>/proxy/stats/summary"   # per-pod CPU and memory
```

The appliance runs no metrics-server, so `kubectl top` does not work there.

**Docker Compose:** `docker stats --no-stream` gives each container's memory
and CPU. Its CPU is a sample of a second or two, which misses the worker's
short tasks; for an average, read `usage_usec` from
`/sys/fs/cgroup/cpu.stat` inside the container twice and divide by the time
between. Read `/proc` on the host as above.

**Kubernetes:** `kubectl top pod -n <namespace>` and `kubectl top node`.
Both need metrics-server, which the api's autoscaler needs too.

Then size from the largest used-memory sample: times 1.5, plus room for
growth, and keep at least 1 GiB of MemAvailable at the worst moment.
