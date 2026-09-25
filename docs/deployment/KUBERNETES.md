# Kubernetes Deployment

> SpatiumDDI ships an umbrella Helm chart (`charts/spatiumddi`) that stands up
> the entire control plane — API, frontend, Celery worker, Celery beat, the
> Alembic migrate Job, plus in-chart PostgreSQL and Redis — and can optionally
> deploy managed DNS (BIND9 / PowerDNS / Technitium) and DHCP (Kea) agent StatefulSets
> alongside it. This page is the operator-facing walkthrough; the two
> reference docs it leans on are
> [`charts/spatiumddi/README.md`](https://github.com/spatiumnorth/spatiumddi/blob/main/charts/spatiumddi/README.md) (full
> values surface) and [`k8s/README.md`](https://github.com/spatiumnorth/spatiumddi/blob/main/k8s/README.md) (raw manifests +
> HA prototypes). Read those for the exhaustive option tables — this page
> avoids duplicating them.

> **Picking a deployment shape?** See
> [`TOPOLOGIES.md`](TOPOLOGIES.md) for reference production topologies with
> sizing notes (single VM through HA cloud + on-prem hybrid). For the
> self-contained OS appliance — which runs a k3s cluster under the hood and
> packages its own umbrella chart variant — see
> [`APPLIANCE.md`](APPLIANCE.md).

---

## 1. What the chart deploys

The umbrella chart is a single self-contained `application` chart — it has
**no subchart dependencies**. PostgreSQL and Redis ship as plain
`StatefulSet` + `Service` templates owned by the chart, using the official
`postgres:16-alpine` and `redis:8.10.1-alpine` images (the same ones
`docker-compose.yml` uses). The Bitnami subcharts the chart used historically
were dropped after Bitnami pruned its public Docker Hub namespace in late 2025;
the rationale is in [`Chart.yaml`](https://github.com/spatiumnorth/spatiumddi/blob/main/charts/spatiumddi/Chart.yaml).

| Workload | Kind | Default replicas | Notes |
|---|---|---|---|
| `api` | Deployment | 2 | FastAPI control plane; HPA-eligible (§5) |
| `frontend` | Deployment | 2 | nginx + Vite build; proxies `/api/` to the api Service |
| `worker` | Deployment | 2 | Celery queues `ipam,dns,dhcp,default,bundles` (a BYO `worker.queues` override must add `bundles`) |
| `beat` | Deployment | 1 (`Recreate`) | Singleton scheduler — never run >1 |
| `migrate` | Job | per Helm revision | `alembic upgrade head`; gates the rest (§4) |
| `postgresql` | StatefulSet / CNPG `Cluster` | 1 / 3 | `kind: standalone` or `cnpg` (§6) |
| `redis` | StatefulSet | 1 / 3 | `kind: standalone` or `sentinel` (§6) |

The chart is published as an OCI artifact to
`oci://ghcr.io/spatiumnorth/charts/spatiumddi`. Chart versions track the
SpatiumDDI CalVer release tag with leading zeroes stripped so it's a valid
SemVer 2 identifier (tag `2026.04.20-1` → chart version `2026.4.20-1`).

### Prerequisites

- Kubernetes 1.31+
- Helm 3.8+ (required for OCI registry support)
- A `StorageClass` supporting `ReadWriteOnce` (Postgres, Redis, and agent
  state all use PVCs)
- An Ingress controller or `LoadBalancer` for external access (optional —
  you can `port-forward` for a quick look)

---

## 2. Install

```bash
# Default install — all-in-one with bundled standalone Postgres + Redis
helm install ddi oci://ghcr.io/spatiumnorth/charts/spatiumddi \
  --version <CHART_VERSION> \
  --namespace spatiumddi --create-namespace
```

Default login: **`admin` / `admin`** (a forced password change happens on
first login). The `NOTES.txt` printed after install tells you how to reach the
frontend, retrieve the generated `SECRET_KEY`, and read the Postgres password.

On first install the chart generates and persists an application `SECRET_KEY`
(the Fernet key for at-rest encryption of auth-provider secrets, session
tokens, etc.) into a chart-owned Secret, preserved across upgrades via a
`lookup`. To consolidate secret management, set `auth.existingSecret` to a
Secret carrying key `secret-key`, or pin `auth.secretKey` directly.

> **`helm template` and fresh installs under a new release name generate a new
> `SECRET_KEY`.** Always `helm install` / `helm upgrade` against the same
> release name, or pre-create the Secret and set `auth.existingSecret` — see
> the chart README's
> [Troubleshooting](https://github.com/spatiumnorth/spatiumddi/blob/main/charts/spatiumddi/README.md#troubleshooting) section.

### Exposing the UI

Two options — an Ingress, or flipping the frontend Service to `LoadBalancer`.
The frontend Pod's embedded nginx proxies `/api/` (plus `/health` and
`/metrics`) to the api Service, so a single entry point fronts both the UI and
the API — the same shape as Docker Compose.

```yaml
# values.yaml — Ingress
ingress:
  enabled: true
  className: nginx
  hosts:
    - host: ddi.example.com
      paths:
        - { path: /, pathType: Prefix }
  tls:
    - secretName: ddi-tls
      hosts: [ddi.example.com]
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
```

```yaml
# values.yaml — LoadBalancer (no Ingress)
frontend:
  service:
    type: LoadBalancer
```

The Ingress template routes every host path to the `<release>-frontend`
Service. For TLS via Ingress, install [cert-manager](https://cert-manager.io/),
create a `ClusterIssuer`, and reference it through `ingress.annotations` +
`ingress.tls` as above.

The nginx-proxy upstream defaults to this release's api Service
(`{{ fullname }}-api` on `api.service.port`, i.e. `8000`); the cluster DNS
resolver is auto-detected from `/etc/resolv.conf` at container start. Override
`frontend.apiUpstream.{host,port}` and `frontend.nginxLocalResolvers` only for
non-default topologies (separate namespace, custom api Service name, or a
pinned external resolver). Full details:
[chart README → Exposing the UI](https://github.com/spatiumnorth/spatiumddi/blob/main/charts/spatiumddi/README.md#exposing-the-ui).

### External Postgres / Redis

To skip the in-chart database or cache and point at an existing one:

```yaml
postgresql:
  enabled: false
externalDatabase:
  host: pg.internal
  port: 5432
  username: spatiumddi
  database: spatiumddi
  existingSecret: my-db-secret        # must carry key `password`
  existingSecretPasswordKey: password

redis:
  enabled: false
externalRedis:
  host: redis.internal
  port: 6379
  existingSecret: my-redis-secret     # optional; omit for unauthenticated redis
```

---

## 3. Managed DNS / DHCP agents

The chart can optionally stand up one StatefulSet (+ Service) per managed DNS
or DHCP server, alongside the control plane. These are **off by default** —
most real deployments run agents in a separate cluster closer to the network
edge, or as standalone containers (see
[`DOCKER.md` → Distributed Agent Deployments](DOCKER.md#10-distributed-agent-deployments)).

```yaml
dnsAgents:
  enabled: true
  agentKey:
    existingSecret: spatium-dns-agent-key   # must carry key DNS_AGENT_KEY
  servers:
    # BIND9 (default flavor — RPZ blocklists, full views support)
    - name: ns1
      role: primary
      group: internal-resolvers
      service: { type: LoadBalancer }
    # PowerDNS (issue #127 — ALIAS, LUA, online DNSSEC, catalog zones).
    # Lives in its own group: the control plane rejects mixed-driver
    # groups for those PowerDNS-only features.
    - name: pdns1
      flavor: powerdns
      role: primary
      group: powerdns-edge
      service: { type: LoadBalancer }
    # Technitium (issue #746 — native DoT / DoH / DoQ with no sidecar,
    # encrypted upstream forwarding, online DNSSEC, catalog zones both
    # ways). Also its own group, same single-driver rule.
    - name: tech1
      flavor: technitium
      role: primary
      group: technitium-edge
      service: { type: LoadBalancer }

dhcpAgents:
  enabled: true
  agentKey:
    existingSecret: spatium-dhcp-agent-key  # must carry key SPATIUM_AGENT_KEY
  servers:
    - name: dhcp1
      role: primary
      hostNetwork: true   # required for real DHCPv4 unless relay-only
```

Pre-create the bootstrap PSK Secrets (or use `agentKey.value` inline for lab
use only):

```bash
kubectl -n spatiumddi create secret generic spatium-dns-agent-key \
  --from-literal=DNS_AGENT_KEY="$(openssl rand -hex 32)"
kubectl -n spatiumddi create secret generic spatium-dhcp-agent-key \
  --from-literal=SPATIUM_AGENT_KEY="$(openssl rand -hex 32)"
```

Each server entry renders a StatefulSet + a Service (default type
`LoadBalancer` for DNS). The image is selected by `flavor`: the default
`dnsAgents.image` configures BIND9; `flavor: powerdns` pulls
`ghcr.io/spatiumnorth/dns-powerdns` and switches the state-volume mount path to
`/var/lib/powerdns` for the LMDB store; `flavor: technitium` pulls
`ghcr.io/spatiumnorth/dns-technitium` and mounts it at `/etc/dns`, where
Technitium keeps its own config + zone store. The agent reads `CONTROL_PLANE_URL`
(set by the chart to the in-cluster api Service), exchanges its PSK for a
rotating JWT, and long-polls the config bundle — the full bootstrap +
registration flow is in [`DNS_AGENT.md`](DNS_AGENT.md) and summarised in
[`k8s/README.md` → How servers register](https://github.com/spatiumnorth/spatiumddi/blob/main/k8s/README.md#how-servers-register).

> **DHCPv4 needs broadcast reception on the client LAN.** Run the pod with
> `hostNetwork: true`, or front it with a DHCP relay (option 82). The static
> manifests under `k8s/dhcp/` expose UDP/67 via `NodePort` for lab use only.

Per-server entry fields (`name`, `role`, `group`, `storage.*`, `service.type`,
`hostNetwork`, `resources`) are documented in the
[chart README → Agents](https://github.com/spatiumnorth/spatiumddi/blob/main/charts/spatiumddi/README.md#agents) table.

---

## 4. Migrations

`migrate.enabled` (default `true`) renders a **regular Job** named per Helm
revision (`<release>-migrate-r<revision>`), not a Helm hook. The earlier
hook-based design raced resource creation; as a plain Job the migrate pod lands
in normal apply order, blocks on a `wait-for-postgres` init container until
Postgres accepts connections, then runs `alembic upgrade head`. The
`api`, `worker`, and `beat` pods each carry a matching `wait-for-migrate` init
container so they don't roll out before the schema lands. Completed Jobs
self-clean via `ttlSecondsAfterFinished` (default 600 s). The full rationale is
in the [migrate-job template](https://github.com/spatiumnorth/spatiumddi/blob/main/charts/spatiumddi/templates/migrate-job.yaml)
header.

Alembic is idempotent, so re-running the migrate Job is always safe.

---

## 5. Replicas, resources, and autoscaling

Every workload has `resources.requests`/`limits` defaults in
[`values.yaml`](https://github.com/spatiumnorth/spatiumddi/blob/main/charts/spatiumddi/values.yaml) (see the per-workload
blocks) and a per-component `nodeSelector` / `tolerations` / `affinity` /
`podAnnotations`. Override them under the matching key.

The **api Deployment has a HorizontalPodAutoscaler** (`autoscaling/v2`), gated
on `api.autoscaling.enabled` (**default `true`**):

```yaml
api:
  replicas: 2
  autoscaling:
    enabled: true
    minReplicas: 2
    maxReplicas: 10
    targetCPUUtilizationPercentage: 70
    targetMemoryUtilizationPercentage: 80
```

The HPA scales on both CPU and memory utilisation. It requires a running
metrics-server in the cluster (most managed Kubernetes offerings ship one); if
yours doesn't, install
[metrics-server](https://github.com/kubernetes-sigs/metrics-server) or set
`api.autoscaling.enabled: false` and manage `api.replicas` directly. No other
workload defines an HPA — `frontend` / `worker` are fixed-replica Deployments
(scale by editing `*.replicas`) and `beat` is a hard singleton.

### Worker `NET_RAW`

The worker pod adds `CAP_NET_RAW` (`worker.netRawCapability: true`, default on)
so `nmap` can run SYN scans + `-O` OS detection from the device-profiling
auto-nmap path. `NET_RAW` is in containerd's default cap set, so this is a
no-op on permissive clusters; on restricted Pod Security Admission, OpenShift
SCC, or GKE Autopilot it's required to keep the cap in the bounding set. Set
`worker.netRawCapability: false` if device profiling is off cluster-wide and you
want a tighter posture.

---

## 6. High availability

For production, flip the in-chart database and cache to their HA shapes via
`kind`. Both render the HA topology as chart-owned templates — you do **not**
apply the raw `k8s/ha/` prototypes when using the chart; those are standalone
references for non-Helm installs.

### PostgreSQL — CloudNativePG

Set `postgresql.kind: cnpg` to render a CloudNativePG `Cluster` CR (a
primary + sync/async replicas with automatic failover) instead of the
single-node StatefulSet:

```yaml
postgresql:
  enabled: true
  kind: cnpg
  cnpg:
    instances: 3        # smallest quorum-friendly default; 5 / 7 for larger
    imageName: "ghcr.io/cloudnative-pg/postgresql:16"
    enablePDB: true
```

This requires the **CloudNativePG operator already installed** in the cluster.
The appliance chart bundles it; for a plain Kubernetes install, apply it
separately first:

```bash
kubectl apply --server-side -f \
  https://raw.githubusercontent.com/cloudnative-pg/cloudnative-pg/release-1.30/releases/cnpg-1.30.0.yaml
```

> **Match the operator line to your cluster, not to this page.** CNPG
> publishes a support matrix per minor: 1.30.x covers Kubernetes
> 1.34-1.36, which is what the appliance ships (k3s v1.36.4+k3s1). On an
> older cluster, apply the CNPG line whose matrix includes your version
> instead — a newer operator against an untested Kubernetes is the one
> combination CNPG will not support.

CNPG creates `<cluster>-rw` (read/write, always the current primary),
`<cluster>-r` (read, primary + sync replicas), and `<cluster>-ro`
(read, replicas only) Services automatically. The api / worker / beat / migrate
pods point at `<cluster>-rw` — no extra wiring. The chart sets short
NoExecute `tolerationSeconds` (20 s) on the instance pods so a hard node loss
fails over in ~1 minute instead of the default ~5; the reasoning is inline in
[`values.yaml`](https://github.com/spatiumnorth/spatiumddi/blob/main/charts/spatiumddi/values.yaml) under
`postgresql.tolerations`.

`postgresql.cnpg.podAntiAffinityType` is `required` on the appliance so
instances never co-locate; the chart default stays `preferred` for
BYO-Kubernetes installs that may run more instances than nodes (where
`required` would leave one instance permanently `Pending`). Because the
`Cluster` CR carries the `helm.sh/resource-policy: keep` annotation
(Helm leaves the resource untouched after create), this setting rides
the supervisor's out-of-band merge-patch rather than a `helm upgrade`.

Flipping an **existing** cluster to `required` can strand an instance
whose PVC is already bound to an occupied node (`Pending`). The one-time
repair is the same shape as Redis but stricter — **only ever delete a
REPLICA's PVC, never the primary's** (that destroys the database);
confirm the role via the `cnpg.io/instanceRole=primary` label first. Full
steps in [`k8s/README.md`](https://github.com/spatiumnorth/spatiumddi/blob/main/k8s/README.md) and
[`charts/spatiumddi/README.md`](https://github.com/spatiumnorth/spatiumddi/blob/main/charts/spatiumddi/README.md).

### Redis — Sentinel

Set `redis.kind: sentinel` to render a StatefulSet where each pod runs a
`redis-server` + a `redis-sentinel` sidecar. Pod-0 starts as master; the rest
replicate from it; the sentinels elect a new master and fail over
automatically. The api / worker / beat pick up a `sentinel://` URL and resolve
the live master through the sentinels — no static master Service needed.

```yaml
redis:
  enabled: true
  kind: sentinel
  sentinel:
    replicas: 3         # quorum = floor(replicas/2)+1 = 2 at 3 replicas
    masterName: mymaster
    downAfterMs: 5000
    failoverTimeoutMs: 60000
```

**Hard-power-loss hardening (#590).** Redis here is cache + Celery
broker; Postgres is the store of record. Three changes make a single
node's abrupt power loss survivable:

- Pod anti-affinity is now **required** (was `preferred`, which
  silently stacked replicas on the seed node — defeating the point of
  HA).
- Each pod announces its stable StatefulSet FQDN via `replica-announce-ip`
  / `sentinel announce-ip`, so a rescheduled pod **replaces** its
  peer-table entry instead of leaving a ghost. Accumulated ghosts stay
  in the failover-quorum denominator and eventually make failover
  impossible.
- `aof-load-corrupt-tail-max-size` is set so a power-cut-torn AOF tail
  is discarded rather than bricking the replica on startup. This is
  **not** redundant with `aof-load-truncated`: that knob handles a
  *short* (mid-record) tail, whereas a *corrupt* (present-but-zero-filled)
  tail is a hard startup failure that `aof-load-truncated` does not
  cover.

If you upgrade an **existing** install whose replicas were co-located, a
replica whose `ReadWriteOnce` PVC is already bound to an occupied node
goes `Pending` — loud, but the alternative is a cluster that silently
isn't HA. The one-time repair is to delete the stranded **replica's**
PVC so it re-provisions on a free node; that data is expendable and
resyncs from the master. Exact commands are in
[`k8s/README.md`](https://github.com/spatiumnorth/spatiumddi/blob/main/k8s/README.md).

### Multi-node control-plane HA

The single-node-to-N-node control-plane HA story (3 / 5 / 7 nodes with
operator-driven promote/demote, the MetalLB Web-UI VIP, and CNPG + Sentinel as
the permanent defaults) is an **appliance feature** — see
[`APPLIANCE.md`](APPLIANCE.md) and the multi-node entries in
[`TOPOLOGIES.md`](TOPOLOGIES.md). On a plain (non-appliance) cluster you get the
same HA database/cache via `postgresql.kind: cnpg` + `redis.kind: sentinel`
above, while the api / frontend / worker scale through their replica counts and
the api HPA. Beat stays a singleton across the cluster (its `Recreate`
strategy guarantees no two beats schedule at once).

**Stateless-tier placement (#590).** api / worker / frontend share a
`podAntiAffinity` helper — `soft` by chart default, `hard` on the
appliance — plus 20 s `not-ready` / `unreachable` NoExecute tolerations
so a hard node loss reschedules them promptly. Under `hard` a
`deploymentStrategy` helper **inverts** `maxSurge` / `maxUnavailable`
(`maxSurge: 0`, `maxUnavailable: 1` instead of the default `1` / `0`):
when `replicas == eligible nodes`, required anti-affinity makes a surge
pod unschedulable, so the default surge-first rollout would deadlock
forever. Retiring one old pod first frees a node for its replacement.

> **The raw HA prototypes in `k8s/ha/`** (`postgres-cluster.yaml`,
> `redis-sentinel.yaml`, `postgres-docker-compose.yaml`) are non-Helm
> references — useful if you're assembling manifests by hand rather than using
> the chart. The chart's `kind`-gated templates supersede them for Helm
> installs.

---

## 7. Node placement

The umbrella chart's six control-plane workloads (api / frontend / worker /
beat / postgres / redis) share one nodeSelector path: each merges
`global.controlPlaneNodeSelector` on top of its per-component `nodeSelector`
override. Both are empty by default, so a plain cluster lets the scheduler
place control-plane pods anywhere. The appliance's firstboot flips
`global.controlPlaneNodeSelector` to `{ spatium.io/role-control-plane: "true" }`
so control-plane pods only land on nodes carrying that per-role label —
the `controlPlaneNodeSelector` helper is in
[`_helpers.tpl`](https://github.com/spatiumnorth/spatiumddi/blob/main/charts/spatiumddi/templates/_helpers.tpl).

Per-role node-label gating for the **managed-service workloads**
(`spatium.io/role-dns-bind9`, `spatium.io/role-dns-powerdns`,
`spatium.io/role-dns-technitium`, `spatium.io/role-dhcp`) is part of the
appliance chart (`charts/spatiumddi-appliance/`), per project
non-negotiable #16 — its `dns-bind9.yaml` / `dns-technitium.yaml` /
`dhcp-kea.yaml` templates are the reference pattern. On the
umbrella chart, DNS/DHCP agent placement is controlled per-server through the
`storage` / `service` / `resources` fields and standard scheduling primitives.

### Pod posture — seccomp and PriorityClasses (#983)

Every pod the chart renders carries
`securityContext.seccompProfile.type: RuntimeDefault`. This is on by
default because Kubernetes runs a container `Unconfined` unless a profile is
asked for, while docker-compose applies the runtime's default profile to
every service — so without it the same images run *less* restricted under
Kubernetes than under Compose. Set `global.seccompProfile` to `Unconfined`,
or to `""` to omit the block, if your runtime's default profile breaks a
workload; `Localhost` is rejected, because it needs a profile file the chart
cannot place on your nodes.

PriorityClasses are **off by default and you should keep them off unless you
create the classes yourself**: a pod naming a PriorityClass that does not
exist is refused by the apiserver, so setting a name the cluster has never
heard of stops new pods being created (running ones are untouched, and it
self-heals once the class exists). When you do have a priority policy:

```yaml
global:
  priorityClassName: my-control-plane   # api, worker, beat, frontend,
                                        # migrate, postgres/CNPG, redis,
                                        # sentinel, slot-image mirror
  servicePriorityClassName: my-serving  # the DNS / DHCP agent StatefulSets
```

Any single workload can override with `<component>.priorityClassName`, where
*unset* (the shipped default) inherits the chart-wide key and `""` means no
class for that workload even when the chart-wide key is set. The
split exists because a DNS agent answering the LAN should outrank the API
that configures it when a node runs out of memory. The appliance sets
`global.priorityClassName: spatium-control-plane` against classes its own
chart renders — see
[APPLIANCE.md § Kubernetes posture](APPLIANCE.md#kubernetes-posture-983) for
the three classes and their values.

For the raw manifests under `k8s/`, the `spatiumddi` namespace carries
`pod-security.kubernetes.io/warn` + `audit` at `baseline`. Both are
report-only — neither can reject a pod — and `enforce` is not usable because
the DHCP agent needs `hostNetwork` and the DNS agents bind `:53` on the host.

### User namespaces (#983 Phase 2)

`hostUsers: false` (GA in Kubernetes 1.36) maps container root to an
unprivileged host uid, so a container escape is not root on the node. Exposed
per workload — `api`, `worker`, `beat`, `redis` — and **unset by default**,
because a runtime without idmapped-mount support refuses the pod outright:

```yaml
api:
  hostUsers: false     # worth most here — this pod runs tcpdump + nmap
beat:
  hostUsers: false
```

Two cautions the chart encodes rather than leaves to discovery:

* `api.hostUsers: false` and `worker.hostUsers: false` are **refused at
  render time** while `api.applianceHostMounts.enabled` is on. Those host
  directories are chowned to the image's uid and the pods *write* to them; a
  user namespace remaps exactly that, which corrupts state rather than
  failing to start.
* `redis` owns a PVC. If your StorageClass is backed by a host directory and
  the runtime does not idmap the mount, the remapped uid cannot read what it
  wrote before the change. Not refused — a runtime that idmaps correctly makes
  it safe — but verify on one replica first. Postgres and CNPG are not offered
  the knob at all for the same reason, only sharper.

### Topology spread (#983 Phase 2)

`api` and `worker` render a `maxSkew: 1` / `kubernetes.io/hostname` /
`whenUnsatisfiable: ScheduleAnyway` constraint when `podAntiAffinity` is
`soft` (the default) and `replicas > 1`. `soft` anti-affinity is only a
*preference*, so without this the scheduler can still stack every replica on
one node.

`ScheduleAnyway`, not `DoNotSchedule`: the strict form leaves surplus replicas
permanently Pending on a cluster with fewer ready nodes than replicas, which
turns a placement preference into an outage. Set `podAntiAffinity: hard` if
you want the strict behaviour — that path uses required anti-affinity and
renders no spread constraint.

Supply `<component>.topologySpreadConstraints` to replace the default
outright; nothing is rendered in `hard`/`none` mode or at `replicas: 1`.

### Kubelet Summary API grants (#983 Phase 2)

The api reads per-node CPU / memory / disk — and, on Kubernetes 1.36+, PSI
stall percentages — straight from the kubelet Summary API, because the
appliance ships no metrics-server. Two transports, two very different grants:

| Transport | Grant | Scope of the grant |
|---|---|---|
| direct, `:10250` | `nodes/stats [get]` | that one page |
| apiserver proxy | `nodes/proxy [get]` | read GETs to **every** kubelet endpoint |

Both are granted by default (`api.upgradeOrchestratorRBAC.enabled`). Direct is
tried first, **per node**, and Cluster → Overview shows a `kubelet:` chip —
green only when every node went direct, which is the condition for dropping the
broad grant. Then set
`api.upgradeOrchestratorRBAC.kubeletProxyFallback: false`.

If a node fell back, `blocked_reasons` names it and why. The common cause is
the kubelet's serving cert not chaining to the ServiceAccount's CA; set
`api.kubeletCA.enabled: true` to mount the right bundle and point
`SPATIUM_KUBELET_CA_PATH` at it:

```yaml
api:
  kubeletCA:
    enabled: true
    hostPath: /var/lib/rancher/k3s/server/tls/server-ca.crt   # k3s default
```

The same mount and env reach the worker, which makes the same call.

### The worker needs a ServiceAccount for PSI alerting

Alert evaluation runs in the **Celery worker**, so the `node_pressure` rule
needs `worker.serviceAccount.enabled: true` — without it the rule sits enabled
and evaluates to nothing. The grant is narrow (`nodes` read + `nodes/stats`,
plus `nodes/proxy` while the fallback is on) and shares none of the api's
eviction / node-patch / Secret-write permissions.

---

## 8. Upgrading

> **Take a backup before upgrading.** Sign in as a superadmin →
> **System Admin → Backup → Manual → Build + download**, supply a passphrase
> you'll remember (or use a configured destination's **Run now**). The archive
> is the single rollback artifact if the upgrade goes sideways. See
> [`SYSTEM_ADMIN.md`](../features/SYSTEM_ADMIN.md#29-backup-and-restore).

```bash
helm upgrade ddi oci://ghcr.io/spatiumnorth/charts/spatiumddi \
  --version <NEW_CHART_VERSION> \
  --namespace spatiumddi --reuse-values
```

Each upgrade renders a fresh per-revision migrate Job; the api / worker / beat
pods' `wait-for-migrate` init containers hold their rollout until the new
schema lands, so the new control-plane pods never come up against an
un-migrated database.

### Manual (manifest) upgrades

If you're running the raw `k8s/base/` manifests instead of the chart, pin the
new tag on every Deployment and re-run the migrate Job by hand — see
[`k8s/README.md` → Upgrading](https://github.com/spatiumnorth/spatiumddi/blob/main/k8s/README.md#upgrading).

---

## 9. Backup on Kubernetes

The full backup + restore surface (build-and-download, S3 / S3-compatible /
SCP / Azure / SMB / FTP / GCS / local-volume destinations, scheduled cron,
retention, selective restore, cross-install secret rewrap, alembic
upgrade-on-restore) lives in **System Admin → Backup**; the operator reference
is [`SYSTEM_ADMIN.md`](../features/SYSTEM_ADMIN.md#29-backup-and-restore).

The Kubernetes-specific shape:

- **Default — no PVC.** Most installs pair SpatiumDDI with an off-cluster
  object store (S3 / Azure Blob / GCS). The in-app **Build + download** button
  streams archives straight to the operator's browser, and scheduled targets
  push to the configured remote destination — neither the api nor the worker
  needs a backup PVC. Pre-restore safety dumps land in the api pod's writable
  layer and vanish on recycle; that's acceptable because the configured remote
  destination *is* the rollback artifact.
- **`local_volume` target needs an RWX PVC** mounted at the same path on
  **both** the api and worker Deployments (the worker runs the scheduled sweep,
  so it must write the files the api lists back). RWO will reject the second
  mount. The kustomize-overlay recipe is in
  [`k8s/README.md` → Backup](https://github.com/spatiumnorth/spatiumddi/blob/main/k8s/README.md#backup). The umbrella chart
  doesn't ship a `backup.localVolume` value yet — patch the rendered manifests
  with a kustomize overlay, or use a remote destination (recommended on K8s
  anyway).

---

## See also

- [`charts/spatiumddi/README.md`](https://github.com/spatiumnorth/spatiumddi/blob/main/charts/spatiumddi/README.md) — full
  values reference, troubleshooting, and a `helm template` dev loop
- [`k8s/README.md`](https://github.com/spatiumnorth/spatiumddi/blob/main/k8s/README.md) — raw `k8s/base/` manifests, the
  `k8s/ha/` prototypes, the static DNS/DHCP StatefulSets, and TLS/Ingress notes
- [`TOPOLOGIES.md`](TOPOLOGIES.md) — reference production topologies + sizing
- [`APPLIANCE.md`](APPLIANCE.md) — the self-contained OS appliance (k3s-based,
  multi-node control-plane HA, MetalLB VIP)
- [`DNS_AGENT.md`](DNS_AGENT.md) — managed DNS container architecture +
  registration flow
- [`DOCKER.md`](DOCKER.md) — Docker Compose deployment + distributed standalone
  agents
