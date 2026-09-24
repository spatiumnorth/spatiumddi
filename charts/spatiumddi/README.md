# SpatiumDDI Helm chart

Umbrella chart that deploys the full SpatiumDDI control plane (API +
frontend + Celery worker + Celery beat + migrate Job) plus PostgreSQL
and Redis via Bitnami subcharts, with optional DNS and DHCP agent
StatefulSets.

- **Chart type:** application
- **Registry:** `oci://ghcr.io/spatiumnorth/charts/spatiumddi`
- **Versioning:** Each SpatiumDDI release tag (CalVer `YYYY.MM.DD-N`)
  publishes a chart version with leading zeroes stripped so it's a
  valid SemVer 2 identifier — e.g. tag `2026.04.20-1` →
  chart version `2026.4.20-1`.

## TL;DR

```bash
helm install ddi oci://ghcr.io/spatiumnorth/charts/spatiumddi \
  --version 2026.4.20-1 \
  --namespace spatiumddi --create-namespace
```

> **Chart versions up to and including `2026.9.4-1` default to the old
> image path.** They were published before the project moved to the
> `spatiumnorth` organization (#1100), so their values name
> `ghcr.io/spatiumddi/*`, which now answers `denied`. The same image tags
> are published under `ghcr.io/spatiumnorth/`; add these to install or
> upgrade one of those versions:
>
> ```bash
>   --set image.repository=spatiumnorth \
>   --set dnsAgents.image.repository=ghcr.io/spatiumnorth/dns-bind9 \
>   --set dnsAgents.flavors.powerdns.repository=ghcr.io/spatiumnorth/dns-powerdns \
>   --set dnsAgents.flavors.technitium.repository=ghcr.io/spatiumnorth/dns-technitium \
>   --set dhcpAgents.image.repository=ghcr.io/spatiumnorth/dhcp-kea
> ```

Default login: **`admin` / `admin`** (forced password change on first login).

## Prerequisites

- Kubernetes 1.31+
- Helm 3.8+ (needed for OCI)
- A StorageClass supporting `ReadWriteOnce` (Postgres, Redis, and
  agent state all use PVCs)
- Ingress controller or LoadBalancer for external access (optional)

## Install

```bash
# Default install — all-in-one with bundled Postgres + Redis
helm install ddi oci://ghcr.io/spatiumnorth/charts/spatiumddi \
  --version <CHART_VERSION> \
  --namespace spatiumddi --create-namespace
```

### Exposing the UI

```yaml
# values.yaml
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

Or, without an Ingress, flip the frontend service to `LoadBalancer`:

```yaml
frontend:
  service:
    type: LoadBalancer
```

The frontend Pod's embedded nginx proxies `/api/` (plus `/health` and
`/metrics`) to the api Service — same shape as Docker Compose. The
upstream host + port come from values; the cluster DNS resolver is
auto-detected from `/etc/resolv.conf` at container start. Defaults
work out of the box (`{{ fullname }}-api` on `api.service.port`).

Override only for non-default topologies — separate namespace, custom
api Service name, pinned external resolver:

```yaml
frontend:
  apiUpstream:
    host: my-api.shared-ns.svc.cluster.local
    port: 8000
  nginxLocalResolvers: "10.96.0.10"   # optional; auto-detected if empty
```

If you'd rather skip the frontend's proxy and split routing at the
ingress controller (`/` → frontend, `/api/` → api Service), the
existing `ingress.hosts[].paths` list accepts both — just declare the
`/api/` path with a manual `backend.service.name = "<release>-api"`
override via a strategic-merge patch or a separate Ingress.

### Using an external Postgres

Point the chart at an existing database and skip the bundled subchart:

```yaml
postgresql:
  enabled: false

externalDatabase:
  host: pg.internal
  port: 5432
  username: spatiumddi
  database: spatiumddi
  existingSecret: my-db-secret       # must carry key `password`
  existingSecretPasswordKey: password
```

### Using an external Redis

```yaml
redis:
  enabled: false

externalRedis:
  host: redis.internal
  port: 6379
  existingSecret: my-redis-secret    # optional; remove for unauth'd redis
```

### Running managed DNS agents

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
    - name: ns2
      role: secondary
      group: internal-resolvers
      service: { type: LoadBalancer }
    # PowerDNS (issue #127 — online DNSSEC, ALIAS, LUA, catalog zones).
    # Lives in its own group so PowerDNS-only features can engage; the
    # control plane rejects mixed-driver groups for those features.
    - name: pdns1
      flavor: powerdns
      role: primary
      group: powerdns-edge
      service: { type: LoadBalancer }
    # Technitium (third DNS driver — online DNSSEC, catalog zones both
    # ways, and native DoT/DoH/DoQ listeners plus encrypted upstream
    # forwarding with no dnsdist-style sidecar). Own group, same rule.
    - name: tdx1
      flavor: technitium
      role: primary
      group: technitium-edge
      service: { type: LoadBalancer }
```

Each server picks its image from `dnsAgents.image` (default,
configures BIND9) or `dnsAgents.flavors.<flavor>` per-driver
override (`powerdns` and `technitium` are both pre-set out of the
box). The `dns-state` volume mounts under `/var/cache/bind` for
BIND9, `/var/lib/powerdns` for PowerDNS LMDB, and `/etc/dns` for
Technitium's own config + zone store — same volume claim, the
template picks the path based on `flavor`.

Pre-create the PSK secret (or use `agentKey.value` inline for lab use only):

```bash
kubectl -n spatiumddi create secret generic spatium-dns-agent-key \
  --from-literal=DNS_AGENT_KEY="$(openssl rand -hex 32)"
```

### Running managed DHCP agents

Same shape as DNS but `SPATIUM_AGENT_KEY`:

```yaml
dhcpAgents:
  enabled: true
  agentKey:
    existingSecret: spatium-dhcp-agent-key  # must carry key SPATIUM_AGENT_KEY
  servers:
    - name: dhcp1
      role: primary
      # hostNetwork: true required for real DHCPv4 unless relay-only.
      hostNetwork: true
```

## Values reference

### Top-level

| Key | Default | Description |
|-----|---------|-------------|
| `image.registry` | `ghcr.io` | Image registry for control-plane images |
| `image.repository` | `spatiumddi` | Repo prefix (images are `<registry>/<repo>/<name>`) |
| `image.tag` | `""` → `Chart.appVersion` | Control-plane image tag |
| `image.pullPolicy` | `IfNotPresent` |  |
| `image.pullSecrets` | `[]` |  |
| `auth.secretKey` | `""` | Fernet key; auto-generated on first install if empty |
| `auth.existingSecret` | `""` | BYO secret with key `secret-key` |
| `fullnameOverride` | `""` |  |
| `nameOverride` | `""` |  |
| `global.controlPlaneNodeSelector` | `{}` | Merged into every control-plane workload's `nodeSelector` |
| `global.seccompProfile` | `RuntimeDefault` | Pod-level seccomp for every workload. `Unconfined` or `""` (omit) also accepted; `Localhost` is rejected |
| `global.priorityClassName` | `""` | PriorityClass for the control-plane workloads. **Leave empty unless the class exists** — the apiserver refuses a pod naming one that does not |
| `global.servicePriorityClassName` | `""` | Same, for the DNS / DHCP agent StatefulSets |
| `<component>.priorityClassName` | unset | Per-workload override. Unset inherits the chart-wide key above; `""` means *no class for this workload*, even when the chart-wide key is set |
| `<component>.hostUsers` | unset | #983 — `false` runs the pod in a user namespace (K8s 1.36+). Refused on `api`/`worker` while `api.applianceHostMounts.enabled` is on |
| `api.topologySpreadConstraints` / `worker.…` | `[]` | #983 — replaces the default `maxSkew: 1` spread rendered in `soft` anti-affinity mode |
| `api.upgradeOrchestratorRBAC.kubeletProxyFallback` | `true` | #983 — also grant the broad `nodes/proxy` read as a fallback transport, on both api and worker. Set false once Cluster → Overview's `kubelet:` chip is green (every node direct) |
| `api.kubeletCA.enabled` / `.hostPath` / `.mountPath` | `false` | #983 — mount the CA that signs kubelet *serving* certs (k3s signs them with its own `server-ca`, not the ServiceAccount CA) and set `SPATIUM_KUBELET_CA_PATH` from it. Needed only if a node reports a CA failure |
| `worker.serviceAccount.enabled` | `false` | #983 — mount a narrow ServiceAccount (`nodes` read + `nodes/stats`) on the worker. **Required for the `node_pressure` PSI alert**: alert evaluation runs in the worker, not the api |

### Control plane

| Key | Default | Description |
|-----|---------|-------------|
| `api.replicas` | `2` |  |
| `api.service.type` | `ClusterIP` |  |
| `api.service.port` | `8000` |  |
| `api.autoscaling.enabled` | `true` | HPA on CPU + memory |
| `api.autoscaling.minReplicas` / `maxReplicas` | `2` / `10` |  |
| `api.probes.liveness.{initialDelaySeconds,periodSeconds,timeoutSeconds,failureThreshold}` | `10` / `30` / `30` / `4` | #1051 — `/health/live` budgets, sized for a busy single-worker loop: four 30 s misses restart a process that has said nothing for two minutes |
| `api.probes.readiness.{initialDelaySeconds,periodSeconds,timeoutSeconds,failureThreshold}` | `5` / `10` / `15` / `3` | #1051 — `/health/ready` budgets; the timeout exceeds the handler's own bounded worst case (4 s db + 4 s schema + 2 s redis) so the kubelet sees the 503 naming the failing check instead of a bare deadline |
| `api.serviceControl.enabled` | `false` | Sets `SERVICE_CONTROL_ENABLED` on the api — what the Services screen's capability probe reports |
| `api.serviceControlRBAC.enabled` | `false` | Grants the api ServiceAccount `list` + `patch` on Deployments / StatefulSets / DaemonSets. Needs `serviceAccount.enabled` |
| `frontend.replicas` | `2` |  |
| `frontend.service.type` / `.port` | `ClusterIP` / `80` |  |
| `frontend.apiUpstream.host` | `""` (→ `{{ fullname }}-api`) | nginx-proxy target Service name |
| `frontend.apiUpstream.port` | `0` (→ `api.service.port`) | nginx-proxy target port |
| `frontend.nginxLocalResolvers` | `""` (auto-detect) | DNS resolver IPs for nginx |
| `worker.replicas` | `2` |  |
| `worker.concurrency` | `4` |  |
| `worker.queues` | `"ipam,dns,dhcp,default"` |  |
| `beat.*` | see values.yaml | Singleton scheduler |
| `migrate.enabled` | `true` | Alembic Job as pre-install/pre-upgrade hook |
| `ingress.*` | disabled |  |

### Dependencies

The `postgresql` and `redis` keys are passed through to the Bitnami
subcharts verbatim — any option those charts accept works here. See:

- https://github.com/bitnami/charts/tree/main/bitnami/postgresql
- https://github.com/bitnami/charts/tree/main/bitnami/redis

### Agents

| Key | Default | Description |
|-----|---------|-------------|
| `dnsAgents.enabled` | `false` |  |
| `dnsAgents.image.repository` | `ghcr.io/spatiumnorth/dns-bind9` | Default image (BIND9 flavor) |
| `dnsAgents.flavors.powerdns.repository` | `ghcr.io/spatiumnorth/dns-powerdns` | Per-flavor image override (issue #127) |
| `dnsAgents.flavors.technitium.repository` | `ghcr.io/spatiumnorth/dns-technitium` | Per-flavor image override |
| `dnsAgents.agentKey.existingSecret` | `""` | Carries `DNS_AGENT_KEY` (shared between flavors) |
| `dnsAgents.servers` | `[]` | One entry → one StatefulSet + Services. `flavor: bind9` (default), `powerdns`, or `technitium` |
| `dhcpAgents.enabled` | `false` |  |
| `dhcpAgents.image.repository` | `ghcr.io/spatiumnorth/dhcp-kea` |  |
| `dhcpAgents.agentKey.existingSecret` | `""` | Carries `SPATIUM_AGENT_KEY` |
| `dhcpAgents.servers` | `[]` |  |

Each server entry accepts `name`, `role`, `group`, `storage.agentState`,
`storage.dnsState` (or `storage.keaState`), `service.type`,
`hostNetwork` (DHCP only), and `resources`.

## Upgrade

```bash
helm upgrade ddi oci://ghcr.io/spatiumnorth/charts/spatiumddi \
  --version <NEW_CHART_VERSION> \
  --namespace spatiumddi --reuse-values
```

The migrate Job runs as a `pre-upgrade` hook, so Alembic applies
before the new API pods roll out.

### Sentinel ghost entries clear themselves on upgrade

Chart versions before the #590 fix let every Redis pod announce itself to
its peers by its **pod IP**. A pod that gets rescheduled (node loss, drain,
OS upgrade) returns with a new IP and a new run id, so the surviving
sentinels record a *second* entry for it and keep the old one as `s_down`
forever — Sentinel never forgets a Sentinel it has seen.

That is not cosmetic. Sentinel authorizes a failover only with a majority
of **all known** sentinels, and dead ghosts sit in the denominator without
ever voting. With three live pods, the third accumulated ghost makes
failover arithmetically impossible (6 known, 4 needed, 3 usable): the
master is stranded, `sentinel://` clients never resolve a new one, and the
API stays down. Each node loss contributes one ghost.

This release pins `replica-announce-ip` / `sentinel announce-ip` to each
pod's stable StatefulSet FQDN, so a returning pod replaces its own entry
instead of adding one.

**No manual step is needed.** The init container rewrites `sentinel.conf`
on every pod start, so the rolling update discards the accumulated ghosts
along with the rest of each sentinel's learned state. To confirm afterwards
(`usable` should equal your replica count, and no `s_down` rows):

```bash
kubectl -n spatiumddi exec <release>-redis-0 -c sentinel -- \
  redis-cli -p 26379 sentinel ckquorum mymaster
kubectl -n spatiumddi exec <release>-redis-0 -c sentinel -- \
  redis-cli -p 26379 sentinel sentinels mymaster | grep -A1 flags
```

On a cluster you cannot roll yet, `SENTINEL RESET *` on each sentinel
clears the ghosts immediately without restarting anything.

### One-time step when upgrading a Sentinel Redis whose replicas were co-located

Chart versions before the #590 fix used best-effort (`preferred`) pod
anti-affinity on the Sentinel Redis StatefulSet, so two replicas could
land on the same node — and `persistence.enabled` then pinned each
replica's `ReadWriteOnce` local PV to whichever node it first scheduled
on. This release makes the anti-affinity **required**, which is what
makes a single node loss survivable. A replica whose PV is stranded on a
node that already hosts another replica cannot schedule, and will sit
`Pending` after the rolling update.

Check for it, and repair by deleting the stranded PVC so it
re-provisions on a free node (Redis here is cache + Celery broker;
Postgres is the store of record, so the data is expendable and the
replica resyncs from the master):

```bash
kubectl -n spatiumddi get pods -l app.kubernetes.io/component=redis \
  -o wide                                    # any Pending, and where?
kubectl -n spatiumddi delete pvc data-<release>-redis-<ordinal>
kubectl -n spatiumddi delete pod <release>-redis-<ordinal>
```

Clusters whose replicas were already spread one-per-node upgrade with no
action. This does not apply to `redis.kind: standalone`.

### The same step for CloudNativePG, if you set `podAntiAffinityType: required`

CNPG has the identical hazard, and the repair is the same shape — but
Postgres is not expendable, so the rule is stricter.

`postgresql.cnpg.podAntiAffinityType` defaults to `preferred` in this chart
(the appliance renders `required`). Flipping an **existing** cluster to
`required` can strand an instance whose PVC is already bound to a node that
now hosts another instance. It goes `Pending`.

Postgres stays available while you fix it: the primary is untouched, and a
surviving replica keeps failover possible.

> **Only ever delete a REPLICA's PVC. Never the primary's.** Deleting the
> primary's PVC destroys the database. Confirm the role before you touch
> anything — CNPG labels the primary `cnpg.io/instanceRole=primary`.

```bash
# Which instance is Pending, and which one is the primary?
kubectl -n spatiumddi get pods -l cnpg.io/cluster=<cluster> \
  -L cnpg.io/instanceRole -o wide

# Confirm the Pending pod is NOT the primary, then drop its PVC.
# CNPG re-clones the replica from the primary (pg_basebackup).
kubectl -n spatiumddi delete pvc <cluster>-<ordinal>
kubectl -n spatiumddi delete pod <cluster>-<ordinal>
```

If the stranded instance *is* the primary, don't delete anything: run a
switchover first (`kubectl cnpg promote <cluster> <other-instance>`), wait
for the role to move, then repair it as a replica.

## Uninstall

```bash
helm uninstall ddi --namespace spatiumddi
```

PVCs for Postgres, Redis, and agent state are **not** deleted
automatically — remove them manually if you want a clean slate:

```bash
kubectl -n spatiumddi delete pvc -l app.kubernetes.io/instance=ddi
```

## Troubleshooting

- **API pods CrashLoopBackOff on first install:** the migrate Job
  probably hasn't finished. `kubectl -n spatiumddi logs job/ddi-spatiumddi-migrate`.
- **`secret-key` rotated unexpectedly:** the chart's `lookup` preserves
  it across upgrades, but `helm template` — or a fresh install under
  a new release name — generates a new one. Always use `helm install` /
  `helm upgrade` against the same release name, or pre-create the
  secret and set `auth.existingSecret`.
- **DNS agent can't reach control plane:** the chart sets
  `CONTROL_PLANE_URL` to `http://<release>-spatiumddi-api.<ns>.svc.cluster.local:8000`.
  Agents running outside the cluster need a different URL via a custom
  `values.yaml` override (not currently exposed — raise an issue).

## Development

```bash
cd charts/spatiumddi
helm dependency update           # pull bitnami/postgresql + bitnami/redis
helm lint .
helm template test . --namespace test | less
```

For local testing against a real cluster:

```bash
helm install test . \
  --namespace spatiumddi --create-namespace \
  --set image.tag=latest \
  --set postgresql.primary.persistence.size=2Gi
```
