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
`postgres:16-alpine` and `redis:8.10.2-alpine` images (the same ones
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
SpatiumDDI release tag. A CalVer tag has its leading zeroes stripped so it's
a valid SemVer 2 identifier (tag `2026.04.20-1` → chart version
`2026.4.20-1`); a SemVer tag from 1.0.0 on is the chart version unchanged.

**Always pass `--version` for a CalVer chart.** The `-N` makes every CalVer
chart a SemVer pre-release, and Helm's unversioned lookup skips
pre-releases, so without `--version` Helm reports *Could not locate a
version matching provided version string*. `1.0.0` is the first chart Helm
resolves as the latest on its own (#1182).

### Prerequisites

- Kubernetes 1.31+
- Helm 3.8+ (required for OCI registry support)
- A `StorageClass` supporting `ReadWriteOnce` (Postgres, Redis, and agent
  state all use PVCs)
- An Ingress controller or `LoadBalancer` for external access (optional —
  you can `port-forward` for a quick look)

### OpenShift

**Supported OpenShift versions**

| OpenShift Container Platform | Kubernetes | Status | Last tested |
|---|---|---|---|
| 5.0 | 1.36 | Supported | 5.0.0 |
| 4.22 | 1.35 | Supported | 4.22.14 |

Supported means the chart is tested on that minor release before each
SpatiumDDI release and installs under OpenShift's default security context
constraints, as described below. Supported from SpatiumDDI 1.0.1, the release
that adds the Red Hat UBI 9 images and the certified values profile
(`values-openshift-certified.yaml`). OpenShift 4.21 and earlier, and OKD, are
not tested and not supported. Report a problem on a supported version in
[GitHub Issues](https://github.com/spatiumnorth/spatiumddi/issues).

**Red Hat Ecosystem Catalog**

SpatiumDDI is listed in the Red Hat Ecosystem Catalog as
[Partner Validated for Red Hat OpenShift](https://catalog.redhat.com/en/software/container-stacks/detail/6af49e43879a2dda6c257559).
Its four Red Hat Universal Base Image 9 images, the ones the certified values
profile installs, are Red Hat certified:
[spatiumddi-api](https://catalog.redhat.com/en/software/containers/spatiumnorth/spatiumddi-api/6afe3a343f920ff278cf212a),
[spatiumddi-frontend](https://catalog.redhat.com/en/software/containers/spatiumnorth/spatiumddi-frontend/6afe3a3d071e4d6a9cc1d123),
[dns-bind9](https://catalog.redhat.com/en/software/containers/spatiumnorth/dns-bind9/6afe3a562f24a256f824dc01)
and
[dhcp-kea](https://catalog.redhat.com/en/software/containers/spatiumnorth/dhcp-kea/6afe3a6f8bdde86e465f92ea).
The images carry a `-ubi` tag suffix on GHCR (for example `1.0.1-ubi`). The
Helm chart is a Red Hat certified chart from 1.0.1, published in the OpenShift
Helm chart repository, so it can be installed from the OpenShift console's
Helm catalog or with Helm:

```bash
helm repo add openshift-helm-charts https://charts.openshift.io/
helm install spatiumddi openshift-helm-charts/spatiumnorth-spatiumddi \
  --version 1.0.1 -n spatiumddi --create-namespace \
  -f values-openshift-certified.yaml
```

Take `values-openshift-certified.yaml` from the chart
(`helm show values` prints only the default values; `helm pull --untar` gives
the whole chart) and add your own overrides after it.

The chart installs on OpenShift under its **default** SecurityContextConstraints:
the control plane runs under plain `restricted-v2`, with no grant. It is the
same chart, not a fork. Tested on OpenShift 5.0.0 (Kubernetes 1.36) and
OpenShift 4.22.14 (Kubernetes 1.35), both on OpenShift Local, from the command
line and through the web console's Helm install: every control-plane pod
admitted by `restricted-v2`, the BIND9 and Kea agents by the chart's own SCCs,
DNS and DHCP serving. OKD is not tested.

```bash
helm install ddi oci://ghcr.io/spatiumnorth/charts/spatiumddi \
  --version <CHART_VERSION> \
  --namespace spatiumddi --create-namespace
```

The platform is detected from the cluster (`security.openshift.io/v1`). Where
there is no cluster to ask (`helm template`, Argo CD), say so with
`--api-versions security.openshift.io/v1 --api-versions route.openshift.io/v1`,
or set `global.platform: openshift` (the values are `auto`, `kubernetes` and
`openshift`). On any other platform nothing below applies and the chart renders
exactly as before.

**Checking an install.** Every pod should be Ready, and the SCC that admitted
each one is on its `openshift.io/scc` annotation:

```bash
oc get pods -n spatiumddi \
  -o custom-columns='NAME:.metadata.name,READY:.status.containerStatuses[*].ready,SCC:.metadata.annotations.openshift\.io/scc'
oc get route -n spatiumddi        # the UI's hostname
```

The api, worker, beat, frontend, migrate Job, Postgres and Redis should show
`restricted-v2` (or `restricted-v3`); the DNS and DHCP agents show the chart's
`<fullname>-<namespace>-dns-agent` / `-dhcp-agent`. An agent shown under
`restricted-v2` means the chart's SCC was not created or not granted (see
`openshift.scc.create` below). Log in at the Route's hostname as `admin` /
`admin`; you are asked to change the password at once.

**What the chart does differently on OpenShift**

- `restricted-v2` assigns each pod a random uid and fsGroup from the namespace's
  range and refuses a pinned one, so the api's `runAsUser`, the cnpg-ca-publisher
  Job's `runAsUser`, and the in-chart Postgres and Redis `fsGroup`s are omitted.
  `seccompProfile: RuntimeDefault` is kept. Celery beat keeps its schedule file
  in `/tmp` instead of its working directory, which only the image's own user
  may write.
- The images run as any uid in group 0: every path they write is group-0 owned
  and group-writable. The frontend nginx listens on `:8080` (`FRONTEND_HTTP_PORT`;
  the Service keeps its own port) because a random uid cannot bind `:80`.
- A `Route` in front of the frontend Service (`openshift.route`): edge TLS with
  the router's certificate, plain HTTP redirected, a 1 h timeout for the
  streaming pages. Set `openshift.route.host` for a fixed hostname, or
  `openshift.route.enabled: false` to bring your own. Behind the router, set
  `frontend.trustedProxyCidrs` to the router's network so the api sees the real
  client address and `https` (see the reverse-proxy page).
- **SecurityContextConstraints for the DNS and DHCP agents only**
  (`openshift.scc.create`). BIND9 binds `:53` and Kea binds `:67` and opens raw
  sockets through *file capabilities* on the daemon binaries. Those work only
  when the capability is in the container's bounding set and `no_new_privs` is
  off, which `restricted-v2` forbids (`allowPrivilegeEscalation: false`, and
  `NET_RAW` is not allowed). The chart therefore renders, per agent kind, a
  ServiceAccount, a SCC, and a Role + RoleBinding letting only that
  ServiceAccount `use` it. Each SCC is `restricted-v2` with three differences:
  the capabilities it allows (`NET_BIND_SERVICE`; plus `NET_RAW` for Kea),
  `allowPrivilegeEscalation: true`, and `allowHostNetwork` / `allowHostPorts`
  only if a DHCP server sets `hostNetwork: true`. The pods still run as a
  non-root uid from the namespace range with `runtime/default` seccomp; the SCC
  is not privileged. The containers add their capabilities explicitly, because
  CRI-O's default set differs from containerd's (it has no `NET_RAW`), and set
  `allowPrivilegeEscalation: true` explicitly, so `restricted-v2` (which also
  allows `NET_BIND_SERVICE`) can never be the SCC that admits them. Where
  cluster admins manage SCCs, set `openshift.scc.create: false`: the chart
  still creates the ServiceAccounts, and you grant an equivalent SCC to
  `<fullname>-dns-agent` / `<fullname>-dhcp-agent` yourself (see **If your cluster admins manage SCCs** below; `<fullname>` is
  `<release>-spatiumddi`, or the release name when it already contains
  `spatiumddi`). `anyuid` is not a substitute: it has no `seccompProfiles`, so it
  rejects every pod that sets `seccompProfile: RuntimeDefault`.
- The worker adds nothing: under `restricted-v2` there is no `NET_RAW`, so `nmap`
  raw scans and the `tcpdump` capture on the Tools page fall back to what an
  unprivileged process can do. To keep them, set `openshift.workerNetRaw: true`
  with `worker.serviceAccount.enabled: true`; the chart then renders a SCC for
  the worker's own ServiceAccount.

**Limits.** Only the `bind9` DNS flavor and Kea DHCP run under these SCCs; a
PowerDNS or Technitium server is refused at render time (their images still
chown and drop privileges at start). `frontend.tls.enabled` (the appliance's
`:80` / `:443` nginx) and `frontend.hostNetwork` are refused: let the Route
terminate TLS. Kea's opt-in
rogue-DHCP probe and fingerprint sniffer need `NET_RAW` in a process that is not
Kea, and are unavailable; so is radvd (`RADVD_MANAGED`), which also needs
`NET_ADMIN`, in the default and the `-ubi` Kea image alike (the `-ubi` image does
ship radvd, for platforms where you grant it). `restricted-v3` (4.22+) also requires `hostUsers:
false`; set the per-workload `hostUsers` values where the chart offers them
(api, worker, beat, redis).

**Red Hat certification status.** From 1.0.1 the chart is a Red Hat certified
Helm chart and the four `-ubi` images are Red Hat certified and published (see
"Red Hat Ecosystem Catalog" above). The release submits `preflight` results for
each `-ubi` image and architecture against the published
`ghcr.io/spatiumnorth/<image>:<version>-ubi` (the `submit-ubi-preflight` job;
non-gating, and skipped without the `PYXIS_API_TOKEN` repository secret). Every
image carries `name`, `vendor`, `version`, `release`, `summary`, `description`,
`maintainer` and `url` labels (plus the `org.opencontainers.image.*` set) and the
project `LICENSE` and `NOTICE` under `/licenses`; the chart has a
`values.schema.json`, `charts.openshift.io/*` annotations in `Chart.yaml` and a
`helm test` hook (`helm test <release>` checks the api and the frontend answer).

**UBI image variants and the certified profile (#3913).** The api, frontend,
`dns-bind9` and `dhcp-kea` images are also published on `ubi9` as
`ghcr.io/spatiumnorth/<image>:<version>-ubi` (and `:latest-ubi`), GHCR only. They
are an addition: the default images, the appliance and the default chart values
are unchanged, and the nightly does not publish `-ubi` tags (the release does,
after the same Trivy gate, per architecture on a native runner). They run as a
numeric non-root `USER` and keep the random-uid behaviour above. BIND 9.20 and
Kea are built from checksummed source, since Red Hat ships neither at these
versions (see `docs/THIRD_PARTY.md`). Compared with the default images the UBI
ones lack `whois` and `traceroute` (the Tools page reports the missing binary),
the NFS backup destination (`libnfs`), `kea-admin` and the SQL lease backends in
the Kea image, and the frontend's nginx is Red Hat's 1.26.

`charts/spatiumddi/values-openshift-certified.yaml` selects them:

```bash
oc create secret docker-registry redhat-registry -n spatiumddi \
  --docker-server=registry.redhat.io \
  --docker-username=<registry service account> --docker-password=<token>
helm install ddi oci://ghcr.io/spatiumnorth/charts/spatiumddi \
  --version <CHART_VERSION> --namespace spatiumddi --create-namespace \
  -f values-openshift-certified.yaml
```

It keeps `openshift.scc.create: true`, so the chart creates the DNS and DHCP
agents' SecurityContextConstraints exactly as the plain chart does (Red Hat
confirmed that SCCs in a certified chart are acceptable). The control plane needs
none and runs under `restricted-v2`; the agents are admitted by the chart's SCCs
when you enable them. Creating an SCC needs cluster-scoped permissions, so a user
who is admin of one namespace only cannot install with the agents on: Helm (and
the web console's Helm install) stops before creating anything, with
`securitycontextconstraints ... is forbidden ... at the cluster scope`. Where your
cluster admins manage SCCs, or the installing user is a namespace admin, set
`openshift.scc.create: false` and follow **If your cluster admins manage SCCs**
below: a cluster admin applies the SCC files once, and the namespace admin can
then install.

It also sets `image.tagSuffix: -ubi` (appended to the tag of those four images; the
agents' BIND9 and Kea included) and runs the bundled PostgreSQL and Redis from
Red Hat's `registry.redhat.io/rhel9/postgresql-16` and `rhel9/redis-7`
(`postgresql.image.flavor: rhel`, `redis.image.flavor: rhel`; standalone kind
only, and the Redis 8-only `aof-load-corrupt-tail-max-size` is not passed to
Redis 7). Those two need a Red Hat registry pull secret, an account at
<https://access.redhat.com/terms-based-registry/>; the chart passes
`image.pullSecrets` to them as to every other pod. The two Red Hat tags are
immutable `<RHEL minor>-<build>` builds. The `rhel` flavors follow the sclorg
image contract (`POSTGRESQL_*` variables, `/var/lib/pgsql/data`,
`/var/lib/redis/data`) and have been rendered and schema-checked, not yet run
against a `registry.redhat.io` pull. For anything beyond a single pod of each,
bring your own PostgreSQL and Redis (`externalDatabase`, `externalRedis`).

The release runs Red Hat's `preflight check container` against each `-ubi` image
(amd64, check only, never submitting); `.github/workflows/build-ubi-images.yml`
does the same on a PR and weekly.

**If your cluster admins manage SCCs.** Set `openshift.scc.create: false` (with the
certified profile or without it), for example `--set openshift.scc.create=false`
after `-f values-openshift-certified.yaml`. The chart still renders the agents' ServiceAccounts (`<fullname>-dns-agent`,
`<fullname>-dhcp-agent`, where `<fullname>` is `<release>-spatiumddi`, or the
release name when it already contains `spatiumddi`) but no SCC, so an agent pod is
admitted under `restricted-v2` and fails to start (`named` and `kea-dhcp4` cannot
get `NET_BIND_SERVICE` / `NET_RAW`) until a cluster admin has done the following.
Ready-to-apply manifests ship in the chart under `files/openshift/`; fetch them
with `helm pull oci://ghcr.io/spatiumnorth/charts/spatiumddi --version <CHART_VERSION> --untar`:

| File | SCC name | Allows | For |
|---|---|---|---|
| `dns-agent-scc.yaml` | `spatiumddi-dns-agent` | `NET_BIND_SERVICE` | BIND9 DNS agents |
| `dhcp-agent-scc.yaml` | `spatiumddi-dhcp-agent` | `NET_BIND_SERVICE`, `NET_RAW` | Kea DHCP agents |
| `dhcp-agent-hostnetwork-scc.yaml` | `spatiumddi-dhcp-agent-hostnetwork` | the above plus host network / ports | Kea only when a server sets `hostNetwork: true` (use instead of the one above) |

Each is the same SCC the chart renders with `openshift.scc.create: true` (a CI
check keeps them identical), with a release-independent name: `restricted-v2`
plus those capabilities and `allowPrivilegeEscalation: true`, not privileged.

1. As a cluster admin, apply the SCC(s) for the agents you will run (cluster-scoped,
   once per cluster):

   ```bash
   oc apply -f spatiumddi/files/openshift/dns-agent-scc.yaml
   oc apply -f spatiumddi/files/openshift/dhcp-agent-scc.yaml   # or dhcp-agent-hostnetwork-scc.yaml
   ```

2. Grant each SCC to its ServiceAccount (the account does not have to exist yet):

   ```bash
   oc adm policy add-scc-to-user spatiumddi-dns-agent  -z ddi-spatiumddi-dns-agent  -n spatiumddi
   oc adm policy add-scc-to-user spatiumddi-dhcp-agent -z ddi-spatiumddi-dhcp-agent -n spatiumddi
   ```

   (shown for release `ddi` in namespace `spatiumddi`; `-z` takes the
   ServiceAccount name without the namespace.) Do not grant an SCC to the
   namespace's `default` account.

3. Enable the agents: `--set dnsAgents.enabled=true --set dnsAgents.servers[0].name=ns1`
   and/or `--set dhcpAgents.enabled=true --set dhcpAgents.servers[0].name=dhcp1`
   on `helm install` / `helm upgrade`. Without a server listed no agent pod is
   rendered.

4. Verify with the `openshift.io/scc` annotation check above: the DNS agent pods
   must show `spatiumddi-dns-agent` and the DHCP agent pods `spatiumddi-dhcp-agent`
   (or `-hostnetwork`). If the agent pods never appear, the grant in step 2 is
   missing or names the wrong ServiceAccount: the StatefulSet's events show
   `FailedCreate ... unable to validate against any security context constraint`.
   Fix the grant and the pods are created without another `helm upgrade`.

To remove the prerequisite after `helm uninstall`, undo the grants and delete the
SCCs. Deleting an SCC leaves behind the ClusterRole that `add-scc-to-user`
created, so delete that as well:

```bash
oc adm policy remove-scc-from-user spatiumddi-dns-agent  -z ddi-spatiumddi-dns-agent  -n spatiumddi
oc adm policy remove-scc-from-user spatiumddi-dhcp-agent -z ddi-spatiumddi-dhcp-agent -n spatiumddi
oc delete scc spatiumddi-dns-agent spatiumddi-dhcp-agent
oc delete clusterrole system:openshift:scc:spatiumddi-dns-agent system:openshift:scc:spatiumddi-dhcp-agent
```

`openshift.workerNetRaw` is not covered by these files: with `openshift.scc.create: false` it needs an SCC for the worker's ServiceAccount that you write yourself, or leave it off (the default).

With the default `openshift.scc.create: true`, certified profile or not, none of this
is needed: the chart creates the same SCCs, named
`<fullname>-<namespace>-dns-agent` / `-dhcp-agent`.

To run Red Hat's checks yourself, install
[`openshift-preflight`](https://github.com/redhat-openshift-ecosystem/openshift-preflight)
and run `preflight check container ghcr.io/spatiumnorth/spatiumddi-api:<version>-ubi`
(add `--platform amd64`). Check-only mode needs no account; do not pass
`--submit`. The default (non-`-ubi`) images fail `RunAsNonRoot` and
`BasedOnUbi` by design. For the chart, `chart-verifier verify` against the packaged
`.tgz` runs the offline checks (`helm lint`, schema, annotations).

**Reaching DNS and DHCP from outside the cluster.** The Route is for the UI
only: a Route carries HTTP and TLS, not DNS on 53 or DHCP on 67. Both need a
`LoadBalancer` Service (MetalLB on bare metal), and DHCP also needs a relay or
`hostNetwork`. See [Exposing DNS to clients](#exposing-dns-to-clients) and
[Exposing DHCP to clients](#exposing-dhcp-to-clients).

---

## 2. Install

```bash
# Default install — all-in-one with bundled standalone Postgres + Redis
helm install ddi oci://ghcr.io/spatiumnorth/charts/spatiumddi \
  --version <CHART_VERSION> \
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

Behind an Ingress or any TLS-terminating proxy, also set `frontend.trustedProxyCidrs`
and add the streaming annotations (`proxy-buffering: "off"`,
`proxy-read-timeout: "3600"`); without them the login throttle keys on the
ingress address and the AI chat stream hangs. See
[`REVERSE_PROXY.md`](REVERSE_PROXY.md).

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
      service: { type: LoadBalancer }   # opt-in; see "Exposing DNS to clients" below
    # PowerDNS (issue #127 — ALIAS, LUA, online DNSSEC, catalog zones).
    # Lives in its own group: the control plane rejects mixed-driver
    # groups for those PowerDNS-only features.
    - name: pdns1
      flavor: powerdns
      role: primary
      group: powerdns-edge
      service: { type: LoadBalancer }   # opt-in; see "Exposing DNS to clients" below
    # Technitium (issue #746 — native DoT / DoH / DoQ with no sidecar,
    # encrypted upstream forwarding; no DNSSEC or catalog zones in 1.0).
    # Also its own group, same single-driver rule.
    - name: tech1
      flavor: technitium
      role: primary
      group: technitium-edge
      service: { type: LoadBalancer }   # opt-in; see "Exposing DNS to clients" below

dhcpAgents:
  enabled: true
  agentKey:
    existingSecret: spatium-dhcp-agent-key  # must carry key SPATIUM_AGENT_KEY
  servers:
    - name: dhcp1
      role: primary
      service: { type: LoadBalancer }   # a relay target; see "Exposing DHCP to clients" below
```

The agent Services default to `ClusterIP` (#3229), reachable in-cluster only.
Getting client traffic to them is different for the two services, and each
has its own section below: [Exposing DNS to clients](#exposing-dns-to-clients)
and [Exposing DHCP to clients](#exposing-dhcp-to-clients).

Pre-create the bootstrap PSK Secrets (or use `agentKey.value` inline for lab
use only):

```bash
kubectl -n spatiumddi create secret generic spatium-dns-agent-key \
  --from-literal=DNS_AGENT_KEY="$(openssl rand -hex 32)"
kubectl -n spatiumddi create secret generic spatium-dhcp-agent-key \
  --from-literal=SPATIUM_AGENT_KEY="$(openssl rand -hex 32)"
```

Each server entry renders a StatefulSet + a Service (default type
`ClusterIP`; `LoadBalancer` and `NodePort` are opt-in, see below). The image is selected by `flavor`: the default
`dnsAgents.image` configures BIND9; `flavor: powerdns` pulls
`ghcr.io/spatiumnorth/dns-powerdns` and switches the state-volume mount path to
`/var/lib/powerdns` for the LMDB store; `flavor: technitium` pulls
`ghcr.io/spatiumnorth/dns-technitium` and mounts it at `/etc/dns`, where
Technitium keeps its own config + zone store. The agent reads `CONTROL_PLANE_URL`
(set by the chart to the in-cluster api Service), exchanges its PSK for a
rotating JWT, and long-polls the config bundle — the full bootstrap +
registration flow is in [`DNS_AGENT.md`](DNS_AGENT.md) and summarised in
[`k8s/README.md` → How servers register](https://github.com/spatiumnorth/spatiumddi/blob/main/k8s/README.md#how-servers-register).

**Naming of agent objects (#3209).** The StatefulSet, Service and headless
Service are named `dns-<flavor>-<name>` (DHCP: `dhcp-<flavor>-<name>`), without
the release fullname, so two releases in one namespace collide. Set
`dnsAgents.prefixWithFullname: true` (and `dhcpAgents.prefixWithFullname`) to
get `<fullname>-dns-<flavor>-<name>` (a name over 52 characters is cut to 43
plus a hash of the whole, so it stays unique). It defaults to `false` because a
StatefulSet cannot be renamed: changing it on a live install deletes the old
StatefulSet and creates a new one with **new PVCs** and a new pod name (the
server's registered identity), so the agent registers again as a new server.
Set it at install time; the default is expected to flip in a later release.

**Placement and storage (#3206).** A server's `affinity` is merged with the
chart's preferred one-per-node anti-affinity, so you can *prefer* a node
without pinning it; `dnsAgents.storageClass` / `dhcpAgents.storageClass` (and
`servers[].storageClass`) set the class of both volume claims, which otherwise
use the cluster's default StorageClass. Set it before the first install: claim
templates are immutable, so Kubernetes refuses the change on a live
StatefulSet, and a PVC that already exists keeps the class it was created with.
On an existing install, `kubectl delete sts <name> -n <ns> --cascade=orphan`
(pod and PVCs survive) and then upgrade or sync again; `helm upgrade` stops
with that command when it detects the change. See the chart README,
[Adopting `storageClass` on an existing install](https://github.com/spatiumnorth/spatiumddi/blob/main/charts/spatiumddi/README.md#adopting-storageclass-on-an-existing-install).

Per-server entry fields (`name`, `role`, `group`, `storage.*`, `storageClass`,
`service.type`, `service.nodePort`, `hostNetwork`, the DNS-only `service.*`
fields and `dotPort` / `dohPort` / `doqPort`, `resources`, `nodeSelector`,
`tolerations`, `affinity`) are documented in the
[chart README → Agents](https://github.com/spatiumnorth/spatiumddi/blob/main/charts/spatiumddi/README.md#agents) table.

### Exposing DNS to clients

**What a DNS agent serves.** The ports are the same for every flavor; which
encrypted listeners exist depends on the flavor.

| Port | Protocol | What | Flavors | In the Service |
|---|---|---|---|---|
| 53 | UDP | DNS | all | always |
| 53 | TCP | DNS: truncated (TC) answers, large DNSSEC responses, AXFR / IXFR | all | always |
| 853 (`dot_port`) | TCP | DNS-over-TLS | `bind9`, `technitium` | only with `servers[].dotPort` |
| 443 (`doh_port`) | TCP | DNS-over-HTTPS, path `/dns-query` | `bind9`, `technitium` | only with `servers[].dohPort` |
| 853 (`doq_port`) | UDP | DNS-over-QUIC | `technitium` only | only with `servers[].doqPort` |

Both 53/udp and 53/tcp have to reach the server: a resolver that answers UDP
but not TCP fails on the first response too large for one datagram. The chart
puts both in one Service, so the address is the same for both.

DoT, DoH and DoQ are off by default, and the listener ports are set on the
server group (DNS → Server Groups → Options → Encrypted transports), not in
the chart: see [DNS §20, Encrypted transports](../features/DNS.md).
`dotPort` / `dohPort` / `doqPort` on a server only add the containerPort and
Service port, so set them to the numbers you chose on the group. The chart
refuses `doqPort` on any flavor but `technitium` (BIND9 has no QUIC listener)
and `dotPort` / `dohPort` on `flavor: powerdns` (its DoT / DoH front is
Docker Compose only). DoH on 443 is allowed on Kubernetes; pick another port
(8443 is the usual choice) only if 443 on that address is already taken.

**How to expose it.** The agent Services default to `ClusterIP` (#3229),
reachable in-cluster only. Each server is its own single-replica StatefulSet
with its own Service, so each server gets its own address; that is what you
want for DNS, where clients are configured with two or more resolver
addresses.

- **`LoadBalancer` with a fixed address** (recommended). Set
  `service.type: LoadBalancer`. The address is what you hand to clients, so
  pin it: with MetalLB use the `metallb.universe.tf/loadBalancerIPs`
  annotation (`service.annotations`), elsewhere `service.loadBalancerIP` or
  your provider's own annotation. `service.loadBalancerSourceRanges`,
  `service.ipFamilyPolicy` and `service.ipFamilies` are rendered when set.
- **`NodePort`**. Port 53 is outside the NodePort range (30000–32767), so
  clients cannot use it directly. It only works behind your own forwarder or
  an external load balancer that listens on 53 and forwards to the node port.
- **`hostNetwork`** is not offered for DNS agents. Binding the node's own :53
  would collide with `systemd-resolved` on most distributions.

```yaml
dnsAgents:
  enabled: true
  agentKey:
    existingSecret: spatium-dns-agent-key
  servers:
    - name: ns1
      role: primary
      group: internal-resolvers
      service:
        type: LoadBalancer
        annotations:
          metallb.universe.tf/loadBalancerIPs: 192.0.2.53
        # externalTrafficPolicy: Local    # the chart's default for LoadBalancer
        # loadBalancerSourceRanges: [10.0.0.0/8]
      # Only when the group has DoT / DoH turned on, matching its ports:
      # dotPort: 853
      # dohPort: 443
    - name: ns2
      role: secondary
      group: internal-resolvers
      service:
        type: LoadBalancer
        annotations:
          metallb.universe.tf/loadBalancerIPs: 192.0.2.54
```

**Client source addresses (`externalTrafficPolicy`).** A `LoadBalancer` DNS
Service is rendered with `externalTrafficPolicy: Local` (#1548). Under
`Cluster`, kube-proxy rewrites the source of every query to a node or CNI
address, so ACLs and views match the wrong address, query logs and blocklist
hits name the node instead of the client, and a per-client rate limit
throttles the whole network at once. `Local` keeps the client address. Its
cost is that only the node running the pod accepts traffic for the address.
With one pod per Service that is no loss: MetalLB announces the address from
that node only, and a cloud load balancer health-checks the other nodes out.
While the pod is rescheduled the address answers nothing, which is why clients
should have a second resolver. Set `service.externalTrafficPolicy: Cluster`
to opt out. On a `NodePort` Service the field is rendered only when you set
it.

**UDP and TCP on one address.** One Service with 53/udp and 53/tcp is a
mixed-protocol `LoadBalancer` Service. Kubernetes supports that on every
version the chart runs on (it has been GA since 1.26), but the load balancer
has to implement it too. MetalLB does. Some cloud load balancers do not, and
leave the Service pending or serve one protocol only. The chart renders one
Service per server, so on such a platform leave the server on `ClusterIP` and
create your own two Services (one per protocol) with the same selector as
the chart's Service (`kubectl get svc dns-bind9-ns1 -o yaml` shows it),
sharing one address the way your provider documents.

**k3s: do not use servicelb for port 53.** The bundled **servicelb** turns a
`LoadBalancer` Service into an `svclb-*` pod with `hostPort: 53` on every
node, and the CNI hostPort DNAT also captures the node's own resolver stub at
`127.0.0.53:53`. The node then cannot resolve anything, so image pulls fail
(`lookup ghcr.io: Try again`), local-path provisioning times out and the
install never converges. UDP 67 for DHCP goes through the same mechanism.
Start k3s with `--disable servicelb` and install MetalLB, or another
implementation that does not use hostPort 53 (kube-vip, Cilium LB-IPAM). If
servicelb already took the port, delete the Service and the `svclb-*`
DaemonSet; `iptables -t nat -S CNI-HOSTPORT-DNAT | grep 'dports 53'` should
then come back empty.

**OpenShift.** A Route carries HTTP and TLS only, so the chart's Route serves
the UI and nothing else: DNS needs a `LoadBalancer` Service exactly as above.
On bare metal that means MetalLB (the MetalLB Operator); on a cloud install,
the platform's load balancer. Nothing extra is needed for the port itself:
the chart's DNS agent SCC already allows `NET_BIND_SERVICE`, and the pod
binds :53 in its own network namespace (see [OpenShift](#openshift)). Only
the `bind9` flavor runs there.

**Check it.**

```bash
kubectl -n spatiumddi get svc dns-bind9-ns1     # EXTERNAL-IP is the address
dig @192.0.2.53 www.example.com A               # UDP
dig +tcp @192.0.2.53 www.example.com A          # TCP: must answer too
dig @192.0.2.53 example.com AXFR                # from a host the zone allows transfers to

# With DoT / DoH on, against the name in the certificate:
kdig +tls @dns.example.com -p 853 www.example.com A
dig +https=/dns-query @192.0.2.53 -p 443 www.example.com A
```

To confirm the client address survives, turn on query logging for the group
and check that the logged client is your workstation, not a node or pod
network address.

Upgrading from a chart that defaulted to `LoadBalancer`: a server that never
set `service.type` becomes `ClusterIP` and **releases its external IP**. Add
`service: { type: LoadBalancer }` (with the same address) to each server that
must keep serving clients before you upgrade. See the
[chart README](https://github.com/spatiumnorth/spatiumddi/blob/main/charts/spatiumddi/README.md#exposing-dns-and-dhcp-to-clients).

### Exposing DHCP to clients

DHCP does not work like DNS. A client with no address sends its DISCOVER from
`0.0.0.0` to the broadcast address `255.255.255.255`, UDP port 67, and the
answer comes back to port 68. A broadcast stays on its own layer-2 segment:
it is not routed into the cluster network, and neither kube-proxy nor a load
balancer forwards it. So a Kea pod behind a Service, of any type, hears
nothing from clients on a plain VLAN. There are two shapes that work.

| Shape | Kea runs | Clients reach it through | Use when |
|---|---|---|---|
| **(a) Relayed** | on the pod network, behind a `LoadBalancer` Service on 67/udp | a DHCP relay on each client VLAN's gateway | the normal routed network: many VLANs, a central DHCP service |
| **(b) Same segment** | with `hostNetwork: true` on a node attached to the client VLAN | the broadcast itself | a single flat network, a lab, or a site with no relay |

#### (a) Behind a DHCP relay

The router or layer-3 switch that is the gateway of each client VLAN runs a
DHCP relay. It picks up the client's broadcast, writes its own address on
that VLAN into the packet's `giaddr` field, and sends the packet as ordinary
unicast UDP to port 67 of the DHCP server. Unicast is something a Service can
carry, so a `LoadBalancer` Service works:

```yaml
dhcpAgents:
  enabled: true
  agentKey:
    existingSecret: spatium-dhcp-agent-key
  servers:
    - name: dhcp1
      role: primary
      group: default
      service: { type: LoadBalancer }
```

Then, on each client VLAN's gateway, point the relay at the Service's
external address (`192.0.2.67` below):

```text
! Cisco IOS / IOS-XE, on each client SVI
interface Vlan30
 ip address 10.20.30.1 255.255.255.0
 ip helper-address 192.0.2.67
```

Other platforms have the same function under another name: Arista EOS
`ip helper-address` on the interface, Juniper Junos
`forwarding-options dhcp-relay` with a `server-group`, Linux `dhcrelay`
(`isc-dhcp-relay`) or a firewall's DHCP relay service.

What has to be true for it to work:

- **A scope for every relayed subnet.** Kea picks the subnet from `giaddr`,
  so the server group needs a scope for each client subnet
  (`10.20.30.0/24` above). If the relay's address is not inside the subnet it
  relays for, list it under **Relay agents (giaddr)** on the scope.
- **The group's Client reachability.** A pod-network server only ever sees
  relayed traffic, which is what **Relay** (`dhcp_socket_mode: relay`) is
  for. The default, **Direct**, also receives relayed packets, but needs raw
  sockets. See [DHCP → Server Groups](../features/DHCP.md#dhcp-server-groups).
- **The return path.** Kea answers a relayed request to `giaddr`, port 67,
  not to the address the packet came from, so the server needs a route to
  every relay address. The answer leaves the pod as ordinary egress traffic,
  so its source address is whatever your CNI uses for pod egress (usually a
  node address), not necessarily the LoadBalancer address. Firewalls between
  the cluster and the relays must allow 67/udp from the relays to the
  LoadBalancer address, and 67/udp from the cluster to every relay address.
  A firewall or relay that only accepts answers from the address it forwarded
  to may drop them; check with your CNI, or use shape (b), with the relay
  pointed at the node, in that case.
- **Renewals.** A client renews by unicast to the server address named in
  its lease (option 54). If that address is not reachable from the client
  VLAN, the client falls back to a broadcast at rebinding time, which the
  relay forwards. Check which address your clients see as their DHCP server
  before relying on unicast renewals.
- **A stable address.** Relays are configured with the address, so it must
  not change. The DHCP Service renders `service.type` and `service.nodePort`
  only: unlike the DNS Service it takes no `annotations`, `loadBalancerIP` or
  `externalTrafficPolicy` from values. Let the load balancer assign the
  address from a pool (it keeps it for the life of the Service) and configure
  the relays with what `kubectl get svc` shows, or pin it outside the chart.
  `externalTrafficPolicy` stays at the Kubernetes default (`Cluster`), which
  is harmless here because Kea uses `giaddr`, not the packet's source.
- **`NodePort` is not a substitute.** `port: 67` on a NodePort Service is
  in-cluster only; the node-facing port is a random 30000–32767 pick, or the
  one you pin with `service.nodePort`. Most relays, `ip helper-address`
  included, send to 67 only.
- **k3s servicelb** breaks here the same way it does for DNS; see above.

Only 67/udp is exposed. Kea's HA listener (TCP 8000) is on the headless
Service only and is never published. For a pair, put two servers in one
group in `hot-standby` or `load-balancing` mode, each with its own
`LoadBalancer` Service, and configure **both** addresses on every relay (two
`ip helper-address` lines); see
[DHCP §14, Kea HA on a server group](../features/DHCP.md)
for the group mode and the peer URLs.

#### (b) On the same segment as the clients (`hostNetwork`)

```yaml
dhcpAgents:
  enabled: true
  agentKey:
    existingSecret: spatium-dhcp-agent-key
  servers:
    - name: dhcp1
      role: primary
      group: default
      hostNetwork: true
      nodeSelector: { kubernetes.io/hostname: node-a }
```

With `hostNetwork: true` Kea binds UDP 67 on the node's own interfaces, so
it hears broadcasts from every VLAN the node has an interface on, and a relay
can also target the node's address directly. Keep the group's Client
reachability on **Direct**. The pod still gets a `ClusterIP` Service, which
plays no part in serving clients.

This is the shape the SpatiumDDI appliance uses: its Kea runs with
`hostNetwork`. On an appliance node with a second interface on a client
network, a broadcast DISCOVER from that network was answered and the lease
showed in SpatiumDDI. A request relayed by `dhcrelay` from another subnet was
also answered, once the node had a route back to the relay's subnet: Kea
replies to `giaddr`, so the node must be able to reach every relay address.

It is rarely the right shape in a cluster: the node needs an interface on
every client VLAN, the server is tied to that node (pin it with
`nodeSelector`, because a pod rescheduled to another node serves a different
set of segments), nothing else on the node may own UDP 67, and the pod gives
up network isolation from the node. On OpenShift the chart's DHCP agent SCC
gains `allowHostNetwork` / `allowHostPorts` as soon as any DHCP server sets
`hostNetwork: true` (see [OpenShift](#openshift)); where cluster admins
manage SCCs, that is an extra grant to ask for. Prefer shape (a) wherever the
network has a relay, and for a site without one consider running the agent
outside the cluster, next to the clients
([`DOCKER.md` → Distributed Agent Deployments](DOCKER.md#10-distributed-agent-deployments)).

#### Check it

```bash
kubectl -n spatiumddi get svc dhcp-kea-dhcp1          # EXTERNAL-IP: the relay target
kubectl -n spatiumddi logs dhcp-kea-dhcp1-0 -f | grep -E 'DHCP4_PACKET_(RECEIVED|SEND)'
```

Renew a lease on a client in a relayed VLAN (`dhclient -v`, or
`ipconfig /renew` on Windows) and watch the log: a `DHCP4_PACKET_RECEIVED`
line for the DISCOVER, then a `DHCP4_PACKET_SEND` for the OFFER, and the
lease on the group's Leases tab under DHCP. Packet logging is on by default
(`kea_packet_logging` on the group). How to read the result:

- **Nothing received**: the relay is not reaching the Service. Check the
  helper address, routing to the LoadBalancer address, and the firewall
  (67/udp towards the cluster).
- **Received, nothing sent**: Kea has no scope matching the `giaddr`, or the
  scope's pool is exhausted.
- **Sent, but the client gets nothing**: the answer is lost on the way back
  to the relay. Check 67/udp from the node addresses to the relay.

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

**A migration never waits silently on a dead client's lock (#3932).** The
1.0.0 upgrade drill left the API "initialising" for over two hours: the
migration's `ALTER TABLE` queued behind a session an old api pod had left *idle
in transaction*. The pod was gone, but PostgreSQL never noticed (the primary had
moved to another node, and the default TCP keepalive is about 2 h 11 min), and
nothing ended the session. Three layers now stop that, none needing a restart:

- **Server side.** `postgresql.cnpg.parameters` sets the TCP keepalives
  (`tcp_keepalives_idle` 60 s, `_interval` 10 s, `_count` 6), so a silent
  peer's session is dropped in about two minutes: that is what fixes the
  drill's case. It also sets `idle_in_transaction_session_timeout` to 1 h, a
  backstop for a client that is alive but stuck in an open transaction. It is
  an hour rather than minutes on purpose: some work legitimately idles in a
  transaction for a while (a scheduled backup's session waits through the
  whole `pg_dump`, up to 30 min, and the upload; a bundle render for a very
  large DNS group computes between statements; a batched WinRM push waits
  between chunks), and Postgres ending that session turns slow work into an
  error. All four are reloads: CNPG applies them to a formed cluster without a
  rolling restart. The in-chart standalone Postgres takes the same values as
  `-c` arguments (`postgresql.idleInTransactionSessionTimeout`); that one
  changes the pod template, so the first upgrade to this chart restarts it
  once. Set `"0"` to turn the idle timeout off.
- **The migrate command** (`alembic upgrade`, so the Job and the compose
  `migrate` service alike) sets `lock_timeout` to
  `MIGRATION_LOCK_TIMEOUT_SECONDS` (default 30), so a revision waiting on a
  lock leaves the lock queue instead of stalling every query queued behind it.
  While a revision waits it samples `pg_blocking_pids` of the migrating backend
  from a second connection; after each timed-out wait it logs `migration
  waiting on lock held by pid N (state, age, application name)` for those
  blockers, and ends the ones that are `idle in transaction`, belong to the
  app's own database role and have been idle longer than `MIGRATION_STALE_IDLE_TXN_SECONDS` (default 300,
  `0` disables), logging each pid, and retries after a pause of up to 30 s.
  It retries **without limit** by default: a migration held up by a
  legitimate long holder, such as a backup's `pg_dump` (which holds a lock on
  every table and is active, not idle; a backup's own idle session holds no
  lock the migration waits on, so it is left alone), waits it out and then succeeds, as it
  did before. `MIGRATION_LOCK_RETRIES` bounds it (`0` gives up on the first
  timeout). Nothing is ended unless a lock wait has actually timed out.
  Revisions commit one by one, so a retry resumes where it stopped. `alembic
  current`, `stamp` and `downgrade` never end a session.
- A session the old api opened before this release's settings applied keeps the
  old keepalive (about 2 h 11 min), since a reloaded setting only reaches a
  session when its client next sends a message; the migration ends it itself
  through the rule above.
- **Still stuck?** Find the holder with `SELECT pid, state, state_change FROM
  pg_stat_activity WHERE state LIKE 'idle in transaction%'` and end it with
  `pg_terminate_backend(pid)`.

**Placement (#3207).** The Job's pod follows the api: `migrate.nodeSelector`,
`migrate.tolerations` and `migrate.affinity` default to unset, meaning
`api.nodeSelector` / `api.tolerations` / `api.affinity.nodeAffinity` (the
api's pod anti-affinity is about api pods and is not copied), with
`global.controlPlaneNodeSelector` merged into the selector as for every
control-plane workload. Set one to `{}` / `[]` to give the Job none of the api's
values. The `wait-for-postgres` / `wait-for-migrate` init containers carry
`initContainers.resources` (#3208; requests `10m` / `32Mi`, limit `256Mi`), so a
namespace LimitRange or a policy that wants resources on every container,
init containers included, admits them.

**GitOps with `helm template` (Argo CD).** A controller that renders with
`helm template` always sees revision `1`, so the Job is `<release>-migrate-r1` on every sync,
and the first image bump fails with `spec.template: field is immutable`. Set
`migrate.annotations` to make the Job a sync hook that is deleted and recreated
on every sync:

```yaml
migrate:
  annotations:
    argocd.argoproj.io/hook: Sync
    argocd.argoproj.io/hook-delete-policy: BeforeHookCreation
```

`helm template` also defeats the chart's `lookup()`, so generated secrets change
on every render. Pre-create them and set the matching `existingSecret` values;
the [chart README](https://github.com/spatiumnorth/spatiumddi/blob/main/charts/spatiumddi/README.md#gitops-with-helm-template-argo-cd)
lists which keys each Secret needs.

---

## 5. Replicas, resources, and autoscaling

Every workload has `resources.requests`/`limits` defaults in
[`values.yaml`](https://github.com/spatiumnorth/spatiumddi/blob/main/charts/spatiumddi/values.yaml) (see the per-workload
blocks) and a per-component `nodeSelector` / `tolerations` / `affinity` /
`podAnnotations`. Override them under the matching key.

Per-pod memory and CPU, measured on a one-node k3s cluster (amd64 and
arm64) and on the appliance, which runs this same chart, are in
[`SIZING.md`](SIZING.md#kubernetes), and the api and worker defaults are
sized from them (#3110). One api process holds about 300 MiB at rest and
held 0.4 to 0.85 GiB on the appliance, hence its 512Mi request and 1Gi
limit; the worker levels off near 1 GiB, hence its 2Gi limit.

The **api Deployment has a HorizontalPodAutoscaler** (`autoscaling/v2`), gated
on `api.autoscaling.enabled` (**default `true`**):

```yaml
api:
  replicas: 2                            # only with autoscaling.enabled: false
  autoscaling:
    enabled: true
    minReplicas: 2
    maxReplicas: 10
    targetCPUUtilizationPercentage: 70   # of the 200m request
    targetMemoryUtilizationPercentage:   # unset: memory is opt-in
  resources:
    requests: { cpu: 200m, memory: 512Mi }
    limits:   { cpu: 1000m, memory: 1Gi }
```

The HPA scales on CPU. Memory is opt-in (#3110): an api process holds about
300 MiB from the moment it starts, and that does not fall as replicas are
added, so a memory target below it holds the HPA at `maxReplicas` for good. If
you set one, use 73 or more with the 512Mi request.

While the HPA is on, the chart renders no `replicas` on the api Deployment, so
the HPA alone sets the count and `helm upgrade` keeps it (#3111); `api.replicas`
applies only with `api.autoscaling.enabled: false`. The HPA needs a running
metrics-server in the cluster (most managed Kubernetes offerings ship one), and
without one it holds the api at `minReplicas`. Install
[metrics-server](https://github.com/kubernetes-sigs/metrics-server), or set
`api.autoscaling.enabled: false` and manage `api.replicas` directly. No other
workload defines an HPA — `frontend` / `worker` are fixed-replica Deployments
(scale by editing `*.replicas`) and `beat` is a hard singleton.

### Worker `NET_RAW`

`nmap`'s SYN scans and `-O` OS detection (the device-profiling auto-nmap path)
use a file capability on the image's `nmap` binary, which works only while
`NET_RAW` is in the container's bounding set. containerd's default capability
set already includes `NET_RAW`, so on k3s, Talos, EKS, AKS and GKE the worker
has it with no setting at all.

`worker.netRawCapability` (default `false`, [#3952](https://github.com/spatiumnorth/spatiumddi/issues/3952))
adds `NET_RAW` explicitly. You need it only on a runtime whose default set lacks
it, which in practice means CRI-O outside OpenShift. Turning it on makes Pod
Security `baseline` and `restricted` **refuse the worker pod at admission**.
They do not drop the capability. A namespace that enforces either level then
needs `pod-security.kubernetes.io/enforce: privileged`, or an exemption. On
OpenShift use `openshift.workerNetRaw` instead (see above).

Verified on k3s with the default (`false`): the worker's bounding set carries
`NET_RAW`, and `nmap -sS` and `-O` both run. Where `NET_RAW` is absent, nmap can
do only what an unprivileged process can, a TCP connect scan with no OS
detection.

### Pod Security levels

The [Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
level each component needs with the chart's defaults:

| Component | Highest level that admits it |
|---|---|
| api, worker, beat, frontend, migrate Job, Postgres, Redis | `baseline` |
| DNS agents (`dns-bind9-*`), DHCP agents with `hostNetwork: false` | `baseline` |
| DHCP agents with `hostNetwork: true` (relay-less LAN) | `privileged`: `baseline` forbids host networking |
| worker with `worker.netRawCapability: true` | `privileged`: `baseline` forbids adding `NET_RAW` |

None of them pass `restricted`: every container fails its
`allowPrivilegeEscalation: false`, `capabilities.drop: ["ALL"]` and
`runAsNonRoot` checks. Measured with
`kubectl label --dry-run=server ns spatiumddi pod-security.kubernetes.io/enforce=<level>`
on a default single-node install with one BIND9 and one Kea agent (#3952).

So a default install, with DHCP agents off host networking, runs in a namespace
that enforces `baseline`. Talos enforces `baseline` cluster-wide by default.

---

## 6. High availability

For production, flip the in-chart database and cache to their HA shapes via
`kind`. Both render the HA topology as chart-owned templates — you do **not**
apply the raw `k8s/ha/` prototypes when using the chart; those are standalone
references for non-Helm installs.

### PostgreSQL — CloudNativePG

Set `postgresql.kind: cnpg` to render a CloudNativePG `Cluster` CR (a
primary + streaming replicas with automatic failover) instead of the
single-node StatefulSet.

Replication is **asynchronous**: the `Cluster` sets no
`postgresql.synchronous`, so a commit returns before a replica has it, and a
failover can lose the last few commits (RPO > 0). That trades a small window
of possible loss for write latency that does not depend on a replica. If you
need zero data loss on failover, configure synchronous replication on the
`Cluster` yourself and accept the latency.

```yaml
postgresql:
  enabled: true
  kind: cnpg
  cnpg:
    instances: 3        # smallest quorum-friendly default; 5 / 7 for larger
    imageName: "ghcr.io/cloudnative-pg/postgresql:16"
    # enablePDB: unset = on only with instances > 1 (#3204). With a single
    # instance the PDB allows 0 disruptions and `kubectl drain` of its node
    # hangs, protecting nothing; set true / false to override.
```

Postgres placement: `postgresql.nodeSelector` hard-pins the instances, and
`postgresql.affinity.nodeAffinity` (#3205) is rendered into the Cluster's
`spec.affinity.nodeAffinity` for a preference ("this node, elsewhere if it is
full") beside it.

This requires the **CloudNativePG operator already installed** in the cluster.
The appliance chart bundles it; for a plain Kubernetes install, apply it
separately first:

```bash
kubectl apply --server-side -f \
  https://raw.githubusercontent.com/cloudnative-pg/cloudnative-pg/release-1.30/releases/cnpg-1.30.0.yaml
```

> **Match the operator line to your cluster, not to this page.** CNPG
> publishes a support matrix per minor: 1.30.x covers Kubernetes
> 1.34-1.36, which is what the appliance ships (k3s v1.36.5+k3s1). On an
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
`redis-server` + a `redis-sentinel` sidecar. A starting pod asks the running
sentinels which pod is the master and replicates from it (or starts as master
when they name the pod itself); only when no sentinel answers, the whole set
starting cold, does pod-0 start as master with the rest replicating from it.
The sentinels elect a new master and fail over automatically. The api / worker / beat pick up a `sentinel://` URL and resolve
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
Under `hard` this holds at one replica too (#1541): a demote from three
nodes to one renders a single replica with no anti-affinity, but the old
pod it replaces still carries the 3-node required term, which keeps a
surged pod off the only node. So a one-node appliance takes a brief api /
worker outage on each rollout, as its frontend already does with
`Recreate`.

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

`--reuse-values` keeps the defaults of the chart the release was installed
from, so upgrade once with `--reset-then-reuse-values` to take a new chart's
defaults, such as the #3110 api sizing
([chart README](https://github.com/spatiumnorth/spatiumddi/blob/main/charts/spatiumddi/README.md#taking-a-new-charts-defaults-3110)).
At the first upgrade to a chart with #3111 the api's replica count changes
hands; the [chart README](https://github.com/spatiumnorth/spatiumddi/blob/main/charts/spatiumddi/README.md#the-apis-replica-count-under-the-autoscaler-3111)
says what each kind of release sees.

Each upgrade renders a fresh per-revision migrate Job; the api / worker / beat
pods' `wait-for-migrate` init containers hold their rollout until the new
schema lands, so the new control-plane pods never come up against an
un-migrated database.

Meanwhile the previous release's api pods stay in service: a pod that has
already been ready keeps answering `/health/ready` while the database is at the
new release's schema, as long as every table and column it uses is still there
(#2777). Under `hard` anti-affinity on a one-node control
plane the only api pod is replaced first, so that install still takes its brief
api outage on every rollout.

### Upgrading from CalVer on Helm with DHCP agents

A Helm install of `2026.10.02-1` or older with `dhcpAgents.enabled` cannot roll
its Kea pod to a newer chart by itself (#3907). That release's readiness probe
was a `tcpSocket` on `:8000`, which a standalone Kea never binds (#1589), so
the pod is never Ready. The `dhcp-kea-*` StatefulSet is `OrderedReady` +
`RollingUpdate`, and Kubernetes does not roll a StatefulSet whose pod is
unready, so the pod stays on the old image and `helm upgrade --wait` times out.

The chart handles this with a `pre-upgrade` hook (a Job, plus a ServiceAccount,
a namespaced Role and a RoleBinding that exist only for the hook). It lists the
DHCP agent StatefulSets of the release and, for one whose pod is Running but
has not been Ready for 2 minutes, deletes the StatefulSet and that pod. Deleting
only the pod would not help, because the hook runs before Helm updates the
StatefulSet and the controller would recreate the pod from the old template.
The volume claims are kept, and `helm upgrade` then creates the StatefulSet from
the new template, so the new pod starts on the new image and probe. A
StatefulSet whose pods are Ready is never touched, a fresh install never runs it, and an
error in the hook is logged without failing the upgrade. DNS agents are not
covered: their probe is the `:53` listener, which no release shipped in a form
that could never pass.

The hook Job runs the **new** release's api image, so an air-gapped site must
load that image into the cluster (or its mirror registry) **before** `helm
upgrade`, as it must for every other pod of the release. If the image cannot be
pulled the Job hits its 120 s deadline and, because Helm waits for hooks, the
upgrade fails; set `dhcpAgents.upgradeUnstickPods=false` to skip the hook.
The hook runs on `helm upgrade` only, not on `helm rollback`: a rollback
re-applies the old template, which cannot be rolled any better than before.
A Job that starts but cannot reach the API server logs the error and exits 0,
leaving the upgrade to proceed (a stuck pod then needs the manual step below);
the hook never fails an upgrade on a cluster error, only on a missing image.

To turn the hook off (`dhcpAgents.upgradeUnstickPods: false`), delete the pod
by hand once `helm upgrade` has applied the new template; the StatefulSet
recreates it from that template, on the new image and probe (the upgrade itself
times out with `--wait`, or run it without):

```bash
kubectl -n <namespace> delete pod <dhcp-kea-name>-0
```

For the version path from 2026.10.02-1 to 1.0.0, and for the appliance and
Compose shapes, see [Upgrading to 1.0.0](APPLIANCE.md#upgrading-to-100).

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

- [`AIRGAP.md`](AIRGAP.md) — air-gapped installs, including every chart image
  value an internal-registry mirror must set
- [`charts/spatiumddi/README.md`](https://github.com/spatiumnorth/spatiumddi/blob/main/charts/spatiumddi/README.md) — full
  values reference, troubleshooting, and a `helm template` dev loop
- [`k8s/README.md`](https://github.com/spatiumnorth/spatiumddi/blob/main/k8s/README.md) — raw `k8s/base/` manifests, the
  `k8s/ha/` prototypes, the static DNS/DHCP StatefulSets, and TLS/Ingress notes
- [`REVERSE_PROXY.md`](REVERSE_PROXY.md) — Ingress / reverse-proxy settings,
  trusted proxies, streaming, troubleshooting
- [`TOPOLOGIES.md`](TOPOLOGIES.md) — reference production topologies + sizing
- [`APPLIANCE.md`](APPLIANCE.md) — the self-contained OS appliance (k3s-based,
  multi-node control-plane HA, MetalLB VIP)
- [`DNS_AGENT.md`](DNS_AGENT.md) — managed DNS container architecture +
  registration flow
- [`DOCKER.md`](DOCKER.md) — Docker Compose deployment + distributed standalone
  agents
