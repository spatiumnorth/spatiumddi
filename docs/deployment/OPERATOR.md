# SpatiumDDI Operator (OperatorHub / OLM)

> **Status: first version, not yet listed or published.** Nothing here changes
> how the Helm chart, Docker Compose or the appliance install. The Operator is
> an additional, optional way to run the chart on a cluster that uses the
> Operator Lifecycle Manager (OLM), notably OpenShift.

## What it is

A Helm-based operator (built with operator-sdk's Helm plugin) around the
[`spatiumddi` umbrella chart](KUBERNETES.md). One custom resource, `SpatiumDDI`
(`ddi.spatiumddi.com/v1alpha1`), is one chart release in its namespace, and its
`spec` is the chart's `values.yaml`. Every chart option and every chart fix is
inherited; there is no second implementation.

- **Capability level II, "Seamless Upgrades".** Install and upgrade. Backups,
  scaling automation, metrics and auto-tuning are not part of it.
- **Install modes:** OwnNamespace and SingleNamespace. One SpatiumDDI per
  namespace; MultiNamespace and AllNamespaces are not supported.
- **Channels:** `stable` (releases) and `candidate` (releases and release
  candidates). A pre-release version goes to `candidate` only.
- **Minimum:** Kubernetes 1.31 (the chart's floor), OpenShift 4.18.
- **One chart version per Operator version.** The chart baked into the image is
  stamped with the Operator's version, which is also the application version, so
  the default image tags (`api`, `frontend`, agents) are that version.

## Install on OpenShift (once listed)

Console: **Operators > OperatorHub**, search for SpatiumDDI, install into a
namespace of its own (suggested: `spatiumddi`), channel `stable`. Then
**Installed Operators > SpatiumDDI > Create SpatiumDDI** and use the example.

Until it is listed, install the bundle by hand (see "Trying a bundle" below).

## Install with OLM on vanilla Kubernetes

Install OLM, then create an OperatorGroup and a Subscription for the catalog
that carries the bundle (OperatorHub.io once listed):

```yaml
apiVersion: v1
kind: Namespace
metadata: {name: spatiumddi}
---
apiVersion: operators.coreos.com/v1
kind: OperatorGroup
metadata: {name: spatiumddi, namespace: spatiumddi}
spec:
  targetNamespaces: [spatiumddi]
---
apiVersion: operators.coreos.com/v1alpha1
kind: Subscription
metadata: {name: spatiumddi, namespace: spatiumddi}
spec:
  channel: stable
  name: spatiumddi
  source: operatorhubio-catalog
  sourceNamespace: olm
```

## An example resource

```yaml
apiVersion: ddi.spatiumddi.com/v1alpha1
kind: SpatiumDDI
metadata:
  name: spatiumddi
spec:
  api: {replicas: 1, autoscaling: {enabled: false}}
  worker: {replicas: 1}
  frontend: {replicas: 1}
  postgresql: {kind: standalone}
  redis: {kind: standalone}
  dnsAgents: {enabled: true, servers: [{name: ns1}]}
  dhcpAgents: {enabled: true, servers: [{name: dhcp1}]}
```

Name it `spatiumddi` to get object names without a doubled prefix. On OpenShift
the Operator creates the Route and the agents' SecurityContextConstraints, as
the chart does ([KUBERNETES.md, OpenShift](KUBERNETES.md#openshift)); the
control plane runs under `restricted-v2`. Check the install the way that page
describes. The default login is `admin` / `admin`, changed at first login.

## Upgrades

Subscribing to a channel with automatic approval follows new Operator versions.
An Operator upgrade swaps the Operator pod, whose image carries the new chart.
For each `SpatiumDDI` it then runs the equivalent of `helm upgrade` with the
resource's unchanged values: the image tags move to the new version, a new
migrate Job runs `alembic upgrade head`, and the api, worker and beat pods wait
for the schema in their `wait-for-migrate` init containers. Take a PostgreSQL
backup before every upgrade; the Operator does not.

How the Operator decides to upgrade matters here. helm-operator dry-runs
`helm upgrade` on every reconcile (every 10 minutes, and whenever a resource of
the release changes) and runs a real upgrade only when that manifest differs
from the deployed one. The Operator therefore sets two things in
`operator/watches.yaml`:

- `dryRunOption: server`, so the chart's `lookup` calls run in the dry-run.
  Without it the generated Secrets (SECRET_KEY, the PostgreSQL and Redis
  passwords) render fresh random values in every dry-run, and every reconcile
  looks like a change.
- `migrate.nameByContent: "true"` as an override value. The migrate Job is then
  named after a hash of the values, the chart version and the Kubernetes
  version instead of the Helm revision, and the finished Job is kept rather than
  expired after 600 s. A revision in the name differs in every dry-run, and an
  expired Job would be re-created and re-run. A change to the resource's spec,
  a new Operator version or a cluster upgrade gives a new name, so the Job is
  replaced, never patched (its pod template is immutable). One finished
  `-migrate-<hash>` Job per release stays in the namespace; this setting is
  forced and the resource cannot turn it off.

OLM orders versions as SemVer (`updateGraph: semver-mode`): `1.0.0-rc.1` <
`1.0.0` < `1.0.1`. CalVer releases (`2026.09.04-1`) are not SemVer, so the
Operator starts at 1.0.0.

## Limits

- Appliance-only chart options need cluster-scoped rights the Operator
  deliberately lacks: `api.serviceAccount`, `api.upgradeOrchestratorRBAC`,
  `worker.serviceAccount` (so `openshift.workerNetRaw`), `api.serviceControlRBAC`
  and `api.applianceHostMounts`. Setting them fails the release with a Forbidden
  error on the resource's status.
- The CRD has no field schema: the chart validates at render time and the
  Operator shows the error on the resource's status.
- **The SecurityContextConstraints grant is a cluster-admin-level trust.** On
  OpenShift the chart creates one SCC per agent kind, named after the release
  and namespace, so OLM grants the Operator create / update / patch / delete on
  every SCC in the cluster (the names cannot be listed in advance), and `use`
  on any SCC in the namespaces it watches. Anything holding those verbs can
  write a privileged SCC, or loosen a built-in one, and so run privileged pods.
  The chart's own SCCs are `restricted-v2` plus the agents' capabilities (no
  privileged containers, no host paths), and the Operator holds no `bind` or
  `escalate`, but install it only where you would let it administer SCCs.
  `openshift.scc.create: false` stops the chart creating them; OLM still grants
  the rights, because a CSV cannot make them optional. On clusters without the
  `security.openshift.io` API the grant matches nothing.
- The bundle has no `relatedImages` yet, so disconnected (mirrored) clusters
  have to mirror the chart's images by hand.
- `migrate.ttlSecondsAfterFinished` has no effect under the Operator (see
  Upgrades).
- **Not yet verified on a real cluster through OLM:** install, the upgrade loop
  being absent (the release revision stays put across reconciles), and an
  Operator upgrade. The behaviour above is from helm-operator's source
  (operator-sdk v1.42.3, Helm 3.18) and chart renders.

## For maintainers

| Path | Purpose |
|---|---|
| `operator/Dockerfile` | helm-operator base + the chart from `charts/spatiumddi`, stamped with `VERSION` |
| `operator/watches.yaml` | the one watch (`SpatiumDDI` to the vendored chart) |
| `operator/config/` | CRD, RBAC, manager Deployment, sample, CSV base |
| `operator/bundle/`, `operator/bundle.Dockerfile` | the generated dev bundle (`0.0.0-dev`), regenerated and diffed by CI |
| `operator/hack/build-bundle.sh` | bundle + community layout generator |
| `operator/hack/check_rbac.py` | fails when the RBAC no longer covers what the chart renders |
| `.github/workflows/operator.yml` | PR checks; opt-in publish |

**Cutting a release.** Nothing is edited by hand; the CSV version, the image tag
and the chart version are the one release version.

```bash
make operator-bundle VERSION=1.0.0 COMMUNITY=/tmp/community VALIDATE=1
# -> /tmp/community/operators/spatiumddi/1.0.0/{manifests,metadata}
#    /tmp/community/operators/spatiumddi/ci.yaml  (reviewers, semver-mode)
```

Copy `operators/spatiumddi/` into
[`k8s-operatorhub/community-operators`](https://github.com/k8s-operatorhub/community-operators)
and
[`redhat-openshift-ecosystem/community-operators-prod`](https://github.com/redhat-openshift-ecosystem/community-operators-prod)
as a PR to each. Publishing the image is off until the repository variable
`OPERATOR_PUBLISH` is `true`; the workflow then pushes
`ghcr.io/spatiumnorth/spatiumddi-operator:<version>` (amd64 and arm64) on a
SemVer release tag and uploads the community layout as an artifact. Unlike
`release.yml`, that job does not wait for CI on the tagged commit and runs no
Trivy scan (the PR check's scan is advisory, because the open findings are inside
upstream's helm-operator binary), so check both before turning it on.

**Trying a bundle.** Build the image (`make operator-image VERSION=...`), push
it somewhere the cluster can pull, generate the bundle with
`OPERATOR_IMAGE_REPO=<your repo>`, then `operator-sdk run bundle` it.

**Adding a chart template.** `make operator-check` renders the chart in each
supported shape and fails when `operator/config/rbac/` does not cover a rendered
kind or Role. Add the matching rule there.

The pinned versions (operator-sdk and the helm-operator base image) are in
`versions.json`; the image's third-party base is in `docs/THIRD_PARTY.md`.
